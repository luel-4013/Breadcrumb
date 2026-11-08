# Release notes — Phase 8 (Leadline importer and hardening)

**Release:** Breadcrumb + Leadline merge, Phase 8
**Date:** 2026-11-08
**Version:** `0.4.0` (Leadline merge release)
**Schema:** version 4
**Test suite:** **182 passed, 1 warning**

Phase 8 closes the merge: existing Leadline data can be imported one way into
Breadcrumb, the import can be verified against the source, and the operational
runbooks/checklists needed to run and roll back the combined system are in
place. Breadcrumb remains the flagship import-first notebook and the only
system of record. The Leadline folder is retained as a reference/fallback.

---

## 1. Highlights

- **`import-leadline` CLI** with dry-run, real import, resume manifest,
  post-import verification and JSON reporting.
- **Read-only source.** The Leadline database is opened `mode=ro` with
  `PRAGMA query_only=ON`; its fingerprint is checked before and after reading.
  Breadcrumb never modifies, archives or deletes the Leadline folder.
- **Complete mapping.** Targets, custom headers, scans, events/phases,
  findings, triage state, graph nodes/parents/edges and timestamps are
  preserved. Headers become encrypted `HeaderProfile` rows; no plaintext is
  written.
- **Historical scans are terminal.** Imported scans are `ScanJob` rows with
  `runner=leadline.imported`; the worker cannot claim them and retry/run-now
  returns `409`.
- **Per-scan history.** Imported snapshots are scoped to their source scan, so
  diffs between imported scans are meaningful while live snapshots remain
  cumulative target state.
- **Real-data verification.** The importer was exercised against a copy of the
  owner's Leadline database and re-run idempotently; the source fingerprint did
  not change.
- **Hardening docs.** Merge guide, compatibility API, security model,
  hardware/AI guide, troubleshooting, backup/restore/upgrade runbook, security
  checklist and rollback plan.
- **Acceptance script.** `scripts/acceptance_phase8.py` runs the whole flow on
  copies and emits a pass/fail report.

---

## 2. Importer

### Command

```bash
.venv/bin/python -m app.cli import-leadline --db /path/to/leadline.db [flags]
```

| Flag | Effect |
|---|---|
| `--db <path>` | Leadline SQLite database (required) |
| `--program <id>` | Merge into an existing Breadcrumb program |
| `--program-name <name>` | Destination program name (default `Leadline import`) |
| `--manifest <path>` | Resume/ID-map JSON (default `<BREADCRUMB_DB_PATH>.leadline-import.json`) |
| `--dry-run` | Counts and warnings only; no rows, no manifest |
| `--verify` | Compare an existing import; no writes |
| `--no-backup` | Skip the destination backup (not recommended) |
| `--no-snapshots` | Skip history snapshots for imported scans |
| `--no-verify` | Skip post-import verification |
| `--report <path>` | Write the full JSON result |
| `--json` | Print the full JSON result |

### Behavior

1. Opens the source read-only and fingerprints it (main file + WAL).
2. On a real import: backs up the destination, enables maintenance mode, and
   writes everything in one transaction.
3. Creates or reuses the destination program.
4. Imports targets and distinct header sets (encrypted), then scans,
   attempts/phases/events, findings with triage, entities and graph
   relationships.
5. Generates snapshots for imported scans, runs verification, and writes the
   manifest atomically with mode `0600`.
6. Aborts rather than storing plaintext if header encryption is unavailable.

### Mapping summary

| Leadline | Breadcrumb |
|---|---|
| `Target` | `Target` in the import program; URL/host as name; notes/timestamps preserved |
| `custom_headers` | Encrypted `HeaderProfile` (`family=leadline`); target meta stores the profile id |
| `Scan` | Historical `ScanJob` (`runner=leadline.imported`, `attempts=1`, `max_attempts=1`) |
| `ScanEvent` | `ScanPhase` with order/status/timestamps and capped result data |
| `Finding` | `Finding` (`source_tool=leadline`, stable fingerprint, `meta` preserves extra data/location/source ids) |
| `triage_status` | `status`/`verdict` through `app.triage` (open / acknowledged / false_positive) |
| `GraphNode` | `Entity` (`parser=leadline-import`); parents/edges become `part_of`/`references` |
| Report blobs | Not stored; reports are regenerated from imported data |

### Verification

`--verify` checks:

- target/scan/event/finding/graph counts;
- triage and severity distributions;
- sampled finding title/severity/triage/notes/location/evidence;
- header-profile decryption round-trip;
- the source fingerprint.

A failed check exits non-zero and lists the mismatch. The manifest is never
deleted automatically.

---

## 3. Real-data result

Source: `<owner's Leadline folder>/leadline.db` (path redacted; target
identifiers are redacted in this public report)
(copied with SQLite's online backup API before reading).

| Item | Result |
|---|---|
| Source rows | 2 targets, 0 scans/events/findings/graph nodes |
| Source size / fingerprint | 106,496 bytes / `a0331f…c26648a` |
| Program | `#1 Leadline import` |
| Imported | 2 targets, 2 encrypted header profiles |
| Destination backup | Created automatically |
| Post-import verification | **OK** (all 6 checks) |
| Re-run | Idempotent (0 imported, 2 targets skipped) |
| Acceptance script | **PASS** (all 6 checks) |

The real database contained no scans, findings or graph rows, so those paths
are proven by the synthetic fixture in `tests/test_phase8.py`, not by this
database. See [LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md).

---

## 4. Schema and upgrade notes

- Schema version **4** adds `target.meta` and `finding.meta` (JSON text). The
  migration is additive; a pre-migration backup is written automatically.
- **Back up the key.** Header profiles are encrypted with
  `<BREADCRUMB_DB_PATH>.key` (or `BREADCRUMB_KEY_FILE` /
  `BREADCRUMB_SECRET_KEY(S)`). A database backup without its key cannot decrypt
  header values.
- The live `breadcrumb.db` still contains two plaintext header profiles and no
  key file. First startup/CLI use creates `breadcrumb.db.key`, backs up the
  database and encrypts them. Older `*.pre-migrate-*.bak` files may contain
  plaintext; keep them private or remove them after verification.
- Imported programs start with **empty scope**. New scans fail closed until the
  operator adds scope explicitly; this is intentional.
- Imported jobs cannot be retried or re-run. Queue a new scan instead.

See [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md) and
[ROLLBACK_PLAN.md](ROLLBACK_PLAN.md).

---

## 5. Safety posture

Unchanged from Phases 0–7:

- Executor default **off**; activation is `breadcrumb worker` or
  `BREADCRUMB_EXECUTOR=inline`.
- External adapters opt-in (`BREADCRUMB_EXTERNAL_TOOLS=1` for worker claims);
  explicit run-now can execute one adapter job.
- Strict mode (`BREADCRUMB_STRICT_MODE=1`) disables unpinnable adapters.
- Private/loopback targets allowed with a visible warning;
  metadata/link-local/multicast/unspecified are hard-blocked; unknown or
  out-of-scope targets fail closed.
- Evidence chain formula unchanged:
  `sha256(f"{prev_chain or 'genesis'}:{content}")`.
- The importer never creates captures or presents imported data as
  Breadcrumb-sealed network evidence.

New in Phase 8:

- Source read-only + before/after fingerprint.
- Dry-run writes nothing.
- Destination backup + maintenance mode + single transaction.
- Abort on unavailable encryption rather than plaintext headers.
- Imported-job guards in the UI, API and worker.

---

## 6. Tests and acceptance

- `tests/test_phase8.py` — 8 tests:
  - dry run reports counts without writing;
  - CLI dry-run wiring;
  - full mapping/triage/headers/snapshots/PDF;
  - idempotent re-import;
  - imported jobs are historical and not runnable;
  - verification detects a missing finding;
  - missing/non-Leadline sources rejected;
  - a source with no scan tables is treated as empty.
- Full suite: **182 passed, 1 warning**.
- `compileall app` passes.
- `scripts/acceptance_phase8.py` passes on real data.

Run the acceptance script on copies:

```bash
.venv/bin/python scripts/acceptance_phase8.py \
  --source "/path/to/Leadline/leadline.db" \
  --database breadcrumb.db \
  --keep --json
```

The script copies both inputs into a temporary directory; it never writes to
the paths you pass.

---

## 7. Documentation added

- [LEADLINE_MERGE_GUIDE.md](LEADLINE_MERGE_GUIDE.md)
- [LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md)
- [COMPATIBILITY_API.md](COMPATIBILITY_API.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [HARDWARE_AI_GUIDE.md](HARDWARE_AI_GUIDE.md)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md)
- Updated: [README.md](README.md), [LEADLINE_PARITY_MATRIX.md](LEADLINE_PARITY_MATRIX.md),
  [MERGE_HISTORY.md](MERGE_HISTORY.md), root `CHANGELOG.md`.

---

## 8. Known limitations

- The real Leadline database had no scans/findings/graph rows; those import
  paths are covered by synthetic fixtures.
- Report blobs are not imported; reports are regenerated from imported data.
- `custom_headers` are not exposed through the compatibility API; manage them
  through Breadcrumb's encrypted header profiles.
- The importer is one-way. Breadcrumb does not write back to Leadline.
- The UI/API remains local-only with no login; do not expose it to a network.
- External tools still resolve names themselves; strict mode and an egress
  firewall are the deployment controls.
- The merge is released as **0.4.0**.

---

## 9. Rollback

See [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md). The short version:

1. Disable the executor/adapters.
2. For a bad import, stop everything and restore the `.pre-import` backup plus
   its key.
3. For a bad migration, restore the `.pre-migrate` backup plus its key and run
   the previous code.
4. The Leadline folder remains available as the original fallback throughout.

**Sign-off:** capability parity and the real-data import are recorded in
[LEADLINE_PARITY_MATRIX.md](LEADLINE_PARITY_MATRIX.md). The checklist in
[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) was signed for `0.4.0` on
2026-11-08; the residual risks listed there are accepted.
