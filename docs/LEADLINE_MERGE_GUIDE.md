# Leadline merge guide

**Status:** Phases 0–8 implemented and verified on 2026-11-08; released as
`0.4.0`.
**Audience:** the owner/operator of a single-user Breadcrumb installation.
**Scope:** how Breadcrumb absorbs Leadline’s scanning capability and how to
import an existing Leadline database without losing data.

Breadcrumb remains the flagship import-first recon notebook and the only system
of record. Leadline’s collectors, job execution, history/diff, triage, PDF and
compatibility API are now additive “hands” inside Breadcrumb. There is no
second service, no second database and no React port.

---

## 1. What changed

| Area | Before | After |
|---|---|---|
| Import | Paste/file/API ingestion | Same workflow, unchanged |
| Execution | External runners post results back | Optional native collectors, durable worker and opt-in external tool adapters |
| Jobs | Queue/status contract | Leases, retries, cancellation, crash recovery, run-now, imported history |
| History | Program change view | Per-target snapshots, timeline and scan-to-scan diffs |
| Reports | HTML/Markdown/JSON/CSV/SARIF/etc. | Adds PDF, risk highlights and triage-aware exports |
| API | `/api/v1` | `/api/v1` plus Leadline-shaped `/api/targets`, `/api/scans`, `/api/findings`, `/api/reports` |
| Data | Breadcrumb DB | One-way `import-leadline` importer; Leadline DB is never modified |
| Leadline folder | Separate app | Retained as reference/fallback; no automatic archive or deletion |

The evidence-chain formula is unchanged:
`sha256(f"{prev_chain or 'genesis'}:{content}")`.

---

## 2. Safety defaults

- The executor is **off** unless you set `BREADCRUMB_EXECUTOR=inline` or run
  `breadcrumb worker`.
- External tool adapters are **not claimed** by the worker unless
  `BREADCRUMB_EXTERNAL_TOOLS=1`.
- Strict mode (`BREADCRUMB_STRICT_MODE=1`) disables adapters that cannot be
  pinned to a resolved address.
- Private/loopback targets are allowed with a visible warning.
  Metadata/link-local/multicast/unspecified addresses are hard-blocked.
  Unknown/out-of-scope targets fail closed.
- The importer opens the source read-only, writes nothing on `--dry-run`,
  backs up the destination, and runs under maintenance mode.
- Header profiles are encrypted at rest. If encryption is unavailable, the
  import aborts rather than storing plaintext.

---

## 3. Before you import

1. **Stop the app and every worker** that uses the destination database.
2. **Back up the destination DB and its key**:

   ```bash
   sqlite3 breadcrumb.db ".backup '/secure/backups/breadcrumb-pre-import.db'"
   cp breadcrumb.db.key /secure/backups/breadcrumb-pre-import.db.key
   cp breadcrumb.db.key.old /secure/backups/breadcrumb-pre-import.db.key.old 2>/dev/null || true
   ```

   Losing the key makes encrypted header values unrecoverable. See
   [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md).

3. **Copy the Leadline database** rather than importing the live file:

   ```bash
   sqlite3 "/path/to/Leadline/leadline.db" ".backup '/tmp/leadline-copy.db'"
   ```

   The importer itself opens the source `mode=ro` and checks its fingerprint
   before/after reading, but a copy avoids racing a running Leadline process.

4. Make sure `BREADCRUMB_DB_PATH` points at the intended Breadcrumb database.
   The default is `./breadcrumb.db` next to the app.

---

## 4. Import workflow

The command is `python -m app.cli import-leadline` (or the equivalent
`breadcrumb import-leadline` entry point if you installed one).

### 4.1 Dry run

```bash
.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db \
  --program-name "Leadline import" \
  --manifest /tmp/leadline-import.json \
  --dry-run
```

The dry run prints source counts, the rows it would import, distinct header
sets, triage/severity distributions, malformed rows, warnings and the
destination state. It writes **no** rows and **no** manifest.

Useful machine-readable output:

```bash
.venv/bin/python -m app.cli import-leadline ... --dry-run --json \
  --report /tmp/leadline-dry-run.json
```

### 4.2 Real import

```bash
.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db \
  --program-name "Leadline import" \
  --manifest /tmp/leadline-import.json \
  --report /tmp/leadline-import-report.json
```

What happens:

1. The destination is backed up to
   `<BREADCRUMB_DB_PATH>.pre-import-<UTC timestamp>.bak`.
2. Maintenance mode is enabled, so no worker can claim a job during the write.
3. The program is created or reused.
4. Targets, encrypted header profiles, scans, attempts, events/phases,
   findings, triage, entities and graph relationships are written in one
   transaction.
5. The transaction commits; maintenance mode is restored.
6. History snapshots are generated for imported scans (unless
   `--no-snapshots`).
7. Post-import verification runs (unless `--no-verify`).
8. The manifest is written atomically with mode `0600`.

If the transaction fails, it is rolled back. If header encryption is
unavailable, the whole import aborts; no plaintext headers are written.

### 4.3 Verify an existing import

```bash
.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db \
  --manifest /tmp/leadline-import.json \
  --verify
```

Verification compares:

- target/scan/event/finding/graph counts;
- triage distribution;
- severity distribution;
- sampled finding title/severity/triage/notes/location/evidence;
- header-profile decryption round-trip;
- the source fingerprint.

`--verify --json` is suitable for CI or an audit record.

### 4.4 Re-run and resume

The manifest records the source path, source fingerprint, destination program
and the source-ID → destination-ID map. Re-running with the same manifest is
idempotent: existing targets/scans/findings/entities are skipped and counted,
not duplicated.

If an import is interrupted, keep the manifest and run the same command again.
Do not edit the manifest. If you import a different source path, the manifest’s
ID map is ignored with a warning and a fresh map is built for that source.

Default manifest path: `<BREADCRUMB_DB_PATH>.leadline-import.json`.

### 4.5 Useful flags

| Flag | Effect |
|---|---|
| `--program <id>` | Merge into an existing program instead of creating/reusing by name |
| `--program-name <name>` | Destination program name (default `Leadline import`) |
| `--manifest <path>` | Resume/ID-map file |
| `--no-backup` | Skip the destination backup (not recommended) |
| `--no-snapshots` | Skip history snapshots for imported scans |
| `--no-verify` | Skip post-import verification |
| `--report <path>` | Write the full JSON result |
| `--json` | Print the full JSON result |
| `--dry-run` | Report only; no writes |
| `--verify` | Compare an existing import; no writes |

---

## 5. Data mapping

| Leadline | Breadcrumb |
|---|---|
| `Target` | `Target` in the destination program; `name`/URL, `kind` inferred, notes and timestamps preserved |
| `Target.custom_headers` | Encrypted `HeaderProfile` named `Leadline import <hash12>`, family `leadline`; target `meta.leadline_header_profile_id` |
| `Target.is_active=false` | Visible note marker in `Target.notes` plus `meta.leadline_is_active=false` |
| `Scan` | Historical `ScanJob` with `runner=leadline.imported`, `params.imported=true`, `attempts=1`, `max_attempts=1` |
| `ScanEvent` | `ScanPhase` with preserved order/status/timestamps and capped `result_data` |
| `Finding` | `Finding` with `source_tool=leadline`, stable `leadline:<sha256(target_url|scan_id|finding_id)[:32]>` fingerprint |
| `Finding.triage_status` | `status`/`verdict` via `app.triage`: open → `open/none`, acknowledged → `in-progress/needs-review`, false_positive → `wont-fix/false-positive` |
| `Finding.triage_note` | `Finding.notes` |
| `Finding.extra_data` | `meta.leadline_extra_data`, plus tags/cvss/CVE tags where present |
| `GraphNode` | `Entity` with `parser=leadline-import`, `normalized=leadline:<scan_id>:<node_id>` |
| `GraphNode.parent_id` | `Relationship` `part_of`; non-contains explicit edges become `references` |
| Timestamps | Preserved where valid; missing timestamps fall back to the import time |
| Reports | Regenerated from imported data; no stored report blobs |

Imported findings/entities are marked with their Leadline scan and node IDs in
`meta`. The importer never fabricates captures or network evidence.

---

## 6. After the import

1. Open the destination program and inspect the target list.
2. Imported scans appear as **imported history** on `/runners` and the job page.
   They are terminal: the worker cannot claim them, **Run now** is hidden, and
   retry/run-now API calls return `409`.
3. The imported program’s scope is deliberately empty. New scans fail closed
   until you add scope rules. This is intentional: the importer does not
   silently authorize scanning the old targets.
4. To refresh a target, add scope and queue a new `leadline-recon` job (or use
   the compatibility API). Do not retry the historical row.
5. Open the target history timeline to see imported snapshots. Each imported
   snapshot is scoped to its own source scan (`meta.leadline_scan_id`), so
   diffs between imported scans are meaningful even though live snapshots
   remain cumulative target state.
6. Run `/api/v1/verify` after the import. Imported rows do not add captures,
   so the chain result depends only on Breadcrumb’s own sealed evidence.

---

## 7. Acceptance

Run the standalone acceptance script on copies:

```bash
.venv/bin/python scripts/acceptance_phase8.py \
  --source "/path/to/Leadline/leadline.db" \
  --database breadcrumb.db \
  --keep
```

It copies both inputs into a temporary directory, performs the dry run, real
import and verification, and checks the source fingerprint and raw header
ciphertext. Exit code 0 means every check passed. The script never writes to
the source or the database path you pass.

The real-data run is recorded in
[LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md).

---

## 8. Keeping Leadline

The local Leadline folder remains as a reference and fallback. Nothing in the
merge archives, tags, deletes or rewrites it. The owner may remove the remote
GitHub repository when satisfied; that is a manual decision, not part of this
work.

---

## 9. Related docs

- [LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md) — real
  data verification report.
- [COMPATIBILITY_API.md](COMPATIBILITY_API.md) — Leadline-shaped API.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — trust boundaries and scope rules.
- [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md) — backup, restore,
  schema upgrade and key handling.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common failures.
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) — release checklist.
- [RELEASE_NOTES_PHASE8.md](RELEASE_NOTES_PHASE8.md) — release notes.
- [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md) — rollback levels and steps.
