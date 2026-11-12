# Security review checklist (Breadcrumb 1.0.0)

Use this before exposing the installation to any new environment or signing a
release. Check every item; record the evidence/commit and the date. “Pass”
means observed, not assumed.

**Release:** Breadcrumb 1.0.0, schema version 8
**Date:** 2026-11-12
**Owner:** luel-4013 (repository maintainer)

**Preparation note (2026-11-12):** the checked items are backed by the automated
suite (`276 passed, 1 warning`), `breadcrumb release check` (0 dangerous
constructs, 0 credential shapes, 0 broken docs links, runtime pins matched,
CLI/API reference coverage complete), the dependency audit (8 runtime pins,
0 OSV matches), the all-tag migration/rollback drill (`v0.4.0`–`v0.9.0`), the
40-cycle soak smoke, configuration review, and the live `/health`/verify
endpoints where noted. The legacy `breadcrumb.db` is ignored by git, contains no
application data, and upgrades cleanly on a copy to schema 8. The wall-clock
24-hour soak remains an operator acceptance step; the harness is shipped and
documented.

---

## 1. Local boundary

- [x] App binds to `127.0.0.1` by default; no `0.0.0.0`/LAN exposure.
      (Docker sets `0.0.0.0` *inside* the container; `docker-compose.yml`
      publishes only `127.0.0.1:8787`.)
- [x] Host allowlist rejects unknown `Host` values (`Invalid Host header`).
- [x] Cross-origin `Origin` and `Sec-Fetch-Site` writes are rejected.
- [x] HTML form POSTs require a valid CSRF token.
- [x] No login is claimed; docs state the app is single-user/local-only.
- [x] `/health` does not expose secrets or header values.

**Evidence:**

```bash
curl -s -H 'Host: evil.example' http://127.0.0.1:8787/health   # rejected
curl -s -H 'Origin: http://evil.example' -X POST ...           # rejected
```

---

## 2. Scope and SSRF

- [x] Unknown/out-of-scope targets fail closed (no connection/spawn).
- [x] Excluded targets fail closed.
- [x] Private/loopback targets warn visibly and are allowed only by policy.
- [x] Metadata/link-local/multicast/unspecified/reserved are hard-blocked.
- [x] CIDR targets must be fully contained in scope.
- [x] Redirects are re-checked; out-of-scope redirects fail permanently.
- [x] Configured proxies are denied for native collectors.
- [x] A denied target never spawns an external adapter process.
- [x] `BREADCRUMB_STRICT_MODE=1` disables unpinnable adapters.

**Evidence:** scope matrix tests; adapter no-spawn marker tests; a manual
out-of-scope attempt in the UI.

---

## 3. Executor and adapters

- [x] Executor default is `off`.
- [x] Worker claims adapters only with `BREADCRUMB_EXTERNAL_TOOLS=1`.
- [x] External tools use argv lists (`shell=False`), never a shell string.
- [x] Options come from a fixed schema; injection attempts are rejected.
- [x] Child runs in a fresh process group; cancel/timeout kills the group.
- [x] Output is capped; truncation is recorded as a warning.
- [x] Child environment excludes proxies and application secrets.
- [x] Header profiles/cookies/authorization are never passed to a tool.
- [x] Missing binary is reported as “not installed”.
- [x] Adapter runs record the scope decision and phase stats.

**Evidence:** `tests/test_phase7.py`; `breadcrumb tools`; one explicit
authorized adapter run on a lab target.

---

## 4. Secrets at rest

- [x] Raw `headerprofile.headers` values start with `enc:v1:` (no plaintext)
      after migration; verified on migrated copies and the acceptance run. The
      ignored live `breadcrumb.db` still holds legacy plaintext until first
      startup of this release.
- [x] `headerprofile.proxy` is encrypted too.
- [x] Key file is created with mode `0600` on first use and is backed up
      separately (verified on copies/tests; the live DB creates it on first
      startup).
- [x] Key-loss produces a clear error; no silent regeneration.
- [x] Rotation works and keeps `<key>.old`.
- [x] Pre-migration backups are scrubbed or removed if scrubbing fails.
- [x] Logs/errors/exports/AI prompts redact secret values.
- [x] No secret appears in the import manifest.

**Evidence:**

```bash
sqlite3 breadcrumb.db "SELECT id, substr(headers,1,12) FROM headerprofile;"
stat -c '%a %n' breadcrumb.db.key
grep -R "Bearer \|api[_-]key\|password" logs/ 2>/dev/null   # no hits
```

---

## 5. Evidence chain

- [x] `/api/v1/verify` reports no broken links/forks.
- [x] Gaps from deleted programs are labeled gaps, not tampering.
- [x] Legacy unsealed captures are labeled unsealed.
- [x] Chain writes use `BEGIN IMMEDIATE`.
- [x] Concurrent writer test passes.
- [x] Restored backups verify cleanly.

**Evidence:** verify output; concurrent claim/seal test.

---

## 6. Leadline import

- [x] Source is opened `mode=ro` with `PRAGMA query_only=ON`.
- [x] Source fingerprint before/after matches.
- [x] `--dry-run` writes no rows and no manifest.
- [x] Destination backup exists before the real import.
- [x] Maintenance mode is on during the write and restored afterward.
- [x] Header profiles are encrypted; raw values are ciphertext.
- [x] Malformed rows are reported and skipped; valid rows import.
- [x] Imported jobs are terminal (`attempts=1`, `max_attempts=1`), not
      claimable, and retry/run-now returns `409`.
- [x] Imported program scope is empty; new scans fail closed.
- [x] Manifest is mode `0600` and source-path-scoped.
- [x] Re-run is idempotent (no duplicates).
- [x] `--verify` checks counts/triage/severity/samples/headers/source hash.
- [x] The Leadline folder was not modified, archived or deleted.

**Evidence:** `docs/LEADLINE_IMPORT_VERIFICATION.md`;
`tests/test_phase8.py`; `scripts/acceptance_phase8.py`.

---

## 7. Reports, redaction and bundles

- [x] False positives are excluded by default.
- [x] `include_triaged=1` is the explicit internal switch.
- [x] Unverified CVE candidates do not contribute to risk.
- [x] Captured text is escaped before PDF/HTML generation.
- [x] Export filenames are safe (no path traversal/control characters).
- [x] Redaction is on by default; built-in masking cannot be disabled by a
      custom rule. `--reveal`/`reveal=1` is explicit and marked unsafe.
- [x] Custom rules are additive (`literal:`/`regex:`) and rule text is never
      echoed into report JSON.
- [x] One redacted context renders every format; report values are typed and
      validated.
- [x] Review bundles are deterministic zips; verification runs in memory and
      checks checksums, manifest and capture manifests.
- [x] Screenshot inclusion is explicit, capped (50 images / 32 MiB) and
      verified by SHA-256; reports and docs state that pixels are **not**
      redacted.

**Evidence:** `tests/test_phase_c.py`, `tests/test_phase_e.py`; hostile-text
fixture; `breadcrumb verify-bundle`; `docs/REDACTION_GUIDE.md` and
`docs/SCREENSHOT_COOKBOOK.md`.

---

## 8. Backup and recovery

- [x] Backup uses SQLite’s online backup API (WAL-safe), not a live `cp`.
- [x] DB and key are backed up together but stored with restricted permissions.
- [x] The artifact directory is backed up with the DB; a DB without its
      artifact bytes is not a complete evidence backup.
- [x] Restore removes stale `-wal`/`-shm`.
- [x] Restored DB passes `PRAGMA integrity_check`.
- [x] Restored DB passes `/api/v1/verify`.
- [x] Restored artifacts pass their SHA-256 checks.
- [x] Pre-migration/pre-import backups are retained until verification.
- [x] Rollback plan is current and tested on a copy.

**Evidence:** restore drill on a copy; backup integrity output; all-tag
migration/rollback drill (`docs/MIGRATION_DRILL.md`).

---

## 9. Dependencies and code hygiene

- [x] `requirements.txt` pins runtime dependencies.
- [x] `compileall app` passes.
- [x] Full test suite passes (276 tests at 1.0.0 sign-off).
- [x] `breadcrumb release check` passes: no `shell=True`/dynamic eval,
      no credential shapes, no broken relative docs links, pins match, and every
      top-level CLI command and `/api/v1` route is documented.
- [x] `scripts/dependency_audit.py --online` matches all runtime pins and
      reports 0 known OSV vulnerabilities (point-in-time).
- [x] No secrets committed to the repo or docs.
- [x] Schema version and additive migration/rollback tests are current.
- [x] No telemetry, analytics or background network call is present.

**Evidence:**

```bash
.venv/bin/python -m compileall -q app
.venv/bin/python -m pytest -q
.venv/bin/python -m app.cli release check --json
.venv/bin/python scripts/dependency_audit.py --online
```

---

## 10. Phase A–F additions

- [x] **Proof (0.5.0):** import reports record parser/version, completeness,
      skipped rows and a zero-entity hint; Evidence Manifest v2 is redacted by
      default and `--reveal` is explicit; `doctor` is read-only.
- [x] **Memory (0.6.0):** Ledger/diff/scope/graph are local SQLite queries;
      scope reason codes are stable; saved views are local rows; ledger JSONL
      round-trips through the normal ingest path.
- [x] **Report (0.7.0):** five built-in templates, typed variables, default-on
      redaction, additive custom rules, deterministic bundle and in-memory
      verification. See section 7.
- [x] **Automate (0.8.0):** schedules read local folders only; failed files
      stay in place; stale `running` rows recover after
      `max(3600, interval × 2)` seconds; parser plugins load only from the
      local parser directory and are documented as in-process trusted code.
- [x] **Capture (0.9.0):** screenshot bytes are sniffed, size/dimension/row
      capped, content-addressed outside SQLite, hash-verified on read, and
      served with `nosniff` plus a sandbox CSP. SVG/PDF are rejected. Imports
      never auto-create targets. See `docs/SCREENSHOT_COOKBOOK.md`.
- [x] **Flagship gate (1.0.0):** offline release checker, dependency audit,
      all-tag migration/rollback drill, soak harness and support policy are
      present. See `docs/RELEASE_NOTES_1.0.0.md`,
      `docs/MIGRATION_DRILL.md` and `docs/RELIABILITY_SOAK.md`.
- [x] **Non-goals hold:** no Postgres/Redis/Neo4j, no cloud scanning, no
      browser automation, no remote plugin marketplace, no multi-tenant auth
      and no autonomous agent.

**Evidence:** `tests/test_phase_a.py` through `tests/test_phase_f.py`;
`scripts/migration_drill.py --all`; `scripts/soak.py --cycles 40`;
`breadcrumb release check`.

---

## 11. Documentation and sign-off

- [x] Merge guide, compatibility API, security model, hardware/AI guide,
      troubleshooting, backup/restore/upgrade, checklist, release notes and
      rollback plan are present and linked from `docs/README.md`.
- [x] 1.0 documentation is present: `WHY_BREADCRUMB.md`, full CLI and API
      references, migration drill, reliability soak, support policy and
      roadmap; every CLI command and `/api/v1` route is covered by the release
      checker.
- [x] Parity matrix O/P rows are marked verified.
- [x] Release notes state known limitations (legacy DB had no scans; synthetic
      fixtures cover those paths; 24-hour soak is an operator run).
- [x] Owner signs the parity matrix and accepts residual risks (private-target
      SSRF, local no-auth UI, external-tool resolution gap, in-process parser
      plugins, unredacted screenshot pixels).
- [x] Leadline folder retained; no automatic deletion.

**Sign-off:**

| Role | Name | Date | Signature/commit |
|---|---|---|---|
| Owner | luel-4013 (repository maintainer) | 2026-11-12 | `1.0.0` release preparation; self-attested under owner instruction |
| Reviewer | Automated suite + release gate | 2026-11-12 | 276 passed, 1 warning; release check PASS; 8 runtime pins, 0 OSV matches |
| Reviewer | Migration/rollback drill | 2026-11-12 | `v0.4.0`–`v0.9.0` PASS; real DB copy PASS |
| Reviewer | Soak smoke | 2026-11-12 | 40 cycles, 0 errors, integrity `ok`, chain valid |

---

## 12. Residual risks accepted at sign-off

1. Private/loopback scanning is allowed with a warning; metadata/link-local
   are blocked but the local network is reachable by design.
2. The UI/API has no authentication and must remain loopback-only.
3. External tools resolve names themselves; strict mode/egress firewall are
   the deployment controls.
4. Header values are visible in the local UI by design (curl-copy workflow);
   encryption protects files/backups, not a compromised local session.
5. The real Leadline database contained no scans/findings/graph rows; those
   import paths are proven by synthetic fixtures, not by that database.
6. Local parser plugins execute in-process with the user's permissions. There
   is no sandbox; only install parsers you trust.
7. Redaction masks text fields, not pixels inside screenshots. Review images
   before sharing a report or bundle.
8. The 24-hour soak is a wall-clock operator acceptance run. 1.0 ships the
   harness and a 40-cycle smoke, not a completed 24-hour result.
9. The OSV dependency audit is a point-in-time check, not a guarantee against
   future disclosures or transitive dependencies.
