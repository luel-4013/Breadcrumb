# Security review checklist (Leadline merge)

Use this before treating the merge as signed off or exposing the installation
to any new environment. Check every item; record the evidence/commit and the
date. “Pass” means observed, not assumed.

**Release:** Breadcrumb + Leadline merge, `0.4.0`, schema version 4
**Date:** 2026-11-08
**Owner:** luel-4013 (repository maintainer)

**Preparation note (2026-11-08):** the checked items are backed by the automated
suite (`182 passed, 1 warning`), the Phase 8 acceptance script (6/6 checks on
copies), configuration review, or the live `/health`/verify endpoints where
noted. The live `breadcrumb.db` still contains legacy plaintext header profiles
and has no key file yet; it is ignored by git and is migrated/encrypted on the
first startup of this release. The release itself is ready for the first push.

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

## 7. Reports and exports

- [x] False positives are excluded by default.
- [x] `include_triaged=1` is the explicit internal switch.
- [x] Unverified CVE candidates do not contribute to risk.
- [x] Captured text is escaped before PDF/HTML generation.
- [x] Export filenames are safe (no path traversal/control characters).
- [x] Secrets are masked unless `reveal=1` is explicitly used.
- [x] Compatibility exports use the same snapshot policy.

**Evidence:** PDF escaping/filename tests; hostile-text fixture.

---

## 8. Backup and recovery

- [x] Backup uses SQLite’s online backup API (WAL-safe), not a live `cp`.
- [x] DB and key are backed up together but stored with restricted permissions.
- [x] Restore removes stale `-wal`/`-shm`.
- [x] Restored DB passes `PRAGMA integrity_check`.
- [x] Restored DB passes `/api/v1/verify`.
- [x] Pre-migration/pre-import backups are retained until verification.
- [x] Rollback plan is current and tested on a copy.

**Evidence:** restore drill on a copy; backup integrity output.

---

## 9. Dependencies and code hygiene

- [x] `requirements.txt` pins runtime dependencies.
- [x] `compileall app` passes.
- [x] Full test suite passes (182 tests at Phase 8 sign-off).
- [x] No `shell=True`, `eval`, or unpinned subprocess path in collectors.
- [x] No raw network client outside the collector/guard path.
- [x] No secrets committed to the repo or docs.
- [x] Schema version and migration test are current.

**Evidence:**

```bash
.venv/bin/python -m compileall -q app
.venv/bin/python -m pytest -q
grep -R "shell=True" app || true
```

---

## 10. Documentation and sign-off

- [x] Merge guide, compatibility API, security model, hardware/AI guide,
      troubleshooting, backup/restore/upgrade, checklist, release notes and
      rollback plan are present and linked from `docs/README.md`.
- [x] Parity matrix O/P rows are marked verified.
- [x] Release notes state known limitations (real DB had no scans; synthetic
      fixture covers those paths).
- [x] Owner signs the parity matrix and accepts residual risks (private-target
      SSRF, local no-auth UI, external-tool resolution gap).
- [x] Leadline folder retained; no automatic deletion.

**Sign-off:**

| Role | Name | Date | Signature/commit |
|---|---|---|---|
| Owner | luel-4013 (repository maintainer) | 2026-11-08 | `0.4.0` release preparation; self-attested under owner instruction |
| Reviewer | Automated suite + Phase 8 acceptance | 2026-11-08 | 182 passed, 1 warning; 6/6 acceptance checks |

---

## 11. Residual risks accepted at sign-off

1. Private/loopback scanning is allowed with a warning; metadata/link-local
   are blocked but the local network is reachable by design.
2. The UI/API has no authentication and must remain loopback-only.
3. External tools resolve names themselves; strict mode/egress firewall are
   the deployment controls.
4. Header values are visible in the local UI by design (curl-copy workflow);
   encryption protects files/backups, not a compromised local session.
5. The real Leadline database contained no scans/findings/graph rows; those
   import paths are proven by synthetic fixtures, not by that database.
