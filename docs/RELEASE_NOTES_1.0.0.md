# Breadcrumb 1.0.0 release notes

**Release date:** 2026-11-12
**Version:** 1.0.0
**Schema:** 8
**Tag:** `v1.0.0`

Breadcrumb 1.0 is the first release with a complete evidence-to-report path and
a signed release gate: import, remember, diff, scope, report, bundle, automate
and capture, with local-only storage and no required cloud service.

## What Breadcrumb is

Breadcrumb is the offline-first evidence notebook for solo bug-bounty hunters.
It turns output from tools you already run into structured, hash-chained
evidence; remembers assets across programs; and renders redacted reports and
verifiable offline review bundles. One SQLite database, one local process, no
account and no telemetry.

## What it is not

- Not a scanner, exploitation framework or brute-force tool.
- Not a full vulnerability-management, ticketing or team-SaaS product.
- Not multi-tenant; there is no SSO/RBAC or default network authentication.
- Not a cloud/distributed scanning control plane.
- Not a browser-automation screenshot tool.
- Not an autonomous AI agent; the optional local LLM narrates deterministic
  evidence.

## Highlights since 0.4.0

### 0.5.0 — Proof

Parser contract and import reports, Evidence Manifest v2, `breadcrumb doctor`,
idempotent demo, pagination and benchmark harness.

### 0.6.0 — Memory

Ledger v2 with cross-program “seen before” memory, Diff v2, Scope v2 with
stable reason codes and status filters, Graph v2 and saved local views.

### 0.7.0 — Report

Five built-in templates, typed variable validation, default-on redaction,
HackerOne/DefectDojo/Ghostwriter/Dradis/SARIF exports, and a deterministic
read-only review bundle with an in-memory verifier.

### 0.8.0 — Automate

Local folder schedules with run history and stale recovery, a local parser SDK,
idempotent/bulk/paginated API automation, and measured 100k-import/1M-read
performance.

### 0.9.0 — Capture

EyeWitness/Gowitness screenshot import, content-addressed artifact storage
outside SQLite, hash verification, explicit screenshot reports/bundles, and
adapter diagnostics. No browser or Chromium dependency.

### 1.0.0 — Flagship gate

- **Offline release checker:** `breadcrumb release check` scans tracked source
  for `shell=True`/dynamic eval, credential shapes, broken relative docs links,
  runtime dependency pin mismatches, and missing CLI/API reference coverage.
- **Migration and rollback drill:** `scripts/migration_drill.py` upgrades
  databases created by `v0.4.0` through `v0.9.0`, verifies counts/schema/chain,
  restores the automatic pre-migration backup, and proves the old code still
  opens it. It can also upgrade a copy of a real database.
- **Reliability harness:** `scripts/soak.py` repeatedly imports folder
  schedules, injects stale runs and expired worker leases, takes integrity
  backups and verifies the chain. Use `--duration 86400` for the wall-clock
  acceptance run.
- **Dependency audit:** `scripts/dependency_audit.py` verifies pins offline and
  optionally queries OSV with package names/versions only.
- **Docs:** [WHY_BREADCRUMB.md](WHY_BREADCRUMB.md), full
  [CLI_REFERENCE.md](CLI_REFERENCE.md) and [API_REFERENCE.md](API_REFERENCE.md),
  [MIGRATION_DRILL.md](MIGRATION_DRILL.md),
  [RELIABILITY_SOAK.md](RELIABILITY_SOAK.md),
  [SUPPORT_POLICY.md](SUPPORT_POLICY.md) and [ROADMAP.md](ROADMAP.md).
- **Security review:** [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) is
  refreshed and signed for 1.0, including manifest, redaction, screenshot,
  parser-plugin and schedule threats.

## Verification at release

| Check | Result |
|---|---|
| Full suite | **276 passed, 1 warning** |
| Release checker | `breadcrumb release check` — PASS (0 dangerous, 0 secrets, 0 broken links, pins match) |
| Dependency audit | 8 runtime pins match; OSV query returned 0 known vulnerabilities |
| Migration drill | `v0.4.0`–`v0.9.0` upgraded; counts/chain preserved; rollback to each old schema passed |
| Real database copy | Legacy `breadcrumb.db` copy upgraded to schema 8, integrity `ok`, chain valid |
| Soak smoke | 40 cycles, 40 ingests, 5 stale-run recoveries, 3 lease recoveries, 4 backups, integrity `ok`, chain valid |
| Scale evidence | 100,001 entities in 80.913 s (~1,236/s); 1M entities seeded in 31.273 s; slowest query 1.395 s |

The wall-clock 24-hour soak is an operator acceptance step, not a claim made by
the short CI smoke. The harness supports it with `--duration 86400`; see
[RELIABILITY_SOAK.md](RELIABILITY_SOAK.md).

## Upgrade from 0.4.0–0.9.0

1. Stop the app and worker.
2. Back up the database **and** the key file; also back up the artifact
   directory if you use screenshots.
3. Install the pinned requirements and start the app (or run a CLI command).
   `init_db()` writes a pre-migration backup, applies additive tables/columns
   and updates `appstate.schema_version` to 8.
4. Run `breadcrumb doctor`, `/api/v1/verify` and open one existing report.
5. If you need to roll back, restore the pre-migration backup and check out the
   previous tag. Do not point an old binary at the migrated database.

Full commands: [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md) and
[ROLLBACK_PLAN.md](ROLLBACK_PLAN.md).

## Known limitations

- The local UI/API has no authentication. Keep it on loopback or put it behind
  a reverse proxy that you control.
- Redaction masks text fields, not pixels visible inside screenshots. Review
  images before sharing them.
- Local parser plugins execute in-process with the user's permissions. Only
  install parsers you trust.
- External tool adapters execute a local binary with the user's permissions;
  there is no sandbox. Strict mode and an egress firewall are deployment
  controls.
- The 24-hour soak is a wall-clock operator run; the release ships the harness
  and a short smoke result.
- The OSV dependency audit is a point-in-time check, not a guarantee.

## Release artifacts

Generate the source archive and checksums after tagging:

```bash
git archive --format=zip --prefix=breadcrumb-1.0.0/ v1.0.0 \
  -o dist/breadcrumb-1.0.0.zip
sha256sum dist/breadcrumb-1.0.0.zip > dist/SHA256SUMS
sha256sum -c dist/SHA256SUMS
```

`dist/` is ignored by git. Publish the archive and `SHA256SUMS` together.
