# Support and deprecation policy

**Applies to:** Breadcrumb 1.0.0 and later.
**Audience:** users and contributors maintaining a local installation.

Breadcrumb is a small, local-first project. Support is best-effort and
repository-based; there is no hosted service, account or guaranteed response
time.

## Supported versions

| Version | Status | Notes |
|---|---|---|
| 1.0.x | Supported | Security and correctness fixes |
| 0.9.x | Upgrade recommended | Superseded by 1.0; no new features |
| 0.8.x and older | Unsupported | Upgrade through the runbook; keep a backup |

Security fixes are issued for the latest 1.x release. A critical fix may be
backported one minor version at the maintainer's discretion. Old schema
versions remain readable through the additive migration path, but running old
code against a newer database is not supported; restore the pre-migration
backup first.

## Release cadence

- Patch releases for security, data-loss or import-correctness defects.
- Minor releases for new parsers, reports, adapters or workflow improvements.
- Major releases only for a breaking storage or API contract.

Every release includes a changelog entry, the schema version, the test count,
and migration/rollback notes when the on-disk contract changes. Tags are
annotated; release archives are published with `SHA256SUMS`.

## Deprecation

- A deprecated CLI flag or API field is documented in the changelog and kept
  for at least one minor release.
- Schema columns are not dropped in a minor release. Additive migrations are
  the default; a destructive migration would require a major version and a
  documented export path.
- Parser output changes are treated as behavioral changes: add a fixture and a
  changelog note. If a tool changes its format, the parser reports a visible
  error or zero-result diagnostic rather than silently guessing.
- File formats (Evidence Manifest v2, review bundle, artifact manifest, ledger
  JSONL) are versioned. A new version ships with a reader for the previous
  version or an explicit migration command.

## Upgrade and rollback support

The supported path is:

1. Read the release notes and [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md).
2. Back up the database, key and artifact directory.
3. Run `breadcrumb doctor` before and after the upgrade.
4. Run `/api/v1/verify` after the upgrade.
5. If the upgrade fails, restore the pre-migration database and the matching
   key, then run the previous tag. See [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md).

`scripts/migration_drill.py` is the repeatable evidence for this path. It is
run before a release, not on a user's live database.

## Security reports

Do not open a public issue with exploit details. Use the repository's private
security-advisory mechanism or contact the maintainer privately. Include the
version/commit, reproduction steps, and whether the issue requires local
access, a malicious target, a malicious parser plugin or an external tool.
See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Scope of support

Supported: installation, migration, imports, reports, bundles, schedules,
screenshot artifacts, local API and the documented CLI.

Not supported: multi-user deployment, SSO/RBAC, cloud/distributed scanning,
exploitation, writing parsers or adapters for third-party tools, or recovering
data when both the database and every backup are lost. A lost encryption key
makes encrypted header profiles unrecoverable; the rest of the database remains
readable.
