# Migration and rollback drill

**Drill date:** 2026-11-12
**Release under test:** Breadcrumb 1.0.0, schema 8
**Script:** [`scripts/migration_drill.py`](../scripts/migration_drill.py)
**Result:** PASS for `v0.4.0`–`v0.9.0` and a copy of the real legacy database.

The drill does not touch the source database. For every tag it creates a
temporary git worktree, seeds a database with that release's own code, upgrades
a copy with the current code, verifies counts/schema/chain, restores the
automatic pre-migration backup, and opens the restored copy with the old code.

## Reproduce

```bash
.venv/bin/python scripts/migration_drill.py --all \
  --real-db breadcrumb.db \
  -o /tmp/breadcrumb-migration-drill.json
```

The command prints a JSON summary and exits non-zero if any check fails. The
`--real-db` argument upgrades a **copy** and reports integrity/schema; the
original file is unchanged.

## Evidence

Each seeded database contained one program, one target, one capture, six
entities and one finding. The capture was created through the old release's
normal ingest path, so the evidence chain is real.

| Source tag | Source schema | Upgrade schema | Pre-migration backup | Counts preserved | Chain valid | Rollback schema | Rollback result |
|---|---|---|---|---|---|---|---|
| `v0.4.0` | 4 | 8 | yes | yes | yes | 4 | PASS |
| `v0.5.0` | 5 | 8 | yes | yes | yes | 5 | PASS |
| `v0.6.0` | 6 | 8 | yes | yes | yes | 6 | PASS |
| `v0.7.0` | 6 | 8 | yes | yes | yes | 6 | PASS |
| `v0.8.0` | 7 | 8 | yes | yes | yes | 7 | PASS |
| `v0.9.0` | 8 | 8 | not needed | yes | yes | 8 | PASS |

Checks performed at every tag:

- `upgrade_schema`: `appstate.schema_version == 8`;
- `upgrade_integrity`: `PRAGMA integrity_check == ok`;
- `upgrade_chain`: `/api/v1/verify` logic reports a valid chain;
- `upgrade_counts`: program/target/paste/entity/finding counts unchanged;
- `rollback_schema`: restored backup reports the source tag's schema;
- `rollback_integrity`: restored backup is `ok`;
- `rollback_chain`: the old code (or the v0.4.0-compatible local chain check)
  validates the restored chain;
- `rollback_counts`: restored counts match the seed counts.

### Real database copy

The checkout's legacy `breadcrumb.db` had no `appstate` row and the old
schema-2-style tables, with zero programs/targets/captures/entities/findings.
A copy upgraded to schema 8 with:

- `PRAGMA integrity_check: ok`
- `schema_version: 8`
- chain verification: valid
- counts preserved (all zero)
- a pre-migration backup created

This proves the migration path runs on the actual legacy file shape; it does
not claim that the legacy file contained rich data. The synthetic seeds above
cover the non-empty case.

## What the migration does

`init_db()` is additive:

1. Detect that the file needs an upgrade and write
   `<database>.pre-migrate-<UTC>.bak` (unless `BREADCRUMB_SKIP_BACKUP=1`).
2. `create_all` adds missing tables (`Schedule`, `ScheduleRun`,
   `EvidenceArtifact`, `AppState`, and earlier additions).
3. Add missing columns with `ALTER TABLE ... ADD COLUMN`.
4. Backfill the linear capture chain only where a sequence/head is missing;
   existing hashes are never recomputed.
5. Create indexes idempotently.
6. Encrypt legacy plaintext header profiles, scrub the pre-migration backup,
   checkpoint/VACUUM.
7. Update `appstate.schema_version`.

No table is dropped and no evidence hash is rewritten. Old binaries should not
open the migrated file; restore the pre-migration backup before running the old
tag.

## Rollback

```bash
cp breadcrumb.db /secure/rollback/before.db
cp breadcrumb.db.pre-migrate-YYYYMMDD-HHMMSS.bak breadcrumb.db
rm -f breadcrumb.db-wal breadcrumb.db-shm
chmod 600 breadcrumb.db
```

Restore the matching key file too. If screenshots were added after the backup,
the restored database will not reference them; leave the artifact directory in
place (orphan files are harmless) or restore the matching artifact snapshot.
See [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md) and
[BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md).

## Limitations

- The drill uses synthesized program/target/capture/finding data. It does not
  copy a user's real findings.
- Parser behavior is covered by the normal parser fixtures, not by every old
  tag's parser corpus.
- A disk-full or interrupted migration still requires the backup; the drill
  proves the backup is created and restorable, not that every I/O failure is
  automatically repaired.
