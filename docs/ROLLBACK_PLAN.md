# Rollback plan — Breadcrumb 1.0.0

**Applies to:** Breadcrumb 1.0.0 (Phases 0–8 plus flagship Phases A–F),
schema version 8.
**Date:** 2026-11-12.
**Audience:** the owner/operator of a single local installation.
**Goal:** return to a known-good state without losing evidence or breaking the
hash chain, at the smallest level that fixes the problem.

The Leadline folder is retained throughout. It is the original fallback and is
never archived, deleted or rewritten by Breadcrumb.

---

## 1. Rollback levels

Choose the smallest level that resolves the problem. Do not jump to a full
restore when disabling a capability is enough.

| Level | When | What you lose | Reversible |
|---|---|---|---|
| **L0 — Disable** | A scan/adapter is misbehaving; the app itself is healthy | Nothing; jobs stay queued | Yes |
| **L1 — Undo an import** | Imported data is wrong/incomplete; pre-import data is fine | Imported rows only (restore removes them) | Yes, re-import |
| **L2 — Undo a schema migration** | The new code cannot start or migrations fail | Any writes made after the migration | Yes, with backup |
| **L3 — Revert code** | New code is broken but the old schema is still valid | New features only | Yes, keep backup |
| **L4 — Full fallback to Leadline** | Breadcrumb is unusable and must be abandoned | Breadcrumb-only data written after the merge | Manual; Leadline folder intact |

---

## 2. Decision guide

| Symptom | First action | Level |
|---|---|---|
| A scan is hitting the wrong target | Cancel the job; clear scope; disable executor | L0 |
| An external tool misbehaves | Unset `BREADCRUMB_EXTERNAL_TOOLS`; cancel/retry | L0 |
| Imported findings/targets look wrong | Restore `.pre-import` backup + key | L1 |
| Import aborted or verification failed | Do **not** delete the manifest; inspect report; restore if the destination changed | L1 |
| Migration failed / app won't start | Restore `.pre-migrate` backup + key + artifacts; run previous code | L2 |
| New code has a bug but DB is fine | Check out previous commit; keep schema 8 | L3 |
| Everything is broken; need the old tool now | Stop Breadcrumb; start Leadline from its folder | L4 |

---

## 3. Before any rollback

1. **Stop the app and every worker.** Do not restore under a live writer.

   ```bash
   pgrep -af "app.main|app.cli|run.py"
   # stop each process
   ```

2. **Snapshot the current state**, even if it is bad. This preserves the
   failure for diagnosis and lets you return to it:

   ```bash
   mkdir -p /secure/rollback
   sqlite3 breadcrumb.db ".backup '/secure/rollback/breadcrumb-before-rollback.db'"
   cp breadcrumb.db.key /secure/rollback/breadcrumb-before-rollback.db.key
   cp breadcrumb.db.key.old /secure/rollback/breadcrumb-before-rollback.db.key.old 2>/dev/null || true
   rsync -a breadcrumb.db.artifacts/ /secure/rollback/breadcrumb-before-rollback.artifacts/
   chmod 600 /secure/rollback/*
   chmod -R u+rwX,go-rwx /secure/rollback/breadcrumb-before-rollback.artifacts
   ```

3. **Identify the target backup and key.** They must match:

   ```bash
   ls -l breadcrumb.db.pre-import-*.bak breadcrumb.db.pre-migrate-*.bak
   ls -l breadcrumb.db.key breadcrumb.db.key.old 2>/dev/null
   ```

4. **Record versions** for the report:

   ```bash
   .venv/bin/python -m app.cli version
   sqlite3 breadcrumb.db "SELECT schema_version FROM appstate WHERE id=1;"
   ```

---

## 4. L0 — Disable execution

No data changes. Use this first for any active scanning problem.

```bash
# Stop the worker (Ctrl-C or kill the `breadcrumb worker` process).
# Keep the executor off in the web process:
export BREADCRUMB_EXECUTOR=off
# Stop adapter claims:
unset BREADCRUMB_EXTERNAL_TOOLS
# Optional: put the queue in maintenance so nothing is claimed:
.venv/bin/python -m app.cli maintenance on --reason "rollback L0"
```

Cancel the affected job from the job page/API/CLI, then clear or narrow the
program scope. Maintenance mode does not stop a currently running job; cancel
it explicitly.

To resume:

```bash
.venv/bin/python -m app.cli maintenance off
```

**Verify:** `/health` shows `maintenance: false`, no running jobs, and the
executor is off.

---

## 5. L1 — Undo an import

Use when the imported rows are wrong but the pre-import database is good.

### 5.1 Find the backup

The importer writes `<BREADCRUMB_DB_PATH>.pre-import-<UTC timestamp>.bak`
unless `--no-backup` was used. If `--no-backup` was used, use the manual backup
you took before the import.

### 5.2 Restore

```bash
cp breadcrumb.db "/secure/rollback/breadcrumb-bad-import-$(date -u +%Y%m%d-%H%M%S).db"
cp breadcrumb.db.pre-import-YYYYMMDD-HHMMSS.bak breadcrumb.db
rm -f breadcrumb.db-wal breadcrumb.db-shm
cp breadcrumb.db.key /secure/rollback/breadcrumb-bad-import-key  # keep the bad state's key with its DB
```

The key does not change during an import, so the existing key still matches the
pre-import backup. If you rotated the key after the import, restore the key
that was active when the backup was taken.

### 5.3 Verify

```bash
sqlite3 breadcrumb.db "PRAGMA integrity_check;"
sqlite3 breadcrumb.db "SELECT schema_version FROM appstate WHERE id=1;"
BREADCRUMB_EXECUTOR=off .venv/bin/python run.py
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/v1/verify
```

Check that the imported program/targets are gone and the pre-import programs
are intact. Keep the import manifest; it is harmless after a restore and useful
for a clean re-import.

### 5.4 Re-import safely

```bash
# Work on a copy first.
sqlite3 "/path/to/Leadline/leadline.db" ".backup '/tmp/leadline-copy.db'"
.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db --program-name "Leadline import" \
  --manifest /tmp/leadline-import.json --dry-run
```

Then run the real import and `--verify`. See
[LEADLINE_MERGE_GUIDE.md](LEADLINE_MERGE_GUIDE.md).

**Do not** delete the manifest or edit its ID map to “fix” a failed import;
that breaks idempotency.

---

## 6. L2 — Undo a schema migration

Use when the new binary cannot start or a migration failed.

The migration path writes `breadcrumb.db.pre-migrate-<timestamp>.bak` before
the first schema change unless `BREADCRUMB_SKIP_BACKUP=1` was set. If it was
skipped, use your quiescent pre-upgrade backup.

### 6.1 Restore the pre-migration database and key

```bash
cp breadcrumb.db "/secure/rollback/breadcrumb-migrated-$(date -u +%Y%m%d-%H%M%S).db"
cp breadcrumb.db.pre-migrate-YYYYMMDD-HHMMSS.bak breadcrumb.db
rm -f breadcrumb.db-wal breadcrumb.db-shm
cp breadcrumb.db.key "/secure/rollback/breadcrumb-migrated-key"
# Restore the key that belongs to the pre-migration DB:
cp /secure/backups/breadcrumb-pre-upgrade.db.key breadcrumb.db.key
chmod 600 breadcrumb.db.key
```

If you use `BREADCRUMB_KEY_FILE` or `BREADCRUMB_SECRET_KEY(S)`, restore those
instead.

Restore the artifact directory that belongs to the pre-migration backup. A
database restored without its artifact bytes still opens, but screenshot rows
will report missing files.

### 6.2 Run the previous code

Schema 5–8 add parser metadata, saved views, schedules and screenshot artifact
tables. Do not point an old binary at the migrated DB. Restore the
pre-migration DB and check out the previous commit/build that produced it.

```bash
git stash            # keep uncommitted work if the repo is a git checkout
git checkout <previous-known-good-commit>
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m compileall -q app
```

If the working tree is not a git checkout, use the archived copy of the
previous code you kept with the backup.

Restore the matching artifact directory with the database. A pre-screenshot
database does not reference the newer files; leaving them in place is harmless.
A database that references screenshots must have those exact SHA-256 files or
the artifact view will report a mismatch.

### 6.3 Verify

```bash
sqlite3 breadcrumb.db "PRAGMA integrity_check;"
sqlite3 breadcrumb.db "SELECT schema_version FROM appstate WHERE id=1;"
BREADCRUMB_EXECUTOR=off .venv/bin/python run.py
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/v1/verify
```

Expected: schema version matches the old binary's `expected_schema_version`,
integrity is `ok`, and the chain has no new broken links or forks.

---

## 7. L3 — Revert code, keep the database

Use when schema 8 is fine but the new code has a defect.

1. Stop the app/worker.
2. Back up the current DB, key and artifacts (section 3).
3. Check out the previous known-good code.
4. Reinstall pinned requirements and run `compileall`.
5. Start with `BREADCRUMB_EXECUTOR=off`.
6. Verify `/health` and `/api/v1/verify`.

The old code may not understand new features, but additive columns are ignored
by SQLModel if the model does not declare them. If the old binary refuses to
start because of the schema version, use L2 instead. Do not delete the artifact
directory when reverting code; older code simply ignores it.

---

## 8. L4 — Full fallback to Leadline

Use only if Breadcrumb cannot be recovered. This is a manual product decision,
not an automated migration.

1. Stop Breadcrumb and its worker.
2. Keep the Breadcrumb database, key, backups and import manifest in place.
   Do not delete them; they are the record of work done in Breadcrumb.
3. Start Leadline from its original folder using its own database and
   environment. The folder was never modified by the merge.
4. Treat Leadline as read-only history until you decide whether to retry
   Breadcrumb later.
5. If you later return to Breadcrumb, restore the newest verified DB+key pair
   and run `/api/v1/verify` before scanning.

No automatic export from Breadcrumb back to Leadline exists. Breadcrumb-only
captures, findings and triage changes made after the merge would not be in
Leadline. Export what you need (JSON/Markdown/PDF/SARIF) before abandoning the
Breadcrumb database.

---

## 9. Verification checklist after any rollback

- [ ] `/health` returns `status: ok` and the expected schema version.
- [ ] `/health` shows `maintenance: false` when you intend to scan.
- [ ] `/api/v1/verify` reports no broken links or forks.
- [ ] `PRAGMA integrity_check` returns `ok`.
- [ ] A header profile opens/decrypts (key matches the DB).
- [ ] A report or PDF generates from an existing snapshot.
- [ ] A screenshot opens and its SHA-256 verifies.
- [ ] A review bundle verifies with `breadcrumb verify-bundle`.
- [ ] The executor is off until you deliberately re-enable it.
- [ ] The Leadline folder is unchanged (compare its fingerprint if in doubt).
- [ ] The rollback reason, level, backup names and verification output are
      recorded in `docs/MERGE_HISTORY.md` or an incident note.

---

## 10. What not to do

- Do not restore a DB without its matching key.
- Do not delete `-wal`/`-shm` while a process is running.
- Do not edit `chain_hash`, `chain_seq`, `content_sha256`, the `evidencechain`
  head, or `appstate.schema_version` by hand.
- Do not delete pre-import/pre-migration backups until the restored state is
  verified.
- Do not run the old binary against a migrated schema.
- Do not delete the import manifest during a failed import.
- Do not archive, delete or rewrite the Leadline folder as part of a rollback.
- Do not expose the UI/API to a network to make recovery easier.

---

## 11. Related documents

- [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md) — backup/restore and
  migration mechanics.
- [MIGRATION_DRILL.md](MIGRATION_DRILL.md) — repeatable all-tag upgrade and
  rollback evidence.
- [RELIABILITY_SOAK.md](RELIABILITY_SOAK.md) — schedule/queue failure injection.
- [LEADLINE_MERGE_GUIDE.md](LEADLINE_MERGE_GUIDE.md) — import workflow.
- [LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md) — real-data
  verification record.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — trust boundaries and controls.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom-first diagnosis.
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) — sign-off checklist.
- [RELEASE_NOTES_1.0.0.md](RELEASE_NOTES_1.0.0.md) — current release summary.
