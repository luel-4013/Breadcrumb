# Backup, restore and upgrade runbook

**Applies to:** Breadcrumb 1.0.0 (schema version 8).
**Audience:** the owner/operator of a single local installation.

Breadcrumb is one SQLite database, one encryption key, and (if screenshots are
used) one artifact directory. A backup that omits the key cannot decrypt header
profiles. A backup that omits the artifact directory loses the screenshot bytes
that the database references. A backup that copies only the main file while
WAL is active can miss committed pages. Follow this runbook rather than `cp`-ing
a live database.

---

## 1. Files to protect

| File | Why |
|---|---|
| `breadcrumb.db` | Programs, targets, captures, findings, jobs, snapshots |
| `breadcrumb.db.key` | Decrypts header profiles (`enc:v1:`) |
| `breadcrumb.db.key.old` | Previous rotation key; needed for older ciphertext |
| `BREADCRUMB_KEY_FILE` target | If you use a custom key path |
| `breadcrumb.db.artifacts/` | Screenshot bytes, content-addressed by SHA-256 |
| `BREADCRUMB_ARTIFACT_DIR` target | If you use a custom artifact directory |
| `breadcrumb.nvd.json` | Local CVE verification cache (optional but expensive to rebuild) |
| `<BREADCRUMB_DB_PATH>.leadline-import.json` | Import ID map/resume state (optional after a completed import) |
| `breadcrumb.llm.json` | Local AI provider/routing config (no provider secrets? treat as sensitive) |

The database may also have `-wal` and `-shm` files while running. Do not treat
them as standalone backups.

---

## 2. Backup

### 2.1 Online backup while running

SQLite’s backup API takes a consistent snapshot without stopping readers:

```bash
mkdir -p backups
.venv/bin/python -m app.cli backup \
  -o "backups/breadcrumb-$(date -u +%Y%m%d-%H%M%S).db"
```

Then copy the key separately:

```bash
cp breadcrumb.db.key "backups/breadcrumb-$(date -u +%Y%m%d-%H%M%S).db.key"
cp breadcrumb.db.key.old "backups/breadcrumb-$(date -u +%Y%m%d-%H%M%S).db.key.old" 2>/dev/null || true
chmod 600 backups/*
```

Copy the artifact directory with the database snapshot:

```bash
rsync -a breadcrumb.db.artifacts/ backups/breadcrumb-artifacts-$(date -u +%Y%m%d-%H%M%S)/
# or: rsync -a "$BREADCRUMB_ARTIFACT_DIR/" backups/breadcrumb-artifacts-.../
```

If you use screenshots, a database-only backup is incomplete: the rows will
restore but their content hashes will not resolve.

Or use the SQLite CLI directly:

```bash
sqlite3 breadcrumb.db ".backup 'backups/breadcrumb.db'"
```

`breadcrumb backup` calls `init_db()`, which may apply pending migrations to
the live DB first. If you are backing up before an upgrade, prefer a
quiescent backup (next section) or accept the automatic pre-migration backup.

### 2.2 Quiescent backup before an upgrade or import

1. Stop the app and every worker.
2. Take the backup:

   ```bash
   sqlite3 breadcrumb.db ".backup 'backups/breadcrumb-pre-upgrade.db'"
   cp breadcrumb.db.key backups/breadcrumb-pre-upgrade.db.key
   cp breadcrumb.db.key.old backups/breadcrumb-pre-upgrade.db.key.old 2>/dev/null || true
   rsync -a breadcrumb.db.artifacts/ backups/breadcrumb-pre-upgrade.artifacts/
   # or: rsync -a "$BREADCRUMB_ARTIFACT_DIR/" backups/breadcrumb-pre-upgrade.artifacts/
   ```

3. Record the current version/schema:

   ```bash
   .venv/bin/python -m app.cli version
   sqlite3 breadcrumb.db "SELECT schema_version FROM appstate WHERE id=1;"
   ```

4. Keep the pre-upgrade code/commit and the Leadline folder available for
   rollback.

### 2.3 Verify a backup

```bash
sqlite3 backups/breadcrumb-pre-upgrade.db "PRAGMA integrity_check;"
```

Expected: `ok`.

If you want to verify the evidence chain in the backup, run the current app
against a **copy** of the backup and call `/api/v1/verify`:

```bash
cp backups/breadcrumb-pre-upgrade.db /tmp/verify-copy.db
cp backups/breadcrumb-pre-upgrade.db.key /tmp/verify-copy.db.key
BREADCRUMB_DB_PATH=/tmp/verify-copy.db .venv/bin/python run.py
# in another terminal:
curl -s http://127.0.0.1:8787/api/v1/verify
```

Do not run verification against the live DB while a scan is writing.

### 2.4 Retention

- Keep at least one pre-import, one pre-upgrade and one recent daily backup.
- Keep the matching key with each backup; store them together but restrict
  permissions.
- Keep the matching artifact directory with each backup. Orphan artifact files
  are harmless; missing files are broken evidence.
- A backup without its key is still useful for non-secret data, but header
  profiles will be unreadable.
- Never commit backups or keys to git.

---

## 3. Restore

### 3.1 Stop everything

```bash
pgrep -af "app.main|app.cli|run.py"
# stop the app and worker processes
```

Do not restore while any process has the DB open.

### 3.2 Restore the database

```bash
cp breadcrumb.db "breadcrumb.db.before-restore-$(date -u +%Y%m%d-%H%M%S)"
cp backups/breadcrumb-pre-upgrade.db breadcrumb.db
```

Remove stale WAL/SHM files from the old database. A SQLite online backup is a
standalone snapshot; mixing it with an old WAL can resurrect stale pages:

```bash
rm -f breadcrumb.db-wal breadcrumb.db-shm
```

### 3.3 Restore the key and artifacts

```bash
cp backups/breadcrumb-pre-upgrade.db.key breadcrumb.db.key
chmod 600 breadcrumb.db.key
# if you use a rotation chain:
cp backups/breadcrumb-pre-upgrade.db.key.old breadcrumb.db.key.old 2>/dev/null || true
chmod 600 breadcrumb.db.key.old 2>/dev/null || true
```

Restore the artifact directory to the path the database expects
(`<database-name>.artifacts` beside the DB, or `BREADCRUMB_ARTIFACT_DIR`):

```bash
rm -rf breadcrumb.db.artifacts
cp -a backups/breadcrumb-pre-upgrade.artifacts breadcrumb.db.artifacts
chmod -R u+rwX,go-rwx breadcrumb.db.artifacts
```

If you use `BREADCRUMB_KEY_FILE` or `BREADCRUMB_SECRET_KEY(S)`, restore/export
those instead. The key must match the ciphertext in the restored DB.

### 3.4 Verify before use

```bash
sqlite3 breadcrumb.db "PRAGMA integrity_check;"
sqlite3 breadcrumb.db "SELECT schema_version FROM appstate WHERE id=1;"
```

Start the app and check:

```bash
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/v1/verify
.venv/bin/python -m app.cli artifacts list --limit 5 --json
.venv/bin/python -m app.cli artifacts show <artifact_id> --json
```

Expected: `status: ok`, schema version matches the binary’s
`expected_schema_version`, no broken/forked chain links, and every opened
artifact reports a matching SHA-256. Gaps from deleted programs are expected
and are not tampering.

Open a header profile in the UI or run a report to confirm decryption works.
Open one screenshot and one report with `include_screenshots` if you use them.

### 3.5 Restore a backup from a different machine

The DB, key and artifact directory are portable. Copy all three; do not copy
only the DB. The key file is machine-independent. Ensure file ownership and
permissions match the local user and that `BREADCRUMB_DB_PATH` and
`BREADCRUMB_ARTIFACT_DIR` point at the restored locations. If the artifact
directory moves, keep the same relative `<database-name>.artifacts` layout or
set the environment variable explicitly.

---

## 4. Upgrade

### 4.1 Pre-upgrade

1. Read the release notes and [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md).
2. Take a quiescent DB + key backup (section 2.2).
3. Record the current version/schema and keep the old code/commit.
4. Stop the app and worker.

### 4.2 Apply the upgrade

```bash
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m compileall -q app
```

Start the app or run a CLI command. `init_db()`:

- detects pending schema changes;
- writes `breadcrumb.db.pre-migrate-<timestamp>.bak` before the first change
  (unless `BREADCRUMB_SKIP_BACKUP=1` is set);
- applies additive `ALTER TABLE` migrations and creates indexes;
- backfills the evidence chain if needed;
- encrypts legacy plaintext header profiles and scrubs the pre-migration
  backup;
- updates the singleton `appstate.schema_version`.

### 4.3 Post-upgrade checks

```bash
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/v1/verify
.venv/bin/python -m pytest -q        # optional, on the upgraded code
```

Then:

- open the programs/targets pages;
- open a header profile (decryption);
- generate a PDF from an existing snapshot and a rendered report;
- open one screenshot and confirm its SHA-256 verifies;
- verify a review bundle with `breadcrumb verify-bundle`;
- queue one safe local/lab job if you are ready to scan;
- confirm `/health` reports `maintenance: false`.

### 4.4 Schema 4 → 8

Breadcrumb 1.0 applies additive migrations through schema 8:

| Schema | Adds |
|---|---|
| 5 | Phase A import-report/parser metadata and indexes |
| 6 | Phase B `SavedView` and cross-program query indexes |
| 7 | Phase D `Schedule` and `ScheduleRun` |
| 8 | Phase E `EvidenceArtifact` metadata (bytes stay outside SQLite) |

Existing columns are added with `ALTER TABLE ... ADD COLUMN`; no table is
dropped and no evidence hash is recomputed. The leadline-merge schema-4 change
(`target.meta`, `finding.meta`) remains part of the path.

Old binaries may not understand the new columns, so rolling back the code after
a migration should be done with the pre-migration backup, not by pointing the
old binary at the migrated DB (see the rollback plan). Before publishing a
release, run `scripts/migration_drill.py --all` and keep the JSON evidence.

### 4.5 Post-import upgrade

If you imported Leadline data, keep the import manifest with the backup. A
future schema upgrade does not need the manifest to read the data, but it is
useful for re-verification or a clean re-import.

---

## 5. Key rotation

```bash
.venv/bin/python -m app.cli secrets rotate
```

- The new key becomes primary; the old key is archived at `<key>.old`.
- Keep `.old` with the DB backup until all ciphertext has been rewritten or all
  old backups are retired.
- After rotation, back up the DB and both key files.
- If you lose the new key, restore the previous DB + key pair.

---

## 6. Disaster recovery matrix

| Scenario | Action |
|---|---|
| DB lost, key intact | Restore newest DB backup; keep key |
| Key lost, DB intact | Restore matching key; if none, encrypted headers are unrecoverable |
| Both lost | Restore newest DB+key pair; re-import Leadline if needed |
| DB corrupt | Stop writes; restore last integrity-checked backup; verify chain |
| Artifact directory lost | Restore it with the matching DB; without it, screenshot rows cannot resolve |
| Artifact hash mismatch | Stop; restore that file from backup or delete the broken row deliberately; do not edit the hash |
| Migration failed | Stop; restore `.pre-migrate` backup + key + artifacts; report traceback |
| Import wrong | Stop; restore `.pre-import` backup + key; re-run dry run |
| Chain broken/forked | Stop; restore known-good backup; run `/api/v1/verify`; do not edit hashes |
| Worker crash mid-job | Restart; lease recovery re-queues or fails with a clear reason |
| Schedule run stuck `running` | Wait for `max(3600, interval × 2)` or restart the scheduler; it becomes `stale` |
| Leadline source changed | Stop Leadline; copy again; re-run import |

---

## 7. What not to do

- Do not `cp` a live WAL database as your only backup.
- Do not back up the DB without the key and then delete the key.
- Do not back up screenshot metadata without the artifact directory.
- Do not restore only the main file while an old `-wal` remains.
- Do not run two workers or two app writers against one DB.
- Do not edit `chain_hash`, `chain_seq`, `content_sha256`, the `evidencechain`
  head, or `appstate.schema_version` by hand.
- Do not delete pre-migration/pre-import backups until verification passes.
- Do not expose the UI/API to a network to “make backup easier”.
