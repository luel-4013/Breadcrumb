# Backup, restore and upgrade runbook

**Applies to:** Breadcrumb with the Leadline merge (schema version 4).
**Audience:** the owner/operator of a single local installation.

Breadcrumb is one SQLite database plus an encryption key. A backup that omits
the key cannot decrypt header profiles. A backup that copies only the main
file while WAL is active can miss committed pages. Follow this runbook rather
than `cp`-ing a live database.

---

## 1. Files to protect

| File | Why |
|---|---|
| `breadcrumb.db` | Programs, targets, captures, findings, jobs, snapshots |
| `breadcrumb.db.key` | Decrypts header profiles (`enc:v1:`) |
| `breadcrumb.db.key.old` | Previous rotation key; needed for older ciphertext |
| `BREADCRUMB_KEY_FILE` target | If you use a custom key path |
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

### 3.3 Restore the key

```bash
cp backups/breadcrumb-pre-upgrade.db.key breadcrumb.db.key
chmod 600 breadcrumb.db.key
# if you use a rotation chain:
cp backups/breadcrumb-pre-upgrade.db.key.old breadcrumb.db.key.old 2>/dev/null || true
chmod 600 breadcrumb.db.key.old 2>/dev/null || true
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
```

Expected: `status: ok`, schema version matches the binary’s
`expected_schema_version`, and no broken/forked chain links. Gaps from deleted
programs are expected and are not tampering.

Open a header profile in the UI or run a report to confirm decryption works.

### 3.5 Restore a backup from a different machine

The DB and key are portable. Copy both; do not copy only the DB. The key file
is machine-independent. Ensure file ownership/permissions match the local user
and that the DB path in `BREADCRUMB_DB_PATH` points at the restored file.

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
- generate a PDF from an existing snapshot;
- queue one safe local/lab job if you are ready to scan;
- confirm `/health` reports `maintenance: false`.

### 4.4 Schema 3 → 4

The Leadline merge adds:

- `target.meta` JSON;
- `finding.meta` JSON;
- schema version 4.

The migration is additive. Old binaries may not understand the new columns, so
rolling back the code after a migration should be done with the pre-migration
backup, not by pointing the old binary at the migrated DB (see the rollback
plan).

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
| Migration failed | Stop; restore `.pre-migrate` backup + key; report traceback |
| Import wrong | Stop; restore `.pre-import` backup + key; re-run dry run |
| Chain broken/forked | Stop; restore known-good backup; run `/api/v1/verify`; do not edit hashes |
| Worker crash mid-job | Restart; lease recovery re-queues or fails with a clear reason |
| Leadline source changed | Stop Leadline; copy again; re-run import |

---

## 7. What not to do

- Do not `cp` a live WAL database as your only backup.
- Do not back up the DB without the key and then delete the key.
- Do not restore only the main file while an old `-wal` remains.
- Do not run two workers or two app writers against one DB.
- Do not edit `chain_hash`, `chain_seq`, `content_sha256`, the `evidencechain`
  head, or `appstate.schema_version` by hand.
- Do not delete pre-migration/pre-import backups until verification passes.
- Do not expose the UI/API to a network to “make backup easier”.
