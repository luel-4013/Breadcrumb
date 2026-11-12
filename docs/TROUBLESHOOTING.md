# Troubleshooting

This guide covers the merged Breadcrumb + Leadline system. Start with the
health endpoint:

```bash
curl -s http://127.0.0.1:8787/health
```

It reports the version, schema version, DB path, WAL mode, maintenance flag,
job counts and expired leases.

Run the read-only diagnostic first when anything feels wrong:

```bash
python -m app.cli doctor
python -m app.cli doctor --json
```

It checks Python, SQLite, the database directory/disk, integrity, WAL mode,
schema version, key file, port, parser registry and optional tools, and prints
a copy-paste `fix` for every failure.

---

## 0. An import produced zero entities

1. Run `python -m app.cli ingest <file> --dry-run`. If `parsers` is empty, the
   input is not a recognized format (often an HTML error page, gzip data, or a
   changed tool version).
2. If a parser matched, read `issues` in the dry-run output or at
   `/api/v1/pastes/<id>/report`. `skipped_row` names the malformed line;
   `exception` means the parser hit a bug and the capture was still sealed with
   the error attached.
3. `completeness < 100%` means the import was partial. Do not trust a report or
   Ledger entry built from it until you re-import a clean artifact.
4. See [IMPORT_COOKBOOK.md](IMPORT_COOKBOOK.md) for format-specific commands
   and the parser contract.

---

## 1. The app will not start or rejects requests

### `Invalid Host header` / HTTP 400

Breadcrumb only accepts loopback Host values by default. Use
`http://127.0.0.1:8787` or `http://localhost:8787`.

If you deliberately use another local name, add it:

```bash
BREADCRUMB_ALLOWED_HOSTS=myhost.local .venv/bin/python run.py
```

Do not expose the port to a network. There is no login.

### `Cross-origin request rejected` / `CSRF token missing or invalid`

- Open the UI from the same origin; do not submit forms from another page.
- Reload the page to refresh the `bc_csrf` cookie/token.
- API clients posting form data must send the hidden `csrf_token` field or the
  `x-csrf-token` header. JSON requests are still subject to Host/Origin checks.
- If a reverse proxy rewrites Host/Origin, add the proxy’s host to
  `BREADCRUMB_ALLOWED_HOSTS` and make sure the proxy preserves the original
  origin. A proxy is not a supported multi-user deployment.

### Port already in use

```bash
BREADCRUMB_PORT=8788 .venv/bin/python run.py
```

Check for an old app/worker:

```bash
pgrep -af "app.main|app.cli|run.py"
```

---

## 2. Database and schema issues

### `database is locked`

SQLite allows one writer. Breadcrumb uses WAL, a 30-second busy timeout and
short write transactions, but two workers or a long external transaction can
still contend.

- Run **one** `breadcrumb worker`.
- Stop duplicate `run.py`/`app.main` processes.
- Do not keep a SQLite browser open in write mode.
- Do not put the DB on NFS/SMB.
- If it persists, stop everything, back up, and check `/health` for a stuck
  running job with an expired lease. Restarting the app runs lease recovery.

### Schema version mismatch

`/health` shows `schema_version` and `expected_schema_version`. On startup
`init_db()` applies additive migrations and updates the app state. If a
migration fails:

1. Stop the app/worker.
2. Find the automatic pre-migration backup:
   `breadcrumb.db.pre-migrate-<timestamp>.bak`.
3. Restore it and the matching key (see
   [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md)).
4. Report the failing migration with the full traceback.

Never delete the pre-migration backup until you have verified the new schema
and `/api/v1/verify`.

### `database disk image is malformed` / integrity check failure

Stop writes immediately. Restore the newest known-good backup and run
`PRAGMA integrity_check` on the restored file. Do not run `VACUUM` or repair
tools on the only copy.

---

## 3. Header-profile secrets

### `encrypted header profiles exist but no secret key was found`

The database contains `enc:v1:` ciphertext, but the key file is missing.
Restore the key that was created with that database:

- `<BREADCRUMB_DB_PATH>.key`, or
- `BREADCRUMB_KEY_FILE`, or
- `BREADCRUMB_SECRET_KEY` / `BREADCRUMB_SECRET_KEYS`.

Do **not** delete the ciphertext or generate a new key over it. If the key is
truly lost, the encrypted header values are unrecoverable; restore the DB and
key from backup or recreate the profiles.

### Plaintext header profiles after an old upgrade

Startup migrates legacy plaintext profiles automatically. If you see plaintext
in a copy, make sure you started the current app against that copy once, or run
the migration in a controlled process. Check raw rows:

```bash
sqlite3 breadcrumb.db "SELECT id, name, substr(headers,1,12) FROM headerprofile;"
```

Every non-null value should start with `enc:v1:`. The pre-migration backup is
scrubbed after encryption; if scrubbing fails, the backup is removed and a
warning is printed.

### Key rotation

```bash
.venv/bin/python -m app.cli secrets rotate
```

Back up the old key (`<key>.old`) as well. Keep it until every backup that
contains old ciphertext has been retired.

---

## 4. Worker and job problems

### Jobs stay `queued`

- Executor default is off. Start a worker:

  ```bash
  .venv/bin/python -m app.cli worker --poll 2 --lease 120
  ```

  or set `BREADCRUMB_EXECUTOR=inline` for the web process.
- Check maintenance mode in `/health`. It must be `false`.
- `breadcrumb worker --once` claims at most one job.
- A queued job with `attempts >= max_attempts` is not claimable; retry or queue
  a new job.
- Adapter jobs are not claimed unless `BREADCRUMB_EXTERNAL_TOOLS=1`. Use
  **Run now** or `breadcrumb collect --run-now` for an explicit one-off.

### `job was not claimable (already running or maintenance mode)`

The job is already running, terminal, or the app is in maintenance. Refresh
the job page or `/health`.

### Imported Leadline job returns `409`

Imported jobs are historical:

```
Imported Leadline jobs are historical; queue a new scan instead of retrying
this row.
```

Add scope and queue a new scan. Do not edit `params.imported`.

### Job fails with `not installed on the executor PATH`

The external adapter binary is missing. Install it on the machine running the
worker, or disable that adapter. `/runners` and `breadcrumb tools` show
presence/version. Missing binaries are not silently treated as empty scans.

### Job fails with a scope denial

The target is unknown, out of scope, excluded, metadata/link-local, or a
redirect/proxy was denied. Add the target to the program’s scope and retry with
a new job. Imported programs start with empty scope by design.

### Cancellation does not stop an external tool

Native collectors check a cooperative event between phases. Adapters run in a
fresh process group and receive SIGTERM then SIGKILL. If a child survives, check
for a wrapper script that detaches into a new session; use a direct binary.

---

## 5. Leadline import problems

### `source database does not exist` / `not a Leadline database`

Pass the path to a SQLite file with a `targets` table. The importer treats
missing `scans`, `scan_events`, `findings` and `graph_nodes` tables as empty and
prints warnings.

### `source database changed while it was being read`

A Leadline process (or another writer) changed the file during the import.
Stop Leadline, copy the DB with SQLite’s backup API, and import the copy.

### `encrypted header profiles exist but no secret key was found` during import

The destination DB has ciphertext but its key is not next to it and no key env
var is set. Restore/copy `<BREADCRUMB_DB_PATH>.key` or set
`BREADCRUMB_SECRET_KEY`. The importer aborts rather than writing plaintext.

### Verification fails

Do not delete the manifest. Inspect the JSON report:

```bash
.venv/bin/python -m app.cli import-leadline ... --verify --json \
  --report /tmp/verify.json
```

Common causes:

- a finding was deleted or edited after import;
- the destination program was changed (`--program` mismatch);
- the manifest belongs to a different source path;
- a header profile/key is missing;
- the source file changed since the import.

Restore from the pre-import backup if the destination is wrong, then re-run.

### Import seems to do nothing on re-run

That is expected. The manifest and fingerprints make the import idempotent:
existing targets/scans/findings/entities are skipped and counted. Look at
`counts.skipped` in the JSON report.

### `manifest belongs to ... its ID map is ignored`

The manifest source path differs from the current `--db` path. Use the same
path, or choose a new manifest path for a different source. The importer will
not mix ID maps across sources.

---

## 6. History, snapshots and reports

### `Snapshot is not ready for this job` / `409`

The job has no ready `ScanSnapshot`. Rebuild it from the job page or:

```bash
.venv/bin/python -m app.cli report <job_id> --format json
```

If the snapshot failed, the job page shows the error. Evidence is intact;
snapshots are rebuildable caches. For imported jobs, snapshots are scoped to
the source scan.

### PDF generation fails

- `reportlab` is a pinned runtime dependency. Reinstall requirements:
  `.venv/bin/python -m pip install -r requirements.txt`.
- A snapshot must be ready first.
- If the error mentions XML/paragraph parsing, report the exact captured text;
  reportlab input is escaped, and this would be a bug.

### Report excludes a finding

False-positive findings are excluded by default. Use the internal
`?include_triaged=1` flag or the CLI `--include-triaged` when you deliberately
need them. Unverified CVE candidates do not contribute to risk.

### Imported scans do not show run/retry

Correct. Imported jobs are read-only history. Queue a new scan.

---

## 7. Automation, screenshots and reports

### A schedule does not run or reports `skipped`

1. Check the schedule is enabled and its interval has elapsed:
   `breadcrumb schedule show <id> --json`.
2. Check the source folder exists and is readable by the user running the
   scheduler. Schedules read local folders only; a network mount may disappear.
3. Check overlap policy. `skip` does nothing while another run is active;
   `queue` queues one follow-up.
4. Inspect the latest `ScheduleRun` detail. A crashed `running` row becomes
   `stale` after `max(3600, interval × 2)` seconds and the next run recovers it.
5. Remember that `scheduler` is a foreground loop or a `--once` cron target; it
   does not install a boot service.

### A file in a watched folder was not imported

- Binary, hidden, temporary and partial-download files are skipped by design.
- Files over 25 MB and runs over 200 files are bounded; the run detail says so.
- A parser may have returned zero entities. Check the import report and
  `breadcrumb ingest <file> --dry-run`.
- Identical content is a duplicate capture; it is counted, not ingested twice.
- Failed files stay in the drop folder. Successful/empty files move to
  `processed/`; look there before assuming the file vanished.

### A screenshot upload or manifest import is rejected

- Accepted formats are PNG, JPEG, GIF and WebP only. SVG and PDF are rejected
  deliberately because they can contain active content.
- Limits: 12 MiB per image, 12,000 px per side, 2,000 rows / 5 MiB per
  manifest, 1,000 images per import.
- An explicit target/entity/finding link must belong to the same program.
- Imports never auto-create targets. Create the target first or supply a source
  URL that matches an existing target.
- Manifest paths must stay under the manifest/base directory; absolute paths
  and `..` traversal are rejected.

### A screenshot reports a hash mismatch or missing file

- The database stores a relative content-addressed path, not the bytes. Confirm
  `BREADCRUMB_ARTIFACT_DIR` or the default `<database>.artifacts` directory was
  restored with the database.
- `breadcrumb artifacts show <id> --json` performs a live SHA-256 check.
- Do not edit the hash to silence the error. Restore the file from backup, or
  deliberately delete the broken row.
- Orphan files (no database row) are harmless; never point the app at a public
  web root.

### A report or bundle has no screenshots

- Report templates include screenshots only with `include_screenshots=1`
  (`breadcrumb render ... --var include_screenshots=1`).
- Bundles require `--include-screenshots` explicitly. Caps are 50 images /
  32 MiB; over-cap images are excluded with a warning.
- Markdown lists image metadata rather than embedding bytes; HTML/PDF embed
  supported images.
- Redaction masks text fields, not image pixels. Review every image before
  sharing.

### `verify-bundle` fails

- The zip is truncated, edited or was built by an incompatible version. Rebuild
  it instead of editing `manifest.json`.
- Verification runs in memory: it checks the zip checksums, bundle manifest,
  capture manifests and optional screenshot hashes.
- A bundle is a redacted evidence copy, not an encrypted container. Treat it as
  sensitive even when verification passes.

### A local parser plugin does not load

- Plugins are read from `BREADCRUMB_PARSER_DIR` or `~/.breadcrumb/parsers`.
- A module must expose `PARSER` or `get_parser()`, subclass `Parser`, and have a
  unique name and version.
- Run `breadcrumb parsers --json` (or open `/parsers`) for the load error. A
  broken plugin is skipped and does not stop built-in parsers.
- Plugins execute in-process with your permissions. There is no sandbox or
  remote marketplace; only install code you trust.

### Redaction looks incomplete

- Redaction is on by default. Built-in masking cannot be disabled by a custom
  rule; `--reveal`/`reveal=1` is the explicit unsafe switch.
- Custom rules are additive and never replace built-in masks.
- Screenshot pixels, filenames inside images and EXIF are not redacted.
- Review the rendered output before sending it; a bundle is still sensitive.

### `breadcrumb release check` fails

The report names each failing check:

```bash
breadcrumb release check --json
```

- `dangerous_code`: remove `shell=True` or dynamic `eval` from tracked source.
- `secrets`: remove the credential shape and rotate the credential if real.
- `docs_links`: fix or remove the broken relative link.
- `dependencies`: install the pinned runtime versions.
- `cli_reference` / `api_reference`: document the new command or `/api/v1`
  route in `docs/CLI_REFERENCE.md` or `docs/API_REFERENCE.md`.

Do not suppress the check to make a release pass; fix the source or the
reference.

---

## 8. External lookups, NVD and AI

### CVE findings are missing

CVE findings are emitted only when the local NVD cache proves CPE/version
applicability. Keyword-only matches are informational and do not create
findings.

```bash
.venv/bin/python -m app.cli nvd stats
.venv/bin/python -m app.cli nvd import /path/to/nvd.json.gz
```

### External lookups fail

External lookups are on by default per owner decision, but failures should be
visible. Check the phase/job event for the provider error. Use the per-job
`enable_external_lookups=false` option to stay offline.

### AI provider is unreachable

- Confirm LM Studio/Jan/Ollama is running on the expected port.
- Set `BREADCRUMB_LMS_PATH` or `BREADCRUMB_JAN_MODELS` if discovery fails.
- Raise `BREADCRUMB_AI_TIMEOUT` for slow inference.
- The rest of Breadcrumb works without AI; do not block a scan on it.

---

## 9. Backup and restore

See [BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md). The short version:
back up the DB, key and artifact directory; use SQLite’s online backup API; and
never copy only the main file while WAL is active. A DB without its artifact
directory restores rows but not screenshot bytes.

---

## 10. Diagnostic bundle

For a bug report, collect:

```bash
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/v1/verify
.venv/bin/python -m app.cli doctor --json
.venv/bin/python -m app.cli version
.venv/bin/python -m app.cli jobs list --limit 20 --json
.venv/bin/python -m app.cli schedules list --json
.venv/bin/python -m app.cli artifacts list --limit 20 --json
.venv/bin/python -m app.cli release check --json
```

Also include the exact command, exit code, and redacted stderr. Never attach a
real database or key file to a public issue; use a synthetic fixture or a
redacted copy.
