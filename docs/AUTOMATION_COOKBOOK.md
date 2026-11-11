# Automation cookbook

Breadcrumb is a local notebook first and an automation target second. It has
no cloud scheduler, no API token and no background daemon: you run
`breadcrumb scheduler` (or call `breadcrumb schedule run`) from cron, systemd,
Task Scheduler or a terminal. Everything below stays on one machine and one
SQLite file.

The Phase D automation surface is deliberately small:

| Job | Command / endpoint |
|---|---|
| Import a folder on an interval | `breadcrumb schedule add`, `breadcrumb scheduler` |
| Import one file now | `POST /api/v1/pastes` |
| Import many files in one request | `POST /api/v1/pastes/bulk` |
| Make retries safe | `capture_key` or `Idempotency-Key` |
| Page through findings | `GET /api/v1/findings?limit=&offset=` |
| Fail CI on a severe finding | `breadcrumb gate`, `GET /api/v1/gate` |
| Save/restore the database | `breadcrumb backup`, `/api/v1/backup` |
| Alert a webhook | Settings → Notifications |

## 1. Scheduled folder re-import

A schedule watches **one local folder**. An external tool (BBOT, a cron job, a
shell pipeline) writes output into the folder; Breadcrumb imports each new file
through the normal ingest path.

### Create a schedule

```bash
mkdir -p ~/recon/acme/drop
breadcrumb schedule add acme-nightly ~/recon/acme/drop \
  --program 1 --interval 3600 --overlap skip
breadcrumb schedule list
breadcrumb schedule show acme-nightly
```

Web: `/schedules` → **Add a schedule**. API:

```bash
curl -X POST http://127.0.0.1:8787/api/v1/schedules \
  -H 'Content-Type: application/json' \
  -d '{"name":"acme-nightly","source":"/home/me/recon/acme/drop",
       "program_id":1,"interval_seconds":3600,"overlap_policy":"skip"}'
```

| Field | Meaning |
|---|---|
| `source` | Absolute or `~`-relative local folder. It must already exist. |
| `program_id` / `target_id` | Optional attribution; both are validated before the save. |
| `interval_seconds` | 10 seconds to 30 days. Default 300. |
| `overlap_policy` | `skip` refuses to start while a recent run is `running`; `queue` starts anyway. |
| `move_processed` | Move successful/empty files to `processed/` (default on). |
| `enabled` | Disabled schedules keep their history but are never due. |

There is intentionally **no URL or API source**. A scheduled fetch would need
credential storage and an SSRF boundary; let the tool that already has network
access drop a file instead. This keeps every schedule a local file read.

### Run it

```bash
# Foreground loop, the closest thing to a daemon
breadcrumb scheduler --poll 30

# One due-check, suitable for cron/systemd timers
breadcrumb scheduler --once
breadcrumb schedule run acme-nightly          # ignore the clock, run now
breadcrumb schedule run acme-nightly --force  # recover a crashed "running" row
```

Example crontab entry:

```cron
*/15 * * * * cd /home/me/Breadcrumb && .venv/bin/python -m app.cli scheduler --once >> ~/breadcrumb-scheduler.log 2>&1
```

The scheduler is single-process by design. Running two schedulers against the
same database is safe but pointless: both will see the same due rows and the
`running`/stale rules will serialize the work. Do not run one scheduler per
folder; add schedules instead.

### What one run does

1. Atomically claims the schedule, writing a `ScheduleRun` row with status
   `running`. A second recent run is skipped (`skip`) or allowed (`queue`).
2. Lists the folder, ignoring subdirectories, dot-files and partial-download
   suffixes (`.part`, `.tmp`, `.crdownload`, `.swp`, `.swx`).
3. Caps a run at 200 files and each file at 25 MB. Binary files and empty files
   are reported, not parsed as text.
4. Imports text through `app.ingest.ingest` with capture key
   `schedule:<id>:<sha256-of-file>`. Identical bytes are duplicates, even if
   the file is re-dropped or retried.
5. Moves successful and empty files to `processed/` when `move_processed` is
   on. Name collisions get a `-<hash8>` suffix. Failed reads/ingests leave the
   file in place so the operator can fix it.
6. Records `ok`, `partial` (some files failed/skipped) or `error` (nothing
   imported and something failed), plus per-file detail, and advances
   `next_run_at`.

A crashed process leaves an honest `running` row. After
`max(3600, interval × 2)` seconds it becomes `stale`, and the next run proceeds.

### Inspect history

```bash
breadcrumb schedule show acme-nightly --json
curl http://127.0.0.1:8787/api/v1/schedules/1
```

Web: `/schedules/<id>`. Each run shows files seen, new captures, duplicates,
entities, findings, errors and a per-file table linking to the capture. Web
and API run endpoints accept `force` only as a recovery tool.

## 2. Idempotent imports

A retried pipeline must not create a second capture. Supply a stable key:

```bash
# JSON body
curl -X POST http://127.0.0.1:8787/api/v1/pastes \
  -H 'Content-Type: application/json' \
  -d '{"text":"{\"url\":\"https://app.example/\"}",
       "program_id":1,
       "capture_key":"subfinder:acme:2026-11-11"}'

# Raw pipeline
subfinder -d example.com -silent \
  | curl -X POST http://127.0.0.1:8787/api/v1/pastes \
         -H 'Idempotency-Key: subfinder:acme:2026-11-11' \
         --data-binary @-
```

- A new capture returns HTTP **201** with `"duplicate": false`.
- A repeated key returns HTTP **200** with `"duplicate": true` and the original
  `paste_id`. The body is safe to retry after a timeout.
- Keys are capped at 200 characters. Use a deterministic string, not a clock.
- Raw requests can set `X-Breadcrumb-Source` to label the capture.

## 3. Bulk ingest

`POST /api/v1/pastes/bulk` is for a wrapper that already has several files in
memory. It is bounded to 100 captures and isolates failures.

```bash
curl -X POST http://127.0.0.1:8787/api/v1/pastes/bulk \
  -H 'Content-Type: application/json' \
  -d '{
    "program_id": 1,
    "captures": [
      {"filename":"httpx.jsonl","text":"...","capture_key":"acme:httpx:1"},
      {"filename":"nuclei.jsonl","text":"...","capture_key":"acme:nuclei:1"},
      {"filename":"empty.txt","text":""}
    ]
  }'
```

The response is **207 Multi-Status**:

```json
{"count": 3, "ok": 2, "failed": 1,
 "results": [
   {"index": 0, "ok": true, "duplicate": false, "paste_id": 41, ...},
   {"index": 1, "ok": true, "duplicate": false, "paste_id": 42, ...},
   {"index": 2, "ok": false, "error": "empty text"}
 ]}
```

A bad item does not roll back its neighbours. Program/target ids are validated;
an unknown id fails that item, not the request.

## 4. Paginated findings

```bash
curl 'http://127.0.0.1:8787/api/v1/findings?program_id=1&min_severity=high&limit=100&offset=0'
```

`limit` is capped at 5000 (default 500). The response includes `total`,
`offset`, `limit` and `next_offset`; `next_offset` is `null` on the last page.
Filters: `program_id`, `min_severity` (info/low/medium/high/critical), `status`
and `q` (title substring). Severity ranking matches the UI and CI gate.

## 5. CI recipes

Generate SARIF for code-scanning uploads and fail the job on a severe finding:

```bash
breadcrumb export 1 --format sarif -o breadcrumb.sarif
breadcrumb gate 1 --max-severity high
```

`gate` exits **1** when an active finding is at/above the threshold; `resolved`
and `wont-fix` findings are excluded. The HTTP equivalent is:

```bash
curl -f 'http://127.0.0.1:8787/api/v1/gate?program_id=1&max_severity=high'
```

A GitHub Actions sketch (run the scan elsewhere, import the artefact):

```yaml
- name: Import recon artefacts
  run: |
    for f in out/*.json; do
      curl -fsS -X POST "$BREADCRUMB_URL/api/v1/pastes/bulk" \
        -H 'Content-Type: application/json' \
        --data-binary "@$f"
    done
- name: Fail on a high finding
  run: breadcrumb gate 1 --max-severity high
```

`BREADCRUMB_URL` must point at a host you control. The default server binds to
`127.0.0.1`; for CI, run Breadcrumb in the job or expose it behind a
reverse-proxy with its own auth. There is no built-in login or multi-user
RBAC.

## 6. Notifications

Configure Discord, Slack, Telegram or a generic webhook in **Settings →
Notifications**, or write `breadcrumb.notify.json` next to the database. A
schedule run notifies only when it imported something or hit an error, and a
failed webhook can never fail the import. The payload is a short title, text
and fields (`schedule`, `folder`, `captures`, `entities`, `findings`).

`on_schedule: false` in `breadcrumb.notify.json` suppresses schedule
notifications; the rest of the channel config is unchanged.

## 7. Backup and maintenance

```bash
breadcrumb backup -o nightly.db          # WAL-safe online backup, integrity-checked
curl -O http://127.0.0.1:8787/api/v1/backup
breadcrumb maintenance on --reason "nightly backup"
breadcrumb maintenance off
```

`maintenance on` pauses worker claims only; imports and UI reads continue.
Restore is a file replacement with an integrity check — see
[BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md).

## 8. Operating rules

- Keep schedules pointed at a folder owned by the same user that runs
  Breadcrumb. Local parser plugins and schedules both run with that user's
  permissions.
- Do not point two schedules at the same folder with different programs unless
  you intend the assets to be attributed twice; capture keys are namespaced by
  schedule id.
- Prefer one small file per tool run. A 200-file/25-MB cap is a guardrail, not
  a target.
- Check `/schedules`, `breadcrumb doctor` and the `partial`/`error` run rows
  after changing a pipeline.
- Never expose the server to an untrusted network without a reverse proxy and
  TLS; API requests are trusted like local shell access.
