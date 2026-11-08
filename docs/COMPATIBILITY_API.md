# Leadline compatibility API

Breadcrumb’s canonical JSON API is `/api/v1`. The compatibility router adds
Leadline-shaped endpoints at `/api/targets`, `/api/scans`, `/api/findings` and
`/api/reports` so existing Leadline scripts can keep working during the
transition.

The compatibility layer is **translation-only**. Reads come from Breadcrumb’s
`Program`, `Target`, `ScanJob`, `Finding`, `ScanPhase`, `ScanSnapshot` and
`Entity` rows. Writes use the same queue and ingest paths as the UI. It never
creates a second database or a second source of truth.

**Local-only:** Breadcrumb has no login and binds to `127.0.0.1` by default.
Do not expose it to a network. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

---

## 1. Status and triage mapping

### Scan status

| Breadcrumb | Leadline |
|---|---|
| `queued` | `pending` |
| `running` | `running` |
| `done` | `completed` |
| `failed` | `failed` |
| `cancelled` | `stopped` |

### Finding triage

| Leadline `triage_status` | Breadcrumb `status` | Breadcrumb `verdict` |
|---|---|---|
| `open` | `open` | `none` |
| `acknowledged` | `in-progress` | `needs-review` |
| `false_positive` | `wont-fix` | `false-positive` |

The reverse mapping treats `resolved` as `acknowledged` (closed work, not a new
finding) and any `false-positive` verdict as `false_positive`.

---

## 2. Targets

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/targets` | List all targets |
| `POST` | `/api/targets` | Create a target |
| `GET` | `/api/targets/{id}` | Get one target |
| `PUT` | `/api/targets/{id}` | Update `name`/`notes` |
| `DELETE` | `/api/targets/{id}` | Delete the target; detach entities/findings/jobs (do not delete sealed evidence) |
| `GET` | `/api/targets/{id}/history` | Snapshot timeline |
| `GET` | `/api/targets/{id}/history/diff?from_scan_id=&to_scan_id=` | Compare two snapshots |

`POST /api/targets` accepts:

```json
{"name": "Example program", "url": "https://example.com", "notes": "optional"}
```

It creates or reuses a Breadcrumb `Program` named from `name` and stores `url`
as a `kind="url"` target. The response includes `program_id` and `kind` in
addition to the Leadline fields. `custom_headers` is always returned empty;
header profiles are managed through Breadcrumb’s encrypted UI/API, not through
this compatibility route.

```bash
curl -s http://127.0.0.1:8787/api/targets
curl -s -X POST http://127.0.0.1:8787/api/targets \
  -H 'content-type: application/json' \
  -d '{"name":"Example","url":"https://example.com"}'
```

---

## 3. Scans

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scans` | List scans |
| `POST` | `/api/scans` | Queue a scan |
| `GET` | `/api/scans/{id}` | Get one scan |
| `POST` | `/api/scans/{id}/start` | Make a pending scan claimable |
| `POST` | `/api/scans/{id}/stop` | Request cancellation |
| `DELETE` | `/api/scans/{id}` | Delete a terminal scan |
| `GET` | `/api/scans/{id}/events` | Phase/event list |

`POST /api/scans` accepts:

```json
{
  "target_id": 1,
  "runner": "leadline-recon",
  "evasion_enabled": true,
  "request_delay": 0.5,
  "enable_external_lookups": true,
  "params": {}
}
```

`runner` defaults to `leadline-recon`. The scan is created `queued`. It becomes
claimable by the durable worker (`breadcrumb worker`). If
`BREADCRUMB_EXECUTOR=inline` is set, `POST /api/scans/{id}/start` also starts an
inline background run.

Only `queued` scans can be started. A terminal scan must be replaced with a new
scan. Imported historical scans (`runner=leadline.imported`) are terminal and
cannot be claimed, started or retried.

```bash
curl -s -X POST http://127.0.0.1:8787/api/scans \
  -H 'content-type: application/json' \
  -d '{"target_id":1}'
curl -s -X POST http://127.0.0.1:8787/api/scans/12/start
curl -s http://127.0.0.1:8787/api/scans/12/events
```

---

## 4. Findings

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/findings` | List/filter findings |
| `GET` | `/api/findings/{id}` | Get one finding |
| `PATCH` | `/api/findings/{id}` | Update triage |

Query filters for `GET /api/findings`:

- `scan_id`
- `target_id`
- `program_id`
- `severity`
- `triage_status`

`PATCH /api/findings/{id}` accepts any of:

```json
{"triage_status": "acknowledged", "triage_note": "known issue"}
{"is_false_positive": true, "triage_note": "expected banner"}
{"triage_note": "note only"}
```

The response contains both Leadline-shaped fields (`triage_status`,
`is_false_positive`, `triage_note`, `triaged_at`, `extra_data`) and
Breadcrumb’s `status`/`verdict`.

```bash
curl -s 'http://127.0.0.1:8787/api/findings?program_id=1&severity=high'
curl -s -X PATCH http://127.0.0.1:8787/api/findings/42 \
  -H 'content-type: application/json' \
  -d '{"triage_status":"false_positive","triage_note":"expected"}'
```

---

## 5. Reports

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/reports/{scan_id}` | Report summary/highlights/phases |
| `GET` | `/api/reports/{scan_id}/export/json` | JSON export |
| `GET` | `/api/reports/{scan_id}/export/markdown` | Markdown export |
| `GET` | `/api/reports/{scan_id}/export/html` | HTML export |
| `GET` | `/api/reports/{scan_id}/export/pdf` | PDF export |

Reports are built from the scan’s `ScanSnapshot`. If the snapshot is missing or
not ready, the endpoint returns `409` rather than fabricating an empty report.
False-positive findings are excluded from compatibility exports by default,
matching Breadcrumb’s report policy.

```bash
curl -s http://127.0.0.1:8787/api/reports/12
curl -s -o report.pdf http://127.0.0.1:8787/api/reports/12/export/pdf
```

---

## 6. Differences from Leadline’s API

- No React SPA and no second service/database.
- Target `custom_headers` are not exposed through the compatibility API.
- Scan creation always uses Breadcrumb’s queue; `start` does not synchronously
  run a scan unless inline mode is enabled.
- Reports may be richer than Leadline’s (risk summary, verified/unverified CVE
  counts, security headers, technologies), but the top-level shapes are
  compatible.
- Imported scans are historical. They can be read, reported and diffed, but not
  re-run.
- New Breadcrumb features may appear only in `/api/v1` first; the compatibility
  layer is allowed to lag.

---

## 7. Security notes

- The API is protected by loopback binding, the Host allowlist, and
  Origin/Sec-Fetch-Site checks. HTML form posts additionally require a CSRF
  token; JSON clients should still send only same-origin requests.
- There is no authentication. Anyone who can reach the port can read and write
  the notebook.
- Do not put tokens, cookies or authorization headers in compatibility
  requests. Use encrypted Breadcrumb header profiles for authenticated scans.
- See [SECURITY_MODEL.md](SECURITY_MODEL.md) before exposing anything beyond
  `127.0.0.1`.
