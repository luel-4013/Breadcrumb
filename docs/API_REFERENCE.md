# API reference

Breadcrumb exposes a local HTTP API at `http://127.0.0.1:8787`. There is no
remote service, account, API key or cloud dependency. The default bind is
loopback-only and the host allowlist rejects unknown `Host` values.

Write requests must satisfy the same local-boundary checks as the UI:

- `Host` must be loopback or listed in `BREADCRUMB_ALLOWED_HOSTS`.
- Cross-origin `Origin`/`Sec-Fetch-Site` writes are rejected.
- Browser form posts need the `bc_csrf` token (hidden field or
  `X-CSRF-Token` header). JSON API clients should fetch `/health` first to
  receive the cookie, then send the header.

Errors use FastAPI's `{"detail": "..."}` shape unless noted. Pagination uses
`limit`, `offset` and a response `total`/`next_offset` where the endpoint
supports it.

## Operational

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Version, schema, DB path, WAL, maintenance, job counts, expired leases |
| GET | `/api/v1/backup` | Download a consistent SQLite snapshot |
| POST | `/backup/restore` | Upload and validate a database, with a safety backup |

## Diagnostics and metadata

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/doctor` | Diagnostics; `200` when healthy, `503` on failure |
| GET | `/api/v1/tools` | Adapter install/version/scope/strict diagnostics |
| GET | `/api/v1/parsers` | Built-in and local parser catalog plus load errors |
| GET | `/api/v1/report-templates` | Report template ids, variables and defaults |
| GET | `/api/v1/verify` | Recompute the evidence chain and report gaps/forks |
| GET | `/api/v1/ledger` | Cross-program asset memory, paginated |
| GET | `/api/v1/ledger/asset` | Timeline and links for one asset |
| GET | `/api/v1/diff` | Diff two captures/targets/programs/jobs |

## Ingest and evidence

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/pastes` | Ingest text; `201` new, `200` duplicate via `Idempotency-Key`/`capture_key` |
| POST | `/api/v1/pastes/bulk` | Bounded bulk ingest (max 100); `207` with per-item isolation |
| GET | `/api/v1/pastes/{paste_id}/report` | Import report: completeness, skipped rows, warnings, hint |
| GET | `/api/v1/pastes/{paste_id}/manifest` | Redacted Evidence Manifest v2 |

## Entities, findings and programs

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/entities` | Paginated/filterable entities |
| POST | `/api/v1/entities/bulk` | Bounded entity update/import endpoint |
| GET | `/api/v1/findings` | Paginated findings; supports severity/program filters |
| GET | `/api/v1/programs` | Programs with counts |
| GET | `/api/v1/gate` | CI gate result for a severity threshold |

## Jobs and collectors

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/jobs` | List jobs |
| POST | `/api/v1/jobs` | Queue a native collector or opt-in adapter |
| GET | `/api/v1/jobs/{job_id}` | Job detail, attempts, phases, events |
| POST | `/api/v1/jobs/{job_id}/cancel` | Request cooperative cancellation |
| POST | `/api/v1/jobs/{job_id}/retry` | Re-arm a finished/failed job |
| POST | `/api/v1/jobs/{job_id}/run` | Run now (queues or claims according to executor mode) |
| POST | `/api/v1/jobs/{job_id}/status` | External runner status update (compatibility path) |
| GET | `/api/v1/headers` | Header profiles (decrypted for the local UI) |
| POST | `/api/v1/headers` | Create/update an encrypted header profile |
| GET | `/api/v1/headers/{profile_id}` | One header profile |

## Schedules

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/schedules` | List local folder schedules |
| POST | `/api/v1/schedules` | Create a schedule |
| GET | `/api/v1/schedules/{schedule_id}` | Schedule detail and run history |
| PATCH | `/api/v1/schedules/{schedule_id}` | Update interval/overlap/enabled |
| DELETE | `/api/v1/schedules/{schedule_id}` | Delete schedule and run history |
| POST | `/api/v1/schedules/{schedule_id}/run` | Run now, optionally `force` |

## Screenshot artifacts

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/artifacts` | Paginated screenshot metadata |
| POST | `/api/v1/artifacts` | Multipart upload; `201` new, `200` duplicate |
| POST | `/api/v1/artifacts/import` | Import EyeWitness/Gowitness JSON/JSONL/CSV manifest |
| GET | `/api/v1/artifacts/manifest` | Artifact metadata manifest (no inline bytes) |
| GET | `/api/v1/artifacts/{artifact_id}` | Detail plus live SHA-256 verification |
| GET | `/api/v1/artifacts/{artifact_id}/content` | Verified image bytes with sandbox CSP |
| DELETE | `/api/v1/artifacts/{artifact_id}` | Delete one row; bytes only after the last reference |

Screenshot bytes live outside SQLite in the artifact directory. The content
endpoint sends `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: default-src 'none'; sandbox`.

## Examples

```bash
# Read the local CSRF cookie once.
curl -c /tmp/bc.cookies http://127.0.0.1:8787/health
TOKEN=$(awk '$6 == "bc_csrf" {print $7}' /tmp/bc.cookies)

# Idempotent ingest.
curl -b /tmp/bc.cookies -X POST http://127.0.0.1:8787/api/v1/pastes \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: nmap:acme:2026-11-12" \
  -d '{"text":"...", "program_id":1}'

# Paginated query.
curl 'http://127.0.0.1:8787/api/v1/entities?program_id=1&limit=100&offset=0'

# Upload a screenshot.
curl -b /tmp/bc.cookies -X POST http://127.0.0.1:8787/api/v1/artifacts \
  -H "X-CSRF-Token: $TOKEN" \
  -F program_id=1 -F source_url='https://app.example.com/' \
  -F upload=@screenshot.png
```

The OpenAPI document is available at `/openapi.json` when the app is running.
It is generated from the same routes; this page documents the operator-facing
contract and the local-boundary rules that are not visible in the schema.
