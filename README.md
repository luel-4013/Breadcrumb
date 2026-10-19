# Breadcrumb

**The offline-first recon notebook for solo bug-bounty hunters.**

Paste raw tool output — nmap, subfinder, URLs, secrets, JWTs, hashes — and
Breadcrumb organizes it into programs, targets, entities, a knowledge graph,
change history, and submission-ready reports. Your data never leaves the
machine. An optional local LLM (Jan, LM Studio, Ollama) acts as your recon
analyst.

## Why Breadcrumb?

| Tool | Model | Breadcrumb difference |
|---|---|---|
| reNgine | Heavy Django + Postgres + Celery, runs scans for you | Single service, SQLite, runs on a laptop; import-first instead of scan-first |
| BBOT / Amass / SpiderFoot | CLI-first recursive scanners | Organizes output from *any* of them; deterministic graph + AI summaries |
| ProjectDiscovery stack | Pipes of single-purpose CLIs | Accepts their output via paste, file upload, or `POST /api/v1/pastes`; emits `targets.txt` ready for `nuclei -l` |
| reNgine / reconFTW / Osmedeus / Faraday | Run/aggregate scans, diff within one engagement | **Cross-program memory** and **tamper-evident evidence** (see below) |
| DefectDojo / Faraday | Team vuln management | Solo-hunter workflow, zero setup, local AI instead of ticket queues |
| Maltego / BloodHound | Visual link analysis (paid / AD-specific) | Free typed recon graph with scope attribution and change diffing |

Core bets: **offline-first** (works on a plane), **deterministic before AI**
(parsers and scope rules are exact and testable; the LLM only narrates),
**boring deploy** (one SQLite file, one container, no Postgres/Redis/Neo4j).

## What only Breadcrumb does

- **Cross-program memory (the Ledger).** Every asset is remembered across *all*
  your programs. When a host, port, secret or finding you met months ago on
  another engagement shows up again, it's flagged `seen ×N` with links back.
  Scanners forget between runs; Breadcrumb remembers across targets. Nobody else
  in this space does this — it's the payoff of being a local notebook.
- **Tamper-evident captures.** Every capture is SHA-256 sealed and hash-chained
  to the previous one. `GET /api/v1/verify` proves offline that no evidence was
  altered after the fact (deleted captures show as *gaps*, not false alarms).
  Useful when scope or a report is disputed — and impossible to fake without a
  chain break. No competitor offers evidence integrity.

## Quickstart

Docker (recommended):

```bash
docker compose up --build
# http://127.0.0.1:8787 — data persists in the breadcrumb-data volume
```

Local Python:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

## Features

- **16+ parsers**: nmap (text/greppable/XML), **ProjectDiscovery nuclei JSONL**
  (→ severity-tagged findings), **httpx JSON** (status, title, tech, CNAME),
  naabu/masscan port output, subfinder-style hosts, URLs, DNS records, HTTP
  headers, JWTs, AWS-style secrets, credentials, hashes, CVEs, emails, IPs/CIDRs.
  Re-importing tool output never duplicates findings.
- **Subdomain-takeover candidates**: a host whose CNAME points at an unclaimed
  S3 bucket, Heroku app, GitHub Pages site, etc. is flagged as a high-severity
  finding (offline heuristic, from the can-i-take-over-xyz fingerprints).
- **Programs, targets, scope rules**: CIDR, wildcard, domain-suffix, negation
  rules *and path-prefix rules* (`example.com/admin/*`) classify every entity as
  in/out/unknown scope; targets are **auto-created from scope** and entities are
  attributed to targets automatically. Programs and targets are fully editable /
  deletable from the UI.
- **Knowledge graph**: typed nodes and edges (runs, resolves_to, belongs_to…)
  with an SVG view and per-target clusters (large clusters are summarized, not
  rendered, so huge programs stay fast).
- **Change detection**: each program has a *Changes* view — latest capture vs
  everything before it (new + disappeared), Amass-`track` style.
- **Triage & accuracy**: mark entities *confirmed*, *needs-review*, or
  *false-positive*; add tags and private notes to entities and findings; ignore
  noise without deleting. False positives and ignored rows never appear in
  reports or exports.
- **Findings workflow**: severity + status (`open → in-progress → resolved /
  wont-fix`), tags + notes, per-target findings, HackerOne-style markdown export.
- **Exports**: HTML, Markdown, JSON, CSV, **SARIF** (CI / GitHub code
  scanning), HackerOne report, printable HTML (**Print → Save as PDF**),
  `targets.txt` (pipe straight into `nuclei -l` / `httpx -l`). Secrets are
  masked in exports unless `?reveal=1`.
- **Local AI analyst**: *Analyze with AI* on any capture, *Summarize* per
  program. Strict JSON extraction with graceful fallback. Works with any
  OpenAI-compatible server.
- **Automation API**: `POST /api/v1/pastes` accepts JSON or raw bytes —
  `subfinder -d t.com -silent | curl -X POST /api/v1/pastes --data-binary @-`.
  Bulk triage, findings query, and a CI **gate** endpoint included.
- **CLI** (`python -m app.cli`): headless `ingest`, `export` (incl. `--format
  sarif`), `findings`, `gate`, `programs`, `backup`, `serve` — same engine, no
  server needed.
- **Recon pipeline generator**: `/pipeline` turns a program's scope into the
  exact copy-paste command chain (subfinder → httpx → nuclei → import),
  pre-filled with your header profile and `targets.txt` — the ProjectDiscovery
  workflow, wired back into Breadcrumb.
- **Runner seam**: a 30+ tool catalog (nmap, naabu, masscan, subfinder, amass,
  ffuf, nuclei, dalfox, katana, …) with activate/deactivate toggles, binary
  presence checks, and validity reports — plus your own custom runners. Queue
  jobs (`/runners`, `POST /api/v1/jobs`), then **cancel / retry / delete / clear**
  and follow each job's log at `/jobs/{id}`. Executors POST results back.
  No agent to install; BYO tooling.
- **Header profiles**: randomized realistic user-agents across OS × browser ×
  device (desktop + mobile), full header sets, custom overrides, optional
  **proxy / SOCKS egress** and **rate-limit hint**, one-click curl flags.
  Attach a profile to any scan job so executors send it.
- **Notifications** (opt-in): Discord, Slack, Telegram, or a generic webhook on
  new findings (severity floor) and surface changes. Disabled by default —
  nothing leaves the machine until you add a channel.
- **Ops**: one-file SQLite backup/restore, **auto-backup before any schema
  migration**, composite indices for large datasets, health endpoint with
  version, command palette (`Ctrl/Cmd+K`), filter language
  (`type:port scope:in program:acme tag:needs-auth verdict:false-positive`),
  light/dark themes.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BREADCRUMB_DB_PATH` | `./breadcrumb.db` | SQLite file location |
| `BREADCRUMB_HOST` | `127.0.0.1` | Bind address |
| `BREADCRUMB_PORT` | `8787` | Port |
| `BREADCRUMB_RELOAD` | `1` | Dev auto-reload (`0` in Docker) |
| `BREADCRUMB_AI_TIMEOUT` | `180` | Seconds before a local-model call is aborted with an error |
| `BREADCRUMB_NOTIFY_CONFIG` | `./breadcrumb.notify.json` | Notification channels config file |
| `BREADCRUMB_SKIP_BACKUP` | unset | Set `1` to skip the pre-migration DB backup |

Limits: 5 MB per paste/file/API body, 25,000 entities per paste (truncated
with a visible notice). Every ingest reports parser failures instead of
failing silently — a zero-entity capture tells you why.

LLM providers are configured in the UI under **Settings** (stored in
`breadcrumb.llm.json`, git-ignored). Point Jan at
`http://127.0.0.1:1337/v1` (Local API Server) or LM Studio at
`http://127.0.0.1:1234/v1`. Notification channels are configured on the same
page (stored in `breadcrumb.notify.json`, git-ignored).

## CLI

```bash
python -m app.cli serve                       # run the web UI
python -m app.cli ingest scan.txt --program 1 # headless ingest (or - for stdin)
python -m app.cli export 1 --format sarif -o out.sarif
python -m app.cli gate 1 --max-severity high   # exit 1 to fail a CI job
python -m app.cli findings --program 1 --min-severity high
python -m app.cli programs --json
python -m app.cli watch ~/recon-drop --program 1   # auto-ingest a drop folder
python -m app.cli backup -o nightly.db
```

## API v1

```bash
# ingest
curl -X POST /api/v1/pastes -H 'Content-Type: application/json' \
  -d '{"text": "...", "program_id": 1}'

# query
curl '/api/v1/entities?program_id=1&type=subdomain'
curl '/api/v1/findings?program_id=1&min_severity=high'
curl /api/v1/programs

# bulk triage (ignore | unignore | delete | tag | untag | verdict)
curl -X POST /api/v1/entities/bulk -H 'Content-Type: application/json' \
  -d '{"action": "verdict", "ids": [1,2,3], "verdict": "false-positive"}'

# CI gate: HTTP 409 + {"pass": false} when findings are at/above the threshold
curl -f '/api/v1/gate?program_id=1&max_severity=high'

# verify evidence integrity (offline hash-chain)
curl '/api/v1/verify'   # {"valid": true, "sealed": N, "gaps": 0, "broken_at": null}

# jobs (runner seam)
curl -X POST /api/v1/jobs -H 'Content-Type: application/json' \
  -d '{"runner": "nmap", "target": "10.0.0.0/24", "program_id": 1}'
curl -X POST /api/v1/jobs/1/status -H 'Content-Type: application/json' \
  -d '{"status": "running", "log": "starting..."}'

# backup
curl -O http://127.0.0.1:8787/api/v1/backup
```

No auth — Breadcrumb binds to localhost and trusts the operator, like ZAP's
API-key-optional local mode. Do not expose it to untrusted networks without a
reverse proxy.

## Roadmap

- Scheduled re-import (cron) on top of the drop-folder watcher
- More parsers (ffuf, gau/katana URLs, Shodan JSON)
- Runner executors (opt-in local job runner) with live progress
- Status-code scope filters and per-rule severity overrides

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). One concern per PR, tests required,
offline-first always.

## License

MIT — see [LICENSE](LICENSE).
