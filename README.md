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
- **Local-only boundaries.** Breadcrumb binds to `127.0.0.1` and rejects
  unknown `Host` headers, cross-origin writes, and form posts without a CSRF
  token. That keeps a random web page from driving the local API through your
  browser. There is still no login: do not expose the port to a network.

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

- **20+ parsers**: nmap (text/greppable/XML), **ProjectDiscovery nuclei JSONL**
  (→ severity-tagged findings), **httpx JSON** (status, title, tech, CNAME),
  naabu/masscan port output, subfinder-style hosts, URLs, DNS records, HTTP
  headers, JWTs, AWS-style secrets, credentials, hashes, CVEs, emails, IPs/CIDRs,
  **ffuf JSON**, **Dalfox JSON/JSONL**, **Amass JSON**, **WhatWeb JSON** and
  **wafw00f JSON**. Re-importing tool output never duplicates findings.
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
  everything before it (new + disappeared), Amass-`track` style — plus
  per-target snapshot timelines and scan-to-scan diffs (findings, ports, DNS,
  endpoints, technologies, headers, risk).
- **Triage & accuracy**: mark entities *confirmed*, *needs-review*, or
  *false-positive*; add tags and private notes to entities and findings; ignore
  noise without deleting. False positives and ignored rows never appear in
  reports or exports.
- **Findings workflow**: severity + status (`open → in-progress → resolved /
  wont-fix`), tags + notes, per-target findings, HackerOne-style markdown export.
- **Exports**: HTML, Markdown, JSON, CSV, **SARIF** (CI / GitHub code
  scanning), HackerOne report, printable HTML, **PDF** with confidentiality
  banner and escaped evidence, and `targets.txt` (pipe straight into
  `nuclei -l` / `httpx -l`). Secrets are masked in exports unless `?reveal=1`.
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
- **Native scanning + runner seam**: the twelve-phase `leadline-recon` preset
  (DNS, host intel, ports/TLS, HTTP, tech, JS, params, headers, API, vuln
  candidates, local CVE verification, graph) runs through a durable local
  queue with leases, retries, cancellation and crash recovery. A 30+ tool
  catalog (nmap, naabu, masscan, subfinder, amass, ffuf, nuclei, dalfox,
  katana, …) keeps its import-first contract; twelve external tools have
  opt-in adapters (`BREADCRUMB_EXTERNAL_TOOLS=1`) with scope preflight,
  argv-only execution, process-group cancellation and output caps. The
  executor is **off by default**; activate it with `breadcrumb worker` or
  `BREADCRUMB_EXECUTOR=inline`.
- **Header profiles**: randomized realistic user-agents across OS × browser ×
  device (desktop + mobile), full header sets, custom overrides, optional
  **proxy / SOCKS egress** and **rate-limit hint**, one-click curl flags.
  Secrets are **encrypted at rest** (`enc:v1:`) with a local key; attach a
  profile to any scan job.
- **Notifications** (opt-in): Discord, Slack, Telegram, or a generic webhook on
  new findings (severity floor) and surface changes. Disabled by default —
  nothing leaves the machine until you add a channel.
- **Ops**: one-file SQLite backup/restore using SQLite's online backup API
  (WAL-safe, integrity-checked, atomic replace), **auto-backup before any
  schema migration**, composite indices for large datasets, health endpoint
  with version, command palette (`Ctrl/Cmd+K`), filter language
  (`type:port scope:in program:acme tag:needs-auth verdict:false-positive`),
  light/dark themes.

## Migrating from Leadline

Breadcrumb absorbed Leadline's scanning capability as additive “hands”; it
remains the import-first notebook and the only system of record. To bring an
existing Leadline database across, work on copies and start with a dry run:

```bash
sqlite3 "/path/to/Leadline/leadline.db" ".backup '/tmp/leadline-copy.db'"
python -m app.cli import-leadline --db /tmp/leadline-copy.db \
  --program-name "Leadline import" --dry-run
python -m app.cli import-leadline --db /tmp/leadline-copy.db \
  --program-name "Leadline import" --report /tmp/leadline-import-report.json
python -m app.cli import-leadline --db /tmp/leadline-copy.db --verify
```

The source is opened read-only and never modified. Imported scans are
historical and cannot be re-run; imported programs start with empty scope.
The executor stays off until you run `python -m app.cli worker` or set
`BREADCRUMB_EXECUTOR=inline`. See
[docs/LEADLINE_MERGE_GUIDE.md](docs/LEADLINE_MERGE_GUIDE.md) for the full
workflow, [docs/LEADLINE_IMPORT_VERIFICATION.md](docs/LEADLINE_IMPORT_VERIFICATION.md)
for the real-data report, and [docs/ROLLBACK_PLAN.md](docs/ROLLBACK_PLAN.md)
for recovery. The original Leadline folder is retained as a reference/fallback.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BREADCRUMB_DB_PATH` | `./breadcrumb.db` | SQLite file location |
| `BREADCRUMB_HOST` | `127.0.0.1` | Bind address |
| `BREADCRUMB_PORT` | `8787` | Port |
| `BREADCRUMB_RELOAD` | `1` | Dev auto-reload (`0` in Docker) |
| `BREADCRUMB_AI_TIMEOUT` | `180` | Seconds before a local-model call is aborted with an error |
| `BREADCRUMB_NOTIFY_CONFIG` | `./breadcrumb.notify.json` | Notification channels config file |
| `BREADCRUMB_SKIP_BACKUP` | unset | Set `1` to skip the pre-migration/restore DB backup |
| `BREADCRUMB_ALLOWED_HOSTS` | `127.0.0.1,localhost,::1` | Extra comma-separated `Host` values allowed for local/dev access (for example `breadcrumb.lan`) |
| `BREADCRUMB_LMS_PATH` | auto-detect | Path to the LM Studio `lms` CLI used by model Auto-fit |
| `BREADCRUMB_JAN_MODELS` | `~/.local/share/Jan/data/llamacpp/models` | Jan model metadata directory |
| `BREADCRUMB_SECRET_KEY` | unset (uses key file) | Fernet key or passphrase for header-profile secrets (cookies, auth headers, proxy credentials) |
| `BREADCRUMB_SECRET_KEYS` | unset | Comma-separated rotation keys, newest first; takes precedence over `BREADCRUMB_SECRET_KEY` |
| `BREADCRUMB_KEY_FILE` | `<DB_PATH>.key` | Secret-key file location; generated with mode `0600` on first use |

Header-profile secrets are encrypted at rest with Fernet/MultiFernet. The key
file is created next to the database on first write; **back it up separately
from the database**. Lose it and encrypted header values are unrecoverable.
Rotate with `python -m app.cli secrets rotate` (file-backed keys only; previous
keys are archived at `<key>.old` until you delete that file). The local UI/API
still shows decrypted values so the existing curl-copy workflow keeps working;
the protection is for database files, backups, and copies of the repo. New
pre-migration backups are scrubbed automatically; treat any older
`*.pre-migrate-*.bak` files from before this version as sensitive and delete
them once you have verified the migration.

Limits: 5 MB per paste/file/API body, 25,000 entities per paste (truncated
with a visible notice). Every ingest reports parser failures instead of
failing silently — a zero-entity capture tells you why.

LLM providers are configured in the UI under **Settings** (stored in
`breadcrumb.llm.json`, git-ignored). Point Jan at
`http://127.0.0.1:1337/v1` (Local API Server) or LM Studio at
`http://127.0.0.1:1234/v1`. Notification channels are configured on the same
page (stored in `breadcrumb.notify.json`, git-ignored).

**Available models** on the Settings page lists only models reported by the
running provider. Each model shows role hints (analysis, writing, report
compilation, code, reasoning, experimental), model max context, and a 4 GB fit
estimate. **Test** measures output and tokens/second; **Auto-fit + test** probes
descending context sizes and keeps the largest one that loads and answers.
Curated download links are static — nothing is downloaded automatically and
too-large models remain selectable with a warning. The picker can assign a
model to one route or all four routes; per-job overrides come with the scanning
work.

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
python -m app.cli worker --poll 2 --lease 120      # durable native/adapter worker
python -m app.cli collect example.com --program 1 --collector leadline-recon
python -m app.cli history 1 --diff                  # target timeline/diff
python -m app.cli report 1 --format pdf -o report.pdf
python -m app.cli import-leadline --db /path/to/leadline.db --dry-run
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

# verify evidence integrity (offline hash-chain + head/length)
curl '/api/v1/verify'
# {"valid": true, "sealed": 12, "gaps": 0, "broken_at": null,
#  "forks": 0, "sequence_ok": true, "head_ok": true, "length_ok": true}

# jobs (runner seam)
curl -X POST /api/v1/jobs -H 'Content-Type: application/json' \
  -d '{"runner": "nmap", "target": "10.0.0.0/24", "program_id": 1}'
curl -X POST /api/v1/jobs/1/status -H 'Content-Type: application/json' \
  -d '{"status": "running", "log": "starting..."}'

# Leadline-shaped compatibility API (translation-only)
curl /api/targets
curl /api/scans
curl '/api/findings?program_id=1&severity=high'

# backup
curl -O http://127.0.0.1:8787/api/v1/backup
```

No auth — Breadcrumb binds to localhost and trusts the operator, like ZAP's
API-key-optional local mode. Unknown `Host` headers, cross-origin writes, and
form posts without a CSRF token are rejected. JSON/raw API calls from `curl`
are unaffected; browser form posts use a hidden token (an `X-CSRF-Token`
header is also accepted). Do not expose it to untrusted networks without a
reverse proxy.

## Roadmap

- Publish the 0.4.0 Leadline merge release
- Scheduled re-import (cron) on top of the drop-folder watcher
- Scanned/OCR PDF export (text PDF is implemented)
- Status-code scope filters and per-rule severity overrides

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). One concern per PR, tests required,
offline-first always.

## License

MIT — see [LICENSE](LICENSE).
