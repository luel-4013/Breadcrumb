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

First report in five minutes:

```bash
.venv/bin/python -m app.cli demo      # seed a sample program and captures
# open the printed URL (or /programs/<id>/reports), pick a template and preview
.venv/bin/python -m app.cli doctor    # check Python, SQLite, paths, key, parsers
```

From the demo program to a downloadable HackerOne Markdown file:

```bash
.venv/bin/python -m app.cli render 1 --template hackerone --format md -o report.md
```

## Features

- **20+ parsers**: nmap (text/greppable/XML), **ProjectDiscovery nuclei JSONL**
  (→ severity-tagged findings), **httpx JSON** (status, title, tech, CNAME),
  **BBOT JSON/JSONL** (DNS, IPs, ports, URLs, technologies, findings),
  naabu/masscan port output, subfinder-style hosts, URLs, DNS records, HTTP
  headers, JWTs, AWS-style secrets, credentials, hashes, CVEs, emails, IPs/CIDRs,
  **ffuf JSON**, **Dalfox JSON/JSONL**, **Amass JSON**, **WhatWeb JSON**,
  **wafw00f JSON**, and **Ledger JSONL** (parser `ledger_jsonl`: round-trip
  import of an exported memory slice). Re-importing tool output never
  duplicates findings.
- **Import trust, not silent drops**: every capture produces a machine-readable
  import report with parser versions, completeness, skipped rows, warnings and
  a “why zero entities” hint. `GET /api/v1/pastes/{id}/report` or
  `breadcrumb ingest --report-json -` shows it; `--dry-run` parses without
  writing. Malformed JSONL rows are counted, not swallowed.
- **Evidence Manifest v2**: every capture exports a redacted JSON/Markdown
  manifest with the source tool, command, parser versions, scope hashes, chain
  position, input SHA-256 and full/redacted output hashes.
  `breadcrumb verify --manifest <file> --raw <artifact>` checks it offline;
  `breadcrumb verify` checks the whole hash chain.
- **`breadcrumb doctor`**: diagnoses Python, SQLite, database directory/disk,
  integrity, schema version, key file, port, parser registry and optional tools
  with copy-paste fixes. `--json` and `/api/v1/doctor` are available for support
  scripts.
- **Subdomain-takeover candidates**: a host whose CNAME points at an unclaimed
  S3 bucket, Heroku app, GitHub Pages site, etc. is flagged as a high-severity
  finding (offline heuristic, from the can-i-take-over-xyz fingerprints).
- **Programs, targets, scope rules**: CIDR, wildcard, domain-suffix, negation
  rules *and path-prefix rules* (`example.com/admin/*`) classify every entity as
  in/out/unknown scope; targets are **auto-created from scope** and entities are
  attributed to targets automatically. Programs and targets are fully editable /
  deletable from the UI.
- **Cross-program memory (the Ledger, v2)**: every asset is remembered across
  *all* programs. The Ledger groups by `(type, normalized)`, shows first/last
  sighting, every program/target/capture that observed it, analyst verdicts,
  tags and notes, and links to a full asset timeline. Filter with
  `type:port scope:in tag:needs-auth seen:other-program status:200`, save the
  view locally, and export the slice as JSONL (round-trips through ingest) or
  CSV. A host seen in program A is surfaced in program B with links to both.
- **Diff v2**: compare any two captures (`paste:`), targets (`target:`),
  programs (`program:`) or scan jobs (`job:`). Categories: findings (new,
  disappeared, changed, still open), entities, ports, DNS, endpoints,
  technologies, security headers, and risk. Open `/diff`, call
  `GET /api/v1/diff?left=program:1&right=program:2`, or use
  `breadcrumb diff ... --format md`; send change alerts through the existing
  notification channels.
- **Scope v2**: status-code filters (`example.com status:200,204`), path-prefix
  rules (`example.com/admin/*`, negative `!example.com/private`), and per-rule
  severity overrides. Every entity gets an explainable decision with a stable
  reason code (`in_rule`, `out_rule`, `status_filter`, `status_unknown`,
  `no_match`, `no_scope`, `no_host`, `in_negated`, `re_included`). The Scope
  page shows "why is this out of scope?", supports bulk re-scope that appends
  durable rules, and never silently drops unknown-status assets.
- **Knowledge graph v2**: typed nodes and edges (runs, resolves_to, belongs_to…)
  with an SVG view, per-target clusters, saved graph views, and a
  **seen-in-other-programs** section that links shared assets to Ledger
  timelines. Large clusters are summarized, not rendered, so huge programs stay
  fast.
- **Change detection**: each program has a *Changes* view — latest capture vs
  everything before it (new + disappeared), Amass-`track` style — plus
  per-target snapshot timelines and the v2 cross-selector diff above.
- **Triage & accuracy**: mark entities *confirmed*, *needs-review*, or
  *false-positive*; add tags and private notes to entities and findings; ignore
  noise without deleting. False positives and ignored rows never appear in
  reports or exports.
- **Findings workflow**: severity + status (`open → in-progress → resolved /
  wont-fix`), tags + notes, per-target findings, HackerOne-style markdown export.
- **Report studio (Phase C)**: five built-in templates — HackerOne submission,
  pentest executive summary, technical finding report, recon inventory and
  change report — with typed variables, live preview, and Markdown/HTML/JSON/PDF
  output from one redacted context. Golden reports keep the formats in sync.
- **Redaction by default**: auth headers, cookies, bearer/JWT tokens, URL
  credentials, query tokens, cloud keys, private keys and sensitive entity
  values are masked in every report, export, manifest and review bundle.
  Custom `literal:`/`regex:` rules are additive; `reveal` is explicit and
  unsafe. See [docs/REDACTION_GUIDE.md](docs/REDACTION_GUIDE.md).
- **Offline review bundle**: one deterministic zip with printable HTML,
  Markdown, JSON, optional PDF, a SHA-256 manifest, per-capture redacted
  evidence manifests, optional comments, and an in-memory verifier that rejects
  tampering, traversal, symlinks and missing files. No login or server needed.
- **Screenshot evidence (Phase E)**: import EyeWitness/Gowitness manifests or
  manual PNG/JPEG/GIF/WebP uploads. Images are hashed, content-addressed and
  stored outside SQLite; metadata links to programs, targets, captures, entities
  and findings. There is no Chromium/Selenium dependency. Reports and bundles
  include screenshots only when explicitly requested, and say clearly that
  pixels are not redacted. See
  [docs/SCREENSHOT_COOKBOOK.md](docs/SCREENSHOT_COOKBOOK.md).
- **Integration exports**: HackerOne Markdown, DefectDojo Generic Findings
  Import JSON, Ghostwriter bridge JSON, Dradis note Markdown, **SARIF** (CI /
  GitHub code scanning), CSV, full JSON, and `targets.txt` (pipe straight into
  `nuclei -l` / `httpx -l`). Field mappings are documented in
  [docs/INTEGRATION_MAPPINGS.md](docs/INTEGRATION_MAPPINGS.md).
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

Limits: 5 MB per paste/file/API body, 25,000 entities per paste by default
(truncated with a visible notice; `--max-entities` and the API `max_entities`
field raise it per import). Every ingest reports parser failures instead of
failing silently — a zero-entity capture tells you why, with a hint and the
parser issues that caused it.

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

## Cross-program memory, diff, and scope cookbook

**Have I seen this before?** Import the same host into two programs, then open
`/ledger` or run `breadcrumb ledger show --type subdomain --value app.example.com`.
The timeline lists every capture, program and target that observed it. The same
asset appears in the other program's graph under *Seen in other programs*. Use
the `seen:other-program` filter to list only assets that crossed a program
boundary.

**Export a slice and bring it back.** `breadcrumb ledger export "tag:needs-auth"
-o auth.jsonl` writes one JSON object per asset. `breadcrumb ledger import
auth.jsonl` reads it through the normal ingest path, recreating programs from
the export's provenance and preserving verdicts, tags, notes, observed status
codes, and occurrence counts. Importing is additive and idempotent; scope is
recomputed for the destination program instead of trusting the file.

**What changed?** Compare captures, targets, programs or jobs:

```bash
breadcrumb diff paste:41 paste:57                  # two tool runs
breadcrumb diff program:1 program:2                # two engagements
breadcrumb diff job:9 job:14 --format md -o diff.md
breadcrumb diff job:14 --right program:1 --notify  # alert configured channels
```

Job selectors use the sealed scan snapshot, so the comparison is point-in-time
and not polluted by later imports. Capture/target/program selectors use live
evidence state. Findings marked false-positive are excluded; "still open" means
the same finding is active on both sides.

**Why is this out of scope?** Open `/programs/1/scope` and filter by
`status_filter` (or click *why?* next to an entity). The rule line that decided
the asset is shown verbatim. A status filter only decides entities whose HTTP
status is known: a URL with no observed status becomes `status_unknown`, not a
silent drop. Status filters compose with path rules, so
`example.com/admin/* status:200` scopes only successful admin paths. Bulk
re-scope appends selected hostnames to the program's in/out text and rebuilds,
which makes the decision durable and visible in the scope editor.

**Per-rule severity overrides.** In the program editor, add one
`rule-id=severity` line per nuclei template or BBOT finding name. Overrides are
applied on import and on *Save & rebuild*; the parser's original severity stays
in `Finding.meta.parser_severity` and `severity_override` records the change.
Remove a line to revert.

## Reports, redaction and review bundles

Open `/programs/<id>/reports` (or click **Report studio** on a program) to pick
a template, fill typed variables and preview the exact HTML that will be
downloaded. The five built-in templates cover a HackerOne submission, an
executive summary, a technical finding report, a recon inventory and a change
report. Markdown, HTML, JSON and PDF all render from the same validated,
redacted context.

```bash
# One finding, full evidence, internal technical report
python -m app.cli render 1 --template technical --var finding_id=42 --format html -o finding.html

# Recon inventory with strict masking for a client
python -m app.cli render 1 --template recon --redaction-profile strict --format pdf -o recon.pdf

# What changed since the previous capture?
python -m app.cli render 1 --template change --format md -o change.md

# Review bundle: report + redacted capture manifests + checksums
python -m app.cli bundle 1 --template technical --comments notes.md --include-pdf -o review.zip
python -m app.cli verify-bundle review.zip
```

Redaction is on by default. Add per-report rules as `literal:text=replacement`
or `regex:pattern=replacement` lines; built-in masking always runs first.
`--reveal` / `reveal=1` disables all masking and is never a safe default for a
shared artifact. A reveal bundle still verifies, but the verifier warns.

The review bundle is a single zip containing `report.html`, `report.md`,
`report.json`, an optional `report.pdf`, a SHA-256 manifest, per-capture
redacted evidence manifests, optional `comments.md`, `SHA256SUMS` and a
`README.txt`. Raw capture bodies are never included. Verification happens
in-memory: traversal, duplicate entries, symlinks, encryption, missing files
and hash mismatches all fail without extracting the zip.

Integration exports live next to the templates:

```bash
python -m app.cli export 1 --format defectdojo -o defectdojo.json
python -m app.cli export 1 --format ghostwriter -o ghostwriter.json
python -m app.cli export 1 --format dradis -o dradis.md
python -m app.cli export 1 --format sarif -o breadcrumb.sarif
```

See [docs/REPORT_COOKBOOK.md](docs/REPORT_COOKBOOK.md),
[docs/REDACTION_GUIDE.md](docs/REDACTION_GUIDE.md) and
[docs/INTEGRATION_MAPPINGS.md](docs/INTEGRATION_MAPPINGS.md).

## Screenshots and evidence artifacts

Breadcrumb does not take screenshots itself. It imports images produced by tools
you already run, links them to the evidence they support, and keeps the bytes
outside SQLite.

```bash
# EyeWitness CSV/JSON or Gowitness JSON/JSONL
python -m app.cli artifacts import ~/recon/acme/eyewitness/report.csv \
  --program 1 --base-dir ~/recon/acme/eyewitness

# Attach the import to a finding, then browse and verify
python -m app.cli artifacts import ~/recon/acme/gowitness/report.jsonl \
  --program 1 --finding 42
python -m app.cli artifacts list --program 1
python -m app.cli artifacts show 7 --json
python -m app.cli artifacts export 7 -o evidence/admin.png
python -m app.cli artifacts manifest --program 1 -o artifacts.json

# Reports and review bundles opt in explicitly
python -m app.cli render 1 --template technical --var include_screenshots=1 \
  --format html -o finding.html
python -m app.cli bundle 1 --template technical --include-screenshots \
  -o review.zip
```

Default root: `<database-name>.artifacts` beside the SQLite file, or
`BREADCRUMB_ARTIFACT_DIR`. PNG/JPEG/GIF/WebP only; SVG and PDF are rejected
because an evidence image is served to a browser. Caps: 12 MiB/image, 2,000
manifest rows, 1,000 images/import. Every read verifies SHA-256 before serving.
Manifests never create targets; the target is explicit or inferred from the
source URL and existing scope rules.

Screenshots are included in reports and bundles **only when requested**. HTML
and PDF embed the image, JSON keeps metadata without base64 bytes, and Markdown
lists source/dimensions/hash. Redaction masks text fields, not pixels: review
every image before sharing. See
[docs/SCREENSHOT_COOKBOOK.md](docs/SCREENSHOT_COOKBOOK.md).

## Automation: schedules and local parsers

**Scheduled re-import** watches one local folder and imports new files through
the normal capture path. There is no cloud scheduler and no daemon installed by
default; run the scheduler from cron/systemd or in a terminal.

```bash
breadcrumb schedule add acme-nightly ~/recon/acme/drop --program 1 --interval 3600
breadcrumb schedule list
breadcrumb schedule show acme-nightly
breadcrumb schedule run acme-nightly        # run one now
breadcrumb scheduler --poll 30              # foreground loop
breadcrumb scheduler --once                 # one due-check, for cron
```

Each run records `ok`/`partial`/`error`/`skipped`, per-file detail, entities,
findings and errors; identical bytes are deduplicated by content hash, and
successful files move to `processed/`. The web UI is `/schedules`, the API is
`/api/v1/schedules`. URL/API pulls are deliberately absent: an external tool
fetches into the folder, so Breadcrumb never stores schedule credentials or
opens an SSRF path.

**Local parser SDK** loads your own parsers from `$BREADCRUMB_PARSER_DIR` or
`~/.breadcrumb/parsers`. There is no remote marketplace; a plugin is imported
Python and runs with your permissions. Broken plugins are listed at `/parsers`
and in `breadcrumb parsers --json` but never stop startup. See
[docs/PARSER_AUTHORING.md](docs/PARSER_AUTHORING.md) for the contract, a full
example and the trust boundary.

**Automation-friendly API**: `capture_key` / `Idempotency-Key` makes retries
safe (201 new, 200 duplicate), `POST /api/v1/pastes/bulk` imports up to 100
captures with per-item isolation, and `GET /api/v1/findings` is paginated with
`total`/`next_offset`. CI can use `breadcrumb gate` or `/api/v1/gate`.
See [docs/AUTOMATION_COOKBOOK.md](docs/AUTOMATION_COOKBOOK.md) for cron, CI,
bulk, pagination and notification recipes.

Performance is measured, not assumed: import and read-path benchmarks, query
plans, the 1M-entity baseline and tuning rules are in
[docs/PERFORMANCE_TUNING.md](docs/PERFORMANCE_TUNING.md).

## CLI

```bash
python -m app.cli serve                       # run the web UI
python -m app.cli demo                        # seed sample program + first report
python -m app.cli doctor --json               # installation/database/parser checks
python -m app.cli ingest scan.txt --program 1 # headless ingest (or - for stdin)
python -m app.cli ingest scan.txt --dry-run   # parse/report without writing
python -m app.cli ingest scan.txt --report-json -  # machine-readable import report
python -m app.cli manifest 1 --format md -o capture.md
python -m app.cli verify --paste 1            # capture/manifest/hash-chain check
python -m app.cli export 1 --format sarif -o out.sarif
python -m app.cli export 1 --format defectdojo -o findings.json
python -m app.cli gate 1 --max-severity high   # exit 1 to fail a CI job
python -m app.cli findings --program 1 --min-severity high
python -m app.cli programs --json
python -m app.cli watch ~/recon-drop --program 1   # auto-ingest a drop folder
python -m app.cli schedule add acme ~/recon/acme/drop --program 1 --interval 3600
python -m app.cli schedule list                    # run history lives on show
python -m app.cli schedule run acme --json
python -m app.cli scheduler --once                 # cron-friendly due check
python -m app.cli parsers --json                   # built-in + local plugins
python -m app.cli artifacts list --program 1       # hashed screenshot evidence
python -m app.cli artifacts import report.json --program 1 --base-dir ~/recon
python -m app.cli artifacts show 7 --json          # hash verification included
python -m app.cli artifacts export 7 -o shot.png
python -m app.cli artifacts manifest --program 1 -o artifacts.json
python -m app.cli artifacts delete 7 --yes
python -m app.cli backup -o nightly.db
python -m app.cli worker --poll 2 --lease 120      # durable native/adapter worker
python -m app.cli collect example.com --program 1 --collector leadline-recon
python -m app.cli history 1 --diff                  # target timeline/diff
python -m app.cli diff paste:4 paste:5              # cross-selector diff (md/json)
python -m app.cli ledger list "seen:other-program"  # cross-program memory
python -m app.cli ledger show --type subdomain --value app.example.com
python -m app.cli ledger export "tag:needs-auth" -o auth.jsonl
python -m app.cli ledger import auth.jsonl          # additive round-trip
python -m app.cli report-templates                  # list built-in report templates
python -m app.cli render 1 --template hackerone --format md -o report.md
python -m app.cli render 1 --template technical --format pdf -o report.pdf
python -m app.cli bundle 1 --template technical --include-pdf -o review.zip
python -m app.cli bundle 1 --template technical --include-screenshots -o review.zip
python -m app.cli verify-bundle review.zip          # offline, in-memory check
python -m app.cli report 1 --format pdf -o report.pdf
python -m app.cli import-leadline --db /path/to/leadline.db --dry-run
```

## API v1

```bash
# ingest (idempotent: 201 new, 200 duplicate)
curl -X POST /api/v1/pastes -H 'Content-Type: application/json' \
  -d '{"text": "...", "program_id": 1, "capture_key": "tool:run:1"}'
subfinder -d example.com -silent \
  | curl -X POST /api/v1/pastes -H 'Idempotency-Key: subfinder:acme:1' --data-binary @-

# bounded bulk ingest (207, per-item isolation, max 100)
curl -X POST /api/v1/pastes/bulk -H 'Content-Type: application/json' \
  -d '{"program_id":1,"captures":[{"filename":"a.jsonl","text":"...","capture_key":"a:1"}]}'

# scheduled local folder re-import
curl -X POST /api/v1/schedules -H 'Content-Type: application/json' \
  -d '{"name":"acme","source":"/home/me/recon/acme/drop","program_id":1,"interval_seconds":3600}'
curl -X POST /api/v1/schedules/1/run
curl /api/v1/parsers                    # built-in + local plugin catalog

# screenshot evidence (metadata in SQLite, hashed bytes outside it)
curl -X POST /api/v1/artifacts \
  -F program_id=1 -F finding_id=42 -F source_url='https://app.example.com/' \
  -F upload=@screenshot.png
curl '/api/v1/artifacts?program_id=1&limit=50'
curl '/api/v1/artifacts/7'              # includes live hash verification
curl '/api/v1/artifacts/7/content' -o screenshot.png
curl '/api/v1/artifacts/manifest?program_id=1'
curl '/api/v1/tools'                    # adapter install/version/scope diagnostics

# import trust + evidence
curl '/api/v1/pastes/1/report'          # completeness, skipped rows, issues, hint
curl '/api/v1/pastes/1/manifest'        # redacted Evidence Manifest v2
curl '/api/v1/doctor'                   # diagnostics (200 ok, 503 failure)

# query (paginated)
curl '/api/v1/entities?program_id=1&type=subdomain&limit=100&offset=0'
curl '/api/v1/findings?program_id=1&min_severity=high&limit=100&offset=0'
curl /api/v1/programs

# cross-program memory + cross-selector diff
curl '/api/v1/ledger?q=type:port%20seen:other-program&limit=50'
curl '/api/v1/ledger/asset?type=subdomain&value=app.example.com'
curl '/api/v1/diff?left=program:1&right=program:2'

# reports, redaction and integration exports (all masked by default)
curl '/api/v1/report-templates'
curl '/reports/1/templates/hackerone.md'
curl '/reports/1/templates/technical.pdf' -o report.pdf
curl '/reports/1/defectdojo' -o defectdojo.json
curl '/reports/1/ghostwriter' -o ghostwriter.json
curl '/reports/1/dradis.md' -o dradis.md
curl '/reports/1/sarif' -o breadcrumb.sarif
# review bundle is a CSRF-protected form POST; use the CLI for scripts:
# python -m app.cli bundle 1 --template technical -o review.zip

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

- **0.5.0 — Proof:** parser contract, import reports/completeness, Manifest v2,
  `breadcrumb doctor`, sample demo, benchmark harness. Implemented.
- **0.6.0 — Memory:** Ledger v2, diff v2, scope v2 (status-code/path/rule),
  graph v2, saved views. Implemented.
- **0.7.0 — Report:** five templates, default-on redaction, review bundle,
  HackerOne/DefectDojo/Ghostwriter/Dradis/SARIF exports. Implemented.
- **0.8.0 — Automate:** scheduled re-import, local parser SDK, stable API
  pagination, 1M-entity performance. Implemented.
- **0.9.0 — Capture:** EyeWitness/Gowitness screenshot import, hashed artifact
  storage, explicit screenshot reports/bundles, adapter diagnostics. Implemented.
- **1.0.0 — Flagship:** security/migration/rollback/soak gates and docs. Next.

See [docs/IMPORT_COOKBOOK.md](docs/IMPORT_COOKBOOK.md),
[docs/MANIFEST_AND_DOCTOR.md](docs/MANIFEST_AND_DOCTOR.md),
[docs/CROSS_PROGRAM_MEMORY.md](docs/CROSS_PROGRAM_MEMORY.md),
[docs/DIFF_COOKBOOK.md](docs/DIFF_COOKBOOK.md),
[docs/SCOPE_DECISIONS.md](docs/SCOPE_DECISIONS.md),
[docs/REPORT_COOKBOOK.md](docs/REPORT_COOKBOOK.md),
[docs/REDACTION_GUIDE.md](docs/REDACTION_GUIDE.md),
[docs/INTEGRATION_MAPPINGS.md](docs/INTEGRATION_MAPPINGS.md),
[docs/AUTOMATION_COOKBOOK.md](docs/AUTOMATION_COOKBOOK.md),
[docs/PARSER_AUTHORING.md](docs/PARSER_AUTHORING.md),
[docs/SCREENSHOT_COOKBOOK.md](docs/SCREENSHOT_COOKBOOK.md),
[docs/ADAPTER_SAFETY.md](docs/ADAPTER_SAFETY.md) and
[docs/PERFORMANCE_TUNING.md](docs/PERFORMANCE_TUNING.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). One concern per PR, tests required,
offline-first always.

## License

MIT — see [LICENSE](LICENSE).
