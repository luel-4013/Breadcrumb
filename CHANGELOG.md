# Changelog

All notable changes to Breadcrumb are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The Leadline merge is the **0.4.0** release; the version in `app/__init__.py`
is `0.4.0`.

## [0.4.0] — 2026-11-08

Breadcrumb remains the flagship, import-first recon notebook and the only
system of record. Leadline has been absorbed as an additive native scanning
capability ("the hands"), not as a second service or replacement workflow.
Everything below is additive; the merge is being prepared for its first push.

### Added — Phase 8: Leadline importer and hardening (2026-11-08)

- `python -m app.cli import-leadline`: a one-way importer for an existing
  Leadline SQLite database. The source is
  opened `mode=ro` with `PRAGMA query_only=ON`; a SHA-256 fingerprint of the
  main file plus WAL is checked before and after reading, and a concurrent
  change aborts the import with instructions. Breadcrumb never modifies,
  archives or deletes the Leadline folder.
- `--dry-run` reports source counts, would-import counts, distinct header sets,
  triage/severity distributions, malformed rows, warnings and destination
  state without writing any rows or manifest. A real import backs up the
  destination, enables maintenance mode, and commits in one transaction.
- Data mapping: targets (URL/host name, notes, timestamps, active/inactive
  marker), encrypted `HeaderProfile` per distinct header set, historical
  `ScanJob` rows (`runner=leadline.imported`, `attempts=1`,
  `max_attempts=1`), `ScanPhase` events, findings with stable
  `leadline:<sha256(...)>` fingerprints, triage (`open`/`acknowledged`/
  `false_positive` via `app.triage`), notes, extra data/location/source IDs in
  `meta`, and graph nodes/parents/edges as entities and
  `part_of`/`references` relationships. Report blobs are not imported; reports
  are regenerated from the data.
- Imported scans are terminal history. The worker cannot claim them, the job
  page hides **Run now**/retry, and retry/run-now API calls return `409`.
  Imported snapshots are scoped to their source scan
  (`meta.leadline_scan_id`), so imported scan-to-scan diffs are meaningful
  while live snapshots remain cumulative target state.
- Idempotent resume manifest (default
  `<BREADCRUMB_DB_PATH>.leadline-import.json`, mode `0600`) with source path,
  fingerprint, program and source-ID → destination-ID map. Re-running skips
  existing rows instead of duplicating them.
- `--verify` checks counts, triage/severity distributions, sampled finding
  fields, header-profile decryption round-trip and the source fingerprint.
  `--report`/`--json` emit the full machine-readable result.
- Schema version 4 adds `target.meta` and `finding.meta` (JSON text) with an
  additive migration and automatic pre-migration backup.
- `scripts/acceptance_phase8.py` copies both source and destination (plus the
  destination key) into a temporary directory, runs the dry run, real import
  and verification, and checks the source fingerprint and raw header
  ciphertext. `--keep` preserves the temp directory; `--json` prints the
  report.
- Hardening documentation: merge/import guide, real-data verification report,
  compatibility API, security model, hardware/AI guide, troubleshooting,
  backup/restore/upgrade runbook, security checklist, release notes and
  rollback plan.
- Test suite: **182 passed, 1 warning**; Phase 8 adds 8 tests covering dry-run
  no-writes, CLI wiring, full mapping/triage/headers/snapshots/PDF, idempotent
  re-import, historical non-runnable jobs, verification failure detection,
  malformed/missing sources and a source without scan tables.

### Added — Phase 7: opt-in external tool adapters (2026-11-07)

- Twelve external-tool adapters registered separately from the native
  collectors: `nmap`, `httpx`, `nuclei`, `subfinder`, `naabu`, `masscan`,
  `katana`, `ffuf`, `dalfox`, `amass`, `whatweb` and `wafw00f`. Each adapter
  emits a format Breadcrumb already parses (or a new parser for
  ffuf/dalfox/amass/whatweb/wafw00f), so evidence still flows through the
  normal ingest/parser/chain path.
- Adapters are opt-in. The durable worker claims adapter jobs only when
  `BREADCRUMB_EXTERNAL_TOOLS=1`; explicit run-now and `breadcrumb collect
  --run-now` can execute one adapter job regardless. Breadcrumb's import-first
  external-runner contract is unchanged.
- Scope preflight before every spawn: denied, out-of-scope and unknown targets
  never start a process; private targets warn; metadata/link-local/multicast
  addresses stay hard-blocked; CIDR targets use `ScopeGuard.check_network`.
- Process isolation: argv lists only (`shell=False`), a fixed option schema,
  a fresh process group, SIGTERM/SIGKILL on cancel/timeout/overflow, per-run
  timeout, output cap, temporary `cwd`/`HOME`, and an environment allowlist
  that excludes proxies and application secrets. Header profiles are never
  passed to an external tool.
- `BREADCRUMB_STRICT_MODE=1` disables adapters that cannot be pinned
  (`nuclei`, `katana`, `ffuf`, `dalfox`, `whatweb`, `wafw00f`); `nmap` and
  `naabu` require an IP/CIDR target in strict mode. `httpx` uses a `-resolve`
  override when a pinned address is available.
- Missing binaries fail the job with an explicit "not installed" error instead
  of looking like an empty successful scan. `/runners` and `breadcrumb tools`
  show presence, version, scope mode and strict-mode state.
- New parsers: ffuf JSON, Dalfox JSON/JSONL (candidate-tagged), Amass
  JSON/JSONL, WhatWeb JSON and wafw00f JSON.
- Test suite: **174 passed, 1 warning**; Phase 7 adds 40 local tests using fake
  binaries (no nmap/httpx/nuclei installation required).

### Added — Phase 6: history, reports, PDF and compatibility (2026-11-07)

- `ScanSnapshot` rows generated when a job finishes. A snapshot is the
  target's state at scan completion (risk, severity counts, findings,
  endpoints, ports, DNS, technologies, headers, phases), is scoped through
  `ScanJob.target_id`, and is rebuildable from sealed evidence. Snapshot
  failure never fails a `done` job; the row is stored `pending`/`failed`.
- Target history timeline and scan-to-scan diff engine
  (`/targets/{id}/history`, `/api/targets/{id}/history`,
  `/api/targets/{id}/history/diff`). Diffs cover findings, ports, DNS,
  subdomains, endpoints, technologies, headers and risk.
- `Finding.verdict` plus a single triage vocabulary shared with entities:
  `open → status=open/verdict=none`, `acknowledged →
  status=in-progress/verdict=needs-review`, `false_positive →
  status=wont-fix/verdict=false-positive`. A primary triage control and a
  compatibility `PATCH /api/findings/{id}` use the same mapping.
- False-positive findings are excluded from reports, PDF, SARIF and the
  HackerOne/Markdown exports by default. `?include_triaged=1` produces an
  internal report that keeps them.
- PDF export (`reportlab`) with target/scan filenames, confidentiality
  banner/footer, authorized-use disclosure, risk summary, highlights, phases,
  findings, evidence, remediation and triage state. All captured text is
  escaped before it reaches reportlab's XML-like paragraph parser.
- Leadline-compatible API mounted at `/api/targets`, `/api/scans`,
  `/api/findings` and `/api/reports`, including history/diff, triage PATCH,
  and JSON/Markdown/HTML/PDF exports. Breadcrumb's own API remains `/api/v1`.
  The compatibility layer is translation-only; it never creates a second
  source of truth.
- CLI parity: `breadcrumb collect`, `jobs list|show|cancel|retry`,
  `history [--diff]`, and `report <job> --format pdf|json|md`.
- UI: program-page PDF/history/triage/snapshot controls, job-page snapshot
  status/rebuild/PDF/history links, and runners-page collector options plus
  run-now.
- `reportlab==4.4.2` is an explicit runtime dependency.
- Test suite: **134 passed, 1 warning**.

### Added — Phase 5: collector depth (2026-11-07)

- Local NVD cache (`breadcrumb.nvd.json` by default) with `breadcrumb nvd
  import`/`nvd stats`, gzip feed support, merge-by-CVE-id imports and a
  vendor/product index. No network access is required for verification.
- CPE 2.3 parsing and version-range matching (`versionStartIncluding`,
  `versionEndIncluding`, `versionEndExcluding`, exact versions and distro
  suffixes). `leadline-cve` emits a nuclei-compatible finding **only** when a
  local CPE/version check proves applicability; referenced IDs and keyword
  results remain informational.
- Cached NVD keyword lookups with a TTL; missing/stale caches degrade to
  offline mode with a warning instead of failing a scan.
- OpenAPI 3.x and Swagger 2.x document parsing (JSON and YAML). Operations are
  listed as inferred endpoints with their HTTP method and are never requested.
  Path templates (`/users/{id}`) become safe `:id` URLs for Breadcrumb's URL
  parser.
- Technology/version fingerprints for Server and X-Powered-By headers,
  generator meta tags, ASP.NET headers, CDN/WAF response headers, and common
  framework assets. The httpx record keeps canonical `tech` labels plus a
  `tech_versions` field used by CVE correlation.
- Graph URL path tree per host, plus case-insensitive value and entity-type
  filters on the graph page.
- Report risk summary and top-finding highlights with explicit explanations
  for locally verified CVEs versus candidate-only patterns.
- Caps for large targets: CVE matches, inferred API URLs, OpenAPI paths and
  operations, graph path-tree nodes, and document parsing size.
- `pyyaml==6.0.3` is now an explicit runtime dependency (YAML OpenAPI
  documents; it was already present through `uvicorn[standard]`).

### Added — Phase 4: native collectors v1 (2026-11-07)

- `leadline-ports`: TCP connect scan of a curated port list, banner grabbing,
  TLS certificate fields, and high-risk-service candidates. Emits nmap XML and
  nuclei-compatible candidate findings.
- `leadline-host-intel`: A/AAAA, CNAME and reverse-DNS evidence in BIND-style
  zone text. External sources (MX/NS/TXT/SOA, WHOIS/RDAP, CT, ASN/geo) are
  explicitly listed as not queried in offline mode.
- `leadline-js`: same-origin JavaScript discovery, inline-script analysis,
  endpoint/parameter/CVE-reference extraction. JavaScript is never executed.
- `leadline-params`: URL query and form-field discovery from HTML; no fuzzing.
- `leadline-api`: fixed-path REST/GraphQL/OpenAPI probing with httpx JSONL
  evidence; HTML/JS references are labeled inferred and never contacted.
- `leadline-vulns`: pattern candidates for debug/config/VCS/test exposure,
  suspicious parameters, observed APIs, high-risk ports and missing security
  headers. Every record is tagged `candidate` and requires manual review.
- `leadline-cve`: offline CVE references plus product/version candidates;
  optional NVD keyword lookup stays explicitly unverified and never creates a
  finding.
- `leadline-graph`: compact nmap-XML graph observations that reinforce
  host/IP/port entities and edges.
- `leadline-recon`: the twelve-phase preset, in Leadline order: DNS, host
  intel, ports/TLS, HTTP, tech, JS, params, security headers, API, vuln
  candidates, CVE candidates, graph.
- `http_ports` and `tls_ports` collector options for fixtures and unusual
  deployments; an HTTPS target's explicit port is treated as TLS automatically.
- URL parser now keeps blank query values (`?param=`) so inferred parameter
  candidates become `param` entities without inventing values.

### Added — Phase 3: encrypted header-profile secrets (2026-11-06)

- `app/secrets_store.py` with `EncryptedText`/`EncryptedJSON`; AES-GCM via
  `cryptography`, key file `breadcrumb.db.key`, `MultiFernet` rotation.
- Startup migration encrypts legacy plaintext `HeaderProfile.headers`/`proxy`.
- Backup scrub removes plaintext from pre-migration SQLite files; key-loss,
  rotation, redaction and tamper tests.
- `breadcrumb secrets rotate` CLI command.

### Added — Phases 1/2: durable executor and safety rails (2026-11-06)

- `app/ingest.py`: single ingest path with `capture_key` idempotency, chain
  sealing, attribution and findings.
- `app/jobs/queue.py` + `app/jobs/worker.py`: atomic claim, leases, heartbeat,
  cancellation, retry/backoff, expired-lease recovery, maintenance pause.
- `app/collect/guard.py`: fail-closed scope guard, pinned resolution, private
  target warning, metadata/link-local hard blocks, redirect re-checks.
- Native DNS, HTTP, tech and security-header collectors.
- Job detail attempts/phases/events, run-now/cancel/retry, health fields,
  maintenance banner, `breadcrumb worker` and `breadcrumb maintenance` CLI.
- Schema version 2 with additive migrations; SQLite WAL/busy-timeout pragmas.

### Added — Phase 0: safety rails (2026-10-29)

- Host allowlist + Origin/Sec-Fetch-Site checks; CSRF token on every POST form.
- WAL, busy timeout and foreign keys at connection time.
- Linear SHA-256 evidence chain with delete-gap recovery.
- WAL-safe backup/restore and legacy chain backfill.

### Changed

- Runner catalog now lists the native recon collectors and enables them by
  default. External runners (`nmap`, `subfinder`, `nuclei`, `httpx`, ...) keep
  their original import-first contract; the same ids also have opt-in adapters
  with scope/strict metadata shown in the runner catalog.
- Native collectors never write to the database directly: they emit nmap XML,
  httpx JSONL, nuclei JSONL, DNS records or raw HTTP dumps, and the normal
  parser/ingest/evidence path seals each phase.
- A native job cannot finish `done` without at least one sealed capture.

### Security

- Executor remains **off by default** (`BREADCRUMB_EXECUTOR=off`); activation
  is the CLI worker or the explicit inline worker.
- Private/loopback targets are allowed only with a visible warning; metadata,
  link-local and multicast addresses are hard-blocked; unknown/out-of-scope
  targets fail closed.
- Native collectors refuse a configured proxy rather than silently bypassing
  it.
- External adapters are opt-in and never claimed by the durable worker without
  `BREADCRUMB_EXTERNAL_TOOLS=1`. They preflight scope before spawning, use
  argv-only execution with process-group cancellation, an output cap and an
  environment allowlist, and never receive header profiles or secrets.
- Pattern findings are candidates, never confirmed vulnerabilities. CVE
  keyword results are unverified and excluded from risk.

### Verification

- Full suite: **182 passed, 1 warning** (`.venv/bin/python -m pytest -q`).
- `compileall` and `git diff --check` pass.
- Local fixture coverage: HTTP banner/port scan, self-signed TLS certificate
  extraction, high-risk-port candidate, twelve-phase recon preset with sealed
  pastes/entities/findings/edges, out-of-scope fail-closed behavior, NVD
  import/merge and CPE version ranges, verified-only CVE findings, OpenAPI
  JSON/YAML parsing, tech/version extraction, graph path tree, report
  highlights, snapshots/diffs/triage/PDF/compatibility API, Phase 7 adapter
  spawn safety, timeout/output caps, process-group cancellation, strict-mode
  gating, worker claim gating and parser fixtures, and Phase 8 dry-run
  no-writes, full Leadline mapping/triage/headers/snapshots/PDF, idempotent
  re-import, imported-job guards, verification failure detection and malformed
  sources.
- Real-data import on copies of the owner's Leadline database and Breadcrumb
  database: 2 targets and 2 encrypted header profiles imported; verification
  passed all 6 checks; re-import was idempotent; the source fingerprint was
  unchanged; `scripts/acceptance_phase8.py` passed all 6 checks.

### Upgrade notes

- Schema version 4 adds `target.meta` and `finding.meta`. The migration is
  additive; `init_db()` writes a pre-migration backup first. If you restore a
  pre-migration backup, restore its matching key too.
- The live `breadcrumb.db` still contains two plaintext header profiles and no
  key file. First startup/CLI use will create `breadcrumb.db.key`, back up the
  database, and encrypt those profiles. Back up the key separately: losing it
  makes encrypted header values unrecoverable. Older `*.pre-migrate-*.bak`
  files may contain plaintext.
- Imported Leadline programs start with empty scope. New scans fail closed
  until you add scope explicitly; imported jobs are historical and cannot be
  retried or re-run.
- CVE verification is opt-in by data presence: without a local NVD cache the
  scan stays offline and reports only referenced IDs/candidates. Import a feed
  with `breadcrumb nvd import <file>`; set `BREADCRUMB_NVD_CACHE` or the
  `nvd_cache` job option to use a non-default path.
- The Leadline folder is retained as a reference. No automatic archive or
  deletion is performed.
- External adapters are opt-in: install the tool on the executor host, use
  `breadcrumb tools` to confirm it is detected, and either run a job
  explicitly or set `BREADCRUMB_EXTERNAL_TOOLS=1` before starting the worker.
  A missing binary is reported as "not installed"; it is not treated as a
  successful empty scan. `BREADCRUMB_STRICT_MODE=1` disables adapters that
  cannot be pinned.
