# Changelog

All notable changes to Breadcrumb are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The Leadline merge is the **0.4.0** release; **0.5.0** is the Phase A “Proof”
release; **0.6.0** is the Phase B “Memory” release; **0.7.0** is the Phase C
“Report” release; **0.8.0** is the Phase D “Automate” release. The version in
`app/__init__.py` is `0.8.0`.

## [0.8.0] — 2026-11-11

Phase D makes Breadcrumb a dependable automation target without turning it into
a platform: local folder schedules with honest run history, a local parser SDK,
idempotent/bulk/paginated API automation, and measured 100k-import/1M-read
performance. Schema **7** adds two tables; no cloud service, daemon, token
system or remote plugin registry is required.

### Added — scheduled folder re-import

- `app/schedules.py` and schema 7 (`Schedule`, `ScheduleRun`): one local folder,
  one interval, and the normal ingest path. No URL/API pull is implemented;
  an external fetch tool drops a file instead, avoiding SSRF and credential
  storage in the core.
- Run history with `ok` / `partial` / `error` / `skipped`, per-file detail,
  last error, next run and notification hook. A crashed `running` row becomes
  `stale` after `max(3600, interval × 2)` seconds.
- Content-hash capture keys namespaced by schedule id, so re-dropping identical
  bytes is a duplicate capture. Successful/empty files move to `processed/`
  (collision-safe); failed files stay in place. Guardrails: 200 files/run,
  25 MB/file, binary/hidden/partial-download handling.
- `skip` and `queue` overlap policies; disabled schedules are never due;
  enabling starts from now rather than replaying missed runs.
- Web: `/schedules`, `/schedules/<id>` with create/edit/run/force/enable/
  disable/delete. API: `GET/POST /api/v1/schedules`, `GET/PATCH/DELETE
  /api/v1/schedules/<id>`, `POST /api/v1/schedules/<id>/run`.
- CLI: `schedule add/list/show/run/enable/disable/delete`, plus
  `scheduler --once/--poll/--max-runs` for cron/systemd/timers.

### Added — local parser SDK

- `app/parsers/sdk.py` loads local parsers from `$BREADCRUMB_PARSER_DIR` or
  `~/.breadcrumb/parsers`. Modules expose `PARSER` or `get_parser()`, subclass
  `Parser`, and are validated for a unique name, required methods and version.
- Broken or duplicate-name plugins are recorded and skipped; they never stop
  startup or affect built-in parsers. `breadcrumb parsers [--json]`,
  `/parsers`, `/api/v1/parsers` and `breadcrumb doctor` show local plugins,
  metadata and load errors.
- No remote marketplace, package index, auto-update or sandbox. The docs state
  the trust boundary: a plugin is imported Python with the user's permissions.
- `parser_catalog()` now reports `source` (`builtin`/`local`), path and
  metadata; the existing parser contract and `analyze()` wrapper are unchanged.

### Added — API automation

- `POST /api/v1/pastes` accepts `capture_key` in JSON or `Idempotency-Key` for
  raw pipelines. New captures return **201**; duplicates return **200** with
  `duplicate: true` and the original `paste_id`.
- `POST /api/v1/pastes/bulk`: up to 100 captures, **207** response, per-item
  isolation, shared or per-item program/target/source/max-entities fields.
- `GET /api/v1/findings`: `program_id`, `min_severity`, `status`, `q`, `limit`
  (cap 5000) and `offset`; returns `total`, `offset`, `limit` and
  `next_offset` (null on the last page).
- Paste APIs validate program/target ids and option types with 400 instead of
  leaking a SQLite foreign-key 500.
- CLI `parsers` and schedule commands documented with CI/cron recipes in
  `docs/AUTOMATION_COOKBOOK.md`.

### Performance

- `scripts/bench_scale.py`: seeds a throwaway 1M-entity database and measures
  Ledger aggregate/filter/search, entity filtering, deep pagination and
  `EXPLAIN QUERY PLAN`; exits non-zero over `--target-seconds` (default 2 s).
- Schema 7 read-path indexes: entity program/type/ignored/scope/status-code,
  `lower(normalized)`, schedule due, schedule-run history/status.
- Recorded 100k httpx import: 100,001 entities in 80.913 s (~1,236/s), 100%
  completeness, 0 skipped, ~61 MB. Recorded 1M reads: filtered Ledger 0.760 s,
  deep page 1.395 s, value search 0.771 s, entity filter 0.148 s — within the
  documented 2 s target.
- No FTS table was added because the measured substring search already meets
  the target; the guide documents the trigger for revisiting that decision.

### Docs

- `docs/AUTOMATION_COOKBOOK.md`, `docs/PARSER_AUTHORING.md` and
  `docs/PERFORMANCE_TUNING.md`; README route/CLI/API examples, docs index and
  `tests/test_docs.py` guards updated.
- `tests/test_benchmarks.py` now smoke-tests `bench_scale.py`; Phase D tests
  cover schedules, overlap/stale handling, parser SDK isolation, idempotent and
  bulk paste, findings pagination and the scheduler.

### Compatibility

- Schema **7** is additive from 6; startup backs up before migration. Existing
  tags, routes, exports and the offline-first SQLite-only defaults are
  unchanged.
- The core executor remains off by default. Schedules are local reads only;
  local parser plugins are opt-in and explicitly trusted.
- Full suite: **249 passed, 1 warning**.

## [0.7.0] — 2026-11-11

Phase C turns evidence into a submission-ready artifact without leaving the
laptop: five built-in report templates, default-on redaction, a verifiable
offline review bundle, and DefectDojo/Ghostwriter/Dradis exports.

### Added — report studio and templates

- `app/report_templates.py`: typed template registry with five built-ins:
  `hackerone`, `executive`, `technical`, `recon` and `change`.
- One validated, redacted context rendered to Markdown, self-contained HTML,
  JSON and PDF; golden Markdown snapshots under `tests/golden/phase_c/` keep
  the formats aligned.
- Report studio at `/programs/<id>/reports` with live preview, field-level
  validation, template picker and downloads. Single-finding technical reports
  via `finding_id`; severity floor and finding caps.
- Routes: `GET /programs/<id>/reports`, `GET /programs/<id>/reports/preview`,
  `GET /reports/<id>/templates/<template>.<fmt>` and
  `GET /api/v1/report-templates`.
- CLI: `render`, `bundle`, `verify-bundle` and `report-templates`; shared
  `--var`, `--redaction-profile`, `--redaction-rule` and `--reveal` flags.
- Change reports reuse Diff v2 categories; false positives are filtered before
  counts are computed. User-entered report fields and evidence are escaped in
  HTML/PDF.

### Added — default-on redaction

- `app/redaction.py`: auth headers, cookies, bearer/JWT tokens, URL credentials,
  query tokens, key/value secrets, session ids, AWS/GitHub/Slack tokens,
  private keys and sensitive entity values are masked by default.
- Strict profile additionally masks long hex/base64 values.
- Per-report custom rules (`literal:` / `regex:`) are additive and capped at
  100; malformed rules fail validation. Rule text is never echoed into report
  JSON or bundle metadata.
- `reveal` is explicit and disables masking; bundles remain verifiable but
  produce a warning. Legacy exporters (`md`, `json`, `csv`, `targets`,
  `hackerone`, `sarif`) now redact finding text by default too.

### Added — review bundle and integrations

- `app/review_bundle.py`: deterministic zip with `report.html`, `report.md`,
  `report.json`, optional `report.pdf`, redacted per-capture Evidence Manifest
  v2 files, `manifest.json`, `manifest.sha256`, `SHA256SUMS`, `README.txt` and
  optional redacted `comments.md`.
- In-memory verifier rejects path traversal, absolute/Windows paths, duplicate
  entries, symlinks, encrypted entries, oversized archives, missing files,
  unlisted files and hash mismatches; verifies nested capture chains.
- `POST /reports/<id>/bundle`; download headers report the included capture
  count.
- DefectDojo Generic Findings Import JSON at `/reports/<id>/defectdojo`;
  Ghostwriter bridge JSON at `/reports/<id>/ghostwriter`; Dradis note Markdown
  at `/reports/<id>/dradis.md`. `export` gained `defectdojo`, `ghostwriter` and
  `dradis` formats.

### Docs

- `docs/REPORT_COOKBOOK.md`, `docs/REDACTION_GUIDE.md` and
  `docs/INTEGRATION_MAPPINGS.md`; README route/CLI/API examples and the docs
  index updated. `tests/test_docs.py` now guards the Phase C routes.

### Compatibility

- Schema remains **6**; no migration is required from 0.6.0.
- Existing routes, exports, tags and the offline-first, SQLite-only,
  no-telemetry defaults are unchanged. The report bundle is additive and
  read-only.
- DefectDojo/Ghostwriter exports are validated against their documented field
  vocabularies; importing into a specific test instance remains an operator
  acceptance check. Ghostwriter has no single stable file-import schema, so its
  export is a documented bridge JSON.

## [0.6.0] — 2026-11-10

Phase B makes cross-program memory and change detection the product’s center of
gravity: the Ledger remembers every asset, Diff v2 compares any two slices, and
Scope v2 explains every in/out decision.

### Added — Ledger v2

- Cross-program asset aggregation by `(type, normalized)` with first/last
  sighting, occurrences, confidence, programs, targets and captures.
- `/ledger` filter language: `type:`, `scope:`, `tag:`, `verdict:`,
  `program:`, `status:`, `seen:other-program|single`, `sort:`, `q:`.
- Asset timeline at `/ledger/asset?type=…&value=…` (JSON at
  `/api/v1/ledger/asset`) with per-sighting annotations.
- JSONL/CSV export at `/ledger/export`; JSON API at `/api/v1/ledger`.
- Saved views (`kind=ledger|diff|graph`) with a local `savedview` table.
- `ledger_jsonl` parser and `breadcrumb ledger import` for additive,
  idempotent round-trips that preserve verdicts, tags, notes and status codes.

### Added — Diff v2

- `app/diff.py`: selectors `paste:`, `target:`, `program:`, `job:` and
  categories findings, entities, ports, DNS, endpoints, technologies, security
  headers and risk.
- New `/diff` UI, `GET /api/v1/diff`, `POST /diff/notify`, saved comparisons,
  and `breadcrumb diff` with Markdown/JSON output.
- Job selectors use sealed history snapshots; entity-level comparison is
  explicitly unavailable for snapshot-vs-live comparisons instead of silently
  wrong.

### Added — Scope v2

- Status-code filters (`status:200,204`) composed with host/path rules.
- Negated path rules and stable, explainable reason codes on every entity
  (`scope_reason`).
- `/programs/<id>/scope` decision table, “why is this out of scope?” focus,
  reason/status filters and bulk re-scope that appends durable rules.
- Per-rule severity overrides stored on the program, applied at ingest and
  re-applied on save; original severity retained for audit.

### Added — Graph v2

- Cross-program “seen in other programs” section on the program graph, linked
  to Ledger timelines.
- Saved graph views and existing large-cluster caps preserved.

### Schema

- Schema version 6 adds `Entity.scope_reason`, `Entity.status_code`,
  `Finding.rule_id`, `Program.rule_severities` and the `savedview` table.
  Migration is additive; existing captures and findings are not rewritten.

## [0.5.0] — 2026-11-09

Phase A makes the first mile trustworthy: every import explains itself, every
capture has a portable manifest, and a broken install is diagnosed before the
user imports real data.

### Added — parser contract and import trust

- Parser Contract v1: `Parser.parse_detailed()` returns a `ParseResult` with
  entities, relationships, findings, `ParserIssue`s, skipped-row counts, a
  parser version and stats. `analyze_detailed()` is the new pipeline;
  `analyze()` remains a four-tuple compatibility wrapper.
- Detailed accounting for nmap (XML fallback), httpx, nuclei and Amass; a new
  **BBOT** JSON/JSONL parser covering DNS names, IPs, ports, URLs, HTTP
  responses, technologies, emails, CIDRs, ASNs, storage buckets and findings.
- Malformed JSONL rows are reported as `skipped_row` issues instead of being
  silently dropped. Pretty-printed JSON and JSON arrays are not misdiagnosed.
- Import reports: `app.ingest.import_report()` and
  `GET /api/v1/pastes/{id}/report` expose parsed/persisted counts, findings,
  completeness, skipped rows, parser versions, issues and a “why zero” hint.
- CLI: `ingest --report-json`, `--json`, `--dry-run`, `--command`,
  `--source-meta`, `--max-entities`.
- Schema 5 adds `paste.completeness`, `paste.skipped_rows`,
  `paste.parser_versions`, `paste.import_stats`, `paste.command` and
  `paste.source_meta`, with an additive migration and pre-migration backup.
- Composite indexes for 100k-scale imports and paginated
  `GET /api/v1/entities` (`total`, `offset`, `next_offset`).

### Added — Evidence Manifest v2 and doctor

- `app/manifest.py`: redacted JSON/Markdown manifests with input SHA-256,
  full/redacted output hashes, parser versions, scope hashes, chain position
  and warnings. Routes: `/pastes/{id}/manifest.json`,
  `/pastes/{id}/manifest.md`, `/api/v1/pastes/{id}/manifest`.
- CLI: `manifest`, `verify --manifest/--raw`, `verify --paste`,
  `verify` (whole chain). `app/evidence.py` shares chain verification between
  the API and CLI.
- `app/redaction.py`: conservative masking for auth headers, API keys,
  passwords, JWTs, cloud/GitHub/Slack tokens, private keys and URL
  credentials; sensitive `source_meta` keys are replaced.
- `app/doctor.py` and `breadcrumb doctor --json` /
  `GET /api/v1/doctor`: read-only Python, SQLite, path, disk, integrity, WAL,
  schema, key, port, parser and optional-tool checks with copy-paste fixes.

### Added — onboarding and performance

- `breadcrumb demo` and the dashboard “Load sample program” button seed five
  idempotent sample captures (nmap, httpx, nuclei, BBOT, Amass), 45 entities
  and six findings with a report and manifest in under a minute.
- `scripts/bench_import.py` measures the full ingest path for 10k/100k
  entities on a laptop and reports completeness, skipped rows and throughput.
  Reference run (Linux, Python 3.12, SQLite 3.45, laptop-class CPU):
  10k httpx entities in 10.4s (~964/s), 100k in 81.9s (~1,221/s), 56 MB
  database, 100% completeness and zero skipped rows in both runs.
- `docs/IMPORT_COOKBOOK.md` and `docs/MANIFEST_AND_DOCTOR.md`.

### Tests

- **195 passed, 1 warning** at the Phase A cut (13 new tests: parser contract,
  BBOT, malformed JSONL, import reports, consolidation, truncation, manifest
  round-trip and redaction, doctor, demo idempotency, pagination, benchmark).
- Old-database subprocess migration now asserts the live `SCHEMA_VERSION`
  instead of a hard-coded value.

### Upgrade notes

- From 0.4.0: start the app once; the additive schema 5 migration runs with a
  pre-migration backup. Existing captures get `completeness = 1.0`,
  `skipped_rows = 0`, empty parser versions/import stats and no command.
- The `v0.4.0` tag and release remain intact. 0.5.0 is additive.

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
