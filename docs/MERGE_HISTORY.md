# Leadline merge — implementation history

This is the chronological work log for absorbing Leadline into Breadcrumb. It
records what changed, why, the evidence that it worked, and what remains. It is
deliberately more detailed than `CHANGELOG.md` (the user-facing release history)
and complements the planning documents in this directory.

**Convention for this and future projects:** keep a root `CHANGELOG.md` in
Keep-a-Changelog form, and keep a dated implementation log in `docs/` whenever
the work spans multiple sessions or phases. Never rewrite history to make a
failed approach disappear; record it and link the replacement.

Status vocabulary follows the planning documents:

- **Implemented** — code exists and a named passing test proves it.
- **Verified** — the implementation was exercised against a fixture or a copy
  of real data.
- **Unverified** — code exists but has not been exercised in the target
  environment.
- **Planned** — designed but not written.
- **Shelved (owner's call)** — deliberately postponed.

---

## 2026-11-08 — Phase 8: Leadline importer, verification and hardening

### Scope

Close the merge with a one-way data migration from Leadline, prove it on a copy
of the owner's real database, and leave the operational runbooks needed to run,
verify and roll back the combined system. No live database was modified and the
Leadline folder was left untouched.

### Implemented

- **Importer core** (`app/leadline_import.py`). `dry_run()`, `import_leadline()`
  and `verify_import()` share one source reader. The source opens with SQLite
  `mode=ro` and `PRAGMA query_only=ON`; a fingerprint over the filename, main
  file bytes and WAL is taken before and after reading. A change aborts with
  instructions rather than importing a torn snapshot.
- **Dry run.** Reports source counts, would-import counts, distinct header
  sets, triage/severity distributions, malformed rows, destination program
  state and warnings. It writes no rows and no manifest.
- **Real import.** Backs up the destination to
  `<BREADCRUMB_DB_PATH>.pre-import-<UTC>.bak`, enables maintenance mode, writes
  in one transaction, restores maintenance state, generates snapshots and
  verifies. Header profiles are written only through `EncryptedJSON`; if
  encryption is unavailable the import aborts rather than storing plaintext.
- **Mapping.** Targets keep URL/host as the name plus notes/timestamps and an
  `is_active` marker. Each distinct header set becomes an encrypted
  `HeaderProfile` (`family=leadline`, name `Leadline import <hash12>`); the
  target's `meta.leadline_header_profile_id` points at it. Scans become
  historical `ScanJob` rows (`runner=leadline.imported`, `params.imported=true`,
  `attempts=1`, `max_attempts=1`). Events become `ScanPhase` rows. Findings
  get `source_tool=leadline`, a stable
  `leadline:<sha256(target_url|scan_id|finding_id)[:32]>` fingerprint, triage
  through `app.triage`, notes, and `meta` with extra data/location/source IDs.
  Graph nodes become entities (`parser=leadline-import`, normalized
  `leadline:<scan_id>:<node_id>`); parents/edges become `part_of`/`references`
  relationships. Report blobs are not stored.
- **History.** Imported snapshots are scoped per source scan through
  `params.leadline_source_id` + `meta.leadline_scan_id` in `app/history.py`;
  live snapshots remain cumulative target state. Snapshot failure stays
  isolated from the imported job's terminal status.
- **Terminal imported jobs.** `app/main.py` rejects retry/run-now with `409`,
  `_arm_native_job` refuses imported rows, the worker cannot claim them, and
  the job/runners templates show an imported-history banner and hide run/retry
  controls.
- **Manifest.** Default `<BREADCRUMB_DB_PATH>.leadline-import.json`, mode
  `0600`, written atomically. It records source path/fingerprint, destination
  program and the source-ID → destination-ID map. A different source path
  ignores the old map with a warning. Re-running is idempotent.
- **Verification.** Counts, triage distribution, severity distribution, sampled
  finding fields, header decryption round-trip and source fingerprint. Failures
  are explicit and exit non-zero.
- **CLI.** `python -m app.cli import-leadline` with `--db`, `--program`,
  `--program-name`, `--manifest`, `--dry-run`, `--verify`, `--no-backup`,
  `--no-snapshots`, `--no-verify`, `--report` and `--json`.
- **Schema.** Version 4 adds `target.meta` and `finding.meta` with an additive
  migration; `tests/test_jobs.py` expects 4.
- **Acceptance.** `scripts/acceptance_phase8.py` copies the source and
  destination (plus destination key) into a temp directory, runs dry run, real
  import and verification, and checks source fingerprint, counts, historical
  jobs and raw header ciphertext. `--keep` preserves the directory; `--json`
  emits the report.
- **Docs.** `LEADLINE_MERGE_GUIDE.md`, `LEADLINE_IMPORT_VERIFICATION.md`,
  `COMPATIBILITY_API.md`, `SECURITY_MODEL.md`, `HARDWARE_AI_GUIDE.md`,
  `TROUBLESHOOTING.md`, `BACKUP_RESTORE_UPGRADE.md`, `SECURITY_CHECKLIST.md`,
  `RELEASE_NOTES_PHASE8.md`, `ROLLBACK_PLAN.md`, plus updates to
  `docs/README.md`, `LEADLINE_PARITY_MATRIX.md`, this file, the root
  `CHANGELOG.md` and `README.md`.

### Real-data verification

- Source: `<owner's Leadline folder>/leadline.db`, copied
  with SQLite's online backup API. 2 targets, 0 scans/events/findings/graph
  nodes, 106,496 bytes, fingerprint
  `a0331f521bcc21ddc3f0639c0b82899caffe7ba1287d6f324d348c846c26648a`.
- Destination: a throwaway copy of `breadcrumb.db`, migrated 3 → 4.
- Result: program `#1 Leadline import`; 2 targets; 2 encrypted header profiles;
  destination backup created; verification passed all 6 checks; re-import was
  idempotent (0 imported, 2 targets skipped); source fingerprint unchanged.
- `scripts/acceptance_phase8.py` passed all 6 checks (source unchanged, import
  ok, verification ok, counts, fingerprint match, headers encrypted at rest).
- The real database had no scans/findings/graph rows; those paths are proven by
  the synthetic fixture in `tests/test_phase8.py`, including malformed rows,
  triage states, graph parents/edges and PDF generation.

### Decisions

- The importer is one-way and read-only on the source. Leadline is never
  archived, deleted or rewritten.
- Imported jobs are history, not runnable work. Refreshing a target means
  configuring scope and queueing a new scan.
- Imported programs start with empty scope so the import does not silently
  authorize scanning old targets.
- Header values are never written in plaintext; the import aborts if
  encryption is unavailable.
- The real-data result is recorded as verification of the paths that database
  exercises, not as proof of the paths it does not.

### Verification

- `tests/test_phase8.py`: 8 tests — dry-run/no writes, CLI dry-run, full
  mapping/triage/headers/snapshots/PDF, idempotent re-import, historical
  non-runnable jobs/UI/API, verification failure detection, malformed/missing
  sources, and a source without scan tables.
- Full suite: **182 passed, 1 warning** (`.venv/bin/python -m pytest -q`).
- `compileall app` passes.

### Residual risk

- The real Leadline database had no scans/findings/graph rows; those paths rely
  on synthetic fixtures.
- A source with a live writer is detected by fingerprint and aborts; operators
  should still import a copy.
- Imported header profiles are visible in the local UI by design; encryption
  protects files/backups, not a compromised local session.
- The merge is released as **0.4.0**; Gate C (external-tool
  strictness) is still an owner sign-off item.

---

## 2026-11-07 — Phase 7: opt-in external tool adapters

### Scope

Absorb Leadline's external-tool execution as an additive capability without
taking over Breadcrumb's import-first runner contract. The tools Breadcrumb
already parses or catalogs (nmap, httpx, nuclei, subfinder, naabu, masscan,
katana, ffuf, dalfox, amass, whatweb, wafw00f) get adapters that produce the
same evidence formats the normal ingest/parser/chain path already understands.

### Implemented

- **Adapter registry.** `app/collect/base.py` keeps `ADAPTER_REGISTRY` separate
  from the native `REGISTRY`. `get_collector()` resolves both; `collector_ids()`
  remains native-only; `adapter_ids()` and `claimable_collector_ids()` make the
  worker's opt-in boundary explicit.
- **Twelve adapters.** `app/collect/tools.py` implements nmap, httpx, nuclei,
  subfinder, naabu, masscan, katana, ffuf, dalfox, amass, whatweb and wafw00f.
  Each declares its binary, version probe, phase, scope mode, strict policy,
  timeout and output cap. Existing runner ids are reused, so the catalog, API
  and UI do not grow a parallel naming scheme.
- **Scope preflight.** Every run parses the target, calls the same
  `ScopeGuard` used by native collectors, and refuses to spawn on a denial.
  CIDR targets use the new `ScopeGuard.check_network()`: the whole range must
  be contained in scope, any overlap with an excluded or hard-blocked range
  fails closed, and private ranges produce the normal visible warning.
- **Process isolation.** `run_tool()` uses argv lists with `shell=False`, a
  fresh process group, SIGTERM then SIGKILL on cancel/timeout/overflow, a
  deadline, output caps, a temporary `cwd`/`HOME`, and an environment
  allowlist that excludes proxies and application secrets. Option parsing is a
  fixed schema (`ports`, `severity`, `depth`, `rate`, `wordlist`), not a
  passthrough; invalid ports/options are rejected before a process starts.
- **Strict mode.** `BREADCRUMB_STRICT_MODE=1` disables adapters whose
  `strict_policy` is `never` (nuclei, katana, ffuf, dalfox, whatweb, wafw00f).
  `ip_only` adapters (nmap, naabu) require an IP/CIDR target; httpx is always
  pinnable through `-resolve host:port:address`.
- **Honest missing binaries.** A missing executable raises an explicit
  "not installed on the executor PATH" error. `/runners` shows "not installed"
  separately from "elsewhere", and `breadcrumb tools [--json]` lists presence,
  version, scope mode and strict state.
- **Opt-in worker claims.** The durable worker uses
  `claimable_collector_ids()`; adapter jobs are claimed only when
  `BREADCRUMB_EXTERNAL_TOOLS=1`. Explicit run-now (UI/API) and
  `breadcrumb collect --run-now` can still execute one adapter job, so the
  original "external runner posts evidence back" workflow is not silently
  claimed.
- **Parsers.** Added `app/parsers/tool_json.py` (tolerant JSON/JSONL/comment
  handling) and parsers for ffuf JSON, Dalfox JSON/JSONL, Amass JSON/JSONL,
  WhatWeb JSON and wafw00f JSON. Dalfox findings carry a `candidate` tag and
  are never treated as confirmed.
- **UI/CLI.** Runner catalog entries carry adapter/scope/strict metadata and
  version strings; job pages distinguish "External tool adapter" from native
  collectors; the API create-job response includes `adapter` and an opt-in
  note.

### Security decisions recorded

- Adapters never receive header profiles, cookies, proxy settings or
  application secrets. Authenticated scanning remains an external-runner
  workflow.
- Target text and options never pass through a shell. Target values starting
  with `-`, containing control characters, or using a non-http(s) scheme are
  rejected.
- Output truncation is a warning, not a job error, so a capped artifact is
  still sealed with an explicit `truncated` stat.
- XML artifacts (nmap) are not prefixed with the scope comment because a
  comment before the XML declaration breaks strict parsers; the scope decision
  remains in phase stats and job events.
- A denied target is verified not to spawn by tests that place a marker-writing
  fake binary on `PATH`.

### Verification

- `tests/test_phase7.py`: 40 tests covering target parsing, option injection,
  scope containment/hard blocks, private warning, denied/metadata/proxy
  no-spawn, missing binary, strict-mode gating, httpx resolve override, ffuf
  output-file handling, nmap XML, header-profile exclusion, argv/shell safety,
  env allowlist, timeout, output cap, process-group cancellation, parser
  fixtures, registry/claim gating and a full opt-in worker adapter job.
- Full suite: **174 passed, 1 warning** (`.venv/bin/python -m pytest -q`).
- `compileall` passes; no external binaries are required by the test suite.

### Residual risk

- An external tool resolves names and makes its own connections; preflight and
  `-resolve` reduce but cannot eliminate the gap between the guard's decision
  and the tool's socket. Strict mode disables the tools that cannot be pinned.
  The egress-firewall recommendation from the pre-mortem remains the
  deployment control.
- Adapters are not sandboxed beyond the process/environment controls above;
  run the worker as an unprivileged user on a dedicated host when scanning
  untrusted targets.

---

## 2026-11-07 — Phase 6: history, reports, PDF, UI, compatibility

### Scope

Make the absorbed scanning capability visible in Breadcrumb's product:
per-target history, scan-to-scan diffs, triage, PDF reports, compatibility
API, CLI parity and the UI controls that connect them.

### Implemented

- **Snapshots.** `ScanSnapshot` stores one rebuildable document per completed
  job. `app/history.py` builds the target state at scan completion: risk,
  severity counts, verified/unverified CVE counts, findings keyed by stable
  fingerprint, endpoints, resolved IPs, hostnames, subdomains, DNS records,
  ports/services/TLS, technologies/versions, CDN/WAF, security headers and
  phase summaries. Target scoping uses `ScanJob.target_id` with legacy
  host-matching fallback.
- **Snapshot lifecycle.** The worker generates a snapshot after a job reaches
  `done`; a failure stores `pending`/`failed` and never changes the job status.
  Snapshots can be rebuilt per job, target or program.
- **Diffs.** `diff_snapshots` compares findings, ports, DNS, subdomains,
  endpoints, technologies/versions, headers, risk and whois/DNSSEC fields.
  False positives are excluded from "new" findings and from risk.
- **Triage.** `Finding.verdict` joins the entity vocabulary. `app/triage.py`
  owns the Leadline mapping, the primary UI route and the compatibility PATCH
  route. Reports exclude false positives by default; `include_triaged=1` is
  the explicit internal-report switch.
- **PDF.** `app/pdf_export.py` ports Leadline's report structure with
  reportlab: confidentiality banner/footer, authorized-use disclosure, risk
  summary, highlights, phases, findings, evidence, remediation, triage and
  target/scan filenames. Untrusted captured text is XML-escaped.
- **Compatibility.** `app/compat.py` mounts Leadline-shaped targets, scans,
  findings, reports, history/diff and export endpoints at `/api/*`. Reads come
  from Breadcrumb models; writes use the same queue/ingest paths. Status
  mapping is `queued→pending`, `done→completed`, `cancelled→stopped`.
- **UI.** Program page: PDF/history/triage/snapshot controls. Job page:
  snapshot status/rebuild/PDF/history links. Runners page: collector options
  JSON and run-now. New `history.html` timeline/diff view.
- **CLI.** `collect`, `jobs list|show|cancel|retry`, `history [--diff]`, and
  `report <job> --format pdf|json|md`.
- **Schema.** Version 3 adds `scansnapshot`, `finding.verdict`,
  `scanjob.target_id` and their indexes. The old-database migration test now
  asserts version 3.

### Decisions

- A snapshot represents target state at completion, not only the job delta.
  It is a cache derived from evidence; rebuilding is always safe.
- Compatibility paths are mounted only where they do not collide with
  Breadcrumb's own `/api/v1`; they are translation-only.
- `compat POST /api/targets` reuses/creates a Program named from Leadline's
  target name and stores the URL as a `kind="url"` Target.
- A missing/not-ready snapshot yields a compatibility `409`, not a fabricated
  empty report.

### Verification

- `tests/test_phase6.py`: snapshot/diff target state, worker snapshot hook,
  snapshot-failure isolation, triage mapping/routes, report false-positive
  exclusion, PDF bytes/escaping/filenames, compatibility end-to-end, UI
  controls, and CLI jobs/history/PDF.
- Full suite: **134 passed, 1 warning**.
- `compileall` and import smoke checks pass.

### Remaining

- Phase 7 external adapters and Phase 8 importer/hardening are still open.
- The live `breadcrumb.db` is still intentionally un-migrated; first live
  startup creates `breadcrumb.db.key`, which must be backed up separately.

---

## 2026-11-07 — Phase 5: collector depth

### Scope

Turn the Phase 4 collectors from useful observations into deeper analysis
without changing the import-first workflow: local CVE proof, real API-document
parsing, versioned fingerprints, graph path navigation, and report highlights.

### Implemented

- **Local NVD cache + CPE matching** (`app/collect/nvd.py`). The cache stores
  NVD CVE 2.0 objects in `breadcrumb.nvd.json` (configurable with
  `BREADCRUMB_NVD_CACHE` or the `nvd_cache` job option), indexes vulnerable
  `cpeMatch` entries by vendor/product, and checks version ranges locally.
  Import accepts plain JSON, JSON.GZ, an NVD API page, a feed list, or a single
  record; repeated imports merge by CVE id.
- **Verified-only CVE findings.** `leadline-cve` emits nuclei-compatible JSONL
  only for locally proven CPE/version matches. Referenced CVE ids and optional
  NVD keyword results stay text-only and never affect risk. Keyword lookups are
  cached with a TTL; cache/network problems degrade to offline mode.
- **OpenAPI/Swagger parsing** (`app/collect/api.py`). JSON and YAML documents
  are parsed into method/path operations. Operations are inferred, never
  requested; path templates become safe `:id` URLs; documents are labeled in
  evidence and counted separately from observed probes.
- **Versioned technology fingerprints** (`app/collect/tech.py`). Server,
  X-Powered-By, ASP.NET, generator-meta, CDN/WAF header, and framework-asset
  versions feed a `tech_versions` field in httpx JSONL while `tech` keeps
  canonical labels. Recon merges versioned observations for CVE correlation.
- **Graph path tree and filters.** `/programs/{id}/graph` now accepts `q` and
  `node_type`, filters nodes/edges consistently, and renders a per-host URL
  path tree capped at 500 paths. `app/graph.path_tree` is deterministic and
  independently testable.
- **Report highlights.** JSON reports gained a finding summary and top-five
  highlights; markdown reports gained a risk summary and per-highlight
  explanations that distinguish locally verified CVEs from candidate-only
  patterns.
- **Large-target caps.** Limits apply to CVE matches (200), inferred API URLs
  (500), OpenAPI paths/operations (300/500), document size (4 MiB), and graph
  path-tree nodes (500).
- **CLI.** `breadcrumb nvd import <file> [--cache PATH] [--replace]` and
  `breadcrumb nvd stats [--cache PATH] [--json]`.
- **Dependency.** `pyyaml==6.0.3` is explicit in `requirements.txt` for YAML
  OpenAPI documents.

### Design decisions

- **Files, not schema.** The NVD cache is a portable JSON file, so importing a
  feed needs no migration and an engagement can carry its own cache. There is
  no network code in the matcher.
- **Proof threshold.** A local match requires a known product resolved to a
  CPE alias and a known version inside the CPE range (or an exact CPE version).
  A wildcard with no range is accepted only because NVD itself declares the
  range as all versions; no-version observations are never matched.
- **Inferred stays inferred.** OpenAPI operations and document paths are
  labeled inferred and are not contacted. Observed probes remain the only
  records marked `observed`.
- **Caps are visible.** Truncation is reported in stats/evidence and the graph
  page instead of silently dropping data.

### Verification

- `test_version_comparison_and_cpe_version_ranges`: trailing-zero equality,
  pre-release ordering, range boundaries, exact versions, alias resolution and
  unknown-product rejection.
- `test_nvd_import_merges_plain_and_gzip_payloads`: merge-by-id, gzip import,
  reload and CLI stats.
- `test_nvd_keyword_cache_ttl_expires_to_offline_mode`: cached keyword results
  and stale-entry degradation.
- `test_cve_collector_emits_findings_only_for_locally_verified_matches`:
  verified finding via `extract_findings`, non-matching version produces none.
- `test_recon_preset_uses_local_nvd_cache_for_verified_cve_finding`: the
  twelve-phase preset carries Server-header versions into a sealed CVE finding.
- `test_tech_detection_captures_versions_and_cdn_headers`.
- `test_openapi_json_and_yaml_documents_are_parsed_but_not_requested`:
  document counts, operation count, path-template normalization and inferred
  labeling.
- `test_graph_path_tree_groups_hosts_and_paths`,
  `test_report_highlights_explain_verified_and_candidate_findings`.
- Full suite: **125 passed, 1 warning**; `compileall` and `git diff --check`
  pass.

### Known limits (carried into Phase 6)

- CPE resolution is alias-based; unknown vendors require extending
  `CPE_ALIASES` or importing a CPE dictionary. The cache does not download
  updates itself.
- OpenAPI parameter/request-body schemas are inventoried only at the path and
  method level.
- Graph path navigation is a rendered tree, not a full interactive tree view.
- Report PDF export, snapshot/diff/history, Finding verdicts/triage mapping,
  the compatibility router and UI scan controls remain Phase 6.
- External binaries remain import-first adapters until Phase 7.

---

## 2026-11-07 — Phase 4: native collectors v1

### Scope

Close the core capability gap: Breadcrumb can now scan, not only import. The
executor, scope guard, evidence chain and import-first workflow stay intact.

### Implemented

| Collector | Runner id | Output format | Notes |
|---|---|---|---|
| Ports/TLS | `leadline-ports` | nmap XML + nuclei JSONL | Curated ports, banners, cert fields, high-risk candidates |
| Host intel | `leadline-host-intel` | BIND zone text | A/AAAA, CNAME, PTR; external sources listed as skipped |
| JavaScript | `leadline-js` | URLs/params text | Same-origin scripts, inline scripts, never executes JS |
| Parameters | `leadline-params` | candidate URLs text | Query/form fields; no fuzzing |
| API discovery | `leadline-api` | httpx JSONL + inferred URLs | Fixed paths, GET only, manual redirects |
| Vulnerability candidates | `leadline-vulns` | nuclei JSONL | Pattern candidates only; never confirmed |
| CVE candidates | `leadline-cve` | text CVE ids | Offline-first; optional NVD keyword lookup is unverified |
| Graph observations | `leadline-graph` | nmap XML | Reinforces host/IP/port entities and edges |
| Twelve-phase preset | `leadline-recon` | one phase per output | DNS → host intel → ports → HTTP → tech → JS → params → headers → API → vulns → CVE → graph |

### Design decisions

- **Shared artifacts, one fetch.** The preset fetches the page once and feeds
  tech, headers, JavaScript, params and API discovery from the same probes.
  Standalone collectors still work independently.
- **Existing formats, existing parsers.** New collectors emit nmap XML, httpx
  JSONL, nuclei JSONL, DNS records, raw HTTP or URL text. No collector writes
  to SQLModel directly; the normal `app.ingest` path seals each phase and
  creates entities/findings/edges.
- **Candidate language is explicit.** Pattern and header findings carry
  `candidate` tags. CVE keyword results do not become findings and do not affect
  risk. The graph phase performs no new connections in the preset.
- **Fail closed.** Scope denials and cancellation are fatal. Optional analysis
  failures are recorded as skipped phases so partial evidence survives.
- **Ports/TLS.** A full connect scan, not SYN. The scope guard's pinned address
  is used for every connection. An HTTPS target with an explicit port is
  treated as TLS automatically. `http_ports`/`tls_ports` options exist for
  fixtures and unusual deployments.
- **Inferred parameters.** The URL parser now keeps blank query values, so
  `?param=` creates a `param` entity without inventing a value or sending a
  request.

### Verification

- `test_port_scan_emits_nmap_banner_and_risk_candidate`: local HTTP fixture,
  nmap XML, nginx banner, high-risk candidate JSONL.
- `test_port_scan_reads_tls_certificate_fields`: self-signed fixture, TLS
  handshake, certificate CN/SAN evidence.
- `test_recon_preset_runs_twelve_phases_and_seals_evidence`: one job produces
  12 ordered phases, 12 sealed captures, URL/param/tech/header/CVE/port
  entities, findings, `has_port` edges and a recorded scope decision.
- `test_recon_preset_fails_closed_for_out_of_scope_target`: no paste, no retry,
  permanent scope failure.
- Full suite: **116 passed, 1 warning**; `compileall` and `git diff --check`
  pass.

### Known limits (carried into Phase 5)

- Host intel is offline-only: MX/NS/TXT/SOA/WHOIS/CT/ASN/geo are not queried
  without an optional resolver/lookup layer.
- API discovery does not parse OpenAPI/Swagger documents into endpoints yet.
- Tech signatures are still the small built-in set, with limited version
  extraction for CPE.
- CVE correlation has no local NVD cache or CPE version-range verification yet;
  only referenced CVE ids and unverified keyword candidates exist.
- The graph UI has no path-tree/filter view for recon observations yet.
- Report highlights/risk explanations and the history/diff/PDF layer are still
  Phase 6.
- External binaries are still import-first adapters; Phase 7 adds execution.

---

## 2026-11-06 — Phase 3: encrypted header-profile secrets

### Implemented

- `app/secrets_store.py`: AES-GCM encrypted text/JSON values, key file
  `breadcrumb.db.key`, `MultiFernet` rotation, legacy plaintext migration,
  redaction helper.
- `HeaderProfile.headers` and `HeaderProfile.proxy` now decrypt transparently
  for the local UI/API and the executor; ciphertext at rest.
- Startup migration on first use; pre-migration backup scrub; `secure_delete`,
  WAL checkpoint and `VACUUM`.
- `breadcrumb secrets rotate` CLI.
- Failure behavior: a missing/wrong key fails closed rather than returning
  ciphertext as a header value.

### Verification

- Migration against a copy of the real `breadcrumb.db`: both existing profiles
  decrypted correctly; ciphertext confirmed; backup scrub confirmed.
- Key-loss, rotation, redaction and tamper tests.
- Full suite at the time: 112 passed.

### Risk

The live database was intentionally **not** migrated in this session. First
live startup will create `breadcrumb.db.key`; the key must be backed up
separately. Older `*.pre-migrate-*.bak` files may contain plaintext.

---

## 2026-11-06 — Phases 1/2: durable executor and native vertical slice

### Implemented

- Extracted `app/ingest.py` as the single ingest path with `capture_key`
  idempotency, chain sealing, attribution and findings.
- Schema version 2, singleton `AppState`, additive migrations, WAL pragmas.
- Durable queue: atomic claim, per-attempt leases, heartbeat thread,
  cancellation, retry/backoff, expired-lease recovery, maintenance pause.
- Scope guard: fail-closed policy, DNS classification, private-target warning,
  metadata/link-local hard blocks, pinned addresses, per-redirect re-checks.
- Native DNS, HTTP, tech and security-header collectors.
- Job detail attempts/phases/events, run-now, cancel/retry, health fields,
  maintenance banner, CLI `worker`/`maintenance`.
- Short-lived DB sessions around collectors and event writes. The earlier stuck
  `running` job was caused by holding a write transaction while another session
  wrote an event; this is now a hard rule.

### Verification

- 112 passed at the time, including two-worker drain, cancellation, retry,
  lease expiry, maintenance, redirect fail-closed, secret redaction and
  header-profile testing.

---

## 2026-10-29 — Phase 0: safety rails

### Implemented

- Host allowlist and Origin/Sec-Fetch-Site checks.
- CSRF token on every POST form.
- SQLite WAL, busy timeout and foreign keys at connection time.
- Linear SHA-256 evidence chain with delete-gap recovery.
- WAL-safe backup/restore and legacy chain backfill.
- Migration tests against an old schema.

### Verification

- 72 passed at the time.

---

## 2026-10-27 — Planning baseline

- Inspected Breadcrumb `e51c91b` and Leadline `6802a50`.
- Wrote the merge plan, parity matrix, pre-mortem, postmortem and research
  notes in `docs/`.
- Decision: **Option A, monorepo absorption** — one Breadcrumb process,
  database and UI; Leadline is additional capability, not a replacement.
- Capability parity is the contract, not React-UI/API parity.
- The Leadline folder stays as a reference/fallback until parity and real
  import pass; no automatic archive or deletion.

---

## Status after Phase 8

All planned phases (0–8) are implemented and released as **0.4.0**. The
capability parity sign-off is recorded in `LEADLINE_PARITY_MATRIX.md`; the
real-data import is recorded in `LEADLINE_IMPORT_VERIFICATION.md`.

Remaining owner actions (not code work):

1. Review and sign `SECURITY_CHECKLIST.md`, accepting the residual risks
   (private-target SSRF, local no-auth UI, external-tool resolution gap, local
   visibility of header values, and the synthetic-fixture coverage for import
   paths the real database did not contain).
2. Commit/release the merge as `0.4.0`; the working tree is ready for the first
   push.
3. Keep the Leadline folder as a reference/fallback; remove the remote GitHub
   repository manually when satisfied.
4. Back up `breadcrumb.db.key` separately from the database; losing it makes
   encrypted header values unrecoverable.
5. Gate C (external-tool strictness) remains an explicit sign-off item, not an
   automatic pass.
