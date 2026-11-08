# Leadline → Breadcrumb feature parity matrix

**Purpose:** prove that every Leadline capability has a home in Breadcrumb, an
explicit addition, or an owner decision. This is the sign-off document for
“I do not want to lose the original functionality.”

**Status legend**

| Status | Meaning |
|---|---|
| **Existing** | Breadcrumb already provides the capability; verify behavior. |
| **Add Pn** | Added in Phase *n* of `LEADLINE_MERGE_PLAN.md`. |
| **Compat** | Preserved through the Leadline compatibility API/importer, not the primary UI. |
| **Owner call** | Requires an explicit decision; recommended option noted. |
| **Not ported** | Intentionally replaced; rationale and replacement given. |
| **Verify** | Needs an acceptance test before sign-off. |

**Rule:** no row may remain blank or “later” at sign-off time. If the owner
chooses not to preserve something, it becomes **Owner call → shelved** and is
recorded here, not silently dropped.

**Baseline:** Leadline v0.2.0 (`6802a50`), 12 phases, FastAPI + async SQLAlchemy
+ SQLite, React/Vite UI, 41 tests. Breadcrumb `e51c91b`, FastAPI + SQLModel +
SQLite, Jinja UI, 62 tests.

---

## Summary

| Area | Rows |
|---|---:|
| Target management | 12 |
| Scan/job lifecycle | 15 |
| Recon phases | 27 |
| Findings/triage/risk | 15 |
| History/diff | 12 |
| Reports/exports | 14 |
| Graph | 7 |
| UI | 13 |
| API | 18 |
| Safety/security | 20 |
| Config/pacing | 28 |
| Operations/deploy | 10 |
| Testing/quality | 7 |
| Intentional differences | 12 |
| **Total** | **210** |

The tables are authoritative. The matrix is dominated by **Add** rows; the
**Existing** rows are behaviors Breadcrumb already has; the **Compat/owner**
rows are product decisions. The two headline **Not ported** items are the React
SPA and the separate service/DB, both replaced by capability parity plus a
compatibility layer. Section N records the full set of intentional differences.
If the owner requires literal UI/API preservation, the project scope changes
substantially (Q1).

---

## A. Target management

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| A1 | Create target | `POST /api/targets` with name, URL, notes | Programs + targets exist; target is name/kind, not URL-first | Target.name holds URL/host; kind inferred; notes preserved | Existing + Verify | P6 |
| A2 | Unique target URL | DB unique constraint on `url` | No target URL uniqueness; entities dedupe | Normalize and dedupe within program; same host in two programs is allowed (ledger) | Add | P6 |
| A3 | List targets | `GET /api/targets` | Programs page lists targets | Existing list + API | Existing | — |
| A4 | Get target | `GET /api/targets/{id}` | Target page | Existing | Existing | — |
| A5 | Update target | `PUT /api/targets/{id}` | Program target update | Existing | Existing | — |
| A6 | Delete target + cascade | Deletes scans/events/findings/graph | Target delete exists; verify cascade/evidence policy | Delete target but preserve sealed pastes unless explicit purge | Add | P0/P6 |
| A7 | Active/inactive flag | `is_active` | No direct flag; targets can be unused | `archived` meta flag; excluded from default pickers | Add | P6 |
| A8 | Target notes | Free text | Existing `notes` | Existing | Existing | — |
| A9 | Per-target custom headers | Plain dict merged into every request | HeaderProfile attached to job | HeaderProfile (encrypted) linked to target; job default | Add + Compat | P3/P6 |
| A10 | Bare host/IP/IPv6 normalization | `_normalize_target_url` | Scope/target parser exists | Reuse/port normalization; IPv6 bracket tests | Add | P2/P6 |
| A11 | Target history timeline | `/history` snapshot list | Program Changes view, not per-target timeline | `ScanSnapshot` timeline per target | Add | P6 |
| A12 | Target diff | `/history/diff` | Program latest-vs-history changes | Snapshot diff with category detail | Add | P6 |

**Notes**

- Breadcrumb’s program model is a superset of Leadline’s flat target list. A
  Leadline target becomes a Breadcrumb target inside an import program; the
  URL/host is the target name and the primary entity.
- Custom headers are a security-sensitive feature. They are not copied into
  plaintext; the importer creates an encrypted HeaderProfile per distinct
  header set (P3).
- Deleting a target must not silently delete evidence that a report references.
  Default: archive target, keep pastes; an explicit “purge target and
  evidence” action is separate and audited.

---

## B. Scan/job lifecycle

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| B1 | Create scan for target | `POST /api/scans` | `POST /api/v1/jobs` creates a job | Job create with target/collector/config | Existing + Add | P1 |
| B2 | Start scan | `POST /api/scans/{id}/start`, BackgroundTasks | No executor | Atomic enqueue/claim; inline or worker | Add | P1 |
| B3 | Stop scan | Sets `stopping`; pipeline polls between phases | Cancel endpoint exists but no running executor | `cancel_requested` + cooperative/process-group kill | Add | P1 |
| B4 | Delete scan | Cascades events/findings/graph | Job delete exists | Keep; explicit evidence policy; no silent chain rewrite | Existing + Verify | P0/P1 |
| B5 | List/get scans | `/api/scans` | `/api/v1/jobs` | Extend fields | Existing | P1 |
| B6 | Progress percentage | `progress` 0–100 | Job status/log only | Compute from phases/attempt | Add | P1 |
| B7 | Current phase | `current_phase` | None | `ScanPhase` current row | Add | P1 |
| B8 | Status vocabulary | pending/running/completed/failed/stopped | queued/running/done/failed/cancelled | Keep Breadcrumb’s `done` as canonical; compat maps `pending→queued`, `completed→done`, `stopped→cancelled` | Existing + Compat | P1/P6 |
| B9 | Started/completed/error timestamps | Columns | `started_at`/`finished_at`; no error field | Add `error_class`/`error_message` | Add | P1 |
| B10 | Per-scan evasion toggle | `evasion_enabled` | HeaderProfile randomization; no per-job toggle | Job config `evasion_enabled`; profile headers | Add | P3/P4 |
| B11 | Per-scan request delay | `request_delay` | HeaderProfile `rate_limit` hint | Job config delay/jitter; per-host limiter | Add | P2/P3 |
| B12 | Per-scan external lookups | `enable_external_lookups` | No collector lookups | Program/job opt-in; default off | Add | P2/P4 |
| B13 | Scan events endpoint | `/api/scans/{id}/events` | Job log only | `/jobs/{id}/events` + `ScanPhase` | Add | P1 |
| B14 | Background execution | FastAPI BackgroundTasks | None | Durable queue + optional worker | Add (replaces) | P1 |
| B15 | Restart recovery | Marks running/stopping failed | None | Lease expiry, attempt `lost`, retry/requeue | Add (improves) | P1 |

**Notes**

- Leadline’s `stopped` is a user cancellation. Breadcrumb maps it to
  `cancelled`; the compatibility API returns `stopped` for old clients.
- Leadline’s `completed` maps to Breadcrumb’s `done`. A compatibility response
  may include both `status` and `legacy_status`.
- A `done` job cannot be “started again” in place; the UI offers “Run
  again,” which creates a new job linked by `parent_job_id`. This preserves the
  old evidence and the hash chain.
- Deleting a job never mutates the hash chain of other pastes. If the job’s
  paste is deleted, `/verify` reports a gap.

---

## C. Recon phases

| # | Leadline phase/capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| C1 | DNS discovery | Resolve target, record addresses | DNS parser (import only) | `leadline.dns` collector; scoped resolver | Add | P4 |
| C2 | Host intel: A/AAAA/MX/NS/TXT/CNAME/SOA | dnspython queries | DNS parser (import only) | `leadline.host_intel`; typed records | Add | P4 |
| C3 | Reverse DNS | PTR lookup | None | Host intel | Add | P4 |
| C4 | WHOIS | WHOIS/RDAP with timeout | None | Host intel, external opt-in | Add | P4 |
| C5 | Certificate-transparency subdomains | crt.sh | None | Host intel, external opt-in, capped | Add | P4 |
| C6 | DNSSEC presence | DNS query | None | Host intel | Add | P4 |
| C7 | Geolocation/ASN | ip-api.com | None | Host intel, external opt-in | Add | P4 |
| C8 | DNSBL check | Spamhaus via DNS | None | Host intel, external opt-in | Add | P4 |
| C9 | TCP connect port scan | ~200 curated ports, concurrency 10 | Port parser (import only) | `leadline.ports`; scoped, capped | Add | P4 |
| C10 | Banner grabbing | Per-port banner | None | Ports collector | Add | P4 |
| C11 | TLS certificate inspection | SANs, issuer, expiry, self-signed | None | Ports/TLS collector; evidence fields | Add | P4 |
| C12 | HTTP fingerprinting | GET/HEAD/OPTIONS, status, redirects, headers | httpx parser (import only) | `leadline.http`; manual redirects, body cap | Add | P4 |
| C13 | Technology detection | Server/framework/CMS/CDN/WAF | httpx tech parser (import only) | `leadline.tech`; signatures + version | Add | P4 |
| C14 | JS analysis | Fetch scripts, extract endpoints/API calls/params | URL/JS parser (import only) | `leadline.js`; same-origin, capped, no execution | Add | P4 |
| C15 | Parameter discovery | Query params + form fields from HTML/JS | None | `leadline.params`; parse artifacts | Add | P4 |
| C16 | Security headers | Present/missing/misconfigured, indicative score | HTTP header parser only | `leadline.headers`; findings + indicative score | Add | P4 |
| C17 | API discovery | Common REST/GraphQL/Swagger/OpenAPI paths | URL parser (import only) | `leadline.api`; max 50, GET/HEAD | Add | P4 |
| C18 | Vulnerability classification | Pattern candidates, manual review | Nuclei/CVE findings from imports | `leadline.vulns`; candidates, never confirmed | Add | P4 |
| C19 | CVE correlation: CPE resolution | Product → CPE | CVE parser (extract only) | `leadline.cve`; CPE mapping | Add | P4 |
| C20 | CVE correlation: version ranges | NVD version-range matching | None | `leadline.cve`; apply ranges | Add | P4 |
| C21 | CVE keyword fallback | NVD keyword candidates, labeled unverified | CVE parser captures text | `leadline.cve`; label + risk exclusion | Add | P4 |
| C22 | Risk excludes unverified CVEs | `applicability_verified` | No risk score | Port `risk.py`; same exclusion | Add | P6 |
| C23 | Attack-surface graph builder | Path tree of endpoints | Typed graph + SVG | `leadline.graph`; observations → relationships; path view | Add | P4/P5 |
| C24 | Phase order/context | 12 phases share context | None | Collector orchestrator with typed prior results | Add | P4 |
| C25 | Phase event records | status/result_data/findings_count | None | `ScanPhase` rows | Add | P1/P4 |
| C26 | Phase failure isolation | Current pipeline does not catch a phase exception | None | Per-phase try/except; failed phase recorded; job policy (continue or fail) | Add (improves) | P4 |
| C27 | Scan timeout / max endpoints / max depth | Global caps | Ingest caps only | Job runtime, URL/endpoint, graph caps | Add | P2/P4 |

**Notes**

- Two “not ported” behaviors are deliberate: Leadline’s unbound `truncated`
  bug (C12) and its startup “mark running failed” recovery (B15). They are
  replaced, not preserved.
- Security-header scoring is kept but labeled **indicative**, as Leadline’s own
  code comments say. A missing header is not automatically a vulnerability.
- `leadline.recon` is a preset that runs C1–C23 in order for parity. Users can
  also run individual collectors.

---

## D. Findings, triage, and risk

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| D1 | Finding types | endpoint/api/vulnerability/cve_match/header | Findings exist; no explicit type field | Add `kind` (or use tags + source_tool) | Add | P6 |
| D2 | Severity levels | info/low/medium/high/critical | Same vocabulary | Existing | Existing | — |
| D3 | Title/description/evidence/remediation | Columns | Same fields | Existing | Existing | — |
| D4 | Location | URL/path column | Target relationship, no location string | Add `location` optional for parity/reporting | Add | P6 |
| D5 | Structured metadata | `extra_data` JSON | No generic metadata? Findings have tags/notes | Use `meta` JSON or add; preserve CVE data | Add | P6 |
| D6 | Finding list/detail | `/api/findings` | `/api/v1/findings`, UI | Existing | Existing | — |
| D7 | Triage status | open/acknowledged/false_positive | `status` open/in-progress/resolved/wont-fix; entity verdict | Add `Finding.verdict`; map triage | Add + Compat | P6 |
| D8 | Triage note | `triage_note` | Finding `notes` | Map to notes; compat field | Existing + Compat | P6 |
| D9 | Triaged timestamp | `triaged_at` | `updated_at` | Use updated_at; compat `triaged_at` | Existing + Compat | P6 |
| D10 | False-positive flag | `is_false_positive` | Entity verdict; finding status | Map to `verdict=false-positive` + `status=wont-fix` | Add | P6 |
| D11 | Triage patch endpoint | `PATCH /api/findings/{id}` | Finding annotate/status endpoints | Compat PATCH; primary UI controls | Add + Compat | P6 |
| D12 | False positives excluded from risk | `compute_risk` skips | No risk score | Port risk; skip ignored/false-positive | Add | P6 |
| D13 | Risk score/level | 0–100 + level | No overall score | Port `compute_risk`; explainable | Add | P6 |
| D14 | Severity counts | Per severity | Findings page counts? Verify | Add summary API/report | Add | P6 |
| D15 | Report highlights | Top findings/risk | No highlights | Add summary/highlights | Add | P6 |

**Notes**

- Breadcrumb already has stronger triage for entities. The gap is findings.
  Adding `Finding.verdict` gives both models one vocabulary without removing
  Breadcrumb’s workflow statuses.
- The compatibility layer exposes `triage_status`, `is_false_positive`, and
  `triage_note`; the canonical storage is `status` + `verdict` + `notes`.
- False positives and ignored entities are excluded from reports/exports by
  default. A report can explicitly include them for internal review.

---

## E. History and diff

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| E1 | Per-target scan timeline | History endpoint + UI | Program Changes view; no per-target timeline | `ScanSnapshot` per job; target timeline | Add | P6 |
| E2 | Snapshot: risk/severity/finding count | `build_snapshot` | Not materialized | Port fields into `ScanSnapshot.data` | Add | P6 |
| E3 | Snapshot: verified/unverified CVE counts | Counts by `applicability_verified` | None | Port | Add | P6 |
| E4 | Snapshot: findings map | Stable key | Changes view uses captures | Use finding fingerprint; port key rules | Add | P6 |
| E5 | Snapshot: endpoints | Findings + JS + API + graph | Graph/entities exist | Derive from observations/entities | Add | P6 |
| E6 | Snapshot: resolved IPs/hostnames/subdomains | Host intel | DNS entities exist | Derive | Add | P6 |
| E7 | Snapshot: DNS records/WHOIS/DNSSEC/IP reputation | Host intel | Partial entities | Derive | Add | P6 |
| E8 | Snapshot: ports/services/TLS | Port phase | Port entities exist | Derive | Add | P6 |
| E9 | Snapshot: technologies/CDN-WAF | Tech phase | Tech entities exist | Derive | Add | P6 |
| E10 | Snapshot: security headers present/missing | Header phase | Header entities | Derive | Add | P6 |
| E11 | Scan-to-scan diff | New/resolved findings, port/DNS drift, tech, endpoints | Program latest-vs-history changes | Snapshot diff engine + API + UI | Add | P6 |
| E12 | Triage state in diff | False positives excluded/labeled | Not applicable yet | Carry verdict; exclude from “new” | Add | P6 |

**Notes**

- Breadcrumb’s existing Changes view is valuable and stays. The new snapshot
  diff is per-target/per-job and is what Leadline users expect.
- Snapshots are derived and rebuildable from evidence. They are a cache, not a
  second source of truth.
- Diff keys must be stable across runs. CVE findings key by CVE id; other
  findings by type + location + normalized title (Leadline’s rule).

---

## F. Reports and exports

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| F1 | Full report JSON | Summary/highlights/findings/graph | JSON export exists | Extend with summary/highlights | Existing + Add | P6 |
| F2 | Report summary | Risk, counts, target, scan | No risk summary | Add | Add | P6 |
| F3 | Report highlights | Top findings/risk | None | Add | Add | P6 |
| F4 | Export JSON | Download | Existing | Existing | Existing | — |
| F5 | Export Markdown | Download | Existing | Existing | Existing | — |
| F6 | Export HTML | Download | Existing | Existing | Existing | — |
| F7 | Export PDF | reportlab | None | Port `pdf_export.py` | Add | P6 |
| F8 | Target-based filenames | `host[_port]-scan-id.ext` | Generic names? Verify | Adopt for all formats | Add | P6 |
| F9 | PDF confidentiality banner/footer | Yes | None | Port | Add | P6 |
| F10 | Authorized-use disclosure | Yes | Report text? Verify | Add | Add | P6 |
| F11 | Findings/evidence/remediation/triage in report | Yes | Existing fields | Add triage/verdict | Existing + Add | P6 |
| F12 | Graph tree in report | Yes | Graph data exists | Include path tree/summary | Add | P6 |
| F13 | Exclude false positives/ignored | Partially | Existing for entities | Extend to findings | Existing + Add | P6 |
| F14 | CSV/SARIF/HackerOne/targets.txt | Not in Leadline | Existing Breadcrumb differentiators | Keep | Existing | — |

**Notes**

- PDF is the only missing export format. reportlab is pure Python and was
  chosen by Leadline specifically to avoid Cairo/Pango; keep that property.
- Escape all untrusted evidence before `Paragraph`; add a test with `<script>`
  and `&`.
- Breadcrumb’s SARIF/HackerOne/targets.txt exports are additions, not parity
  requirements; they must not regress.

---

## G. Graph

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| G1 | Graph nodes | root/endpoint/api/parameter/debug/javascript | Typed entities/relationships + SVG | Map observations to existing graph | Existing + Add | P4 |
| G2 | Parent/depth tree | `parent_id`, `depth` | Relationships; no explicit tree depth | Add depth/meta to edges; path view | Add | P5 |
| G3 | Graph data in report | Tree | Graph view only | Include path tree/summary | Add | P6 |
| G4 | Graph per scan | Nodes tied to scan | Graph per program | Filter by job/phase | Add | P5 |
| G5 | Large graph handling | Not specified | Large clusters summarized | Keep + cap | Existing | — |
| G6 | Node metadata | `extra_data` | Entity meta | Preserve | Existing | — |
| G7 | Graph edges evidence link | Scan FK | Paste/relationship provenance | Add job/phase meta | Add | P4 |

---

## H. UI

| # | Leadline UI capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| H1 | Target list/add/edit/delete | React pages | Programs/targets Jinja | Existing | Existing | — |
| H2 | Target detail + notes | React page | Target page | Existing | Existing | — |
| H3 | Target history timeline | React page | Program Changes | Add per-target timeline | Add | P6 |
| H4 | Scan-to-scan diff | React page | Changes view | Add diff view | Add | P6 |
| H5 | Scan list/create/start/stop/delete | React pages | Jobs page | Add start/collector picker | Existing + Add | P1/P6 |
| H6 | Live phase progress | React polling | Job log | Add phase progress/events | Add | P1 |
| H7 | Findings list/detail/triage | React pages | Findings page | Add verdict control | Existing + Add | P6 |
| H8 | Report view + export buttons | React page | Reports page | Add PDF/summary/highlights | Existing + Add | P6 |
| H9 | Graph visualization | React (if present) | SVG graph | Keep + filters | Existing | — |
| H10 | Settings | Env/config | Settings page | Keep; add collector/AI fit | Existing | — |
| H11 | Dark/light theme | React/Tailwind | Breadcrumb themes | Existing | Existing | — |
| H12 | React SPA itself | Vite app, 3000 | Jinja | Not ported; capability parity | Not ported (Q1) | — |
| H13 | Mobile/responsive | React | Jinja responsive? Verify | Ensure job/history pages usable | Verify | P6 |

**Notes**

- This is the largest interpretation risk. The recommendation is capability
  parity, not a React port. If the owner wants the exact SPA, that is a
  separate frontend project (Q1).
- Breadcrumb’s UI is server-rendered and already covers most of the workflow;
  the additions are job progress, history/diff, and finding triage.

---

## I. API

| # | Leadline endpoint | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|
| I1 | `GET /api/targets` | `/api/v1/programs`, entities | Compat list | Compat | P6 |
| I2 | `POST /api/targets` | Program/target forms, API? | Compat create | Compat | P6 |
| I3 | `GET /api/targets/{id}` | Target page | Compat read | Compat | P6 |
| I4 | `PUT /api/targets/{id}` | Target update form | Compat update | Compat | P6 |
| I5 | `DELETE /api/targets/{id}` | Target delete | Compat delete/archive | Compat | P6 |
| I6 | `GET /api/targets/{id}/history` | None | Compat snapshot list | Compat | P6 |
| I7 | `GET /api/targets/{id}/history/diff` | None | Compat diff | Compat | P6 |
| I8 | `GET/POST /api/scans` | `/api/v1/jobs` | Compat create/list | Compat | P6 |
| I9 | `GET /api/scans/{id}` | `/api/v1/jobs` | Compat read | Compat | P6 |
| I10 | `POST /api/scans/{id}/start` | Job create/executor | Compat enqueue | Compat | P6 |
| I11 | `POST /api/scans/{id}/stop` | Job cancel | Compat cancel | Compat | P6 |
| I12 | `DELETE /api/scans/{id}` | Job delete | Compat delete policy | Compat | P6 |
| I13 | `GET /api/scans/{id}/events` | Job log | Compat phases/events | Compat | P6 |
| I14 | `GET /api/findings` | `/api/v1/findings` | Compat list | Compat | P6 |
| I15 | `GET /api/findings/{id}` | Findings UI | Compat read | Compat | P6 |
| I16 | `PATCH /api/findings/{id}` | Annotate/status | Compat triage | Compat | P6 |
| I17 | `GET /api/reports/{id}` | Report page | Compat summary | Compat | P6 |
| I18 | `GET /api/reports/{id}/export/*` | Existing exports | Add PDF; compat shapes | Compat + Add | P6 |

**Notes**

- Exact `/api/...` paths do not collide with Breadcrumb’s `/api/v1/...`,
  `/api/analyze`, `/api/search`, `/api/llm/models`. Mount them only if a route
  audit confirms no conflict; otherwise `/api/leadline/...` with a redirect.
- Additive fields are allowed; removing/renaming fields is not.
- A compatibility endpoint is not a second source of truth. It translates to
  the same models and evidence chain.
- OpenAPI docs remain available at `/docs`; document the legacy routes there.

---

---

## J. Safety and security

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| J1 | Localhost bind | `127.0.0.1` default | `127.0.0.1` default | Keep | Existing | — |
| J2 | No authentication | Local single-user | Same | Keep; optional token for non-loopback | Existing + Owner call | Q7 |
| J3 | Host header allowlist | Middleware | Missing | Add | Add | P0 |
| J4 | CORS restriction | Local UI origins | Verify; likely closed | Explicit allowlist; no `*` | Add/Verify | P0 |
| J5 | No telemetry | None | None | Keep | Existing | — |
| J6 | Authorization disclaimer | README/UI | README | Add UI/report disclosure | Add | P6 |
| J7 | Private/loopback targets allowed | By default | Program scope can allow private CIDRs but executor unaware | Private-target mode on by default with global warning; metadata/link-local hard-blocked | Add (replaces) | P2 |
| J8 | Scope enforcement | None | Attribution only | Fail-closed guard before every connection | Add | P2 |
| J9 | External lookups toggle | Per scan, default on | No collector lookups | On by default; per-job opt-out; visible failure + retry | Add | P2/P4 |
| J10 | Per-target custom headers | Plaintext JSON | HeaderProfile | Encrypted profile; replace-only | Add | P3 |
| J11 | Proxy support | Global proxy | HeaderProfile proxy | Scoped, warning, strict-mode disallow | Existing + Add | P2/P3 |
| J12 | UA rotation | Browser-like list | HeaderProfile family/randomize | Existing; per-job evasion toggle | Existing + Add | P3 |
| J13 | Request jitter/delay | Random delay | Rate limit hint | Per-job delay + jitter | Add | P2 |
| J14 | Response size cap | 2 MB | Ingest 5 MB; no network | 2 MB per HTTP response | Add | P2 |
| J15 | Timeouts | DNS/WHOIS/HTTP/port | None | Per-collector limits | Add | P2 |
| J16 | Redirect handling | aiohttp follows | None | Manual, revalidated, max 5 | Add | P2 |
| J17 | No shell injection | Python calls | No executor | argv-only, process group, env allowlist | Add P7 (implemented) | P7 |
| J18 | Secret redaction | Partial | Secret masking in exports only | Central redactor; encrypted headers | Add | P3 |
| J19 | PDF confidentiality | Yes | None | Port | Add | P6 |
| J20 | Backup safety | None | Raw copy (unsafe) | `Connection.backup` + integrity check | Add (fixes) | P0 |

**Notes**

- Leadline’s “any target” default is preserved as an explicit private-target
  mode with a global warning (owner decision, 2026-10-29). The capability is
  kept; metadata/link-local hard blocks, pinned resolution, and evidence
  recording are new. This is a documented residual risk, not a silent default.
- The no-auth model is retained for localhost. Host/Origin/CSRF checks are
  required because the browser is an attack surface even without auth.
- **Phase 7 adapter coverage (implemented 2026-11-07):** twelve opt-in
  adapters reuse the existing runner ids and emit formats Breadcrumb already
  parses (or a new parser). They are never claimed by the durable worker
  unless `BREADCRUMB_EXTERNAL_TOOLS=1`; explicit run-now can run one job.

| Adapter | Output / parser | Scope mode | Strict policy |
|---|---|---|---|
| nmap | XML → existing nmap XML parser | `ip_literal` (host → preflight) | `ip_only` |
| httpx | JSONL → existing httpx JSON parser | `resolve_override` | `always` |
| nuclei | JSONL → existing nuclei parser | `preflight_only` | `never` |
| subfinder | host list → existing host parser | `passive` | `always` |
| naabu | JSONL → existing ports parser | `ip_literal` | `ip_only` |
| masscan | text → existing ports parser | `ip_literal` | `always` |
| katana | URL list → existing URL parser | `preflight_only` | `never` |
| ffuf | JSON → new ffuf parser | `preflight_only` | `never` |
| dalfox | JSON → new dalfox parser (candidate) | `preflight_only` | `never` |
| amass | JSON → new amass parser | `passive` | `always` |
| whatweb | JSON → new whatweb parser | `preflight_only` | `never` |
| wafw00f | JSON → new wafw00f parser | `preflight_only` | `never` |

Every adapter preflights the target through the same scope guard as native
collectors; a denied target never spawns. Missing binaries are reported as
"not installed", not as an empty successful scan. `tests/test_phase7.py` proves
the no-spawn, timeout, output-cap, process-group cancellation, strict-mode and
worker-claim behavior.

---

## K. Configuration and pacing

| # | Leadline setting | Leadline default | Breadcrumb equivalent | Status | Phase |
|---|---|---|---|---|---|
| K1 | `DATABASE_URL` | `sqlite+aiosqlite:///./leadline.db` | `BREADCRUMB_DB_PATH` | Existing | — |
| K2 | `API_PREFIX` | `/api` | `/api/v1` + compat `/api` | Compat | P6 |
| K3 | `CORS_ORIGINS` | localhost:3000/5173 | `BREADCRUMB_CORS_ORIGINS` | Add | P0 |
| K4 | `ALLOWED_HOSTS` | localhost, 127.0.0.1, ::1, backend, testserver | `BREADCRUMB_ALLOWED_HOSTS` | Add | P0 |
| K5 | `DEFAULT_USER_AGENT` | Leadline UA | HeaderProfile default | Existing | — |
| K6 | `USER_AGENTS` | 5 browser/self IDs | HeaderProfile generator | Existing | — |
| K7 | `REQUEST_DELAY` | 0.5 s | Job config `request_delay` | Add | P2 |
| K8 | `MAX_CONCURRENT` | 5 | Per-host/global limits | Add | P2 |
| K9 | `TIMEOUT` | 10 s | Per-request timeout | Add | P2 |
| K10 | `MAX_RESPONSE_BYTES` | 2 MB | Response cap | Add | P2 |
| K11 | `PROXY_URL` | None | HeaderProfile proxy | Existing | P3 |
| K12 | `MAX_ENDPOINTS_PER_SCAN` | 500 | Job cap | Add | P2/P4 |
| K13 | `MAX_DEPTH` | 5 | Graph/JS depth cap | Add | P4 |
| K14 | `SCAN_TIMEOUT` | 3600 s | Job runtime cap | Add | P1 |
| K15 | `RANDOM_DELAY_MIN/MAX` | 0.1/0.5 | Jitter config | Add | P2 |
| K16 | `DNS_TIMEOUT` | 5 s | Collector limit | Add | P4 |
| K17 | `WHOIS_TIMEOUT` | 8 s | Collector limit | Add | P4 |
| K18 | `GEOIP_TIMEOUT` | 6 s | Collector limit | Add | P4 |
| K19 | `PORT_SCAN_TIMEOUT` | 3 s | Collector limit | Add | P4 |
| K20 | `PORT_SCAN_CONCURRENCY` | 10 | Per-host concurrency | Add | P4 |
| K21 | `CVE_LOOKUP_TIMEOUT` | 10 s | Collector limit | Add | P4 |
| K22 | `CVE_LOOKUP_MAX_CANDIDATES` | 8 | Cap | Add | P4 |
| K23 | `CVE_LOOKUP_SPACING` | 7 s | Rate limit | Add | P4 |
| K24 | `NVD_API_KEY` | None | Secret/env | Add | P4 |
| K25 | `NVD_API_KEY_SPACING` | 0.7 s | Rate limit | Add | P4 |
| K26 | `CVE_CPE_MAX_RESULTS` | 2000 | Cap | Add | P4 |
| K27 | `CVE_MAX_MATCHES_PER_PRODUCT` | 25 | Cap | Add | P4 |
| K28 | `.env` loading | pydantic-settings | Breadcrumb env/config | Existing | — |

**Notes**

- Leadline uses a global proxy; Breadcrumb uses a per-header-profile proxy.
  Preserve the capability, but make the scope warning explicit.
- External lookups stay on by default (owner decision), but every failure is
  visible with provider/status/error and a retry path; per-job opt-out remains.
  Imported Leadline jobs retain their original setting in `config` as
  historical metadata; they are not re-run automatically.

---

## L. Operations and deployment

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| L1 | Docker Compose | UI 3000 + API 8000, loopback | One service 8787 | Keep one service; optional worker profile | Existing + Add | P8 |
| L2 | Manual venv | Backend + frontend | One venv | Keep; document optional extras | Existing | — |
| L3 | SQLite file | `leadline.db` | `breadcrumb.db` | One DB; importer reads old file | Existing | — |
| L4 | Schema creation | `create_all` | `create_all` + additive migrations | Add `schema_version`, migration tests | Add | P0 |
| L5 | Startup recovery | Marks running failed | None | Lease recovery | Add | P1 |
| L6 | Queue | None (BackgroundTasks) | None | Durable job queue | Add | P1 |
| L7 | Single-user | Yes | Yes | Keep | Existing | — |
| L8 | Health endpoint | Verify | `/health` | Extend worker/queue/chain | Existing + Add | P0/P1 |
| L9 | Logs | Uvicorn/app logs | Job log | Structured JobEvent + redaction | Add | P1/P3 |
| L10 | Backup/restore | None | Raw copy | Safe backup/restore | Add (fixes) | P0 |

---

## M. Testing and quality

| # | Leadline capability | Leadline behavior | Breadcrumb today | Target design | Status | Phase |
|---|---|---|---|---|---|---|
| M1 | Backend unit/integration tests | 41 tests | 62 tests | Keep both; port Leadline tests | Existing + Add | P4/P6 |
| M2 | Async API tests | pytest-asyncio/httpx | pytest | Add deps/test config | Add | P1 |
| M3 | Phase tests | test_recon* | Parser tests | Port with fixtures/mocks | Add | P4 |
| M4 | History/diff tests | test_history* | Changes tests | Port + snapshot tests | Add | P6 |
| M5 | Risk tests | test_risk | Severity/gate tests | Port + mapping tests | Add | P6 |
| M6 | CI backend | pytest, pyflakes, compileall | CI? Verify | Merge both checks | Existing + Add | P0 |
| M7 | CI frontend | typecheck/build | N/A (Jinja) | Not applicable if SPA not ported | Not ported (Q1) | — |

---

## N. Intentional differences and “not ported” items

| # | Item | Why not ported | Replacement | Owner action |
|---|---|---|---|---|
| N1 | React/Vite SPA | Duplicates Breadcrumb’s Jinja UI; huge frontend rewrite; capability parity is the goal | Breadcrumb pages + compatibility API | Q1 |
| N2 | Separate `leadline.db` and service | Splits evidence/scope; doubles ops | One Breadcrumb DB + importer | Q1/Q3 |
| N3 | FastAPI `BackgroundTasks` runner | No durability, no lease, no recovery | Durable queue/worker | — |
| N4 | Startup “mark running failed” | Loses work; no resume | Lease recovery/retry | — |
| N5 | “Any target” default | SSRF/scope risk | Scope + private-target warning; metadata/link-local hard-blocked | Q2 |
| N6 | In-process `truncated` bug | Bug, not a feature | Fixed during port + regression test | — |
| N7 | Exact `/api` paths | Collision/ambiguity risk | Compatibility router; `/api/leadline` fallback | Q1 |
| N8 | `is_active` boolean | Breadcrumb uses archive/meta | `archived` flag + filters | — |
| N9 | Plaintext custom headers | Secret leak | Encrypted HeaderProfile; replace-only | — |
| N10 | External lookups on by default | Offline-first/engagement privacy | On by default with visible failure/retry and per-job opt-out; imported setting kept as metadata | Q6 |
| N11 | Global proxy setting | Scope bypass; per-profile is better | HeaderProfile proxy + warning | — |
| N12 | React build CI | No SPA | Backend CI + Jinja smoke tests | Q1 |

---

## O. Data migration parity

Implemented in Phase 8 and exercised on a copy of the owner's real database.
Rows marked “fixture” were not present in that database and are proven by
`tests/test_phase8.py`.

| Leadline data | Imported? | Mapping | Verification |
|---|---|---|---|
| Targets | Yes (real) | Target under import program; name=URL/host; notes/timestamps | Count + sample |
| Custom headers | Yes (real) | Encrypted HeaderProfile per set | Decrypt round-trip + raw `enc:v1:` check |
| Scans | Yes (fixture) | Historical `ScanJob` (`runner=leadline.imported`) | Count/status + non-runnable guard |
| Scan events | Yes (fixture) | `ScanPhase` + snapshot inputs | Phase count/status |
| Findings | Yes (fixture) | `Finding` + `verdict`/`status`; metadata | Count/triage/sample |
| False positives | Yes (fixture) | `verdict=false-positive`, `wont-fix` | Count |
| Triage notes | Yes (fixture) | `notes` | Sample |
| Graph nodes | Yes (fixture) | Entities/relationships | Count/sample |
| Graph edges/parents | Yes (fixture) | Relationships with depth meta | Sample |
| Report exports | No (regenerate) | PDF/JSON/MD/HTML from imported data | PDF/export smoke test |
| Scan config | Yes (fixture) | `params`/`meta` (`evasion`, delay, lookups) | Sample |
| Timestamps | Yes (real where present) | Preserve where valid; import time fallback | Sample |
| Source DB | Read-only | Never modified | SHA-256 before/after |
| Import resume | Yes | Manifest ID map; mode `0600` | Idempotent re-run test |
| Import verification | Yes | `--verify` counts/triage/severity/samples/headers/hash | 6 checks pass on real data |

**Evidence:** `docs/LEADLINE_IMPORT_VERIFICATION.md`,
`tests/test_phase8.py`, `scripts/acceptance_phase8.py`.

---

## P. Acceptance flow (the “did we lose anything?” test)

Run this against a copy of a real Leadline database and a local fixture target:

1. **Add a target** in Breadcrumb → appears in the target list with notes.
2. **Set custom headers** → stored encrypted; UI shows redacted; requests use
   them only in memory.
3. **Start a scan** → job queues, claims, and runs all 12 phases.
4. **Watch progress** → phase list, current phase, logs, cancel button.
5. **Stop a scan** → status cancelled; no orphan process; partial evidence
   sealed.
6. **Kill the worker** → restart; job recovers or fails with a clear reason; no
   duplicate output.
7. **Open findings** → severity, evidence, remediation, location, type.
8. **Triage** → open/acknowledged/false-positive; risk excludes false
   positives; notes persist.
9. **Re-scan** → history timeline and diff show new/resolved ports, DNS,
   technologies, endpoints, findings.
10. **Export** → JSON/Markdown/HTML/PDF; filename is target-based; PDF has
    confidentiality banner and escaped evidence.
11. **Graph** → endpoints/parameters visible; per-job filter.
12. **API** → run the Leadline curl examples against the compatibility router.
13. **Verify** → `/api/v1/verify` passes; deleting a paste in a copy shows a
    gap.
14. **Offline** → disable external lookups and block egress; scan still works
    with no outbound calls.
15. **Import** → dry-run counts match; real import preserves targets/scans/
    findings/triage; source DB unchanged.

| Step | Evidence | Status |
|---|---|---|
| 1–2 | Existing target tests; Phase 3 encryption/migration tests | Pass |
| 3–6 | Phase 1/2 queue tests; Phase 4 twelve-phase end-to-end test; cancel/lease recovery tests | Pass |
| 7–8 | Phase 6 triage mapping/route tests; risk exclusion test | Pass |
| 9 | Phase 6 snapshot/diff timeline test | Pass |
| 10 | Phase 6 PDF bytes/escaping/filename test | Pass |
| 11 | Phase 4/5 graph and path-tree tests | Pass |
| 12 | Phase 6 compatibility end-to-end contract test | Pass |
| 13 | Phase 0 evidence-chain/verify and delete-gap tests | Pass |
| 14 | Phase 2/4 offline and per-job opt-out tests | Pass |
| 15 | Phase 8 real-data import + verification + acceptance script | Pass (real DB had no scans/findings; fixture covers them) |

If any step fails, the corresponding matrix row is not green and the
parity/import sign-off is not met.

---

## Q. Sign-off block

| Item | Owner decision | Date | Notes |
|---|---|---|---|
| Q1 — parity definition (capability vs exact UI/API) | **Capability parity; keep Breadcrumb’s current UI/pages and add scanning as a feature** | 2026-10-29 | Owner: existing Breadcrumb functionality stays; Leadline becomes an added feature, not a replacement. No React port. |
| Q2 — lab/private targets | **Allow all private/public targets with a global warning** | 2026-10-29 | Owner chose option (c). Metadata, link-local, multicast, unspecified, and reserved addresses stay hard-blocked. Accepted SSRF residual risk; Host/CSRF/evidence controls mandatory. |
| Q3 — archive Leadline repo | **Keep the local Leadline folder; no automatic archive/delete** | 2026-10-29 | Owner will remove the GitHub repo himself. Parity/import still required before the folder is treated as frozen. |
| Q4 — executor default | **Inline default + optional worker** | 2026-11-03 | Owner confirmed after explanation. Inline = same web process; worker = separate process sharing the DB. Phase 0 does not depend on this choice. |
| Q5 — local LLM runtime/model | **LM Studio + Jan both; LM Studio default with installed Qwen3-4B-Instruct-2507 at 4096 context** | 2026-11-03 | Owner confirmed LM Studio as default runtime and requires a model picker with per-route/per-job overrides. Jan remains available. Settings → Available models now lists only reachable provider models, labels roles/fit, tests speed/output, auto-fits context, and assigns per-route (per-job overrides still pending). Optional Qwen2.5-3B-Instruct Q4_K_M (2.10 GB) for speed; 3B Coder optional for code. Installed 7–16 GB models do not fit 4 GB VRAM. |
| Q6 — external lookups default | **On by default; surface failures and offer retry** | 2026-10-29 | Owner chose on. Show provider/status/error/timestamp, distinguish “failed” from “no results,” add per-job opt-out and a privacy warning. |
| Q7 — localhost no-auth | **No login; bind 127.0.0.1 only** | 2026-11-03 | Owner confirmed. Keep Host/Origin/CSRF checks. Add a token only if exposed beyond loopback. |
| Q8 — PDF in first parity release | **Yes — text PDF in first parity release** | 2026-11-03 | Phase 6. Scanned/OCR PDFs deferred. |
| Q9 — import existing Leadline data | **Yes, one-way importer with dry-run** | 2026-10-29 | Preserve targets, scans, findings, triage, notes, history, and evidence links; source DB read-only. |
| Q10 — post-Phase-4 priority | **History/reports/UI first, then external tools, then CVE depth** | 2026-10-29 | Owner confirmed the recommended order; do not drop the later phases. |

**Phase 8 parity/import sign-off (2026-11-08):**

| Item | Status | Evidence |
|---|---|---|
| Capability parity (sections A–N) | Green | Phase 1–7 tests; this matrix; acceptance flow P |
| One-way Leadline import (section O) | Green | `tests/test_phase8.py`; `LEADLINE_IMPORT_VERIFICATION.md` |
| Dry-run/real import on copies | Green | 2 targets + 2 encrypted profiles; verification OK |
| Idempotent re-run | Green | 0 imported, 2 targets skipped; fingerprint unchanged |
| Acceptance script | Green | `scripts/acceptance_phase8.py` — 6/6 checks |
| Leadline folder retained | Green | Never modified/archived/deleted |
| Hardening docs | Green | Merge guide, API, security, hardware/AI, troubleshooting, backup, checklist, release notes, rollback |
| Residual-risk acceptance | **Done** | `SECURITY_CHECKLIST.md` signed for `0.4.0`; Gate C remains a deployment control |
| Commit/release | **Done** | Version `0.4.0`; working tree prepared for the first push |

The parity/import work is complete and verified; the only remaining items are
owner decisions (sign the checklist, accept residual risks, choose when to
commit/release).

**Parity sign-off:** every row above is **Existing**, **Add Pn** with a passing
test, **Compat** with a contract test, **Verify** with an acceptance check, or
**Owner call** with a recorded decision. No row may be silently skipped. The
**Not ported** items in section N are explicit and have replacements.

---

## R. Residual differences after the merge

These are the differences the owner should expect even after full parity. They
are intentional and documented in the README:

1. **Jinja UI, not React.** Same capabilities, different interaction.
2. **One database.** No `leadline.db`; the importer is one-way.
3. **Private targets allowed with a warning.** Metadata/link-local are
   hard-blocked; Host/Origin/CSRF and pinned resolution still apply.
4. **External lookups on by default, with visible failures and per-job opt-out.**
5. **Durable jobs.** Jobs can resume/retry; a crash does not mark everything
   failed.
6. **Evidence-first.** Every collector output is a sealed paste, not just a
   scan event row.
7. **No autonomous pivoting.** Discovered hosts are recorded, not scanned,
   until a new scoped job is queued.
8. **Encrypted header profiles.** Secrets are replace-only, not readable back.
9. **Compatibility API is a translation layer.** It may lag new features; the
   canonical API is `/api/v1`.
10. **Breadcrumb additions.** Ledger, SARIF/HackerOne/targets.txt, CI gate,
    notifications, graph, backup, CLI, local AI.

If any of these is unacceptable, it must be resolved before the merge is
released, not after sign-off.
