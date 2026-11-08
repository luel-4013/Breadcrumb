# Leadline → Breadcrumb merge: pre-mortem and critical review

**Status:** review of the proposal in `LEADLINE_MERGE_PLAN.md`. No code exists
for any recommendation below. “Fixed” would require a merged change and a
passing test; nothing here is fixed.

**Implementation update (2026-11-08).** Phases 0–8 are now implemented and
verified on a copy of the real Leadline database; released as `0.4.0`. The
statuses and pending notes below describe the pre-implementation review;
current status is in `docs/README.md`, `docs/MERGE_HISTORY.md` and
`docs/LEADLINE_PARITY_MATRIX.md`.

**Method:** assume it is six months after the merge and the project has failed.
Work backward to the decisions that caused the failure. Then test the plan’s
weakest assumptions, red-team the new attack surface, and list the release
gates that must pass before the executor is enabled or the Leadline folder is
treated as frozen.

**Verdict: conditional go.** The direction is right — Breadcrumb is the better
flagship and Leadline is the missing executor — but the plan is not safe to
implement wholesale yet. Four risks are existential:

1. **The definition of “do not lose functionality” is unresolved.** Capability
   parity may not satisfy an owner who means “keep the React UI and exact API.”
2. **The scope guard is the hardest code in the project.** A wrapper around
   HTTP calls is not a security boundary if redirects, proxies, DNS rebinding,
   or external tools can bypass it.
3. **Evidence and data migration are irreversible in practice.** A forked hash
   chain or a bad import destroys the trust proposition that makes Breadcrumb
   worth merging into.
4. **The port can become a rewrite.** Leadline’s collectors are coupled to its
   ORM, async session, and context shape; “port the behavior” is not the same
   as “copy the files.”

Recommendation: **approve Phase 0–2 only** (safety rails, job skeleton, scope
guard), resolve Q1/Q2 with the owner, and re-estimate after the scope tests and
a 2–3 collector spike. Do not start Phase 4 at scale or treat the Leadline
folder as frozen until those gates pass.

**Decision update (2026-10-29).** Q1 (capability parity), Q2 (private targets
allowed with a global warning), Q3 (keep the folder; no automatic archive),
Q6 (external lookups on by default, failures visible with retry), Q9 (one-way
importer), and Q10 (history/reports/UI first) are answered. Q4 (inline vs
worker), Q7 (no-auth), and Q8 (PDF) were answered on 2026-11-03 and recorded in
the parity matrix. The “unresolved definition”
risk is resolved as capability parity; the scope risk is now an **accepted
residual risk**, so the SSRF test matrix and Host/CSRF controls become more
important, not less.

---

## 1. Scorecard

Scores are 1–5, where 5 is best. This is a judgment call, not a measurement.

| Dimension | Score | Why |
|---|---:|---|
| Strategic fit | 4 | One product with evidence + execution is stronger than two half-products. |
| User value | 5 | The user explicitly wants Breadcrumb as flagship and Leadline’s scanning capability. |
| Technical feasibility | 3 | Feasible, but scope pinning, SQLite concurrency, and the port are nontrivial. |
| Safety readiness | 2 | Leadline has no scope enforcement; Breadcrumb has no executor, Host allowlist, or secret encryption. |
| Evidence readiness | 2 | Chain sealing is not concurrency-safe; ingest is embedded and multi-commit. |
| Schedule confidence | 2 | 9–13 weeks solo is optimistic for 12 phases + parity + migration. |
| Maintainability | 4 | One codebase is better than two, if the collector boundary stays clean. |
| Reversibility | 4 | Feature flags, backups, and the Leadline tag make rollback possible. |

The low safety/evidence scores are the reason Phase 0/2 are gates, not “nice to
have.”

---

## 2. Failure narratives

### F1 — “The scope guard was a wrapper, not a boundary”

**Scenario:** Breadcrumb ships with `ScopeGuard.check(url)` called before an
HTTP GET. A target returns a 302 to `http://169.254.169.254/latest/meta-data/`;
the HTTP client follows it automatically, and the guard is never consulted.
Or a user configures a proxy, and the proxy resolves an in-scope hostname to an
internal IP. Or an external `nuclei`/`nmap` adapter resolves the hostname
itself after the preflight check. A report captures cloud credentials.

**Why it is plausible:** every one of these is a normal feature (redirects,
proxies, external tools), and each has a different enforcement point. A guard
that is only at the “start job” layer is a false sense of security.

**Early warning:** the first collector uses `aiohttp` directly; redirects are
enabled by default; an adapter’s command line contains a hostname; a proxy is
configured; a test only checks the initial URL.

**Prevention:** the design in §9 of the plan — resolve once, validate every IP,
pin the connection, manual redirects, revalidate each hop, strip auth headers
cross-origin, deny metadata always, disallow proxies in strict mode, preflight
external tools and mark `scope_mode=preflight_only`, plus an SSRF matrix that
runs in CI. The guard must be the only network path; add a static check that
collectors use `ctx.http`.

**Response if it happens:** kill switch (`BREADCRUMB_EXECUTOR=off`), revoke
credentials, preserve logs/evidence, publish an advisory, add a regression
test. Do not “patch the URL check” and call it done.

**Release gate:** no executor default until the full §9.8 matrix passes,
including rebinding, CNAME, IPv6-mapped, multi-A, redirect-to-metadata, proxy,
and external-tool denial.

---

### F2 — “The evidence chain forked”

**Scenario:** the web ingest route and the worker both read the latest paste,
compute `prev_paste_id`, and insert. Both succeed under SQLite’s default
isolation because neither takes a write lock before reading. `/verify` reports
two children of one parent, or a valid-looking chain that omits a branch. A
report’s evidence is disputed and Breadcrumb cannot prove which capture came
first.

**Why it is plausible:** the current sealing code is read-then-insert and
`db.py` has no WAL/busy timeout. The executor adds a second writer for the
first time. This is exactly the kind of bug that only appears under real
concurrency.

**Early warning:** `prev_paste_id` is not unique; `verify` only walks one path;
a concurrency test is absent; the chain head is “latest row by id.”

**Prevention:** `EvidenceChain` single-row head, `UNIQUE(prev_paste_id)`,
`UNIQUE(chain_seq)`, `BEGIN IMMEDIATE`, `capture_key` idempotency, and a
two-process test. Backfill legacy data with a backup. Verify head/length/tail
separately. A late writer must fail the lease check and discard its
transaction.

**Response:** stop ingestion, preserve the DB, run a forensic export, rebuild
from raw only with an explicit repair record. Never silently re-seal.

**Release gate:** concurrency test + legacy migration test + verify gap/tail
tests pass before any collector writes evidence.

---

### F3 — “The port became a rewrite”

**Scenario:** the first collector is copied, but it expects Leadline’s
`AsyncSession`, `ScanEvent`, `Finding`, and `context` shapes. The team writes
adapters, then a compatibility ORM layer, then a second migration. Six weeks
later, only 3 of 12 phases work, the test suite is split, and the “merge” is a
second product in the same repo.

**Why it is plausible:** 8,265 LOC of Python with phase-to-phase context,
async SQLAlchemy, and report/history assumptions. The collectors are not a
clean library; they were written for Leadline’s models.

**Early warning:** more time spent on compatibility shims than collectors; two
schemas alive; tests importing `app.models` from both projects; the plan’s
“port” estimate grows every week.

**Prevention:** port **behavior**, not files. Define `CollectorContext` and
`CollectorResult` first; rewrite each phase against that contract; keep the
original as reference; port tests with fixtures. Timebox a 2–3 collector spike
in Phase 4 before committing to all 12. If the spike exceeds ~1.5× estimate,
cut scope to v1 collectors and defer JS/API/CVE depth.

**Response:** stop, re-scope to the highest-value collectors (DNS, ports, HTTP,
headers, tech), keep the rest as external tools, and revisit.

**Release gate:** a spike of `dns` + `ports` + `http` against local fixtures
with no Leadline ORM imports. If it cannot be done cleanly, the architecture
is wrong.

---

### F4 — “The user kept using Leadline”

**Scenario:** Breadcrumb ships the collector, but the owner wants the React
target history page, the exact `/api/scans` response, or the PDF layout. The
compatibility layer is “close enough,” the Jinja UI is unfamiliar, and the
owner keeps the old app running. The merge adds maintenance without replacing
the old workflow.

**Why it is plausible:** the phrase “do not lose the original functionality”
is ambiguous, and the plan interprets it as capability parity. That is a
product decision, not a technical one.

**Early warning:** Q1 is unanswered; the owner asks for a React page; the
compatibility API returns different field names; the parity matrix has
“Owner call” rows without decisions.

**Prevention:** get Q1 in writing before Phase 4. Build the acceptance flow in
§P of the parity matrix and run it with the owner. If exact UI parity is
required, plan a separate frontend that consumes Breadcrumb’s API — do not
pretend the Jinja UI is the same thing.

**Response:** if the owner rejects capability parity, stop the absorption and
choose Option B/C (separate service or shared package) rather than forcing a
UI rewrite into the merge.

**Release gate:** Q1 signed; acceptance flow passed; no unmarked parity rows.

---

### F5 — “Secrets leaked before encryption landed”

**Scenario:** the executor uses HeaderProfile plaintext; a job log prints the
request headers; an export includes a curl command with `Authorization`; an AI
prompt sends the header; a backup copies the DB; the secret ends up in a
report or a screenshot. Or the encryption key is stored next to the DB and the
“encryption” is decorative.

**Why it is plausible:** the current API returns full headers and curl flags;
logs are free text; the LLM prompt is built from evidence; notifications send
finding descriptions off-machine.

**Early warning:** a secret-scan test is absent; `reveal=1` bypasses
redaction; the key file is world-readable; the key is in `breadcrumb.db`; AI
prompts include raw headers.

**Prevention:** Phase 3 before collectors; Fernet/MultiFernet; key from env →
keyring → 0600 file, never DB; redacted API/UI; replace-only; centralized
redactor at every boundary; no `reveal` for encrypted fields; secret-scan
tests over DB/API/logs/exports; document that the DB is not encrypted at rest.

**Response:** rotate keys/credentials, purge logs/exports, add the missing
redaction test, publish a note.

**Release gate:** no plaintext test secret in DB/API/log/export/AI; key
rotation and key-loss tests pass.

---

### F6 — “SQLite locked, the worker died, the UI froze”

**Scenario:** a long ingest holds a write transaction while parsing a 5 MB
paste; the worker heartbeats on the same connection; the UI blocks on a write;
`database is locked` becomes a 500; the inline worker starves the web loop; a
backup copies a torn WAL state.

**Why it is plausible:** SQLite has one writer; Breadcrumb currently does
multi-stage commits; the plan adds a second writer; a laptop is not a server.

**Early warning:** write transactions include network/parse work; no busy
timeout; no WAL; backup uses `shutil.copy2`; the inline worker runs CPU-heavy
parsing on the event loop.

**Prevention:** WAL + busy timeout + foreign keys; parse outside the write
transaction; short `BEGIN IMMEDIATE` sections; one writer; optional separate
worker; `Connection.backup()`; maintenance mode; run CPU parsing in a thread;
load test with two workers/50 fake jobs.

**Response:** disable inline worker, switch to standalone, restore from the
last good backup, add the missing test.

**Release gate:** two-worker claim/seal test, crash recovery test, backup
during write test, no `database is locked` 500 under the acceptance load.

---

### F7 — “The AI was useless on a 4 GB GPU”

**Scenario:** the default model is a 7B/8B that spills to RAM at 2 tok/s; the
prompt includes 50 findings and 8k tokens; the call times out at 120 s; users
turn AI off. The “local AI analyst” differentiator looks broken.

**Why it is plausible:** current defaults are 8B/12B/14B/30B; 4 GB VRAM is
small; 7B Q4 is 4.68 GB before context/KV cache.

**Early warning:** no hardware smoke test; model list includes models that
cannot fit; prompt budget is unbounded; timeout is 180 s.

**Prevention:** 3B/4B Q4 default, 4k–8k context, top-N prompt, 120 s timeout,
fit badges, graceful fallback, deterministic summaries, no auto-download. Run
the 1650 smoke test before release.

**Response:** lower the default model/context, disable AI by default, keep the
feature as opt-in.

**Release gate:** 20-finding summary completes within 120 s on the 1650; if
not, the default changes.

---

### F8 — “Archived too early; the fallback was gone”

**Scenario:** The Leadline folder is treated as frozen, the importer misses triage state or graph
edges, Breadcrumb has a regression, and the user has no maintained fallback.
The old repo is read-only and its dependencies have drifted.

**Why it is plausible:** the importer is one-way and mapping is lossy
(`is_active`, custom headers, scan statuses, graph depth). Archive feels like
cleanup, not a release gate.

**Early warning:** dry-run counts differ; triage notes missing; graph edges
flattened; no real import test; freeze before Q1/Q9.

**Prevention:** dry-run + real import on a copy; count/sample verification;
source DB read-only; backup; keep the folder runnable; freeze only after
Gate E/F; document rollback.

**Response:** keep it runnable, fix the importer, re-run on a copy.

**Release gate:** import parity report signed; Leadline tagged and runnable;
Breadcrumb parity acceptance passed.

---

### F9 — “A malicious target owned the report”

**Scenario:** a target returns `<script>` in a header/body; the PDF exporter
interprets it as reportlab markup; the HTML report renders raw evidence; a CSV
export contains `=cmd|...` and executes when opened in Excel; a log contains
ANSI escapes/newlines that forge entries.

**Why it is plausible:** scan data is untrusted; reportlab `Paragraph` parses a
small XML dialect; exports are often opened in spreadsheets/browsers.

**Early warning:** no escaping test; HTML uses `|safe`; CSV writes raw values;
logs interpolate target text.

**Prevention:** escape reportlab text (`&`, `<`, `>`); rely on Jinja
autoescape and test it; CSV formula-injection escaping for leading
`= + - @`; strip/control ANSI in logs; cap lengths; no remote images in PDFs;
treat all target content as data.

**Response:** regenerate reports, purge cached exports, add regression tests.

**Release gate:** injection tests for PDF/HTML/CSV/logs pass.

---

### F10 — “Breadcrumb stopped being a notebook”

**Scenario:** the merge adds 12 phases, a worker, secrets, PDF, history, and a
compat API. Breadcrumb becomes a heavier scanner, the UI slows, the schema
grows, and the import-first simplicity that made it distinctive is buried. The
owner uses it less.

**Why it is plausible:** feature accretion is the default outcome of “merge
everything.” Leadline and Breadcrumb have different product centers
(scan-first vs import-first).

**Early warning:** the home page becomes a scan dashboard; imports are harder
to find; startup time grows; the README leads with scanning; new users must
configure scope before importing.

**Prevention:** keep import as the primary path; make scanning a tab/action,
not the home page; preserve one-command ingest; measure startup and import
time; keep the collector optional; do not auto-run scans; keep the “offline
notebook” positioning in the README.

**Response:** split the UI into “Notebook” and “Scans,” or make the executor a
separate optional package/process.

**Release gate:** the original import flow and its tests still pass; home page
still centers the notebook; startup/import benchmarks do not regress.

---

### F11 — “An external tool was the weak link”

**Scenario:** `nmap`/`nuclei` is passed a hostname, resolves it itself, follows
a redirect, or is given a malicious flag via a custom runner. Output is
unbounded; a child process survives cancellation; a tool writes outside its
temp dir.

**Why it is plausible:** external tools are black boxes with their own
resolvers and options; Breadcrumb’s runner catalog accepts custom runners.

**Early warning:** `shell=True`; target interpolated into a string; no version
probe; no output cap; no process group; custom runner flags unvalidated.

**Prevention:** argv-only, allowlisted flags, preflight scope, IP literals
where possible, `start_new_session`, RLIMIT, output caps, temp cwd, no inherited
secrets, strict mode for unpinnable tools, no auto-install.

**Response:** disable the adapter, kill the process group, rotate any exposed
credentials, add a regression test.

**Release gate:** denied target never spawns; shell injection test; cancel
kills the group; output cap enforced.

---

### F12 — “The local API was attacked from the browser”

**Scenario:** a malicious page POSTs to `http://127.0.0.1:8787/jobs` or
`/settings/notify` via a simple form, or uses DNS rebinding to bypass
same-origin. The user’s browser is the vector; no auth is required.

**Why it is plausible:** Breadcrumb is localhost-only with no Host allowlist or
Origin check. Adding an executor makes a forged job actually scan.

**Early warning:** no Host middleware; no Origin check; state-changing GETs;
no CSRF token; CORS `*`.

**Prevention:** Host allowlist, Origin/Referer checks, CSRF tokens for forms,
JSON content-type requirement for API writes, no state-changing GETs, CORS
closed, job rate limits.

**Response:** disable executor, review logs, rotate secrets, patch.

**Release gate:** Host/CSRF tests pass before executor default.

---

## 3. Weakest assumptions

| # | Assumption | Confidence | Evidence | Test that would falsify it | If false |
|---|---|---|---|---|---|
| A1 | Leadline collectors can be ported against a clean contract without importing Leadline’s ORM | Medium | Collectors are async and mostly self-contained, but context/models are coupled | Spike DNS+ports+HTTP with no `app.models` import | Port behavior, not code; extend timeline |
| A2 | SQLite + WAL + one writer is enough for one user | High | Huey/prior art; SQLite 3.45; local workload | 2-worker/50-job load test | Separate worker/Postgres, loses one-file |
| A3 | Scope can be enforced for native HTTP/DNS/TCP | Medium | aiohttp custom resolver, manual redirects | SSRF matrix + rebinding test | No executor; import-only |
| A4 | Scope can be enforced for external tools | Low | Tools resolve themselves; some support `--resolve` | Try nmap/nuclei against a rebinding fixture | Strict mode; drop unpinnable tools |
| A5 | Capability parity satisfies “do not lose functionality” | Medium-low | User wording is ambiguous | Q1 sign-off + acceptance flow | Separate frontend/keep Leadline |
| A6 | One codebase is maintainable by one person | Medium | 8k + 8k LOC; tests | Measure after Phase 4 | Split packages, reduce scope |
| A7 | 9–13 weeks solo | Low | 43–65 dev-days; 12 phases + migration | Re-estimate after Phase 2/4 spike | Cut v1 scope or extend |
| A8 | 3B/4B Q4 is useful enough on 4 GB | Medium | Model sizes; quality unknown | 1650 smoke test | Smaller model/disable AI |
| A9 | Compatibility API is cheap | Medium | Routes translate to models | Contract tests | Drop exact API; document break |
| A10 | Import preserves triage/history semantics | Medium | Mapping is lossy | Dry-run count/sample | Manual export/keep Leadline |
| A11 | Evidence chain can be made linear across processes | High | `BEGIN IMMEDIATE`, unique constraints | Two-process test | Single writer process only |
| A12 | The merge does not dilute Breadcrumb’s import-first identity | Medium | UI/README choices | Acceptance review | Separate “Scans” mode/package |

**The two assumptions to test first:** A1 (port spike) and A3/A4 (scope). If
either fails, the plan’s shape changes more than any schedule slip.

---

## 4. Red-team checklist

### Network and scope

- [ ] Redirect to `http://169.254.169.254/`, `http://[::ffff:169.254.169.254]/`,
      `http://0x7f000001/`, `http://2130706433/`, `http://127.1/`.
- [ ] DNS rebinding: first answer public, second private; short TTL.
- [ ] CNAME to private; multi-A with one private; IPv6-only private.
- [ ] Hostname with trailing dot, IDNA/punycode, mixed case, zone id.
- [ ] URL userinfo (`http://user:pass@host/`), fragment, encoded host.
- [ ] Proxy configured; `HTTP_PROXY`/`ALL_PROXY` env; PAC.
- [ ] External tool resolves hostname itself; tool follows redirects.
- [ ] Port scan of a shared CDN IP (scope is hostname, IP is shared).
- [ ] Scan of a public IP that hosts other tenants; rate/intrusiveness.
- [ ] Redirect to `file://`, `gopher://`, `ftp://`.
- [ ] Cross-origin redirect carries `Authorization`/`Cookie`.
- [ ] TLS certificate mismatch; do not disable verification.
- [ ] DNS failure; do not fall back to literal/other resolver.
- [ ] External lookup receives target data; consent/off switch.

### API and browser

- [ ] `Host: evil.example` against the UI/API.
- [ ] Cross-origin form POST to `/jobs`, `/settings`, `/headers`.
- [ ] Missing/invalid CSRF token.
- [ ] DNS rebinding to localhost.
- [ ] State-changing GET.
- [ ] CORS `*` or credentialed CORS.
- [ ] Job flood/disk fill; rate limit.
- [ ] Oversized JSON/paste; 5 MB boundary.
- [ ] Log injection via newlines/ANSI in target/headers.
- [ ] XSS in entity/finding/evidence rendering; Jinja `|safe`.
- [ ] Open redirect in UI.
- [ ] Notification webhook pointed at internal service (SSRF) / Telegram
      token in plaintext config.
- [ ] AI base URL pointed at internal service; API key storage.

### Evidence and data

- [ ] Two concurrent ingests; same `capture_key`; different content.
- [ ] Delete a middle paste; verify gap.
- [ ] Delete the tail; verify head/length.
- [ ] Restore a backup taken during a write; verify chain.
- [ ] Import a DB with duplicate targets/URLs, naive datetimes, missing
      fields, huge findings.
- [ ] Import twice; no duplicates.
- [ ] CSV formula injection (`=`, `+`, `-`, `@`).
- [ ] PDF `<script>`/`&` injection; enormous evidence; page cap.
- [ ] HTML report raw evidence; Markdown injection.
- [ ] Artifact path traversal/symlink; download `Content-Disposition`.
- [ ] DB/key/backup file permissions.

### Jobs and processes

- [ ] Two workers claim one job.
- [ ] Worker killed mid-write; recovery.
- [ ] Cancel during DNS/port/HTTP/CVE; process group gone.
- [ ] Tool ignores SIGTERM; SIGKILL; orphan check.
- [ ] Tool writes huge output; cap/kill.
- [ ] Tool inherits secret env; verify allowlist.
- [ ] Retry storm; backoff/jitter; max attempts.
- [ ] Clock skew/naive datetime; lease expiry.
- [ ] Maintenance mode during backup; claims paused.
- [ ] Disk full mid-ingest; transaction rollback; clear error.

### AI

- [ ] Prompt injection in target content (“ignore previous instructions”).
- [ ] Secret in evidence; redaction before prompt.
- [ ] Model returns malformed JSON/HTML; strict parse/fallback.
- [ ] Model timeout/500; job unaffected.
- [ ] Oversized prompt; truncation.
- [ ] Model changes triage/scope? It must not.

---

## 5. Critical review of the plan

### 5.1 What the plan gets right

- It puts evidence and scope before execution, not after.
- It treats SQLite as a queue with explicit leases, not a `BackgroundTasks`
  afterthought.
- It separates “collector” from “job” from “evidence,” which is the only way
  the port stays testable.
- It preserves Breadcrumb’s differentiators instead of replacing them with a
  generic scanner.
- It names the hardware constraint and refuses 14B/30B defaults.
- It defines parity as a matrix, not a vibe.
- It keeps a rollback path and a read-only source for migration.

### 5.2 Gaps and corrections

These are additions the plan should absorb before implementation.

1. **Authorization attestation.** Add a per-program “I am authorized to test
   these targets” checkbox with a stored timestamp/note, shown on job creation.
   It is not a legal shield, but it makes the operator’s intent explicit and
   auditable. Required for private-target mode.
2. **Data retention and DB growth.** 5 MB/paste × many scans × 12 phases can
   balloon. Add a retention policy: per-program cap, artifact cleanup, vacuum
   guidance, “keep evidence for N days” option (off by default), and a disk
   space warning. Never silently delete sealed evidence; require explicit
   purge with a chain-repair/gap record.
3. **Job/API rate limits.** A local malicious page or a loop can queue
   thousands of jobs. Add per-minute job creation limits, max queue depth, and
   a UI warning. The executor is a local resource; it still needs a quota.
4. **Versioned collector/evidence schema.** Add `schema_version` to collector
   results and `ScanSnapshot`; document migration of observations. Otherwise a
   future collector change silently reinterprets old evidence.
5. **Timezone/naive datetime handling.** Leadline’s history code has a comment
   about mixed naive/aware SQLite rows. Breadcrumb should normalize UTC on
   write/read and test DST/naive fixtures. Lease comparisons must use one clock
   source.
6. **Shared-IP / CDN port scanning policy.** Scope by hostname does not make a
   port scan of a shared CDN IP safe or meaningful. Default: port scanning is
   allowed only when the target is an IP literal or the program explicitly
   opts into `allow_shared_ip_ports`; otherwise use HTTP/TLS only and record
   the decision. This is both a safety and a data-quality issue.
7. **Notification/AI secret handling.** `breadcrumb.notify.json` stores
   Telegram/webhook tokens in plaintext; `breadcrumb.llm.json` may store an API
   key. Encrypt them with the same key or document them as 0600 local secrets;
   validate webhook schemes and warn on private/loopback webhook URLs (a
   generic webhook is intentionally arbitrary, but it is also an SSRF vector).
8. **CSV/HTML/Markdown injection.** Add formula-injection escaping for CSV,
   rely on Jinja autoescape and test it, and sanitize Markdown/HTML exports.
   This is not in the current plan and is a real report-integrity issue.
9. **Log hygiene.** Strip ANSI/control characters, cap line length, and prevent
   newline injection in job logs/events. A target can otherwise forge log
   entries.
10. **Key management on headless/Linux.** `keyring` may be unavailable or
    locked. The key-file fallback needs a clear warning, 0600 check, and a
    documented backup/restore procedure. Do not silently generate a new key
    when the old one is missing; fail closed for decryption.
11. **Packaging.** Put `aiohttp`, `dnspython`, `cryptography`, `reportlab`, and
    `keyring` behind an optional extra (`breadcrumb[collect]`) or document them
    as required. Breadcrumb’s current 5-line requirements are a feature; do not
    make the import-only path heavy.
12. **Dependency/license check.** Leadline is MIT (checked), compatible with
    Breadcrumb MIT. Keep the copyright notice in ported files. Pin versions and
    test Python 3.12.
13. **Python version.** Leadline’s Docker uses 3.11; Breadcrumb targets 3.12.
    Run the ported tests under 3.12 and fix `asyncio`/typing differences.
14. **CI cost/flakiness.** 41 tests take 30.8 s; ported network tests must be
    mocked and deterministic. Add a `-m "not network"` marker and a separate
    manual lab job. Do not let CI hit the internet.
15. **Compatibility API lifecycle.** Decide now whether it is permanent or
    deprecated. A permanent second API is a maintenance tax; a temporary one
    needs a removal date and a migration guide.
16. **Archive policy.** Archiving disables issues/PRs. If the owner wants to
    report a security issue in the old version, provide a contact in the README.
17. **Incident kill switch.** Add a single env/UI switch that stops all
    network activity and claims, not just “cancel job.” Document it in the
    README and health endpoint.
18. **User education.** A scan can be intrusive and slow. The UI should show
    the target, scope rule, collector set, rate, and estimated requests before
    “Start,” and require confirmation for port scans/CVE lookups.
19. **NVD/CVE terms and rate limits.** Cache, attribute, respect rate limits,
    and never imply a CVE match is a confirmed vulnerability. Keyword fallback
    stays labeled.
20. **External lookup privacy.** crt.sh/ip-api/Spamhaus/WHOIS receive target
    identifiers. The consent screen must list them and the data sent; logs must
    record whether lookups were on.
21. **Test the actual laptop.** CI is not a 4 GB GPU or a slow disk. Run the
    acceptance script on the target hardware, including a 1-hour job, a
    backup, and an import.
22. **Rollback for encrypted headers.** Once plaintext columns are cleared, a
    code rollback cannot read them without the old code + key. Keep a
    documented restore path and do not clear plaintext until the new path has
    passed a release.
23. **Schema migration ordering.** `MIGRATIONS` is a dict, not an ordered
    history. Add `schema_version` and test from multiple old versions, not just
    the latest.
24. **Import conflicts.** Two Leadline targets can normalize to the same
    Breadcrumb target; decide merge vs skip vs suffix, and report it. Do not
    silently drop.
25. **Observability without telemetry.** Local structured logs + `doctor` are
    the only diagnostics. Add a “download diagnostics” bundle that is redacted,
    so the user can report a bug without shipping secrets.
26. **Scope path rules.** Breadcrumb supports path-prefix rules, but network
    scope is host/IP. Define that path rules apply only to HTTP collectors, and
    a port scan needs host/CIDR scope. Test the distinction.
27. **Wildcard scope and CDN.** `*.example.com` may resolve to a shared CDN;
    scope is hostname-based. Record the resolved IP and warn when the IP is
    shared/has many names (reverse DNS), without blocking by default.
28. **No autonomous recursion.** The plan says this; enforce it in code: a
    collector cannot enqueue a job. Only the API/user can. Add a test.
29. **Backup encryption.** The plan says DB not encrypted. Backups contain
    secrets/evidence; recommend age/GPG encryption or full-disk encryption,
    and never write backups world-readable.
30. **Documentation truth.** Do not claim “tamper-proof” or “stealth.” Say
    “tamper-evident” and “traffic shaping.” Leadline’s README already does this
    well; keep it.

### 5.3 Things the plan intentionally leaves out (and why)

- Full-disk encryption/SQLCipher: deployment friction; document instead.
- Multi-user auth/RBAC: not the product; a reverse proxy can add it.
- Distributed workers: SQLite + one laptop; the optional worker is enough.
- Automatic exploitation: out of scope and dangerous.
- Exact React parity: Q1.
- External tool auto-install: supply-chain risk.
- A local NVD mirror in v1: size/complexity; cache + optional API first.
- Autonomous recursion: scope and safety risk.

---

## 6. What would change the recommendation

| If this is true | Then the plan should change |
|---|---|
| Q1 = exact React UI and `/api` behavior | **Not active:** owner chose capability parity (2026-10-29). If it reopens, keep a separate frontend/service; the estimate grows substantially. |
| Q2 = private/any target by default | **Active:** owner chose this (2026-10-29). The guard must still hard-block metadata/link-local; Host/CSRF and the full SSRF matrix become release blockers before the executor is enabled. |
| Multi-user/remote access is required | Add auth, TLS, RBAC, Postgres/queue; the one-file deploy and SQLite queue no longer fit. |
| External tools cannot be pinned and the owner requires them | Strict mode/drop them, or add an egress firewall/container network policy as a hard requirement. |
| SQLite contention fails the load test | Move to Postgres + a real queue; this is a different architecture (Option B). |
| The Leadline port spike imports its ORM/models | Port behavior from scratch or keep Leadline as a service; do not build a compatibility ORM. |
| 3B/4B AI is not useful | Disable AI by default; keep deterministic summaries; revisit with a larger GPU. |
| The owner will not run the acceptance flow | Do not treat the Leadline folder as frozen; parity is unproven. |

---

## 7. Go/no-go gates and tripwires

| Gate | Must be true | If false |
|---|---|---|
| **G0 — Direction** | Q1/Q2 answered (2026-10-29); owner accepts capability parity and the private-target warning | Stop; re-plan |
| **G1 — Safety rails** | Host/CSRF/WAL/chain/backup tests pass | Fix before any executor |
| **G2 — Jobs** | Claim/lease/cancel/recovery/concurrency pass | Do not add collectors |
| **G3 — Scope** | Full SSRF matrix + external-tool denial pass | Do not enable network |
| **G4 — Secrets** | No plaintext in DB/API/log/export/AI; key rotation/loss | Do not use headers |
| **G5 — Port spike** | DNS+ports+HTTP clean against contract, no Leadline ORM | Re-scope or stop |
| **G6 — Evidence** | Concurrent ingest linear; import preserves chain | Do not freeze |
| **G7 — Parity** | Acceptance flow + matrix signed | Do not freeze |
| **G8 — Hardware** | 1650 AI smoke, 1-hour job, backup/import | Adjust defaults |

**Tripwires during execution:**

- Any scope bypass → stop, incident review, add test, re-run gate.
- Any chain fork → stop ingestion, forensic review.
- Port estimate > 1.5× after the spike → cut v1 scope.
- More than 20% of time on compatibility shims → reconsider Option B/C.
- User keeps using Leadline after parity → Q1 was wrong; revisit.
- Secret in a log/export → stop, rotate, fix redaction.
- `database is locked` in acceptance → fix concurrency before release.
- AI smoke > 120 s → lower model/context or disable default.

---

## 8. Pre-mortem status vocabulary

These are **release gates**, not a claim that code is fixed:

| Status | Meaning in this document |
|---|---|
| **Fixed** | A merged change plus a passing test proves it. None yet; no code was changed. |
| **Mitigated** | A concrete design and release gate exist; implementation pending. |
| **Platform limit** | Cannot be fully solved in-app (e.g., external tool resolver, DB-at-rest encryption); documented residual risk + compensating control. |
| **Shelved (owner’s call)** | Deliberately not preserved; recorded in the parity matrix with a decision. |

Current status of the top risks:

| Risk | Status | Gate |
|---|---|---|
| Scope bypass | Mitigated (design) | G3 |
| Chain fork | Mitigated (design) | G1/G6 |
| Port rewrite | Mitigated (spike/timebox) | G5 |
| User rejects parity | Open — owner decision | G0 |
| Secret leak | Mitigated (design) | G4 |
| SQLite contention | Mitigated (design/load test) | G2 |
| AI unusable | Mitigated (defaults/smoke) | G8 |
| Data loss import | Mitigated (dry-run/backup) | G6/G7 |
| Report injection | Mitigated (tests) | G1/G7 |
| External tool bypass | Platform limit + strict mode | G3/G7 |
| DB at rest unencrypted | Platform limit + docs | G4 |

---

## 9. Conclusion

The merge is worth doing, but the plan’s success depends on three sequencing
decisions:

1. **Do not enable the executor until the scope guard and evidence chain are
   proven.** A fast scanner with a weak boundary is worse than an import tool.
2. **Do not port all 12 phases until a 3-collector spike proves the contract.**
   The port is where schedules die.
3. **Do not freeze the Leadline folder until the owner signs the parity matrix and a
   real database imports cleanly.** Archive is the last step, not the first.

If those hold, Breadcrumb becomes the product the user described: a notebook
with memory and evidence that can also collect its own data. If they do not,
the merge produces a heavier scanner and a lighter notebook — the worst of
both.
