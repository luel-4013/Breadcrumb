# Postmortem: the two-product era (and what it means for the merge)

**What this document is.** A postmortem of the *separate Breadcrumb + Leadline
era* and of the research that led to the merge proposal. It is not a claim that
the merge has shipped or failed. No merge code exists. The merge has not
started.

**Implementation update (2026-11-08).** The merge has since been implemented
through Phase 8 and verified on a copy of the real Leadline database; released
as `0.4.0`. The statuses and “pending” notes below describe the planning
snapshot, not the current state. Current status is in `docs/README.md`,
`docs/MERGE_HISTORY.md` and `docs/LEADLINE_PARITY_MATRIX.md`; the importer,
pinned-resolver tests, PDF tests and Q4/Q7/Q8 answers now exist.

**Status vocabulary.** These words are used strictly:

- **Fixed** — code exists and a named passing test proves it. All “Fixed” rows
  below refer to **pre-existing fixes in the current products**, not merge
  work. No merge issue can be “Fixed” yet.
- **Mitigated** — a concrete design and a release gate exist; implementation
  is pending. This is the default status for merge issues in this document.
- **Platform limit** — cannot be fully solved inside a local Python app
  (e.g., external tools resolving names themselves, DB-at-rest encryption);
  documented with a compensating control.
- **Shelved (owner’s call)** — deliberately not preserved or postponed; it is
  visible in the parity matrix, not silently dropped.

**Read with:** `LEADLINE_MERGE_PLAN.md` (the proposal),
`LEADLINE_PARITY_MATRIX.md` (the functionality contract), and
`LEADLINE_MERGE_PRE_MORTEM.md` (the failure rehearsal). This document is the
autopsy of why the two-product arrangement needed to end.

**Decision update (2026-10-29).** The owner answered the gating questions:
Q1 = capability parity while keeping Breadcrumb’s current UI and adding
scanning as a feature; Q2 = private/public targets allowed with a global
warning (metadata/link-local hard-blocked); Q3 = keep the local Leadline
folder, no automatic archive; Q6 = external lookups on by default with visible
failures and retry; Q9 = one-way importer; Q10 = history/reports/UI first.
Q4 (inline vs worker), Q7 (no login) and Q8 (PDF) were subsequently answered
on 2026-11-03 and recorded in the parity matrix. The rows below that say
“Q1 unanswered” or “archive” describe the pre-decision state; the sign-off
block in `LEADLINE_PARITY_MATRIX.md` is authoritative.

---

## 1. Executive summary

Breadcrumb and Leadline did not fail because either was badly built. They
failed as a **pair**: each held half of the workflow, and the boundary between
them was where trust, scope, and evidence leaked.

- Breadcrumb had the system of record — programs, scope attribution, sealed
  captures, a cross-program ledger, parsers, reports — but no executor. Its
  job UI ended with “No executor connected yet.”
- Leadline had the execution — 12 phases, history, diffs, PDF, triage — but no
  scope enforcement, no evidence chain, and a second database and UI.
- The user had to move output between them by hand, which meant the evidence
  guarantee stopped at the exact moment a scan produced something worth
  keeping.

The merge proposal is the repair: **Breadcrumb becomes the flagship and the
only system of record; Leadline’s collectors and history/report behavior are
absorbed; the Leadline repository is retained as a read-only artifact after
parity and data migration are proven.**

The research also found that the hard part is **not** porting collectors. The
hard parts are:

1. enforcing scope at the socket, not the UI;
2. making the evidence chain linear under two writers;
3. keeping header/proxy secrets out of a local database, logs, exports, and AI
   prompts;
4. importing existing Leadline history without lying about it;
5. agreeing with the owner on what “do not lose functionality” means.

Collectors are the visible work. These five are the work that decides whether
the merge is trustworthy.

**Verdict: conditional go.** Approve Phase 0–2, run a three-collector spike,
get Q1/Q2 answered, and do not archive Leadline until the parity matrix and a
real data import pass.

---

## 2. Timeline of the two-product era

| When | What happened | Consequence |
|---|---|---|
| Early Breadcrumb | Import-first notebook: paste nmap/httpx/nuclei output, get entities/findings/graph/reports | Strong memory/evidence, no execution |
| Early Leadline | Scan-first recon workspace: 12 phases, target history, PDF, triage | Strong execution, no scope/evidence |
| Breadcrumb job seam | `ScanJob` + runner catalog + job UI, but no worker | A promise with no delivery |
| Leadline v0.2.0 | Full pipeline, history, reports, 41 tests | A complete scanner with a separate DB/UI |
| User request | “Make Breadcrumb the flagship; Leadline the executor; do not lose functionality” | The merge question becomes a product decision |
| 2026-10-27 | Deep inspection: both codebases, tests, schemas, security posture | Baselines: 62 + 41 passing |
| 2026-10-27/28 | Research: SSRF, DNS pinning, Fernet/keyring, aiohttp resolvers, SQLite WAL/queue, subprocess isolation, model sizes, competitors | The plan’s safety/evidence design |
| 2026-10-28/29 | Documents: plan, parity matrix, pre-mortem, this postmortem | No code changed |

The era did not end with a crash. It ended with a realization: the user was
running two half-products and manually gluing them together.

---

## 3. The death certificate

*Causes are listed in the order they would actually kill trust, not in the
order they appear in the code.*

### 3.1 Split-brain system of record `Mitigated`

**Mechanism.** Two databases, two target models, two triage vocabularies, two
UIs. A scan lives in `leadline.db`; the report/ledger lives in
`breadcrumb.db`. The user is the integration layer. Every manual copy is a
chance to lose provenance, and the cross-program memory never sees the scan
that just ran.

**Evidence found.** Leadline has its own `Target`/`Scan`/`ScanEvent`/`Finding`/
`GraphNode` tables and React UI. Breadcrumb has `Program`/`Target`/`Paste`/
`Entity`/`Finding`/`Graph` and a Jinja UI. Both bind to localhost; both have
their own job/scan models. Nothing in either repo imports the other.

**Repair site.** Option A monorepo absorption: one SQLite DB, one evidence
chain, one UI, optional worker. Leadline’s data is imported one-way.

**Status.** `Mitigated` — design + Phase 8 importer; not implemented.

**Gate.** G0 (owner accepts parity definition) and G7 (acceptance flow).

---

### 3.2 The executor promise with no executor `Mitigated`

**Mechanism.** Breadcrumb’s runner catalog and job UI imply that queuing a job
does something. It does not. `POST /api/v1/jobs` returns a 202 and a message:
“No executor connected yet — POST output to /api/v1/pastes, then update
status.” A user who queues a scan and walks away gets nothing. The product’s
most visible promise is the emptiest.

**Evidence found.** Confirmed in the job API and `ScanJob` model. The model has
only `id, program_id, runner, target, status, header_profile_id, log,
created_at, started_at, finished_at` — no attempts, lease, heartbeat, cancel
flag, output link, or evidence metadata. The `test_job_control_flow` test
covers CRUD, not execution.

**Repair site.** Phase 1: `ScanJob` extension, `JobAttempt`, `ScanPhase`,
`JobEvent`, atomic claim, lease/heartbeat, retry, cancel, recovery, worker
loop. Phase 4: real collectors.

**Status.** `Mitigated` — design; no code changed.

**Gate.** G2 (claim/lease/cancel/recovery/concurrency).

---

### 3.3 Leadline’s intentional “any target” stance `Mitigated` for native, `Platform limit` for external tools

**Mechanism.** Leadline’s README and `THREAT_MODEL.md` say it intentionally
does not block private, internal, or loopback targets. That is reasonable for
a single operator pointing it at a lab. It is not reasonable once an executor
can be driven by a web page, a discovered link, or a target’s redirect. An
unscoped scanner on localhost is an SSRF engine with a nice UI.

**Evidence found.** Leadline has `ALLOWED_HOSTS` (DNS-rebinding defense) but no
target scope guard. Its collectors use raw `aiohttp`/sockets and follow
redirects. Breadcrumb has scope **attribution** (CIDR/wildcard/negation/path
rules) but no enforcement before a connection.

**Repair site.** Phase 2: `ScopeGuard`, scoped resolver, pinned connector,
manual redirects, lab CIDRs, metadata denylist, evidence decision record.
External tools are a `Platform limit`: they resolve names themselves; mitigate
with preflight, IP literals, supported resolve overrides, process isolation,
and strict mode.

**Status.** `Mitigated` for native HTTP/DNS/TCP; `Platform limit` for
unpinnable external tools (documented residual risk + strict mode).

**Gate.** G3 (full SSRF matrix, including rebinding, CNAME, IPv6-mapped,
multi-A, redirect-to-metadata, proxy, and tool denial).

---

### 3.4 The evidence chain was not concurrency-safe `Mitigated`

**Mechanism.** Breadcrumb seals a paste by reading the latest hash, computing
the next chain hash, and inserting. That is correct with one writer and a
single transaction. Add a worker ingesting output while the web UI ingests a
paste, and both can read the same “latest” row. The result is a fork: two
children of one parent, or a chain that verifies only if you follow one branch.
The differentiator — tamper evidence — becomes a liability.

**Evidence found.** `Paste` has `content_sha256`, `chain_hash`,
`prev_paste_id`; `tests/test_unique.py` proves sealing and tamper detection in
the single-writer case (`test_captures_are_sealed_and_verify_clean`,
`test_tampering_breaks_the_chain`). `db.py` sets no WAL, busy timeout, or
chain-head row. There is no unique constraint on `prev_paste_id` and no
concurrency test.

**Repair site.** Phase 0: `EvidenceChain` head, `UNIQUE(prev_paste_id)`,
`UNIQUE(chain_seq)`, `BEGIN IMMEDIATE`, `capture_key` idempotency, legacy
backfill, verify head/length/tail, two-process test.

**Status.** `Mitigated` — design; the single-writer behavior is `Fixed` in the
current product, the multi-writer case is not.

**Gate.** G1 (chain/concurrency) and G6 (import preserves chain).

---

### 3.5 Header profiles and proxy credentials were plaintext `Mitigated`

**Mechanism.** `HeaderProfile.headers` and `proxy` are stored as plain JSON.
The API returns full headers and curl flags. A header profile can contain
`Authorization`, `Cookie`, `X-Api-Key`, or proxy credentials. Logs, job
output, exports, backups, and AI prompts can echo them. “Local-only” is not a
security boundary once a report leaves the machine or a screenshot is taken.

**Evidence found.** `models.py` shows plaintext columns; the header profile
route returns them; `test_header_profile_proxy_and_curl` exercises the proxy
and curl flags. Breadcrumb masks secrets in exports (`test_exports_and_masking`),
but that is a display filter, not encryption.

**Repair site.** Phase 3: Fernet/MultiFernet encryption, env → keyring → 0600
key file, redacted API/UI, replace-only values, centralized redaction, secret
scan tests, key rotation/loss tests. Also encrypt notification/AI config
secrets and document DB-at-rest encryption as the operator’s responsibility.

**Status.** `Mitigated` — design; not implemented.

**Gate.** G4 (no plaintext test secret in DB/API/log/export/AI; rotation/loss
tests).

---

### 3.6 Backup was unsafe once a worker existed `Mitigated`

**Mechanism.** Breadcrumb’s backup copies the live SQLite file and calls
`engine.dispose()`. With WAL and a worker, a file copy can capture a torn
state: a valid-looking DB with a missing WAL frame or an inconsistent chain.
Restore can then destroy the evidence it was meant to protect. The same
pattern applies to migrations: a pre-migration copy is better than nothing,
but it is not a guaranteed point-in-time backup under concurrent writes.

**Evidence found.** `app/db.py` uses `shutil.copy2` before migration;
`app/main.py` has backup/restore routes; `test_backup_download` covers the
happy path. No WAL, no `Connection.backup()`, no integrity check, no
maintenance mode.

**Repair site.** Phase 0: maintenance mode, `sqlite3.Connection.backup()`,
`PRAGMA integrity_check`, atomic rename, restore verification, refuse corrupt
files, test backup during a write.

**Status.** `Mitigated` — design; not implemented.

**Gate.** G1 (backup/restore during write; corrupt restore refused).

---

### 3.7 The local API trusted the browser `Mitigated`

**Mechanism.** Breadcrumb binds to localhost and has no auth. That is fine for
a notebook. Add an executor and a malicious web page can attempt a simple form
POST to `http://127.0.0.1:8787/jobs`, or use DNS rebinding to make its own
hostname resolve to loopback and reach the API as a same-origin service. A
forged job would actually scan. The browser is the threat model, not a remote
attacker.

**Evidence found.** Breadcrumb has no Host allowlist middleware and no
Origin/CSRF checks. Leadline **does** have `HostAllowListMiddleware` and
`test_host_allow_list_rejects_unknown_host` /
`test_host_allow_list_accepts_loopback` — proof that the defense is practical
and testable. Breadcrumb’s absence is the gap.

**Repair site.** Phase 0: Host allowlist, Origin/Referer checks, CSRF token for
forms, JSON content-type requirement, no state-changing GETs, closed CORS, job
rate limits.

**Status.** `Mitigated` — design; not implemented in Breadcrumb. (The Host
allowlist is `Fixed` in Leadline, with the two named tests, but that does not
protect Breadcrumb.)

**Gate.** G1.

---

### 3.8 Feature asymmetry forced the user to be the glue `Mitigated`

**Mechanism.** Neither product is complete alone:

- Breadcrumb has the ledger, evidence, parsers, reports/exports, notifications,
  CLI, and a graph, but no native scan, no per-target history/diff, and no PDF.
- Leadline has the 12 phases, target history/diff, risk score, triage, and
  PDF, but no ledger, no evidence chain, no parser ecosystem, and no
  cross-program memory.

The user has to choose which half to use for each task, then copy data across.
This is not a feature gap; it is a product-boundary gap.

**Evidence found.** The parity matrix has 210 rows. Most need additions;
Breadcrumb already covers the notebook/evidence half; a smaller set are
compatibility or owner decisions; two headline items (the React SPA and the
separate service/DB) are intentionally not ported. The gaps cluster exactly
where the products split: execution, history/diff, PDF, and triage vocabulary.

**Repair site.** Phases 1–7: executor, collectors, snapshots/diff, PDF, triage
mapping, compatibility API, UI additions.

**Status.** `Mitigated` — plan + matrix; not implemented.

**Gate.** G7 (parity acceptance flow).

---

### 3.9 Job execution was fragile by design `Mitigated`

**Mechanism.** Leadline runs scans in FastAPI `BackgroundTasks`. There is no
queue, no lease, no heartbeat, no retry, no resume. On startup, `running` and
`stopping` scans are marked failed. A restart during a long scan loses the
work. Breadcrumb has a job table but no runner. Neither side has durable
execution.

**Evidence found.** Leadline’s pipeline polls `stopping` between phases; its
startup recovery marks interrupted scans failed. Breadcrumb’s `ScanJob` has no
attempt/lease fields. Existing tests cover job CRUD, not execution.

**Repair site.** Phase 1: atomic claim, lease, heartbeat, retry/backoff,
cancellation, crash recovery, attempt/phase records, idempotent output linking.

**Status.** `Mitigated` — design; not implemented.

**Gate.** G2.

---

### 3.10 The local AI defaults did not fit the hardware `Mitigated`

**Mechanism.** Breadcrumb suggests `qwen3-8b`, `deepseek-r1-distill-14b`,
`qwen3-coder-30b-a3b`, and `gemma-3-12b`. On a 4 GB GTX 1650, these either
fail to load, spill heavily to system RAM, or run at unusable speed. The
“local AI analyst” becomes a timeout, not a feature. The user’s hardware is
not a niche; it is the stated target.

**Evidence found.** Model file sizes: Qwen2.5-3B-Instruct Q4_K_M ~2.1 GB;
Qwen3-4B-Instruct-2507 Q4_K_M ~2.5 GB; Qwen2.5-7B-Instruct Q4_K_M ~4.68 GB
(does not fit 4 GB before context/KV cache). Current defaults are 8B+.

**Repair site.** Plan §13 plus Phase 8 hardening: 3B/4B Q4 default, 4k–8k
context, top-N prompt, 120 s timeout, fit badges, graceful fallback, hardware
smoke test.

**Status.** `Mitigated` — design; not implemented.

**Gate.** G8 (1650 smoke test; 20-finding summary within 120 s).

---

### 3.11 Product identity was split between “notebook” and “autonomous scanner” `Shelved (owner’s call)`

**Mechanism.** Breadcrumb’s README says “offline-first recon notebook,”
“import-first,” “deterministic before AI.” Leadline’s README says “attack
surface mapper,” “12-phase pipeline,” and explicitly “not autonomous.” The
merge could drift into “Breadcrumb is now a scanner,” burying the import-first
identity that makes it different from reNgine/BBOT.

**Evidence found.** The two READMEs describe different product centers. The
user’s stated direction (“Breadcrumb flagship, Leadline executor”) resolves
the hierarchy but not the home-page identity. The plan keeps import as the
primary path and scanning as an action; that is a recommendation, not a
decision.

**Repair site.** README/UI positioning; keep the notebook as the home page,
scanning as a tab/action, no auto-scan, no “autonomous” branding. The
parity matrix records this as an owner decision.

**Status.** `Resolved (2026-10-29)` — the owner chose capability parity:
Breadcrumb’s current pages stay, and scanning is an added feature rather than
a replacement home page.

**Gate.** G0/G7 (owner sign-off).

---

### 3.12 The HTTP fingerprinting bug that would have shipped `Mitigated`

**Mechanism.** Leadline’s `http_fingerprinting.py` can return an unbound
`truncated` if the GET request fails: the variable is assigned inside a branch
but referenced outside it. A failed request can raise `UnboundLocalError`,
turning a clean “no response” into a phase crash. It is a portability bug, not
a design flaw, but it is exactly the kind of thing a copy-paste port carries
forward.

**Evidence found.** Source inspection; no test covers the GET-fails path.

**Repair site.** Phase 4: initialize `truncated = False` before the branch;
add a regression test with a failing GET.

**Status.** `Mitigated` — identified; fix + test planned. Not fixed today.

**Gate.** G5 (port spike).

---

## 4. The fix ledger

Every row names the repair site and the proof required. “Status” is about the
merge, not the pre-existing product.

| # | Cause | Repair site | Proof required | Status |
|---|---|---|---|---|
| 1 | Split-brain system of record | One DB, one UI, importer | Acceptance flow + import counts | **Mitigated** |
| 2 | Executor promise with no executor | Job model + worker | Claim/lease/cancel/recovery tests | **Mitigated** |
| 3 | No scope enforcement | `ScopeGuard` + pinned networking | Full SSRF matrix | **Mitigated** (native), **Platform limit** (external tools) |
| 4 | Evidence chain race | Chain head + unique constraints + `BEGIN IMMEDIATE` | Two-process ingest test | **Mitigated** |
| 5 | Plaintext secrets | Fernet/keyring + redaction | Secret-scan + rotation/loss tests | **Mitigated** |
| 6 | Unsafe backup | `Connection.backup()` + integrity check | Backup-during-write + corrupt-restore tests | **Mitigated** |
| 7 | Browser-facing local API | Host/Origin/CSRF + rate limits | Host/CSRF tests | **Mitigated** |
| 8 | Feature asymmetry | Executor, history/diff, PDF, triage, compat | Parity acceptance flow | **Mitigated** |
| 9 | Fragile job execution | Durable queue/worker | Crash/cancel/concurrency tests | **Mitigated** |
| 10 | AI defaults too large | 3B/4B Q4 + context cap | 1650 smoke test | **Mitigated** |
| 11 | Product identity split | Notebook-first UI/README | Owner sign-off | **Shelved (owner’s call)** |
| 12 | HTTP `truncated` bug | Initialize + regression test | Failing-GET test | **Mitigated** |

No row is **Fixed** for the merge. That is the honest state: this is a plan,
not a repair.

---

## 5. What is actually fixed today (pre-existing, with named tests)

These are real, but they belong to the current products. They are the
foundation the merge builds on — not evidence that the merge is done.

| Capability | Product | Test that proves it |
|---|---|---|
| Host header allowlist (DNS-rebinding defense) | Leadline | `test_host_allow_list_rejects_unknown_host`, `test_host_allow_list_accepts_loopback` |
| CVE risk excludes unverified keyword matches | Leadline | `test_unverified_cve_is_excluded_from_risk` |
| Verified CPE/version-range CVE affects risk | Leadline | `test_verified_cpe_cve_is_included_in_risk` |
| Target-based export filenames, path characters rejected | Leadline | `test_export_filename_uses_target_host_and_scan_id`, `test_export_filename_rejects_path_characters` |
| History diff + triage | Leadline | `test_history_diff_and_triage` |
| Full 12-phase pipeline against a controlled target | Leadline | `test_full_recon_pipeline` |
| Single-writer evidence sealing + tamper detection | Breadcrumb | `test_captures_are_sealed_and_verify_clean`, `test_tampering_breaks_the_chain` |
| Parser failures reported, not fatal | Breadcrumb | `test_faulty_parser_is_reported_not_fatal` |
| Export secret masking | Breadcrumb | `test_exports_and_masking` |
| Scope attribution (CIDR/wildcard/path/negation) | Breadcrumb | `test_path_scope_rules`, `test_path_scope_in_ui` |
| Dedup/re-import stability and cross-program ledger | Breadcrumb | `test_reimport_same_report_is_stable`, `test_cross_program_memory_flags_repeat_assets` |
| Job CRUD/cancel/retry UI state | Breadcrumb | `test_job_control_flow` |
| Backup download (import-only, single writer) | Breadcrumb | `test_backup_download` |

**Caveat:** “Fixed” here means “the named test proves the current behavior.”
It does not mean the behavior is sufficient for the merge. For example, the
single-writer chain test does not prove concurrent sealing, and the backup
download test does not prove a backup during a WAL write.

---

## 6. What can still kill the merge

Residual risks, with honest status and a watch-file. These are the rows to
reopen if the signal appears.

| # | Risk | Status | Watch-file signal |
|---|---|---|---|
| 1 | Owner means “exact React UI/API,” not capability parity | **Resolved (2026-10-29)** | Owner chose capability parity; a later React-page request would reopen it |
| 2 | Scope bypass via redirect/rebinding/proxy | **Mitigated** (G3) | Any SSRF test failure; a collector uses raw `aiohttp` |
| 3 | Scope bypass via external tool resolver | **Platform limit** (strict mode) | Tool accepts hostname; no `--resolve`; preflight only |
| 4 | Evidence chain fork under two writers | **Mitigated** (G1/G6) | `verify` shows two children; `database is locked`; no concurrency test |
| 5 | Secret leak via headers/logs/exports/AI | **Mitigated** (G4) | Plaintext secret in DB/log/export; `reveal=1` bypass |
| 6 | SQLite contention/worker starvation | **Mitigated** (G2) | Long write transactions; 500 on lock; inline worker blocks UI |
| 7 | Port becomes a rewrite | **Mitigated** (spike) | Compatibility shims > collectors; Leadline ORM imports |
| 8 | Data import loses triage/history | **Mitigated** (G6/G7) | Dry-run count mismatch; missing notes/edges |
| 9 | Report/PDF/CSV injection | **Mitigated** (G1/G7) | Unescaped `<script>`; CSV formula execution |
| 10 | AI unusable on 4 GB | **Mitigated** (G8) | Smoke > 120 s; 7B default; context > 8k |
| 11 | Archive too early | **Not applicable** | Owner keeps the folder; no automatic archive/delete |
| 12 | DB at rest unencrypted | **Platform limit** | Full-disk encryption absent; backup unencrypted |
| 13 | Local no-auth model | **Shelved (owner’s call)** | Remote access requested; reverse proxy without auth |
| 14 | External tool supply chain | **Platform limit** | Unknown binary; auto-install; `shell=True` |
| 15 | Legal/authorization ambiguity | **Shelved (owner’s call)** | Lab mode on; no authorization note; private targets |
| 16 | Retention/DB growth | **Mitigated** (plan gap) | DB size grows without policy; disk full |
| 17 | NVD/CVE false confidence | **Mitigated** | Keyword hit unlabeled; risk includes unverified CVE |
| 18 | Notification/AI config secrets | **Mitigated** (plan gap) | Plaintext tokens in `breadcrumb.notify.json`/`breadcrumb.llm.json` |
| 19 | User never runs acceptance | **Shelved (owner’s call)** | Parity matrix unsigned; no real import test |
| 20 | Schedule slips past tolerance | **Open** | Phase 4 estimate > 1.5×; repeated scope cuts |

**The two risks most likely to be underestimated:** #2 (scope is never “done”;
it is a test matrix that must stay green) and #7 (the port’s hidden coupling).
Both have explicit gate/spike responses.

---

## 7. What the research changed our mind about

These are corrections to assumptions made before reading the code and sources.
They matter because they change the plan.

| # | Earlier assumption | What was found | Consequence |
|---|---|---|---|
| 1 | Leadline CVE matching is keyword-only | It already resolves CPEs and matches NVD version ranges, with labeled keyword fallback | Preserve it; do not rewrite from scratch; add offline cache/key support |
| 2 | Leadline is a thin scanner | 12 phases, TLS/banner inspection, history/diff, PDF, triage, 8k LOC + React UI | The port is a real absorption, not a weekend copy |
| 3 | Breadcrumb’s job UI means execution exists | The API explicitly says no executor; `ScanJob` is shallow | Phase 1 is a build, not a wiring task |
| 4 | SQLite is too weak for a queue | WAL + `BEGIN IMMEDIATE` + `RETURNING` + leases is viable for one user; Huey/prior art confirms | Keep one-file deploy; add concurrency tests |
| 5 | The hard part is porting collectors | The hard parts are scope, evidence concurrency, secrets, migration, and parity definition | Reorder phases: safety/evidence first, secrets before collectors |
| 6 | “Do not lose functionality” can be satisfied by keeping the code | The user’s UI/DB/reports/graph are product surface, not just code | Parity matrix + compatibility API + importer; Q1 decision |
| 7 | Leadline’s no-scope stance is an oversight | It is explicit and documented for lab use | Replace the default, preserve the capability via lab mode; do not shame the design |
| 8 | The current LLM defaults are usable | 8B/12B/14B/30B do not fit 4 GB VRAM | 3B/4B Q4 default; hardware smoke gate |
| 9 | Leadline jobs can resume after restart | Startup marks running/stopping failed | Add lease recovery; do not copy the failure behavior |
| 10 | Official SQLite/OWASP docs are the primary source | Several pages timed out from this network | Verify locally (SQLite 3.45.3), use Python docs/SQLite repo/Huey, record the limitation |
| 11 | A single large doc write is fine | It exceeded the output limit and produced nothing | Write in chunks; verify markers/length after each |
| 12 | The merge is a code task | It is a product-boundary task with a code component | Lead with parity/owner decisions, then code |

---

## 8. Postmortem of the planning process itself

### 8.1 What went well

- Both repos were read at the source level, not just READMEs.
- Both test suites were run and baselines recorded (`62 passed` / `41 passed`).
- The core seams were found: `ScanJob` emptiness, `_ingest` in `main.py`,
  chain sealing, plaintext headers, unsafe backup, missing Host/CSRF, Leadline
  scope stance, `BackgroundTasks`, startup failure recovery.
- Primary sources were used for SSRF, Fernet/keyring, aiohttp resolvers, SQLite
  WAL/queue, subprocess isolation, model sizes, and competitor patterns.
- The plan was red-teamed before code; the parity matrix makes “no
  functionality loss” testable.
- No code, schema, commit, push, or merge change was made. The working trees
  remained clean.

### 8.2 What went wrong

| # | Problem | Impact | Status | Fix |
|---|---|---|---|---|
| 1 | First `LEADLINE_MERGE_PLAN.md` write exceeded the output limit | No file was created; time lost | **Mitigated** | Split into sections, verify markers/length after each write |
| 2 | Official SQLite docs (`sqlite.org/wal.html`, `lang_transaction.html`, `lang_returning.html`) timed out | Could not cite the canonical pages | **Platform limit** | Verified behavior on local SQLite 3.45.3; used Python `sqlite3` docs, SQLite repo notes, Huey prior art |
| 3 | OWASP SSRF page timed out on a final pass | One citation unavailable | **Platform limit** | Used earlier review + primary guidance; note limitation |
| 4 | No code spike / no real Leadline import / no 1650 benchmark | Port and hardware assumptions unproven | **Shelved (owner’s call)** until approval | Phase 2/4 spike; Phase 8 import; Phase 8 hardware smoke |
| 5 | Q1–Q10 unanswered | Plan uses recommended defaults; product scope ambiguous | **Partially resolved** | Q1/Q2/Q3/Q6/Q9/Q10 recorded; Q4/Q7/Q8 still pending |
| 6 | Initial “port is straightforward” assumption | Would have underestimated coupling | **Fixed in understanding** | Contract-first port; 3-collector spike |
| 7 | Initial “CVE is keyword-only” assumption | Would have discarded good logic | **Fixed in understanding** | Preserve CPE/version-range path |
| 8 | No line-by-line audit of all 8k Leadline LOC | Some phase-specific bugs may remain | **Open** | Read each phase during port; add failing-path tests |
| 9 | No actual pinned-resolver/rebinding test | Scope design is not yet proven | **Open** | Phase 2 SSRF matrix |
| 10 | No performance/concurrency benchmark on the laptop | SQLite/worker assumptions unproven | **Open** | Phase 1/2 load test; Phase 8 acceptance |
| 11 | No Windows/macOS keyring test | Key management may be Linux-only in practice | **Platform limit** | Document Linux-first; test key-file fallback |
| 12 | No reportlab-on-3.12 test | PDF port may hit dependency issues | **Open** | Phase 6 spike |
| 13 | Competitor research took time | Delayed docs; but justified the positioning | **Shelved (owner’s call)** | Keep as appendix; do not expand further |

### 8.3 What would have changed the outcome

If the two products had been designed together from the start:

1. **One scope model** would have existed before the first scan.
2. **One evidence chain** would have existed before the first report.
3. **One job model** with leases would have existed before the first long scan.
4. **One target/triage vocabulary** would have avoided the compatibility layer.
5. **One UI** would have avoided the React/Jinja split.
6. **Secrets encryption** would have shipped with header profiles, not after.
7. **A parity matrix** would have been written before “merge” was proposed.

The merge is paying for those boundaries now. That is cheaper than paying for
them forever, but it is not free.

---

## 9. Lessons for the merge

1. **Two products create two truths.** Merge the system of record first; the
   code can follow.
2. **Scope is a socket-level property.** A UI checkbox or a preflight URL check
   is not enforcement.
3. **Evidence is a concurrency problem.** A hash function is the easy part; a
   linear chain under two writers is the hard part.
4. **“Do not lose functionality” needs a matrix and a signature.** Capability
   parity is a product decision, not an engineering assumption.
5. **The port is the easy part.** Scope, secrets, migration, and parity are
   where the schedule goes.
6. **Encrypt secrets before collectors use them.** Retrofitting encryption
   after logs/exports/AI have seen plaintext is too late.
7. **AI is garnish; deterministic facts are the meal.** A 3B model that
   summarizes 20 findings is useful; a 14B model that times out is not.
8. **Archive is a release gate, not cleanup.** Keep the fallback until parity
   and import are proven.
9. **Tests are the only credible “fixed.”** A design document is a mitigation,
   not a repair.
10. **Write big documents in chunks.** A failed write is a silent no-op; verify
    the file after every chunk.
11. **Verify claims locally when the canonical docs are unreachable.** Record
    the limitation instead of pretending.
12. **Do not confuse capability parity with code parity.** The user wants the
    workflow, not necessarily the React components.

---

## 10. Glossary

- **Breadcrumb** — the flagship import-first recon notebook and system of
  record.
- **Leadline** — the scan-first recon workspace whose collectors/history are
  absorbed.
- **Program** — Breadcrumb’s scope container; owns targets and rules.
- **Target** — a host/URL/CIDR inside a program.
- **Scope guard** — the fail-closed function that decides whether a network
  action is allowed, before it happens.
- **SSRF** — server-side request forgery; making the app connect somewhere it
  should not.
- **DNS rebinding** — a hostname resolves to a public IP for the check, then a
  private IP for the connection; defeated by resolving once and pinning.
- **Pinned resolver** — a resolver/connector that returns only the validated
  IPs for a host and refuses to re-resolve at connect time.
- **Hash chain** — each capture’s hash includes the previous capture’s hash;
  altering or deleting one breaks the chain.
- **Paste/capture** — Breadcrumb’s sealed raw evidence row.
- **Lease** — a time-bounded claim on a job by a worker; expires if the worker
  dies.
- **Heartbeat** — periodic proof that a worker is still alive and owns the
  lease.
- **WAL** — SQLite write-ahead logging; readers do not block the writer, but
  there is still one writer.
- **Lab mode** — explicit program permission for private/loopback ranges;
  off by default.
- **Parity matrix** — the row-by-row contract mapping every Leadline
  capability to Breadcrumb.
- **Compatibility API** — a translation layer that preserves Leadline’s HTTP
  shapes.
- **CPE** — Common Platform Enumeration; a structured product identifier used
  for CVE matching.
- **NVD** — National Vulnerability Database; source of CVE/CPE data.
- **CVE** — a publicly disclosed vulnerability identifier; a match is a
  correlation, not a confirmed exploit.
- **Collector** — a unit of recon that produces evidence + observations.
- **Observation** — a typed entity/relationship/finding produced by a
  collector.
- **Snapshot** — a materialized history record for one job.
- **Pre-mortem** — imagining the failure before it happens.
- **Postmortem** — reconstructing the failure after it happens; here, the
  failure of the separate-product era.
- **Platform limit** — something the app cannot fully solve (external tool
  resolvers, DB-at-rest encryption).
- **Shelved (owner’s call)** — a visible, deliberate postponement.

---

## 11. Closing

What is true now that was not true before:

- The two-product era has a name and a diagnosis: **split system of record,
  split scope, split evidence**.
- The merge is no longer a vague “combine them” idea; it has a target
  architecture, a job state machine, a scope design, an evidence transaction, a
  secrets plan, a parity matrix, and release gates.
- The weakest assumptions are written down: exact-UI parity, external-tool
  pinning, the port spike, SQLite contention, and 4 GB AI.
- The parts that are already good are documented with named tests, so the merge
  does not “fix” what is not broken.
- No code was changed, which means the user still has a clean rollback and a
  clean decision point.

The next death should be of something new — not of two products that each held
half of the same truth.
