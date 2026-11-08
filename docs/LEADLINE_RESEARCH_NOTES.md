# Research notes: scope, evidence, execution, hardware, and competition

**Status:** research record for `LEADLINE_MERGE_PLAN.md`. No implementation.
**Date:** 2026-10-27 to 2026-10-29.
**Question:** should Breadcrumb absorb Leadline’s execution layer, and if so,
what design makes that safe on a single-user laptop?

These notes record what was read, what was verified locally, what was inferred,
and what could not be reached. They are deliberately separate from the plan so
the plan can be read as a proposal and this file can be checked as evidence.

---

## 1. Method

1. Read both repositories at source level, not just READMEs:
   - Breadcrumb: `app/main.py`, `models.py`, `db.py`, `scope.py`,
     `attribution.py`, `runners.py`, `pipeline.py`, `notify.py`, `llm.py`,
     `ai.py`, parsers, reports, tests.
   - Leadline: models, DB, config, API routers, pipeline, all 12 recon phases,
     history, risk, reporting, PDF, threat model, README, tests.
2. Run both test suites and record exact baselines.
3. Verify SQLite behavior locally (version, `RETURNING`, `BEGIN IMMEDIATE`,
   backup API) instead of trusting memory.
4. Read primary sources for the risky mechanisms: SSRF/scope, DNS pinning,
   SQLite WAL/queueing, Fernet/keyring, aiohttp resolvers, subprocess
   isolation, model sizes.
5. Read competitor documentation to test the product positioning, not to copy
   features.
6. Record failures/timeouts and the alternative used.

---

## 2. Baselines (measured)

| Check | Command | Result |
|---|---|---|
| Breadcrumb tests | `.venv/bin/python -m pytest -q` | `62 passed, 1 warning in 2.21s` (re-run after docs; initial 1.91s) |
| Leadline tests | `/tmp/opencode/leadline-venv/bin/python -m pytest -q` | `41 passed, 7 warnings in 29.96s` (initial 30.80s) |
| SQLite version | local Python `sqlite3.sqlite_version` | `3.45.3` |
| Breadcrumb stack | source | FastAPI, SQLModel, SQLite, Jinja, ~7,723 LOC Python |
| Leadline stack | source | FastAPI, async SQLAlchemy, SQLite, React/Vite, ~8,265 LOC Python + ~2,317 LOC UI |
| Breadcrumb repo | `git log -1` | `e51c91b First functional phase` |
| Leadline repo | `git log -1` | `6802a50 Prepare repository for public release` |
| Working trees | `git status --porcelain` | clean before docs; only `docs/` added |

The test counts are the regression floor, not a coverage claim. Leadline’s
suite is slower because its integration tests exercise a controlled HTTP
target.

---

## 3. Scope and SSRF research

### 3.1 OWASP guidance

Source: OWASP Server-Side Request Forgery Prevention Cheat Sheet
(`https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`).

The relevant guidance:

- Do not accept an arbitrary URL from the user and fetch it.
- Resolve the hostname and validate the **resolved IP** against an allowlist
  (or deny private/reserved ranges), not just the hostname string.
- Connect to the validated IP, not to a second resolution of the hostname.
- Revalidate on redirects.
- Block loopback, link-local, private, and cloud metadata addresses.
- Be aware of DNS rebinding/TOCTOU: the check and the connection must use the
  same answer.
- Prefer an allowlist over a denylist where possible.

**How this shaped the plan:** `ScopeGuard` resolves once, validates every
address, pins the connection, follows redirects manually, and records the
decision. It does not rely on a URL regex.

### 3.2 Private/lab targets

Leadline explicitly allows private, internal, and loopback targets. That is a
legitimate lab capability, but it cannot be the default once a job can be
created from a browser or from discovered content.

**Owner decision (2026-10-29):** private and loopback targets are allowed by
default with a global warning; `lab_cidrs` becomes an optional narrowing
control. Metadata and link-local remain hard-blocked. This preserves the lab
use case; the SSRF residual risk is accepted and the Host/CSRF/pinned-resolver
controls become mandatory. The original recommendation was an explicit
per-program CIDR allowlist; the owner chose the broader option.

### 3.3 DNS rebinding / TOCTOU

Two resolutions of the same hostname can return different answers. A guard that
checks one answer and lets the HTTP client resolve again is bypassable.

**Design response:** a scoped resolver returns the validated `ResolveResult`
list; the connector uses only that list; no re-resolution at connect time.
Redirects and retries re-run the guard as a new decision. A changed answer
fails closed.

**Caveat:** this is design, not yet tested. Phase 2 must include a fake resolver
that returns public then private and prove the second answer is never used.

### 3.4 Redirects and proxies

- aiohttp follows redirects by default; a guard on the initial URL is not
  enough. The plan uses `allow_redirects=False` and manual revalidation.
- A proxy resolves the target itself; pinning is not end-to-end. The plan warns
  and disallows proxies in strict mode.
- Cross-origin redirects must strip `Authorization`/`Cookie`; otherwise a
  scoped target can harvest credentials for another host.

### 3.5 External tools

External tools (`nmap`, `nuclei`, `httpx`, ...) resolve names themselves and
have their own redirect/proxy behavior. The app cannot fully pin them without
an OS-level network namespace or egress firewall.

**Design response:** preflight scope check, prefer IP literals, use supported
resolve overrides, process-group isolation, output caps, and `strict` mode that
disables unpinnable tools. Record `scope_mode=preflight_only`. This is an honest
`Platform limit`, not a claim of complete enforcement.

### 3.6 Shared IP/CDN

Scope by hostname does not make a port scan of a shared CDN IP safe or
meaningful. The plan adds `allow_shared_ip_ports` (default false) and prefers
HTTP/TLS for hostnames behind shared infrastructure. This was a gap found during
the critical review, not in the original brief.

---

## 4. SQLite, WAL, and the job queue

### 4.1 Local verification

| Check | Result |
|---|---|
| `sqlite3.sqlite_version` | `3.45.3` |
| `UPDATE ... WHERE id = (SELECT ...) RETURNING ...` | works |
| `BEGIN IMMEDIATE` claim pattern | works with a single writer |
| `Connection.backup()` | available in Python’s `sqlite3` |
| WAL mode | supported; one writer at a time |

Official pages attempted:

- `https://sqlite.org/wal.html` — timed out/blocked from this network.
- `https://sqlite.org/lang_transaction.html` — timed out/blocked.
- `https://sqlite.org/lang_returning.html` — timed out/blocked.

Alternatives used:

- Python `sqlite3` documentation: `https://docs.python.org/3/library/sqlite3.html`
  (transactions, `Connection.backup`, `timeout`, `check_same_thread`).
- SQLite repository design notes, including `doc/wal-lock.md`:
  `https://github.com/sqlite/sqlite/blob/master/doc/wal-lock.md`.
- Huey’s SQLite queue as prior art:
  `https://github.com/coleifer/huey` (WAL, `begin exclusive`, busy timeout,
  atomic dequeue/delete).
- Direct local experiments on SQLite 3.45.3.

**Conclusion:** SQLite is sufficient for a single-user queue if writes are
short, WAL + `busy_timeout` are set, claims use `BEGIN IMMEDIATE`, and there is
one writer at a time. It is not a multi-user queue. The optional worker process
is the escape hatch; Postgres is the “different architecture” fallback.

### 4.2 Job claim

The claim query in the plan is deliberately a single `UPDATE ... RETURNING`
inside `BEGIN IMMEDIATE`. This avoids the “select then update” race that two
workers would otherwise hit. The `lease_owner` check on heartbeat prevents a
stale worker from writing after losing its lease.

**Not yet proven:** a two-process test on the actual laptop. This is Phase 1’s
main gate.

### 4.3 Backups

Python’s `sqlite3.Connection.backup()` is documented to work while the database
is being accessed. That is the basis for the safe backup design, plus
`PRAGMA integrity_check` and an atomic rename. A raw `shutil.copy2` of a live
WAL database is not a point-in-time backup.

---

## 5. Evidence chain

No external source is needed for the core idea: a hash chain is only meaningful
if each node has exactly one predecessor and one successor, and if the latest
head is part of the verified state.

Findings from the source audit:

- Breadcrumb already seals each paste with `content_sha256`, `chain_hash`, and
  `prev_paste_id`.
- The current `_seal_paste` selects the latest sealed paste, then inserts. That
  is safe with one writer but not with two.
- `db.py` has no WAL/busy timeout and no chain-head row.
- There is no unique constraint on `prev_paste_id` or a monotonic `chain_seq`.
- Existing tests prove single-writer sealing and tamper detection, not
  concurrent sealing.

**Design response:** a single-row `EvidenceChain` head, `BEGIN IMMEDIATE`,
unique `prev_paste_id`/`chain_seq`, `capture_key` idempotency, and a
two-process test. Keep the existing chain formula exactly:
`sha256(f"{prev_chain or 'genesis'}:{raw_text}")`; changing it would break old
captures.

**Open question:** how to handle a deliberate purge (GDPR/retention) without
pretending the chain is intact. The plan reports gaps and records a purge event;
it does not silently re-seal.

---

## 6. Secrets and key management

### 6.1 Fernet

Source: `https://cryptography.io/en/latest/fernet/`.

- Fernet is authenticated symmetric encryption (AES-128-CBC + HMAC-SHA256).
- `MultiFernet` supports key rotation: decrypt with any key, encrypt with the
  primary.
- The key must remain secret; encryption does not help if the key sits next to
  the DB.

**Design response:** key from `BREADCRUMB_SECRET_KEY` → OS keyring → 0600 key
file; never in the DB; `MultiFernet` for rotation; encrypt header profiles,
proxy credentials, notification tokens, and AI API keys; redact derived views.

### 6.2 keyring

Source: `https://pypi.org/project/keyring/` and
`https://github.com/jaraco/keyring`.

- Backends exist for macOS Keychain, Windows Credential Locker, KDE KWallet,
  GNOME Keyring/libsecret, and others.
- Headless Linux may have no unlocked backend; a key-file fallback is required.
- The fallback must be `0600` and documented; it is not as strong as an OS
  keychain.

**Design response:** env → keyring → key file; fail closed on decryption if the
key is missing; do not silently generate a new key over an existing encrypted
profile.

### 6.3 Redaction

No library solves “this is a secret” reliably. The plan uses a centralized
pattern list plus exact-match replacement of configured values, applied at
logs/events/errors/exports/AI/notifications. It is best-effort and documented
as such. The sealed raw capture is not rewritten by default; derived views are.

### 6.4 DB at rest

SQLite is not encrypted by default. SQLCipher is a deployment burden and not in
v1. The plan documents full-disk encryption and backup encryption as operator
responsibilities. This is a `Platform limit`, not a hidden promise.

---

## 7. HTTP client behavior (aiohttp)

Sources:

- Client reference: `https://docs.aiohttp.org/en/stable/client_reference.html`
- Advanced/client resolver: `https://docs.aiohttp.org/en/stable/client_advanced.html`
- `TCPConnector` parameters: `limit`, `limit_per_host`, `resolver`, `ssl`,
  `force_close`.
- DNS cache default is short (10 s); do not rely on it for pinning.
- Redirects are followed by default; `allow_redirects=False` is required for
  manual revalidation.
- Proxy support is per-request/session; a proxy bypasses app-level DNS pinning.

**Design response:** a custom `AbstractResolver` returns only validated
`ResolveResult`s; `limit_per_host` and global limits; manual redirects; body
read caps (`read(limit+1)`); preserve `Host`/SNI and certificate verification.

**Caveat:** the exact aiohttp API for a pinned resolver must be spiked in Phase
2. The plan does not claim it is already implemented.

---

## 8. Subprocess isolation

Source: `https://docs.python.org/3/library/subprocess.html`.

- `shell=False` with an argv list avoids shell injection.
- `start_new_session=True` creates a new process group; cancellation can signal
  the group (`os.killpg`) instead of only the parent.
- `timeout` on `communicate()` is not enough for a process that spawns children;
  process-group kill is needed.
- Resource limits (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`) are available on
  Unix via `resource`; not portable to Windows.

**Design response:** argv-only templates, `start_new_session`, process-group
kill with SIGTERM→SIGKILL, output caps, temp cwd, environment allowlist, and
no inherited secrets.

---

## 9. Hardware and local AI

### 9.1 Target hardware

- GPU: GTX 1650, 4 GB VRAM.
- CPU: Ryzen 5 5600H.
- RAM: 20 GB.
- Implication: a 3B/4B Q4 model fits in VRAM with a modest context; a 7B Q4
  does not fit without partial offload; 8B+ is impractical for interactive use.

### 9.2 Model sizes (approximate GGUF quant files)

| Model | Quant | Exact file | Size | Fit |
|---|---|---|---:|---|
| Qwen2.5-3B-Instruct | Q4_K_M | `qwen2.5-3b-instruct-q4_k_m.gguf` | 2,104,932,768 B (2.10 GB) | fits 4 GB with 4k–8k context; safest default |
| Qwen3-4B-Instruct-2507 | Q4_K_M | `Qwen3-4B-Instruct-2507-Q4_K_M.gguf` | 2,497,280,448 B (2.50 GB) | fits 4 GB at 4k context; tighter at 8k |
| Qwen3.5-4B | Q4_K_M | `Qwen3.5-4B-Q4_K_M.gguf` | 2,740,937,888 B (2.74 GB) | fits 4 GB only with a small context; multimodal projector not needed for text |
| Qwen2.5-7B-Instruct | Q4_K_M | `qwen2.5-7b-instruct-q4_k_m.gguf` | ~4.68 GB | partial offload; slow; not default |
| 8B/12B/14B/30B | any | — | 5–18 GB+ | not practical on 4 GB |

Sources: Hugging Face model repos/cards and tree APIs:
`https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF`,
`https://huggingface.co/lmstudio-community/Qwen3-4B-Instruct-2507-GGUF`,
`https://huggingface.co/unsloth/Qwen3.5-4B-GGUF`,
`https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF`. Sizes are exact file
sizes from the Hugging Face tree API; KV cache/context overhead is additional.

### 9.4 What is already installed (2026-10-29)

| Runtime | Model file | Size | Verdict |
|---|---|---:|---|
| LM Studio | `gemma-4-12B-it-QAT-Q4_0.gguf` | 6.98 GB | does not fit 4 GB; partial offload only |
| LM Studio | `Qwen3.5-9B-Q8_0.gguf` | 9.53 GB | does not fit 4 GB |
| LM Studio | `DeepSeek-R1-0528-Qwen3-8B-Q8_0.gguf` | 8.71 GB | does not fit 4 GB |
| Jan | `Qwen3-Coder-30B-A3B-Instruct-IQ4_XS/model.gguf` | 16.38 GB | does not fit 4 GB; 30B |
| Jan | `GLM-4_7-Flash-Uncen-Hrt-NEO-CODE-MAX-imat-D_AU-IQ4_XS/model.gguf` | 16.41 GB | does not fit 4 GB |

**Recommendation:** none of the installed models is suitable as the default.
Download exactly one of the first two rows above. Use the same GGUF in both
LM Studio and Jan (import/copy it into each runtime’s model directory) or
download it once per runtime. Set all four Breadcrumb routes
(`fast`/`reason`/`long`/`prose`) to that model ID at first; add a second model
later only if the first is too slow.

### 9.3 Design response

- Default to 3B/4B Q4, 4k–8k context, top-N prompt, 120 s timeout.
- Show “fits/does not fit” badges; do not auto-download.
- Deterministic summaries/risk/diff are primary; AI is optional narration.
- 7B is allowed only as an explicit “slow” option; 14B/30B are not defaults.
- Hardware smoke test is a release gate.

---

## 10. Competitive research

The point was to test Breadcrumb’s positioning, not to copy features.

| Tool | Model | Strength | Gap vs Breadcrumb |
|---|---|---|---|
| reNgine | Django + Celery + Postgres, scan orchestration | Full scan platform, UI, recon engines | Heavy deploy; scan-first; within-engagement; not a local notebook |
| BBOT | Python recursive scanner, scope, output modules | Excellent CLI scanning, modules, scope | CLI-first; no cross-program ledger/evidence chain; AGPL |
| Osmedeus | Workflow engine, SQLite/Postgres/Redis | Powerful workflows, recon | Heavy; workflow-centric; not import-first |
| Amass | OWASP asset discovery | Deep DNS/asset discovery | One purpose; no notebook/evidence/report workflow |
| Faraday | Vulnerability management | Multi-user, workspaces, integrations | Team/server product; not local-first single file |
| DefectDojo | Vulnerability management | Triage, metrics, integrations | Team workflow; not a scanner/notebook |
| ProjectDiscovery stack | Single-purpose CLIs | Best-in-class modules | Pipes; no memory/evidence by itself |

**Conclusion:** the market is crowded with scan/orchestration tools and with
vuln-management tools. Breadcrumb’s defensible position is not “another
scanner”; it is **cross-program memory + tamper-evident evidence + one-file
local deploy + import-first**. Leadline adds execution without changing that
position, provided the scanner does not take over the home page.

This directly supports the plan’s “flagship” decision and the pre-mortem’s F10
(“Breadcrumb stopped being a notebook”).

---

## 11. Leadline source-audit findings

| Area | Finding | Implication |
|---|---|---|
| Pipeline | 12 phases, shared context, per-phase `ScanEvent` | Port the phase behavior, not the ORM |
| Recovery | Startup marks `running`/`stopping` failed | Replace with lease recovery |
| Scope | No target scope enforcement; private/loopback allowed | Private-target warning; metadata/link-local hard-blocked |
| HTTP | aiohttp, follows redirects, 2 MB cap, 10 s timeout | Reuse caps; add manual redirects/pinning |
| Ports | ~200 curated TCP ports, concurrency 10, banner/TLS | Reuse; add shared-IP policy |
| CVE | CPE + NVD version ranges, keyword fallback labeled | Preserve; add cache/offline |
| Risk | Excludes unverified CVE candidates | Port exactly |
| History | Snapshot/diff fields | Port to `ScanSnapshot` |
| Reports | JSON/MD/HTML/PDF, target filenames, disclosure | Port PDF/reportlab with escaping |
| UI | React/Vite targets/scans/reports/history | Capability parity, not SPA port |
| Security | Host allowlist, CORS, no auth | Keep Host allowlist idea; add CSRF |
| Bug | Unbound `truncated` if GET fails | Fix + regression test |

---

## 12. Source-access limitations

| Source | Status | Alternative |
|---|---|---|
| `sqlite.org/wal.html` | timed out/blocked | Local SQLite 3.45.3; Python docs; SQLite repo `doc/wal-lock.md`; Huey |
| `sqlite.org/lang_transaction.html` | timed out/blocked | Python `sqlite3` docs; local `BEGIN IMMEDIATE` test |
| `sqlite.org/lang_returning.html` | timed out/blocked | Local `RETURNING` test on 3.45.3 |
| OWASP SSRF page (final pass) | timed out | Earlier review of the cheat sheet; design based on its published guidance |
| Some ProjectDiscovery docs | stale/timeouts | GitHub READMEs/source |

This does not change the conclusions, but it is recorded so no one assumes the
canonical pages were quoted directly.

---

## 13. Research conclusions that changed the plan

1. **Scope is the first gate, not a feature.** Native HTTP/DNS/TCP can be
   pinned; external tools are a documented residual risk.
2. **Evidence sealing is a concurrency problem.** The chain head and unique
   constraints are mandatory before a worker writes.
3. **Secrets must be encrypted before collectors use headers.** Retrofitting
   after logs/exports/AI is too late.
4. **SQLite is adequate for one user, not for a fleet.** WAL + leases + one
   writer; Postgres only if the load test fails.
5. **The port is not the hard part.** Contract-first, three-collector spike,
   then the rest.
6. **The user’s “no functionality loss” is a product contract.** Parity matrix
   + compatibility API + importer; exact React parity is a separate decision.
7. **4 GB VRAM invalidates the current AI defaults.** 3B/4B Q4 is the default;
   7B is optional; 14B/30B are not.
8. **Breadcrumb’s identity is the notebook.** Scanning is an action, not the
   home page.

---

## 14. Open research questions

These need measurement or owner decisions, not more reading:

1. Can aiohttp’s pinned resolver be made to work cleanly with TLS/SNI and
   redirects on Python 3.12? (Phase 2 spike)
2. Does a two-worker SQLite queue meet the laptop load target? (Phase 1 load
   test)
3. How long does a real 12-phase scan take on a local lab target? (Phase 4)
4. Does reportlab 4.x install and render cleanly on Python 3.12? (Phase 6)
5. Does a 3B/4B Q4 model summarize 20 findings within 120 s on the 1650?
   (Phase 8 smoke)
6. Does the Leadline importer preserve all triage/history semantics on a real
   DB? (Phase 8 dry-run)
7. Which external tools can be pinned with `--resolve`/equivalent, and which
   must be strict-mode-only? (Phase 7)
8. ~~Does the owner require the React UI or only the capability?~~ **Answered
   2026-10-29: capability parity; keep Breadcrumb’s UI and add scanning as a
   feature.**
9. ~~Should external lookups be off by default for new programs?~~ **Answered
   2026-10-29: on by default, with visible failures and retry.**
10. ~~Is the Leadline repository to be archived read-only?~~ **Answered
    2026-10-29: keep the local folder; no automatic archive; owner handles the
    GitHub repo.**
