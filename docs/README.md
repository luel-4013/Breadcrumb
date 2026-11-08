# Breadcrumb + Leadline planning documents

Status: **planning complete; Phases 0–8 implemented, verified and released as
`0.4.0` (2026-11-08).**
Included: durable job queue/worker, scope guard, encrypted-at-rest
header-profile secrets, the twelve-phase `leadline-recon` preset (DNS, host
intel, ports/TLS, HTTP, tech, JS, params, headers, API, vuln candidates, CVE
verification, graph), local NVD/CPE verification, OpenAPI parsing, graph path
navigation, report highlights, per-target history snapshots and diffs,
finding triage, PDF reports, the Leadline compatibility API, CLI parity,
opt-in external tool adapters for nmap/httpx/nuclei/subfinder/naabu/masscan/
katana/ffuf/dalfox/amass/whatweb/wafw00f, and the one-way Leadline importer
with dry-run, resume manifest, verification and an acceptance script.
Phase 8 is closed: importer, real-data verification, merge guide, compatibility
API, security model, hardware/AI guide, troubleshooting, backup/restore/upgrade
runbook, security checklist, release notes and rollback plan are present.
Date: 2026-10-27 to 2026-11-08
Repos inspected:

- Breadcrumb: `e51c91b` — *First functional phase*
- Leadline: `6802a50` — *Prepare repository for public release*

Both working trees were clean when the research began. Planning itself changed
no code. The implementation is additive and is released as `0.4.0`.

## Phase 0 implementation status (2026-10-29)

| Rail | Status | Evidence |
|---|---|---|
| Host allowlist + Origin/Sec-Fetch-Site checks | Implemented | `LocalBoundaryMiddleware`; Host/CSRF tests |
| CSRF token on every POST form | Implemented | hidden tokens in all templates; reject/accept tests |
| SQLite WAL, busy timeout, foreign keys | Implemented | connect-time pragmas in `app/db.py` |
| Linear evidence chain | Implemented | chain head/length row, `BEGIN IMMEDIATE`, partial unique indexes |
| Delete recovery | Implemented | program deletion reconciles head/length; verify reports gaps |
| WAL-safe backup/restore | Implemented | SQLite online backup API + integrity check + atomic replace |
| Legacy schema backfill | Implemented | `chain_seq`, `capture_key`, `evidencechain` migration test |

Test baseline after Phase 0: **72 passed, 1 warning** (historical).
Current suite after the native-executor, secrets, Phase 4, Phase 5, Phase 6,
Phase 7 and Phase 8 slices: **182 passed, 1 warning**.

## Native-executor vertical slice (2026-11-06)

| Capability | Status | Evidence |
|---|---|---|
| Extracted single ingest path with `capture_key` idempotency | Implemented | `app/ingest.py`; duplicate delivery test |
| Schema version + singleton app state + maintenance flag | Implemented | `SCHEMA_VERSION = 3`; old-DB subprocess migration test |
| Atomic claim, lease, heartbeat, retry/backoff, cancel, recovery | Implemented | `app/jobs/queue.py`; two-worker, maintenance, retry, cancel, lease-expiry tests |
| Native worker + optional inline worker | Implemented, **off by default** | `breadcrumb worker`; `BREADCRUMB_EXECUTOR=inline` |
| Scope guard: fail-closed, private warning, metadata/link-local block, redirect re-check | Implemented | `app/collect/guard.py`; scope matrix tests |
| Native DNS collector | Implemented | `leadline-dns`; BIND-style output, scope-aware subdomains |
| Native HTTP/tech/headers collectors | Implemented | `leadline-http`, `leadline-tech`, `leadline-headers`; pinned connections, local-server tests |
| Sealed phase evidence + attempts/phases/events UI | Implemented | job page; native HTTP end-to-end test |
| Health fields + job detail API + cancel/retry/run-now | Implemented | `/health`, `/api/v1/jobs/{id}`, `POST /jobs/{id}/run`, `POST /api/v1/jobs/{id}/run` |
| CLI `worker` and `maintenance` commands | Implemented | parser/CLI smoke test |
| Header-profile secrets encrypted at rest | Implemented | `EncryptedText`/`EncryptedJSON` in `app/secrets_store.py`; plaintext migration, backup scrub, error redaction, key-loss, rotation tests |
| Key rotation CLI | Implemented | `breadcrumb secrets rotate`; `MultiFernet` archives previous keys at `<key>.old` |

## Phase 4 implementation status (2026-11-07)

| Capability | Status | Evidence |
|---|---|---|
| Ports + banners + TLS certificates | Implemented | `leadline-ports`; local HTTP and self-signed TLS fixture tests |
| Host intel (offline subset) | Implemented | `leadline-host-intel`; A/AAAA, CNAME, PTR; skipped external sources stated |
| JavaScript analysis (never executed) | Implemented | `leadline-js`; same-origin scripts, inline scripts, endpoint/param/CVE extraction |
| Parameter discovery | Implemented | `leadline-params`; query/form fields, no fuzzing |
| API discovery | Implemented | `leadline-api`; fixed paths, GET-only, httpx JSONL evidence, inferred references |
| Vulnerability candidates | Implemented | `leadline-vulns`; pattern/header/IDOR/high-risk-port candidates, never confirmed |
| CVE candidates (offline-first) | Implemented | `leadline-cve`; referenced CVEs + product/version candidates; Phase 5 adds local proof of applicability |
| Graph observations | Implemented | `leadline-graph`; nmap XML reinforces host/IP/port entities and edges |
| Twelve-phase job preset | Implemented | `leadline-recon`; 12 ordered sealed phases in one job |
| Fail-closed recon scope | Implemented | out-of-scope preset test; no paste and no retry |
| Regression gate G5 / evidence gate G2 | Verified for fixtures | 12-phase end-to-end test; full suite 125 passed |

## Phase 5 implementation status (2026-11-07)

| Capability | Status | Evidence |
|---|---|---|
| Local NVD cache + import | Implemented | `breadcrumb nvd import/stats`; plain JSON/JSON.GZ merge tests |
| CPE 2.3 parsing + version ranges | Implemented | `app/collect/nvd.py`; range/exact/alias tests |
| Verified-only CVE findings | Implemented | local match emits nuclei JSONL; non-matching version emits none |
| Keyword lookup cache/degradation | Implemented | TTL cache; missing/stale cache stays offline with warnings |
| OpenAPI/Swagger parsing | Implemented | JSON + YAML documents; operations inferred, never requested |
| Versioned tech fingerprints | Implemented | Server/X-Powered-By/generator/CDN/framework signatures; `tech_versions` |
| Graph path tree + filters | Implemented | `graph.path_tree`; value/type filters; capped tree |
| Report risk highlights | Implemented | JSON summary/highlights; markdown risk explanation |
| Large-target caps | Implemented | CVE matches, inferred API URLs, OpenAPI paths/operations, path-tree nodes, document size |

## Phase 6 implementation status (2026-11-07)

| Capability | Status | Evidence |
|---|---|---|
| `ScanSnapshot` generation/rebuild | Implemented | `app/history.py`; worker hook; failure-isolation test |
| Target timeline + diff engine/API/UI | Implemented | `/targets/{id}/history`, compat history/diff, `history.html` |
| Risk excludes false positives/unverified CVEs | Implemented | `history.compute_risk`; snapshot/diff test |
| `Finding.verdict` + triage mapping | Implemented | `app/triage.py`; mapping and route tests |
| reportlab PDF with escaping/filenames/disclosure | Implemented | `app/pdf_export.py`; hostile-text PDF test |
| Leadline compatibility API | Implemented | `app/compat.py`; end-to-end contract test |
| UI: triage/history/PDF/snapshot/run-now | Implemented | program/job/history/runners pages; UI control test |
| CLI: collect/jobs/history/report | Implemented | `app/cli.py`; jobs/history/PDF CLI test |
| Acceptance script comparing reports | Implemented | `scripts/acceptance_phase8.py`; 6/6 checks on real data |

## Phase 7 implementation status (2026-11-07)

| Capability | Status | Evidence |
|---|---|---|
| Twelve external tool adapters | Implemented | `app/collect/tools.py`; `ADAPTER_REGISTRY`; adapter spec test |
| Opt-in worker claims | Implemented | `claimable_collector_ids()`; worker gating test |
| Scope preflight before spawn | Implemented | denied/metadata/proxy no-spawn tests; `ScopeGuard.check_network` |
| argv-only + process-group isolation | Implemented | `run_tool`; shell/argv, timeout, output-cap and child-death tests |
| Environment allowlist | Implemented | no proxy/secrets in child env; header profiles never passed |
| Strict mode | Implemented | `BREADCRUMB_STRICT_MODE=1`; nuclei blocked / httpx allowed tests |
| Missing binary reported honestly | Implemented | explicit "not installed" error; `/runners` and `breadcrumb tools` |
| Adapter parsers | Implemented | ffuf/dalfox/amass/whatweb/wafw00f fixtures; candidate tags on dalfox |
| Runner/job UI and CLI | Implemented | adapter metadata, version/scope/strict display, `breadcrumb tools` |
| Adapter job evidence path | Implemented | opt-in worker runs fake nmap → sealed phase/capture |

## Phase 8 implementation status (2026-11-08)

| Capability | Status | Evidence |
|---|---|---|
| One-way Leadline importer | Implemented | `app/leadline_import.py`; `python -m app.cli import-leadline` |
| Read-only source + fingerprint guard | Implemented | `mode=ro`, `PRAGMA query_only=ON`, before/after SHA-256 |
| Dry run with no writes | Implemented | `--dry-run`; dry-run/no-manifest test |
| Destination backup + maintenance + one transaction | Implemented | `.pre-import-*.bak`; maintenance flag; backup-existence test |
| Target/header/scan/event/finding/graph mapping | Implemented | `tests/test_phase8.py`; synthetic Leadline DB |
| Encrypted imported header profiles | Implemented | `EncryptedJSON`; raw ciphertext acceptance check |
| Triage/history/graph preservation | Implemented | `app.triage` mapping; per-scan snapshots; `part_of`/`references` |
| Historical, non-runnable imported jobs | Implemented | `runner=leadline.imported`; worker/API/UI guards; `409` |
| Idempotent resume manifest | Implemented | default `<db>.leadline-import.json`; re-import test |
| Post-import verification | Implemented | counts/triage/severity/samples/header round-trip/source hash |
| Acceptance script | Implemented | `scripts/acceptance_phase8.py`; 6 checks on real data |
| Merge/import guide + verification report | Implemented | `LEADLINE_MERGE_GUIDE.md`; `LEADLINE_IMPORT_VERIFICATION.md` |
| Compatibility API/security/hardware/troubleshooting docs | Implemented | `COMPATIBILITY_API.md`; `SECURITY_MODEL.md`; `HARDWARE_AI_GUIDE.md`; `TROUBLESHOOTING.md` |
| Backup/restore/upgrade + checklist + release/rollback | Implemented | `BACKUP_RESTORE_UPGRADE.md`; `SECURITY_CHECKLIST.md`; `RELEASE_NOTES_PHASE8.md`; `ROLLBACK_PLAN.md` |
| Schema 4 (`target.meta`, `finding.meta`) | Implemented | additive migration; old-DB migration test |

Phase 8 is complete on a copy of the owner's real Leadline database: 2 targets
and 2 encrypted header profiles imported, verification passed, re-import was
idempotent, and the acceptance script passed all six checks. The real database
had no scans/findings/graph rows, so those paths are covered by the synthetic
fixture. See [LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md).

The executor default is **off**; external adapters are **opt-in**
(`BREADCRUMB_EXTERNAL_TOOLS=1` for worker claims); `BREADCRUMB_STRICT_MODE=1`
disables unpinnable adapters. Gate C (external-tool strictness) remains an
owner sign-off item, not an automatic pass.


## Read in this order

1. **[LEADLINE_MERGE_PLAN.md](LEADLINE_MERGE_PLAN.md)** — the recommendation,
   target architecture, safety design, phased delivery plan, acceptance
   criteria, and open decisions.
2. **[LEADLINE_PARITY_MATRIX.md](LEADLINE_PARITY_MATRIX.md)** — every Leadline
   capability mapped to a Breadcrumb equivalent, an addition, or an explicit
   owner decision. This is the contract for “do not lose the original
   functionality.”
3. **[LEADLINE_MERGE_PRE_MORTEM.md](LEADLINE_MERGE_PRE_MORTEM.md)** — the
   critical review: weakest assumptions, failure scenarios, red-team findings,
   release gates, and alternatives.
4. **[LEADLINE_MERGE_POSTMORTEM.md](LEADLINE_MERGE_POSTMORTEM.md)** — what the
   research and planning phase actually found, what was wrong in the original
   assumptions, and which issues remain open.
5. **[LEADLINE_RESEARCH_NOTES.md](LEADLINE_RESEARCH_NOTES.md)** — sources,
   local verification, competitor analysis, hardware math, and source-access
   limitations.

Operational documents for the merged system:

6. **[LEADLINE_MERGE_GUIDE.md](LEADLINE_MERGE_GUIDE.md)** — how to import an
   existing Leadline database and what changes after the merge.
7. **[LEADLINE_IMPORT_VERIFICATION.md](LEADLINE_IMPORT_VERIFICATION.md)** —
   real-data verification report, counts, fingerprints and reproduction steps.
8. **[COMPATIBILITY_API.md](COMPATIBILITY_API.md)** — Leadline-shaped API
   paths, status/triage mapping and differences.
9. **[SECURITY_MODEL.md](SECURITY_MODEL.md)** — trust boundaries, scope/SSRF
   controls, secrets at rest, evidence integrity and residual risks.
10. **[HARDWARE_AI_GUIDE.md](HARDWARE_AI_GUIDE.md)** — measured local-model
    setup on the 4 GB GTX 1650, performance and tuning.
11. **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — symptom-first diagnosis for
    startup, DB, secrets, jobs, import, snapshots/reports and AI.
12. **[BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md)** — WAL-safe
    backup, restore, schema upgrade, key rotation and disaster matrix.
13. **[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)** — pre-sign-off review
    with evidence commands and accepted residual risks.
14. **[RELEASE_NOTES_PHASE8.md](RELEASE_NOTES_PHASE8.md)** — Phase 8 summary,
    mapping, schema/upgrade notes, tests and limitations.
15. **[ROLLBACK_PLAN.md](ROLLBACK_PLAN.md)** — rollback levels from disabling
    the executor through restoring a pre-migration database or falling back to
    Leadline.

## One-paragraph summary

Breadcrumb should remain the flagship product and system of record. Leadline’s
native collectors, phase model, history/diff logic, PDF export, and triage
semantics should be absorbed into Breadcrumb rather than kept as a second
service with its own database and UI. Breadcrumb gains a real, scope-guarded
executor; the local Leadline folder is retained as a reference (the owner will
remove the GitHub repo himself), and no automatic archive/delete happens.
“Do not lose
functionality” is interpreted as **capability parity inside Breadcrumb**, plus
a compatibility API and a one-way Leadline data importer — not a pixel-for-pixel
port of Leadline’s React UI.

Current state: the import-first product is intact, and a safety-first executor
runs native collectors and opt-in external tool adapters through the durable
local queue. The one-way Leadline importer, real-data verification and all
Phase 8 hardening runbooks are complete.

## Baseline evidence

| Check | Result |
|---|---|
| Breadcrumb tests (planning baseline) | `62 passed, 1 warning in 1.91s` (`.venv/bin/python -m pytest -q`) |
| Breadcrumb tests (current slice) | `182 passed, 1 warning` (`.venv/bin/python -m pytest -q`) |
| Leadline tests | `41 passed, 7 warnings in 30.80s` (`/tmp/opencode/leadline-venv/bin/python -m pytest -q`) |
| Breadcrumb stack | FastAPI, SQLModel, SQLite, Jinja UI, ~7,723 LOC Python |
| Leadline stack | FastAPI, async SQLAlchemy, SQLite, React/Vite UI, ~8,265 LOC Python + ~2,317 LOC UI |
| Local SQLite | 3.45.3; `RETURNING` and `BEGIN IMMEDIATE` verified locally |
| Target hardware | GTX 1650 4 GB VRAM, Ryzen 5 5600H, 20 GB RAM |

## What these documents deliberately do not claim

- The merge is **implemented** through Phase 8 — durable executor, scope guard,
  encrypted header profiles, the twelve-phase native recon preset, local
  NVD/CPE verification, OpenAPI parsing, graph path navigation, report
  highlights, snapshots/diffs/triage, PDF and compatibility API, opt-in
  external tool adapters, and the one-way Leadline importer with verification
  and runbooks. It is released as **`0.4.0`**.
- They do not claim literal UI/API parity. Parity is capability parity inside
  Breadcrumb plus a compatibility API; the React SPA and second service/database
  are intentionally not ported (owner decision Q1).
- They do not claim the real Leadline database exercised every path. It had no
  scans/findings/graph rows; those paths are covered by synthetic fixtures.
- They do not claim external tool execution is sandboxed. Strict mode and an
  egress firewall remain deployment controls; Gate C is an owner sign-off item.
- They do not claim external primary sources were all reachable. The official
  SQLite pages and one OWASP page timed out from this network; equivalent
  behavior was verified against the local SQLite build, Python’s `sqlite3`
  documentation, SQLite repository design notes, and prior-art queue code.
  This limitation is recorded in the postmortem.
