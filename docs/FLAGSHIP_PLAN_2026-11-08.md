# Flagship plan: Breadcrumb 1.0 as the evidence-first recon notebook

**Status:** planning only. No application code changed. The 0.4.0 release and
tag `v0.4.0` remain intact on commit `4b0066d`.
**Date:** 2026-11-08
**Evidence base:** [`COMPETITIVE_RESEARCH_2026-11-08.md`](COMPETITIVE_RESEARCH_2026-11-08.md)
(19 external projects plus the Leadline baseline, 20 reasons each).
**Owner:** Breadcrumb maintainer
**Decision requested:** approve the flagship direction and the first slice; do
not start implementation until approved.

---

## 1. Decision summary

**Recommendation: Go — with guardrails.**

The research says Breadcrumb should **not** try to become a better reNgine, a
lighter Faraday, or an open-source DefectDojo. Those markets are already
crowded, operationally heavy, and separated from Breadcrumb's real advantage.
The winning move is to make Breadcrumb the **evidence-first recon notebook**:

> Import anything. Remember everything across programs. Prove what changed.
> Turn evidence into a report locally. Keep the scanner optional.

This is a narrower product than "all-in-one recon platform", but it is a
defensible one. It matches the existing 0.4.0 architecture, the owner's
hardware, and the actual gaps in the market:

- No surveyed competitor has a first-class **cross-program memory**.
- No surveyed competitor has a **tamper-evident evidence chain**.
- Most competitors make the user pay an install/operations tax that a solo
  hunter should not pay.
- The tools that do reporting (Dradis, Ghostwriter, DefectDojo) are heavy,
  team-oriented, and not import-first.
- The tools that do scanning (reNgine, reconFTW, BBOT, Amass) leave the
  evidence/reporting layer to files, Faraday, or manual work.

**Go on Phases A and B first.** They deepen the moat and fix the issues that
would otherwise make the flagship plan collapse under its own weight. Phase C
and D are justified after A/B acceptance. Phase E is optional and should be
treated as an integration surface, not a browser/exploit platform. Phase F is
the 1.0 hardening/release gate.

**No-go conditions.** Stop and reconsider if any of these become true:

1. Phase A cannot demonstrate reliable import of 100k entities without data
   loss or unacceptable latency on the target laptop.
2. The evidence manifest cannot be made understandable to a normal user
   without turning every import into a compliance exercise.
3. The plan starts requiring Postgres/Redis/Neo4j, a cloud account, or a
   multi-user auth system to deliver the core value.
4. The team cannot keep the local-only, no-telemetry default.
5. The work drifts into scanner/exploit features that duplicate competitors
   instead of strengthening the notebook.

---

## 2. Product thesis

**Breadcrumb is the system of record for a solo hunter's recon evidence.**

It is not the scanner. It is not the ticketing system. It is not the exploit
framework. It is the place where:

- raw output from any tool becomes structured, deduplicated evidence;
- every capture has a source, a timestamp, a hash, and a place in a chain;
- assets are remembered across programs, so old work compounds;
- scope and triage are deterministic and reviewable;
- a local LLM can explain evidence without inventing it;
- a report can be produced without leaving the machine.

The flagship plan should make that thesis undeniable in the product, the docs,
and the first-run experience.

### The one-sentence positioning

> **Breadcrumb is the offline-first evidence notebook that turns any recon
> output into a searchable, tamper-evident, cross-program memory — and then
> into a report.**

### What "flagship" means here

Flagship does **not** mean "most features". It means:

- the best first-run experience in the category;
- the most trustworthy evidence model;
- the fastest path from raw output to a useful report;
- the only tool that remembers across programs;
- the least operational burden for a solo hunter;
- a product that is still understandable a year later.

---

## 3. What the research changes

The research does not change the 0.4.0 architecture. It changes the priority
order and the definition of done.

### Keep

- Import-first architecture and the universal paste/upload/API ingest path.
- SQLite + one process + one container; no Postgres/Redis/Neo4j.
- Cross-program Ledger, typed graph, snapshots/diffs, triage.
- Tamper-evident capture chain and offline verification.
- Deterministic parsers, optional local AI, encrypted header profiles.
- Durable local queue and optional native/adapter execution.
- Local-only boundary, CSRF/Host checks, no telemetry.

### Strengthen

- Import reliability and parser error reporting.
- Evidence provenance/manifest and exportable proof.
- Cross-program memory UX (the Ledger as a headline, not a hidden table).
- Report templates, redaction, and integration-friendly exports.
- Onboarding, doctor/preflight, sample data, and docs.
- Large-import performance and benchmark evidence.
- Release cadence and migration discipline.

### Do not build

- Cloud/distributed scanning (Axiom/Osmedeus).
- Exploitation or exploit verification (Sn1per/Legion).
- Full vulnerability management/ticketing (DefectDojo/Faraday).
- Multi-tenant MSSP platform (Reconmap).
- Remote plugin marketplace (Recon-ng/Sn0int).
- Autonomous AI agents that act without evidence.
- A browser automation stack just to take screenshots.
- A second service/database or a React SPA port.

### Integrate instead

- **BBOT / Amass / theHarvester / reconFTW / reNgine** → import JSON/JSONL/CSV.
- **EyeWitness / Gowitness** → import screenshot manifests and images.
- **DefectDojo / Faraday / Ghostwriter / Dradis** → export findings/reports.
- **Jira / MISP / Elastic / Splunk** → optional export/webhook adapters.
- **Ollama / LM Studio / Jan** → local LLM routes.
- **Nuclei / httpx / nmap / subfinder** → existing adapter/import paths.

---

## 4. Competitive position

| Job | Who owns it today | Breadcrumb's play |
|---|---|---|
| Run a full recon pipeline | reNgine, reconFTW, Osmedeus, BBOT | Import their output; optionally run the twelve-phase preset. |
| Collect OSINT | theHarvester, SpiderFoot, Amass, Sn0int | Import/normalize; do not rebuild 200 modules. |
| Take screenshots | EyeWitness, Gowitness | Import screenshot manifests; do not embed Chromium/Selenium. |
| Manage vulnerabilities | DefectDojo, Faraday, Dradis | Export findings; do not become a ticketing system. |
| Write reports | Ghostwriter, Dradis, reNgine | Local report templates + export to their formats. |
| Manage teams/engagements | Reconmap, DefectDojo, Faraday | Local-first; optional review bundle, not SaaS. |
| Distribute scans | Axiom, Osmedeus | Document external adapters; do not build cloud infra. |
| Remember across programs | **Nobody in this set** | Make the Ledger the headline. |
| Prove evidence integrity | **Nobody in this set** | Make the chain + manifest the headline. |
| Local AI analysis | reNgine (cloud GPT), Breadcrumb (local) | Keep local, cited, optional. |

### Where Breadcrumb can lose

- If it becomes a slow, heavy scanner, it loses to reNgine/reconFTW.
- If it becomes a ticketing system, it loses to DefectDojo/Faraday.
- If it becomes a team platform, it loses to Reconmap/Ghostwriter.
- If it adds a browser stack, it inherits EyeWitness's reliability problems.
- If it adds a marketplace, it inherits Recon-ng's maintenance problems.
- If it adds cloud execution, it inherits Axiom's provider-maintenance problems.
- If it adds autonomous AI, it inherits the trust problem of every opaque
  scanner.

### Where Breadcrumb can win

- **Time-to-first-insight:** paste output → structured evidence in seconds.
- **Trust:** deterministic parsers, scope rules, evidence chain, no telemetry.
- **Memory:** "I saw this host six months ago in another program."
- **Portability:** one SQLite file + a full export bundle.
- **Report speed:** evidence → redacted report without a second product.
- **Operational simplicity:** one container, no external DB, no cloud.
- **Local AI:** a 4 GB GPU can produce useful summaries without sending data
  away.

---

## 5. The flagship definition

**Breadcrumb 1.0 = the evidence-first recon notebook.**

### Five pillars

1. **Ingest anything.** Any common recon output, paste, file, API, or drop
   folder becomes structured evidence with a parser contract and visible errors.
2. **Remember everything.** Every asset, finding, and capture is linked across
   programs, targets, and time; the Ledger answers "have I seen this before?"
3. **Prove everything.** Every capture has provenance and a chain position; the
   evidence manifest can be exported and verified offline.
4. **Understand quickly.** Scope, dedup, triage, diffs, graph, search, and local
   AI summaries turn raw output into an answer.
5. **Report locally.** Templates, redaction, PDF/HTML/Markdown/JSON, and
   integration exports produce a submission-ready artifact without a cloud.

### Release story

| Release | Theme | Exit criteria |
|---|---|---|
| `0.5.0` | **Proof** | Phase A: import reliability, doctor, evidence manifest, performance baseline. |
| `0.6.0` | **Memory** | Phase B: Ledger v2, cross-program/cross-scan diff, scope v2. |
| `0.7.0` | **Report** | Phase C: templates, redaction, review bundle, DefectDojo/Ghostwriter export. |
| `0.8.0` | **Automate** | Phase D: scheduled re-import, parser SDK, OpenAPI, benchmarks. |
| `0.9.0` | **Capture** | Phase E (optional): screenshot/evidence import, adapter hardening. |
| `1.0.0` | **Flagship** | Phase F: security review, migration, docs, performance, release gate. |

The version numbers are proposals. The order is the important part.

---

## 6. Design principles

1. **Local-first, always.** No cloud dependency for core value; no telemetry;
   no account. Cloud/LLM integrations are optional adapters.
2. **Evidence before AI.** Deterministic parsers and scope rules produce the
   facts; the LLM only explains, summarizes, or drafts.
3. **One file, one process.** SQLite is the default and the only required
   datastore. Do not add Postgres/Redis/Neo4j for core features.
4. **Import-first, scanner-optional.** The notebook must be useful with zero
   scanning; native scanning is a bonus, not a requirement.
5. **Provenance is a product feature.** Every import records source, tool,
   command, timestamp, hash, and chain position. "Where did this come from?"
   must always have an answer.
6. **Show your work.** Parser errors, partial imports, skipped rows, and source
   degradation are visible; never silently return zero.
7. **Progressive disclosure.** A first-time user sees a simple paste/import
   flow; power features (graph, ledger, adapters, API) appear when needed.
8. **No destructive defaults.** Imports are additive/idempotent; deletes are
   explicit; migrations back up first; config is never silently overwritten.
9. **Export or it didn't happen.** Every core object has a documented export
   path; no data lock-in.
10. **Small releases, migration tests.** Parser/schema changes ship with
    fixtures, golden files, and a migration path.

---

## 7. Gap-to-plan traceability

Every major issue found in the research maps to a concrete action. This is the
"fixing all of the issues you discovered" contract.

| Issue discovered | Evidence | Flagship fix | Phase |
|---|---|---|---|
| Install/dependency hell | Dradis, Faraday, Legion, Recon-ng, EyeWitness, Sn1per, BBOT modules | `breadcrumb doctor`, one-command Docker, pinned deps, no system Ruby/Java/Postgres | A |
| Silent/partial imports | theHarvester, Amass, reconFTW, BBOT | Parser contract, row-level errors, partial-import report, "zero entities" explanation | A |
| Evidence provenance is missing everywhere | All competitors | Evidence manifest v2: source/tool/command/time/hash/chain position, exportable and verifiable | A |
| Large-import performance unknown | reNgine, BBOT, Amass, Faraday | Streaming/batched import, pagination, FTS, 10k/100k benchmarks, memory caps | A/D |
| First-run friction | reNgine, DefectDojo, Faraday, Reconmap | Sample data, guided import, doctor, "first report in 5 minutes" path | A |
| No cross-program memory | All except Amass's DNS asset DB | Ledger v2: asset timeline, "seen before", cross-program links, saved views | B |
| Weak cross-scan/cross-program diff | reNgine, Sn1per, Amass | Diff v2: findings/ports/DNS/endpoints/tech/headers/risk, cross-program view, alerts | B |
| Scope controls are coarse | reNgine, reconFTW, theHarvester | Status-code/path/rule filters, per-rule severity, import-time scope classification | B |
| Reporting is a separate product | Dradis, Ghostwriter, DefectDojo, reNgine | Templates, redaction, PDF/HTML/Markdown/JSON, HackerOne/DefectDojo/Ghostwriter exports | C |
| No team review path | Ghostwriter, Dradis, Reconmap | Read-only review bundle (HTML + JSON + manifest), optional comments file; no auth wall | C |
| No integrations | DefectDojo, Faraday, IntelOwl, Ghostwriter | Export adapters first; optional Jira/MISP/Elastic webhooks later | C |
| No scheduled automation | reNgine, Faraday, DefectDojo | Scheduled re-import/watch folder first; optional scheduled native jobs later | D |
| Parser extension is hard | Recon-ng, Sn0int, BBOT, IntelOwl | Curated parser SDK, local examples, contract tests; no remote marketplace | D |
| API is incomplete | reNgine, Osmedeus, Faraday, Ghostwriter | OpenAPI, stable pagination, bulk endpoints, examples, CI gate | D |
| Screenshot evidence is missing | EyeWitness, reNgine, Sn1per | Import EyeWitness/Gowitness manifests/images; no embedded browser | E |
| Native execution can be unsafe | Breadcrumb 0.4.0 | Keep executor off by default; scope preflight; argv-only; egress guidance; strict mode | E/F |
| Release/staleness risk | SpiderFoot, Recon-ng, Axiom, Legion, EyeWitness | Small, frequent releases; support policy; deprecation/migration notes | F |
| Team/SSO/RBAC demand | reNgine, DefectDojo, Reconmap, Ghostwriter | Document reverse-proxy auth; optional review bundle; defer multi-user | C/F |
| Cloud/distributed demand | Axiom, Osmedeus | Document external adapters; do not build | Non-goal |
| Exploit demand | Sn1per, Legion | Do not build; export evidence to the exploit tool | Non-goal |
| AI trust | reNgine cloud GPT | Local-only, cited summaries, no auto-confirm, model picker, fallback | A/C |

---

## 8. Phases

### Phase A — Proof: import reliability, onboarding, evidence manifest

**Goal:** make the first hour trustworthy and fast. This is the foundation for
everything else.

**Deliverables**

1. **Parser contract v1**
   - Every parser returns structured `entities`, `findings`, `warnings`, and
     `skipped_rows` with a reason.
   - Auto-detect common formats (nmap, nuclei, httpx, subfinder, amass, ffuf,
     dalfox, whatweb, wafw00f, Burp, Nessus, CSV/JSONL) with a confidence hint.
   - Golden-file fixtures for each parser; malformed/partial inputs are tested.
   - Idempotency: re-import never duplicates findings/entities.
2. **Evidence manifest v2**
   - Per capture: source tool, command, timestamp, input hash, output hash,
     parser version, scope decision, chain position, and warnings.
   - Exportable `manifest.json` + human-readable `manifest.md`.
   - `breadcrumb verify` checks chain + manifest consistency offline.
   - Redaction: secrets never appear in the manifest.
3. **Onboarding**
   - `breadcrumb doctor` checks Python, SQLite, disk, permissions, key file,
     optional tools, and port availability.
   - Sample program + sample capture + one-click demo report.
   - "First report in 5 minutes" guide with a real paste.
   - Clear error messages for the top 20 failure modes.
4. **Performance baseline**
   - Benchmarks for 10k/100k entities on the target laptop.
   - Streaming/batched inserts; pagination; FTS for search.
   - Memory caps and a visible truncation warning.
5. **Docs**
   - Import cookbook per tool.
   - "What Breadcrumb is / is not" page.
   - Troubleshooting matrix.

**Acceptance criteria**

- 100% of parser fixtures pass; malformed inputs produce actionable errors.
- 100k-entity import completes without data loss on the target laptop; time and
  memory are documented.
- Re-import is idempotent for every fixture.
- A new user can go from install to a report in under 10 minutes using the
  sample data.
- `breadcrumb doctor` identifies a missing tool/key/permission with a fix.
- Manifest export/verify round-trips on a real capture.

**Effort:** 2–3 focused weeks.
**Risk:** parser scope creep. Keep the initial format list to the tools already
in the README; add more only after the contract is stable.

---

### Phase B — Memory: Ledger v2, diff v2, scope v2

**Goal:** make the cross-program memory and change detection undeniable.

**Deliverables**

1. **Ledger v2**
   - Asset timeline across all programs: first seen, last seen, programs,
     targets, captures, verdicts, tags, notes.
   - "Seen before" badge with links and a diff of what changed.
   - Saved views/filters (`type:port scope:in tag:needs-auth seen:other-program`).
   - Export Ledger slice to JSONL/CSV.
2. **Diff v2**
   - Compare any two captures, scans, targets, or programs.
   - Categories: findings, ports, DNS, endpoints, technologies, headers, risk.
   - "New since last run", "disappeared", "changed", "still open".
   - Change alerts via the existing notification channels.
3. **Scope v2**
   - Status-code filters, path-prefix rules, per-rule severity overrides.
   - Import-time scope classification with an explainable decision.
   - Bulk re-scope and "why is this out of scope?" UI.
4. **Graph v2**
   - Ledger-aware graph: cross-program edges, path highlighting, saved clusters.
   - Large-cluster summaries and filters; no browser performance cliff.
5. **Docs**
   - "Cross-program memory" narrative with a worked example.
   - Diff cookbook.
   - Scope decision reference.

**Acceptance criteria**

- A host seen in program A is surfaced in program B with links to both.
- Diff between two real scans is accurate for all categories and exportable.
- Scope decisions are explainable and testable; no silent out-of-scope drops.
- Graph remains responsive on a 100k-entity program.
- Ledger export round-trips into a new database.

**Effort:** 2–3 focused weeks.
**Risk:** over-modeling the graph. Start with the existing typed nodes/edges and
add only the cross-program queries the UI needs.

---

### Phase C — Report: templates, redaction, review bundle, integrations

**Goal:** turn evidence into a submission-ready artifact faster than any
competitor's local path.

**Deliverables**

1. **Report templates**
   - Built-in: HackerOne, pentest executive summary, technical finding, recon
     inventory, change report.
   - Template variables with validation and preview.
   - PDF/HTML/Markdown/JSON; optional DOCX later if a dependency is acceptable.
2. **Redaction**
   - Secret/cookie/auth-header masking by default.
   - Per-report redaction rules; `?reveal=1` remains explicit.
   - Redaction tests with hostile text/HTML/PDF escaping.
3. **Review bundle**
   - Read-only HTML + JSON + manifest + evidence files in a zip.
   - Optional comments file (local, exportable); no login.
   - "Send to reviewer" instructions that preserve local-only defaults.
4. **Integration exports**
   - DefectDojo-compatible findings JSON.
   - Ghostwriter/Dradis-friendly report bundle.
   - HackerOne markdown; SARIF; CSV/JSONL.
   - Optional webhook/Jira/MISP adapter design (not necessarily implementation).
5. **Docs**
   - Report cookbook per template.
   - Redaction/security guide.
   - Integration mapping tables.

**Acceptance criteria**

- Golden reports for each template pass snapshot tests.
- Secrets never appear in a default export; redaction is test-covered.
- A review bundle opens offline and includes a verifiable manifest.
- DefectDojo import of the exported JSON succeeds in a test instance.
- A user can produce a HackerOne report from a sample program in under 5
  minutes.

**Effort:** 2–3 focused weeks.
**Risk:** template engine complexity. Keep a small, documented template
language; do not build a full document editor.

---

### Phase D — Automate: scheduled re-import, parser SDK, API, performance

**Goal:** make Breadcrumb a dependable automation target without becoming a
platform.

**Deliverables**

1. **Scheduled re-import**
   - Cron-like schedule for watch folders/URLs/API pulls.
   - Run history, last success/failure, next run, notifications.
   - Idempotent imports and clear overlap policy.
2. **Parser SDK**
   - `Parser` protocol + example package + tests.
   - Local parser directory (`~/.breadcrumb/parsers` or repo-local) with
     version pinning and a safety review checklist.
   - No remote marketplace; examples are curated in-repo.
3. **API/automation**
   - OpenAPI spec and generated examples.
   - Stable pagination/filtering; bulk ingest/triage; idempotency keys.
   - CI gate, SARIF, webhook, and backup endpoints documented.
   - API token/reverse-proxy auth guidance (no built-in multi-user).
4. **Performance**
   - 100k/1M entity benchmarks; query plans; FTS; streaming export.
   - Background maintenance (VACUUM/ANALYZE) and health metrics.
5. **Docs**
   - Automation cookbook (CI, cron, drop folder, API).
   - Parser authoring guide.
   - Performance tuning guide.

**Acceptance criteria**

- A scheduled re-import runs unattended for 7 days with correct run history.
- A sample third-party parser passes the contract tests without core changes.
- OpenAPI examples work against a fresh database.
- 1M-entity search/filter responds within the documented target.
- No core feature requires a cloud service.

**Effort:** 2–3 focused weeks.
**Risk:** API surface creep. Version the API and keep the contract small.

---

### Phase E — Capture: optional screenshot/evidence import and adapter hardening

**Goal:** close the evidence gap without inheriting browser fragility.

**Deliverables**

1. **Screenshot import**
   - EyeWitness/Gowitness manifest + image import.
   - Link screenshots to targets/URLs/findings; thumbnails in the UI.
   - Store images as evidence artifacts with hashes; no browser dependency.
2. **Adapter hardening**
   - More opt-in adapters (only where a stable output contract exists).
   - Scope preflight, argv-only, process-group cancellation, output caps.
   - "Tool not installed" and "version mismatch" diagnostics.
3. **Optional browser capture (decision gate)**
   - Only if a maintained headless dependency can be isolated and tested.
   - Default off; never required for core value.
4. **Docs**
   - Screenshot import cookbook.
   - Adapter safety model.

**Acceptance criteria**

- Screenshot import preserves hashes and links to the right target.
- No browser/Chromium dependency in the default install.
- Adapter tests cover denial, timeout, cancellation, and missing binary.
- A screenshot-bearing report passes redaction/escaping tests.

**Effort:** 1–2 focused weeks (import path); browser capture is a separate
decision.
**Risk:** image storage bloat. Use content-addressed storage and size caps.

---

### Phase F — Flagship: hardening, migration, docs, release

**Goal:** ship 1.0 as a trustworthy, documented, benchmarked product.

**Deliverables**

1. **Security review**
   - Re-run the checklist; add evidence manifest/redaction/screenshot threats.
   - Dependency audit; no shell=True; secret scan; local boundary tests.
2. **Migration/rollback**
   - Schema/parser migration tests from 0.4.0 and each prior release.
   - Backup/restore drill; key rotation; import rollback.
3. **Performance/reliability**
   - 24-hour soak test for the worker/watch folder.
   - Crash recovery, lease expiry, cancellation, disk-full behavior.
4. **Docs**
   - "Why Breadcrumb" narrative with the research findings.
   - Full CLI/API/report/parser references.
   - Troubleshooting, backup/restore, security, and contribution guides.
5. **Release**
   - `1.0.0` changelog, release notes, tag, checksums.
   - Support/deprecation policy.
   - Public roadmap with the next three bets.

**Acceptance criteria**

- Full test suite passes; new benchmarks are documented.
- Security checklist is signed with evidence.
- Upgrade from 0.4.0 works on a copy of the real database.
- Rollback drill succeeds.
- Docs links are valid; no secrets/PII in the repo.
- 1.0 release notes clearly state what Breadcrumb is and is not.

**Effort:** 2 focused weeks.
**Risk:** release gate becomes a forever project. Timebox it and ship.

---

## 9. Data model, API, and UX changes (conceptual)

### Data model

- `Capture`: add `source_tool`, `source_command`, `input_hash`, `output_hash`,
  `parser_version`, `scope_decision`, `warnings`, `manifest_version`.
- `EvidenceManifest`: a derived, exportable view over captures and chain
  positions; no new source of truth.
- `AssetMemory`: a derived Ledger view over entities/targets/programs; no
  duplicate storage unless benchmarks require a materialized table.
- `ReportTemplate`: name, version, variables schema, redaction policy.
- `ReviewBundle`: a build artifact, not a database entity.
- `Schedule`: watch folder/URL/API pull, cron expression, last/next run,
  overlap policy, notification config.
- `Parser`: a local plugin descriptor with version/contract/safety metadata.

### API

- Keep `/api/v1` stable; add OpenAPI.
- Add idempotency keys for ingest.
- Add pagination/filtering for Ledger/diff/report endpoints.
- Add `POST /api/v1/reports` with template + redaction options.
- Add `GET /api/v1/manifest/{capture_id}` and `POST /api/v1/verify-manifest`.
- Add `POST /api/v1/schedules` and run history.
- Do not add auth by default; document reverse-proxy auth.

### UX

- First-run: paste/upload → auto-detect → preview → import → report.
- "Seen before" badge and Ledger panel on every entity.
- "Why is this out of scope?" explainer.
- Report builder with template preview and redaction toggles.
- Doctor/preflight page with copy-paste fixes.
- Command palette entries for every new flow.
- Saved views and shareable (local) links.

---

## 10. Metrics and KPIs

The flagship plan should be judged on outcomes, not feature count.

| Metric | Baseline | Target |
|---|---|---|
| Time to first structured import | Unknown | < 2 minutes with sample data |
| Time to first report | Unknown | < 10 minutes from install |
| Import success rate on fixtures | Unknown | 100% with visible errors for malformed input |
| 100k-entity import time | Unknown | Documented; no data loss |
| Re-import duplicate rate | 0 expected | 0 for all fixtures |
| Cross-program recall | Unknown | 100% of seeded assets surfaced in the Ledger test |
| Diff accuracy | Unknown | 100% on golden scan pairs |
| Default-export secret leaks | 0 expected | 0 in redaction tests |
| Manifest verify round-trip | N/A | 100% on real captures |
| Crash-free worker soak | Unknown | 24 hours |
| Test suite | 182 passed | No regressions; new parser/report tests |
| Install success on clean Linux | Unknown | One command; doctor explains failures |
| Docs link check | 0 broken | 0 broken |

---

## 11. Security and privacy

The research found that security is both a differentiator and a failure mode
(reNgine CVEs, local no-auth UIs, scanner supply chains).

**Non-negotiables**

- Bind to `127.0.0.1` by default; Docker publishes only to localhost.
- Host allowlist, Origin/Sec-Fetch-Site checks, CSRF on form posts.
- No telemetry; no cloud call unless the user configures it.
- Secrets encrypted at rest; key file `0600`; key-loss error is explicit.
- Redaction by default in exports/manifests/AI prompts.
- External tools: argv-only, no shell, scope preflight, process-group kill,
  output caps, environment allowlist.
- Executor off by default; adapters opt-in; strict mode documented.
- Dependency audit and secret scan before each release.
- Report/screenshot escaping tests for hostile content.

**New threats to cover**

- Manifest tampering: verify hashes/chain positions, not just presence.
- Review bundle leakage: redaction + explicit "include evidence" choices.
- Screenshot metadata leakage: strip EXIF/location by default.
- Parser plugin code execution: local plugins are trusted code; document the
  trust boundary and offer a sandbox for optional plugins later.
- Scheduled imports: SSRF/scope checks, credential storage, overlap/cancel.
- Large-file DoS: size caps, streaming, timeouts, disk-full handling.

---

## 12. Non-goals

These are explicit product decisions, not missing features:

1. Cloud/distributed scanning.
2. Exploitation/exploit verification.
3. Full vulnerability management/ticketing.
4. Multi-tenant SaaS, SSO, RBAC in the core.
5. Remote plugin marketplace.
6. Autonomous AI agents.
7. Built-in browser automation as a default dependency.
8. Postgres/Redis/Neo4j.
9. A second service/database or React SPA port.
10. Chasing feature parity with reNgine/DefectDojo/Faraday.

If a future owner wants any of these, they should be a separate product or an
optional adapter, not a change to the core thesis.

---

## 13. Pre-mortem: how this plan could fail

| Failure scenario | Early warning | Mitigation |
|---|---|---|
| Phase A becomes a parser forever-project | More than 2 weeks on formats, no manifest | Freeze the format list; ship the contract + top 10 parsers. |
| Evidence manifest is too complex for users | Users ignore it; reports don't include it | Default to a one-line provenance badge; manifest is opt-in detail. |
| Ledger queries are slow at 100k+ | UI lag; full-table scans | Materialized summary table only if benchmarks require it; pagination. |
| Report templates become a document editor | Scope creep; dependency bloat | Small template language; export to Ghostwriter/Dradis for advanced layout. |
| Review bundle becomes multi-user auth | Login/SSO requests dominate | Keep read-only bundle; document reverse-proxy auth; defer. |
| Parser SDK becomes a marketplace | Supply-chain/security burden | Local, curated, version-pinned; no remote index. |
| Screenshot import bloats the DB | Large files; slow backup | Content-addressed artifacts + size caps + optional external store. |
| Scheduled imports surprise users | Duplicate/overlapping runs | Idempotency, overlap policy, run history, notifications. |
| Release gate slips | 1.0 never ships | Timebox Phase F; ship 0.9/1.0-rc if needed. |
| Owner burnout | No releases for months | Small releases; docs; ask for help; keep non-goals explicit. |

---

## 14. Go/no-go recommendation

**Go.** The plan is worth implementing because it strengthens what is already
unique and fixes the issues that actually block adoption. The research does not
support building a generic scanner platform; it supports making Breadcrumb the
best local evidence notebook.

**Recommended sequence**

1. Approve the thesis and non-goals.
2. Implement **Phase A** only; ship `0.5.0` "Proof".
3. Review the benchmark/manifest/onboarding results.
4. If A passes, implement **Phase B**; ship `0.6.0` "Memory".
5. Then C (`0.7.0` "Report"), D (`0.8.0` "Automate").
6. Treat E as optional; ship F as `1.0.0`.

**What would make it not worth it**

- If the owner wants to compete with reNgine/DefectDojo on breadth, the plan is
  too narrow.
- If the owner cannot commit to release discipline, the plan will stall.
- If the core must become multi-user/cloud, the local-first thesis and the
  plan's advantages disappear.

**Bottom line:** This is the best use of Breadcrumb's existing strengths and
the owner's constraints. It is worth implementing, but only if it stays
ruthlessly focused on evidence, memory, and reporting.

---

## 15. Decision log and open questions

| # | Decision | Status |
|---|---|---|
| Q1 | Keep Breadcrumb as the single system of record; Leadline is absorbed | Accepted in 0.4.0 |
| Q2 | Stay SQLite/single-process; no Postgres/Redis/Neo4j | Accepted |
| Q3 | Keep import-first; native scanning optional | Accepted |
| Q4 | Make the Ledger + evidence chain the flagship moat | Proposed |
| Q5 | Add report templates + review bundle before multi-user auth | Proposed |
| Q6 | Add a curated parser SDK, not a marketplace | Proposed |
| Q7 | Import screenshots; do not embed a browser by default | Proposed |
| Q8 | No cloud/distributed scanning in the core | Proposed |
| Q9 | No exploitation in the core | Proposed |
| Q10 | Ship 0.5.0 "Proof" before any other phase | Proposed |

**Open questions for the owner**

1. Is the "evidence-first notebook" thesis the right flagship, or is there a
   stronger niche you want to own?
2. Which first slice matters most: import reliability/onboarding (A), Ledger/
   diff (B), or reporting (C)?
3. Do you want DOCX report output, or are PDF/HTML/Markdown enough?
4. Is a read-only review bundle enough for team feedback, or do you need
   comments/auth in the core?
5. Which integrations are must-have: DefectDojo, Ghostwriter, Jira, MISP,
   Elastic, or none yet?
6. How much release cadence can you sustain: weekly, biweekly, monthly?
7. Should screenshot import be in 1.0, or is it a later integration?
8. What is the maximum acceptable import time for 100k entities on your
   laptop?

Only one of these should be answered now: the first-slice question. The rest
can wait until Phase A is measured.

---

## 16. Status

| Item | Status |
|---|---|
| Competitive research (19 external + baseline) | Done |
| 20 reasons per project | Done |
| Feature/anti-feature/improvement synthesis | Done |
| Breadcrumb comparison | Done |
| Flagship plan | Done |
| Application code changes | None |
| 0.4.0 release intact | Yes; `v0.4.0` on `4b0066d` |
| Implementation approval | **Pending owner decision** |
| Next step | Answer the first-slice question; then write the Phase A spec |

**Document maintenance:** update this plan after each phase with measured
results. Do not rewrite history; add a dated decision log entry.
