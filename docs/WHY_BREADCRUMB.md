# Why Breadcrumb

Breadcrumb exists because recon work is not lost at the scanning step. It is
lost afterwards: output sits in a dozen folders, the same host is rediscovered
on the next program, the screenshot that proved a finding is somewhere in a
Downloads directory, and the report is assembled by hand from memory.

The 2026-11 research looked at 19 projects in this space, plus the Leadline
baseline. The pattern was consistent:

- scanners are good at producing output and bad at remembering it;
- dashboards are good at aggregating a current engagement and bad at
  cross-program memory;
- report tools are good at formatting and bad at proving where the facts came
  from;
- most "platforms" buy those features with Postgres, Redis, a worker fleet, a
  cloud account, or a login system a solo hunter does not need.

Breadcrumb takes the opposite trade. It is one local SQLite database, one
process, and an import-first workflow. It does not try to be the scanner. It is
the place where the output becomes structured, deduplicated, tamper-evident
evidence, and then a report.

## The job it is hired for

A solo bug-bounty hunter is working three or more programs. They already run
nmap, subfinder, httpx, nuclei, BBOT, Amass, ffuf or a custom script. They want:

1. **One import path.** Paste, upload or POST output; get structured entities,
   findings and a visible import report. No per-tool database.
2. **Memory across programs.** When `api.example.com` appears again six weeks
   later on a different program, see that it was seen before, with links.
3. **Evidence that survives review.** Every capture has a source, timestamp,
   hash and chain position. A reviewer can verify it offline.
4. **A report in minutes.** Pick a template, apply default-on redaction, export
   HTML/Markdown/JSON/PDF or a read-only review zip.
5. **No operations tax.** No server to run, no account, no telemetry, no
   Postgres, no Redis, no graph database.

That is the whole product. Features that do not shorten one of those five paths
are not automatically welcome.

## What makes it different

| Common alternative | What it optimizes | What Breadcrumb does differently |
|---|---|---|
| reNgine, Faraday, reconFTW | Run and aggregate scans for one engagement | Imports from any tool, remembers across programs, one SQLite file |
| BBOT, Amass, SpiderFoot | Recursive discovery | Deterministic evidence notebook; scanner-optional |
| DefectDojo, Ghostwriter | Team vulnerability workflow | Solo workflow, no ticket queue, offline review bundle |
| Dradis, Reconmap | Report collaboration | Local report engine plus verifiable evidence, no auth wall |
| EyeWitness, Gowitness | Capture screenshots | Imports their output and links images to findings and provenance |
| Maltego, BloodHound | Visual link analysis | Free typed recon graph with scope attribution and diffs |

The distinctive combination is **cross-program memory + tamper-evident
captures + local-only reporting**. Each is useful alone. Together they make
old recon compound instead of evaporate.

## What Breadcrumb is not

- It is not a scanner. Native collectors and opt-in adapters exist, but the
  notebook is useful with zero scanning.
- It is not an exploitation or brute-force framework.
- It is not a full vulnerability-management or ticketing system.
- It is not a multi-tenant SaaS. There is no SSO, RBAC or remote account.
- It is not a cloud/distributed scanning control plane.
- It is not a browser-automation product. Screenshots are imported from tools
  that already captured them.
- It is not an autonomous AI agent. The local LLM explains and drafts; the
  deterministic parsers produce the facts.

These are deliberate boundaries, not missing roadmap items. Every one of them
would add operational or trust cost that the target user does not want to pay.

## The evidence model

Three ideas do most of the work:

1. **A capture is sealed.** The raw text is hashed and linked to the previous
   capture. Changing history breaks the chain; deleting a program creates a
   labeled gap, not a false tamper alarm.
2. **An import is explainable.** The parser contract records which parser ran,
   how complete the result was, which rows were skipped and why. A zero-entity
   import is a diagnostic, not a silent success.
3. **A report is derived.** Templates render one redacted context into every
   format. The review bundle ships the context, hashes and capture manifests so
   a reviewer can verify it without a server.

Screenshots extend the same model: the bytes are content-addressed outside
SQLite, the metadata is linked to the program/target/finding, and the hash is
verified on every read. Redaction masks text fields, not image pixels; the
product says so instead of implying otherwise.

## Who it is for

The primary user is a solo bug-bounty hunter or independent researcher with at
least three active programs who already uses CLI recon tools on a laptop. They
value recall, provenance and speed over dashboards and team features.

A small team can use a shared read-only bundle or put the app behind a reverse
proxy, but multi-user auth is intentionally out of scope. The local boundary is
part of the security model.

## What success looks like

- First structured import in under two minutes with the sample data.
- First report in under ten minutes from a clean install.
- A 100k-entity import with no loss and visible completeness.
- A re-import that creates no duplicates.
- A cross-program asset that is found every time it was seeded.
- A clean report with zero default-export secret leaks.
- A reviewer who can verify the bundle offline.
- A database and artifact directory a user can back up, move and still read a
  year later.

The 1.0 release gate checks the parts that can be checked automatically and
records the parts that still require an operator. See
[RELEASE_NOTES_1.0.0.md](RELEASE_NOTES_1.0.0.md) and
[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md).

## Where the research lives

- [COMPETITIVE_RESEARCH_2026-11-08.md](COMPETITIVE_RESEARCH_2026-11-08.md) —
  19 projects, success/failure reasons, feature demand and anti-features.
- [FLAGSHIP_PLAN_2026-11-08.md](FLAGSHIP_PLAN_2026-11-08.md) — thesis, phases,
  acceptance criteria, metrics and pre-mortem.
- [ROADMAP.md](ROADMAP.md) — the next three bets and explicit non-goals.
