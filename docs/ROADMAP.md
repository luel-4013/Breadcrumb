# Public roadmap

**Current release:** 1.0.0 (schema 8).
**Thesis:** the offline-first evidence notebook for solo bug-bounty hunters.
**Rule:** a proposal must shorten import → evidence → memory → report, or make
one of those paths more trustworthy. Feature count is not a goal.

This roadmap is directional, not a promise. Security and data-integrity work
always takes priority.

## Next three bets

### 1. Faster evidence at scale

**Problem:** the 1.0 path is comfortable at 100k entities and readable at 1M,
but a hunter who imports years of output should not wait minutes for a search
or a diff.

**Bets:**
- streaming import with bounded memory and resumable checkpoints;
- FTS ranking and saved-view query plans tuned for 1M+ rows;
- incremental snapshot/diff work instead of rebuilding a whole target;
- a repeatable benchmark gate for every release.

**Not:** a distributed database, Postgres, or a separate search service.

### 2. Richer capture without a browser

**Problem:** screenshots are the first non-text evidence type, but HTTP
responses, TLS certificates and HAR files carry proof that a screenshot cannot.

**Bets:**
- import HTTP response bodies, headers, TLS chains and HAR files as hashed
  artifacts with explicit size caps;
- content-addressed storage and manifests shared with the screenshot path;
- report/bundle inclusion rules that keep redaction and “pixels/bytes are not
  redacted” warnings honest;
- no embedded browser, no automatic crawling, no remote fetch.

**Not:** a browser-automation or exploitation platform.

### 3. Review without a server

**Problem:** a solo hunter still needs a reviewer to trust a bundle without
installing Breadcrumb or creating an account.

**Bets:**
- signed bundle manifests and a small standalone verifier;
- diffable report revisions so a reviewer can see what changed;
- optional reviewer comments that round-trip into the next revision;
- clearer redaction previews before export.

**Not:** SaaS review rooms, SSO, RBAC, or a hosted evidence locker.

## Explicit non-goals

- Cloud/distributed scanning or a scan control plane.
- Exploitation, brute force or credential attacks.
- Full vulnerability-management, ticketing or asset-inventory suites.
- Multi-tenant SaaS, SSO, RBAC or per-user audit.
- A remote plugin/adapter marketplace.
- Autonomous AI agents that invent findings or take actions.
- Default browser automation or embedded Chromium/Selenium.
- Postgres, Redis, Neo4j or another required service.

## How items graduate

1. A written problem statement with a hunter workflow and a non-goal check.
2. A fixture or benchmark that fails today.
3. A small, additive implementation behind an explicit opt-in when it expands
   the trust boundary.
4. Tests, docs, a migration/rollback note if storage changes, and a release
   gate run.

See [FLAGSHIP_PLAN_2026-11-08.md](FLAGSHIP_PLAN_2026-11-08.md) for the original
phase plan and [WHY_BREADCRUMB.md](WHY_BREADCRUMB.md) for the product thesis.
