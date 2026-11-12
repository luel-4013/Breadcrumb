# Contributing to Breadcrumb

Thanks for helping. Breadcrumb is a small, dependency-light codebase on purpose —
please keep it that way.

## Setup

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python run.py   # http://127.0.0.1:8787
```

Tests use an isolated temp database, never your real `breadcrumb.db`:

```bash
.venv/bin/python -m pytest tests/ -q
```

## Ground rules

- **Offline-first.** No network calls except to a user-configured LLM endpoint.
  New features must work fully offline.
- **SQLite + stdlib where possible.** Avoid adding dependencies; every new
  dependency needs justification in the PR.
- **Deterministic before AI.** Parsers, scope, attribution, and reports must be
  exact and testable. AI is a layer on top, never the source of truth.
- **Timezone-aware datetimes.** Use `datetime.now(timezone.utc)`, never
  `utcnow()`.
- **Migrations, not resets.** New model fields go in `app/db.py` `MIGRATIONS`
  so existing databases keep working.
- **Docs live in `docs/`.** Keep code comments short. Operator-facing docs,
  release notes and runbooks belong under `docs/`; root publishing files are
  `README.md`, `CONTRIBUTING.md` and `CHANGELOG.md`.

## Adding a parser

1. Create `app/parsers/<name>.py` with a `Parser` subclass (see
   `app/parsers/base.py`), decorated with `@register`.
2. Add unit coverage in `tests/test_app.py` or a new test module: one positive
   sample, one negative sample, expected entities.
3. Update the parser list in `README.md`.

## Pull requests

- One concern per PR. Include a test for behavior changes.
- Run `compileall` and `pytest` before pushing — CI runs both.
- Describe the hunter workflow your change improves, with a short example.
- If you add a top-level CLI command or an `/api/v1` route, update
  `docs/CLI_REFERENCE.md` or `docs/API_REFERENCE.md`; the release checker fails
  otherwise.
- If you change storage, add an additive migration in `app/db.py`, bump
  `SCHEMA_VERSION`, and extend the migration test. Do not drop tables or rewrite
  evidence hashes.

## Release gates

Run these before tagging a release. The short versions are safe on a laptop:

```bash
# Full suite (isolated temp DB; never the real breadcrumb.db)
.venv/bin/python -m pytest -q

# Static/source gate: dangerous code, secrets, docs links, pins, CLI/API coverage
TMPD=$(mktemp -d)
BREADCRUMB_DB_PATH="$TMPD/release.db" BREADCRUMB_SKIP_BACKUP=1 \
  .venv/bin/python -m app.cli release check --json

# Dependency inventory; --online queries OSV with package names/versions only
.venv/bin/python scripts/dependency_audit.py --online

# Upgrade/rollback every prior tag plus a copy of the local DB
.venv/bin/python scripts/migration_drill.py --all --real-db breadcrumb.db

# Accelerated schedule/queue soak; use --duration 86400 for acceptance
.venv/bin/python scripts/soak.py --cycles 40
```

A release also needs a clean `compileall`, a changelog entry with the schema
version and test count, migration/rollback notes when storage changes, and an
archive generated from the tag:

```bash
git archive --format=zip --prefix=breadcrumb-<version>/ v<version> \
  -o dist/breadcrumb-<version>.zip
sha256sum dist/breadcrumb-<version>.zip > dist/SHA256SUMS
```

Do not rewrite an existing tag. Record the release-gate output with the release
notes or an incident/evidence file.

## Adding a local parser plugin

The core parser contract is described in `docs/PARSER_AUTHORING.md`. A plugin is
trusted local Python, loaded from `BREADCRUMB_PARSER_DIR` or
`~/.breadcrumb/parsers`; it is not sandboxed and there is no remote marketplace.
Keep built-in behavior deterministic and add a fixture plus a test for every new
format or tool version.

## Reporting security issues

Do not open a public issue for vulnerabilities. Contact the maintainers
privately (see README) so a fix can ship first.
