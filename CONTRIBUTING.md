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
- **No markdown docs in code PRs** except under `.github/` and the root
  publishing files (`README.md`, `CONTRIBUTING.md`). Keep code comments short.

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

## Reporting security issues

Do not open a public issue for vulnerabilities. Contact the maintainers
privately (see README) so a fix can ship first.
