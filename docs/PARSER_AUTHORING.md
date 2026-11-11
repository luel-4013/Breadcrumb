# Parser authoring guide

Breadcrumb imports tool output through parsers. A parser turns one blob of
text into entities, relationships and optional findings while reporting what it
could not understand. Phase D adds a **local parser SDK**: you can add your own
parser in a folder without changing core code or publishing a package.

There is no remote marketplace, package index or auto-update. A parser is
ordinary Python imported into the Breadcrumb process, so it has the same trust
as code you run in a shell. Read [Trust boundary](#trust-boundary) before
installing one.

## 1. Where local parsers live

Resolution order:

1. `$BREADCRUMB_PARSER_DIR` when set;
2. `~/.breadcrumb/parsers` otherwise.

Create the directory, put one `.py` file per parser in it, and restart
Breadcrumb (or call `breadcrumb parsers` to load and list them):

```bash
mkdir -p ~/.breadcrumb/parsers
cp my_parser.py ~/.breadcrumb/parsers/
breadcrumb parsers
breadcrumb parsers --json
```

Files beginning with `_` or `.` are ignored, as are non-`.py` files and
subdirectories. A file larger than 2 MB is rejected. A broken file is recorded
as a load error and skipped; it never stops startup and never prevents the
built-in parsers from loading. See `/parsers` or `breadcrumb doctor` for the
error list.

## 2. The contract

A module must expose either:

- `PARSER` — a `Parser` instance or subclass, or
- `get_parser()` — a callable returning a `Parser`.

The parser must:

- subclass `app.parsers.base.Parser`;
- have a non-empty, unique `name` (the name `base` is reserved);
- implement `detect(text) -> float`, `parse(text)` and/or
  `parse_detailed(text) -> ParseResult`;
- have a non-empty `parser_version` (string, int or float is coerced to text).

`description` is optional. Optional `PARSER_META` (a dict) may carry `author`,
`homepage`, `license`, `description` and `version`; it is shown in the catalog
and is not used for execution.

The loader calls `parse_detailed()` during analysis. The base class implements
it by wrapping the legacy `parse()` + `findings()` methods, so a minimal parser
can implement only `parse()`. New parsers should override `parse_detailed()` to
account for skipped rows and warnings.

### `detect(text)`

Return a confidence score. `0` or less means “not mine”; any positive score
means the parser will run. Multiple parsers may match the same blob; their
entities are merged and sorted by detection score. Built-in formats usually
return `0.9`–`1.0`. Keep detection conservative: a parser that matches every
text will pollute unrelated imports.

### `ParseResult`

```python
from app.parsers.base import Entity, ParseResult, ParserIssue, Relationship

result = ParseResult(
    entities=[Entity(type="domain", value="app.example.com")],
    relationships=[
        Relationship(
            src_value="app.example.com", src_type="domain",
            dst_value="192.0.2.10", dst_type="ip",
            rel_type="resolves_to",
        )
    ],
    findings=[],
    issues=[ParserIssue(
        parser="example_scanner", code="skipped_row",
        message="line 4: missing host", line=4,
    )],
    skipped_rows=1,
    parser_version="1",
    stats={"records": 3},
)
```

`Entity` fields:

| Field | Notes |
|---|---|
| `type` | Stable lower-case kind, e.g. `domain`, `subdomain`, `url`, `ip`, `port`, `technology`, `header`, `secret`, `cve`. |
| `value` | Human-visible value. |
| `normalized` | Merge key; defaults to `value.strip()`. Lower-case host-like values yourself if case is not meaningful. |
| `confidence` | `0.0`–`1.0`; higher wins when two parsers emit the same `(type, normalized)`. |
| `meta` | JSON-serialisable extra facts (status, title, tech, source line). |
| `status_code` | Optional observed HTTP status (never guessed). Used by scope filters and the Ledger. |
| `tags`, `verdict`, `notes` | Analyst/provenance fields used by the Ledger JSONL importer; leave defaults in ordinary parsers. |

`Relationship` links two entity values. `rel_type` should be a stable verb such
as `resolves_to`, `has_port`, `references` or `part_of`.

`ParserIssue.code` should be one of the stable codes `exception`,
`skipped_row`, `truncated`, `unsupported` or `warning`. The message is shown to
the user and stored in the import report; do not put secrets in it.

### Findings

A finding is a plain dict. The ingest layer understands:

| Key | Meaning |
|---|---|
| `title` | Required, short finding title. |
| `severity` | `info`, `low`, `medium`, `high`, `critical`. |
| `cvss` | Optional numeric score. |
| `description`, `evidence` | Analyst-facing context; evidence is redacted at export. |
| `tags` | List of strings. |
| `dedup_key` | Stable identity so a re-import does not duplicate the finding. |
| `target` | Host/URL used to attribute the finding to a target. |

A parser that recognizes a vulnerability should emit a **candidate** with its
evidence, never claim exploitation. Breadcrumb is not a scanner clone.

## 3. Complete example

Save as `~/.breadcrumb/parsers/example_scanner.py`:

```python
"""Example local parser for a fictional JSONL scanner."""

import json

from app.parsers.base import Entity, ParseResult, Parser, ParserIssue

PARSER_META = {
    "author": "you",
    "homepage": "https://example.invalid",
    "license": "MIT",
    "version": "1.0",
}


class ExampleScanner(Parser):
    name = "example_scanner"
    description = "Example scanner JSONL (one object per line)"
    parser_version = "1.0"

    def detect(self, text: str) -> float:
        # Look for a distinctive marker, not a generic word.
        return 0.95 if '"example_scan"' in text else 0.0

    def parse_detailed(self, text: str) -> ParseResult:
        result = ParseResult(parser_version=self.parser_version)
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                result.skipped_rows += 1
                result.issues.append(
                    ParserIssue(
                        parser=self.name,
                        code="skipped_row",
                        message=f"line {number}: invalid JSON",
                        line=number,
                    )
                )
                continue
            if row.get("kind") != "example_scan":
                continue
            host = str(row.get("host") or "").strip()
            if not host:
                result.skipped_rows += 1
                result.issues.append(
                    ParserIssue(
                        parser=self.name,
                        code="skipped_row",
                        message=f"line {number}: missing host",
                        line=number,
                    )
                )
                continue
            result.entities.append(
                Entity(
                    type="subdomain",
                    value=host,
                    normalized=host.lower(),
                    meta={"source": "example"},
                )
            )
            result.stats["records"] = result.stats.get("records", 0) + 1
        return result


PARSER = ExampleScanner()
```

Verify it:

```bash
breadcrumb parsers                 # example_scanner appears as local
printf '{"kind":"example_scan","host":"App.Example.com"}\n' \
  | breadcrumb ingest - --dry-run
```

The dry-run report includes the parser name, version, entity count, skipped
rows and completeness.

## 4. Contract checklist

Before trusting a parser, confirm:

- [ ] `detect()` returns 0 for unrelated inputs (try a P99 nmap file and a
      random README).
- [ ] `parse_detailed()` always returns `ParseResult`, never `None`.
- [ ] Malformed JSON/CSV rows increment `skipped_rows` and add an issue with a
      line number; they are not silently dropped.
- [ ] `normalized` is stable across case/whitespace variants so the Ledger
      merges duplicates instead of creating twins.
- [ ] No network calls, subprocesses, file writes or environment reads during
      `detect()`/`parse_detailed()`; parsers are pure functions of the text.
- [ ] No secret values in issue messages, `stats` or `meta`.
- [ ] Findings have a stable `dedup_key` and a conservative severity.
- [ ] `parser_version` changes when output semantics change.
- [ ] A 10k-line fixture completes quickly and does not hold the input twice
      unnecessarily.
- [ ] The parser works with `BREADCRUMB_PARSER_DIR` pointing at a copy of the
      folder, with no imports from your home directory.

## 5. Testing without core changes

A plugin can be tested like any module. Point the loader at a temporary folder
and restore the registry afterwards:

```python
from app.parsers import REGISTRY, analyze_detailed
from app.parsers import sdk

def test_my_parser(tmp_path):
    (tmp_path / "my_parser.py").write_text(source)
    before = list(REGISTRY)
    try:
        loaded = sdk.load_local_parsers(tmp_path)
        assert [item["name"] for item in loaded] == ["my_parser"]
        result = analyze_detailed(sample_text)
        assert result.parsers == ["my_parser"]
        assert result.skipped_rows == 1
    finally:
        REGISTRY[:] = before
        sdk.PLUGINS.clear()
        sdk._LOADED_PATHS.clear()
        sdk.PLUGIN_ERRORS.clear()
```

The Phase D test suite (`tests/test_phase_d.py`) uses this exact pattern,
including a broken plugin and a duplicate-name plugin to prove isolation.

## 6. Trust boundary

- A local parser is **executed**, not sandboxed. It can read files, open
  sockets and import anything the Breadcrumb process can. Only install code
  you wrote or reviewed.
- The SDK does not download, sign, verify or update plugins. There is no
  registry, no dependency resolver and no privilege separation.
- `load_local_parsers()` imports modules at startup and on the first analysis.
  A syntax error or exception is captured in the plugin error list; a plugin
  that hangs or exhausts memory can still hang the process. Test untrusted code
  outside Breadcrumb first.
- Removing a plugin file removes it from the next process start; no database
  migration is involved. Captures already parsed keep their original parser
  name/version in their manifest.
- Bundled parsers are covered by the repository's tests; local parsers are
  your responsibility. `breadcrumb doctor` reports the local count and any
  load errors but cannot vouch for behaviour.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| Parser missing from `breadcrumb parsers` | Correct directory (`BREADCRUMB_PARSER_DIR`), `.py` suffix, file not starting with `_`, size < 2 MB. |
| Load error shown | Run `breadcrumb parsers --json`; fix the import/contract error, then restart. |
| Parser loads but never runs | `detect()` returns 0 for the fixture; make the marker distinctive. |
| Entities missing from the Ledger | `normalized` values differ by case or whitespace; use a stable key. |
| Completeness below 1.0 | `skipped_rows` is non-zero; that is honest. Fix the rows or lower the count only if they were intentionally ignored. |
| Duplicate entities | Another parser emitted the same `(type, normalized)` with higher confidence; check `result.parsers` order. |
| Findings not de-duplicated | Give each stable finding a `dedup_key` (for example `template-id|host|path`). |
