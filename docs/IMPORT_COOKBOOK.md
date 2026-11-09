# Import cookbook

The first mile is the product. This page shows the supported commands for the
top formats, how to read the import report, and what to do when an import
produces zero entities.

Start with:

```bash
python -m app.cli doctor
python -m app.cli demo
```

`doctor` checks Python, SQLite, the database directory, disk space, schema,
key file, port, parser registry and optional tools. `demo` seeds a sample
program and prints a report URL.

## 1. The five formats that matter

### nmap (text, greppable, XML)

```bash
nmap -sV -oN nmap.txt app.example.com
python -m app.cli ingest nmap.txt --program 1 \
  --command "nmap -sV -oN nmap.txt app.example.com"
```

### httpx JSONL

```bash
httpx -json -l hosts.txt -o httpx.jsonl
python -m app.cli ingest httpx.jsonl --program 1 \
  --command "httpx -json -l hosts.txt -o httpx.jsonl"
```

### nuclei JSONL

```bash
nuclei -jsonl -l urls.txt -o nuclei.jsonl
python -m app.cli ingest nuclei.jsonl --program 1 \
  --command "nuclei -jsonl -l urls.txt -o nuclei.jsonl"
```

Nuclei findings become severity-tagged `Finding` rows. Re-importing the same
output does not duplicate them (stable `nuclei|template|matched-at|matcher`
fingerprint).

### BBOT JSON/JSONL

```bash
bbot -t example.com -f json -o bbot.jsonl
python -m app.cli ingest bbot.jsonl --program 1 \
  --command "bbot -t example.com -f json -o bbot.jsonl"
```

The BBOT parser understands `DNS_NAME`, `IP_ADDRESS`, `OPEN_TCP_PORT`,
`URL`, `HTTP_RESPONSE`, `TECHNOLOGY`, `EMAIL_ADDRESS`, `CIDR`, `ASN`,
`STORAGE_BUCKET`, `WEBSCREENSHOT`, `FINDING` and `VULNERABILITY` events.
Unknown event types are ignored; malformed JSON rows are reported.

### Amass JSON

```bash
amass enum -json amass.json -d example.com
python -m app.cli ingest amass.json --program 1 \
  --command "amass enum -json amass.json -d example.com"
```

## 2. Read the import report

Every import writes a report. Print it:

```bash
python -m app.cli ingest scan.txt --program 1 --report-json -
```

Or query the API:

```bash
curl '/api/v1/pastes/12/report'
```

Key fields:

| Field | Meaning |
|---|---|
| `parsers` / `parser_versions` | Which parsers matched and their contract version |
| `parsed_entities` | What the parser produced before cross-capture dedup |
| `entities` | What survives in the notebook after consolidation |
| `consolidated` | True when every parsed row merged into records that already existed (a successful re-import, not an empty capture) |
| `findings` | New findings attributed to this capture |
| `skipped_rows` | Rows the parser could not read |
| `completeness` | Accounted-for output / (output + skipped rows) |
| `issues` | Stable `code` + human `message`; codes include `no_parser`, `skipped_row`, `truncated`, `exception` |
| `hint` | The next action when nothing was imported |

`--dry-run` runs the same parse and report without writing a capture:

```bash
python -m app.cli ingest scan.txt --dry-run
```

`--max-entities` raises the per-import cap (default 25,000). The API accepts
`max_entities` in the JSON body. Truncation is never silent: it appears as a
`truncated` issue and lowers `completeness`.

## 3. Zero entities: the diagnostic ladder

1. Run `python -m app.cli ingest <file> --dry-run`. If `parsers` is empty, the
   format is not recognized. Check for an HTML error page, a gzip file, or a
   tool version whose output shape changed.
2. If a parser matched but `parsed_entities` is zero, read the `issues` list.
   `skipped_row` points at a malformed line; `exception` means the parser hit a
   bug and the capture is still sealed with the error attached.
3. If `completeness` is below 100%, the import was partial. Do not trust a
   Ledger/report built from it until you re-import a clean artifact.
4. If the file is valid but the tool is new, add a parser under
   `app/parsers/` and a fixture under `tests/fixtures/parsers/`. The parser
   contract is `parse_detailed()` returning `ParseResult`; the legacy
   `parse()`/`findings()` methods still work.

## 4. Provenance and evidence

Pass the exact command and non-secret context so the manifest is useful:

```bash
python -m app.cli ingest httpx.jsonl --program 1 \
  --command "httpx -json -l hosts.txt -o httpx.jsonl" \
  --source-meta '{"filename":"httpx.jsonl","tool_version":"1.6.9"}'
```

Secrets in `--command` and `source_meta` are redacted in exported manifests by
default. See [MANIFEST_AND_DOCTOR.md](MANIFEST_AND_DOCTOR.md).

## 5. API equivalent

```bash
curl -X POST /api/v1/pastes \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "...",
    "program_id": 1,
    "source": "httpx",
    "command": "httpx -json -l hosts.txt",
    "source_meta": {"filename": "httpx.jsonl"},
    "max_entities": 50000
  }'
```

The response includes `paste_id`, `entities`, `findings`, `completeness`,
`skipped_rows`, `parser_versions`, `report_url` and `manifest_url`.

## 6. Version matrix and fixtures

The parser contract is tested against pinned fixtures for nmap, httpx, nuclei,
Amass, BBOT, ffuf, Dalfox, WhatWeb and wafw00f. When a tool changes output:

1. Save a redacted sample under `tests/fixtures/parsers/`.
2. Add a contract test that asserts entities/findings and zero skipped rows.
3. Bump the parser's `parser_version` if the meaning of a field changes.
4. Add the sample to the import report's version matrix in the release notes.

Do not "fix" a parser by silently dropping rows. The import report is the
contract with the user: every skipped row is visible.
