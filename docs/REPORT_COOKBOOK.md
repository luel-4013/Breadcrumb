# Report cookbook

Status: **Phase C, Breadcrumb 0.7.0.** Five built-in templates, one validated
context, four formats, and an offline review bundle. There is deliberately no
document editor and no remote template marketplace.

The report path is designed around one rule: **the same redacted context feeds
every format.** Markdown, HTML, JSON and PDF cannot disagree about a finding,
and a secret cannot be masked in one download but leak in another.

## The five-minute path

```bash
# 1. Seed a sample program with findings, entities and two captures.
python -m app.cli demo

# 2. Open the printed URL, for example:
#    http://127.0.0.1:8787/programs/1/reports

# 3. Pick a template, adjust the date/author, and press Preview.
# 4. Download Markdown, HTML, JSON or PDF, or build a review bundle.
```

From the CLI, without a browser:

```bash
python -m app.cli report-templates
python -m app.cli render 1 --template hackerone --format md -o report.md
python -m app.cli render 1 --template technical --format pdf -o report.pdf
python -m app.cli bundle 1 --template technical --comments notes.md -o review.zip
python -m app.cli verify-bundle review.zip
```

The demo is idempotent: running it again does not duplicate the sample program
or its captures. If the demo already exists, the same program id is reused.

## Built-in templates

| Template id | Name | Sections | Best for |
|---|---|---|---|
| `hackerone` | HackerOne submission | summary, scope, targets, findings | A submission-ready writeup per finding |
| `executive` | Pentest executive summary | summary, risk, scope, highlights, findings table, recommendations, methodology | A client/program manager who needs risk and priorities |
| `technical` | Technical finding report | summary, findings | Full reproduction, evidence, impact and remediation |
| `recon` | Recon inventory | summary, scope, targets, inventory, findings table | Showing attack surface, scope and collected assets |
| `change` | Change report | summary, changes, findings table | "What changed since last time?" |

`hackerone`, `executive`, `technical` and `recon` are finding-oriented.
`recon` adds the entity inventory. `change` uses the same Diff v2 engine as
`/diff` and defaults to the previous capture versus the latest capture.

## Variables

Variables are typed, validated once, and stored in the report JSON under
`variables`. Unknown query parameters are ignored by routes (message flags such
as `submitted` should not fail a report); `strict_unknown=True` is available to
library callers.

### Common variables

| Key | Type | Default | Notes |
|---|---|---|---|
| `title` | text | empty | Defaults to `<program> — <template name>` |
| `client` | text | empty | Client or organization |
| `author` | text | empty | Researcher/author |
| `engagement` | text | empty | Engagement or program reference |
| `report_date` | date | today (UTC) | Must be `YYYY-MM-DD` |
| `confidentiality` | choice | `confidential` | `confidential`, `internal`, `public` |
| `executive_summary` | textarea | empty | Escaped in HTML/PDF |
| `methodology` | textarea | empty | Escaped in HTML/PDF |
| `severity_floor` | choice | `info` | `info`, `low`, `medium`, `high`, `critical` |
| `max_findings` | integer | `50` | 1–250 |
| `include_scope` | checkbox | `true` | Scope section |
| `include_targets` | checkbox | `true` | Targets section |
| `include_inventory` | checkbox | `false` | Entity inventory |
| `include_findings` | checkbox | `true` | Finding detail/table |
| `include_evidence` | checkbox | `true` | Evidence blocks |
| `include_changes` | checkbox | `false` | Change summary where supported |
| `include_triaged` | checkbox | `false` | Include false-positive/triaged findings for internal review |
| `redaction_profile` | choice | `default` | `default` or `strict` |
| `redaction_rules` | textarea | empty | `literal:` / `regex:` lines; additive |
| `reveal` | checkbox | `false` | **Unsafe.** Disables all masking |
| `footer` | text | empty | Optional footer note |

### Template-specific variables

| Template | Key | Purpose |
|---|---|---|
| `hackerone` | `program_handle` | HackerOne program handle |
| `hackerone` | `submission_url` | Submission URL |
| `hackerone` | `researcher` | Researcher handle |
| `executive` | `business_context` | Why the work matters |
| `executive` | `recommendations` | Prioritized recommendations |
| `technical` | `finding_id` | Render one finding by database id |
| `technical` | `affected_version` | Affected product/build |
| `technical` | `cwe` | CWE reference |
| `recon` | `target_notes` | Free-text target notes |
| `change` | `left_selector` | `paste:1`, `target:2`, `program:3`, `job:4` |
| `change` | `right_selector` | Optional; defaults to latest/previous capture |

Checkbox values accept `1`, `true`, `yes`, `on` (case-insensitive). A blank
date becomes today. A bad date, an out-of-range integer, an unknown choice or a
malformed custom rule produces a field-level validation error instead of a
partial report.

## Formats and routes

| Surface | Route / command | Notes |
|---|---|---|
| Builder + preview | `GET /programs/<id>/reports` | Interactive report studio |
| Preview fragment | `GET /programs/<id>/reports/preview` | Returns standalone HTML; 400 on validation error |
| Markdown | `GET /reports/<id>/templates/<template>.md` | `Content-Disposition: attachment` |
| HTML | `GET /reports/<id>/templates/<template>.html` | Self-contained, autoescaped |
| JSON | `GET /reports/<id>/templates/<template>.json` | Includes context, redaction metadata, warnings |
| PDF | `GET /reports/<id>/templates/<template>.pdf` | `%PDF` output; reportlab |
| Review bundle | `POST /reports/<id>/bundle` | Zip; form-encoded report variables |
| Template catalog | `GET /api/v1/report-templates` | Typed variable schema for scripts |
| CLI render | `python -m app.cli render <id> ...` | `md`, `markdown`, `html`, `json`, `pdf` |
| CLI bundle | `python -m app.cli bundle <id> ...` | `--comments`, `--include-pdf` |
| CLI verify | `python -m app.cli verify-bundle <zip>` | In-memory; no extraction |
| CLI catalog | `python -m app.cli report-templates` | One block per template |

CLI report flags are shared by `render` and `bundle`:

```bash
--template hackerone
--var report_date=2026-11-10
--var include_inventory=1
--redaction-profile strict
--redaction-rule 'literal:Project Falcon=Project X'
--redaction-rule 'regex:acme-[0-9]+=acme-REDACTED'
--reveal                              # unsafe, explicit
```

`--var` is repeatable. PDF output requires `-o/--output`.

## Template recipes

### HackerOne submission

Use this when a finding is ready to submit.

1. Open `/programs/<id>/reports?template=hackerone`.
2. Fill `report_date`, `author`, `program_handle`, `researcher`.
3. Set `severity_floor` so low-value noise stays out.
4. Keep `include_evidence` on for the supporting-material block.
5. Preview, then download Markdown. Paste it into the report form.

The template orders findings by severity, then title. Each finding gets a
description, steps to reproduce, impact, supporting material and remediation
when the evidence record has them. The report starts with a severity summary,
scope and affected assets.

The older one-click HackerOne exporter (`GET /reports/<id>/h1`) still exists for
a flat submission-style export. The Phase C template is the richer,
variable-driven path.

### Executive summary

Use `executive` for a client-facing summary rather than a submission.

- `risk` shows the deterministic risk score/level and severity distribution.
- `highlights` shows the top findings with their risk explanation.
- `findings_table` is a compact inventory, not a full writeup.
- `recommendations` and `methodology` come from your variables.
- `business_context` is available for engagement framing.

Avoid `include_evidence` for an executive audience. Use `technical` for the
appendix instead.

### Technical finding report

Use `technical` for the full evidence trail:

- description, steps, impact, evidence, remediation;
- CVSS, CVE/CWE, tags, source tool, rule id and timestamps;
- optional single-finding mode via `finding_id`;
- severity floor and maximum finding cap.

`finding_id` must belong to the selected program and pass the severity floor;
otherwise validation fails instead of silently rendering an empty report.

### Recon inventory

Use `recon` when the deliverable is the attack surface, not just findings.

- Entities are grouped by type, sorted by value and capped at 250 per group in
  the rendered report; the JSON context carries `shown`, `truncated` and full
  counts.
- Sensitive entity types keep a short prefix and are masked by default (for
  example `AKIA…LE  [masked]`). Use `reveal` only for an internal copy.
- Scope status, HTTP status, tags and confidence travel with each entity.
- `target_notes` is free text for context that is not in the database.

The JSON download is the complete machine-readable inventory. The Markdown,
HTML and PDF versions deliberately cap long groups.

### Change report

Use `change` for a standup, a retest or a "what did the new scan add?" note.

```bash
# Previous capture vs latest (default)
python -m app.cli render 1 --template change --format md

# Explicit slices
python -m app.cli render 1 --template change \
  --var left_selector=paste:41 --var right_selector=paste:57 \
  --format md -o change.md
```

The report reuses Diff v2 categories: findings, ports, DNS, endpoints,
technologies, headers, entities and risk. The summary counts are recalculated
after false-positive filtering, so a filtered finding cannot inflate "new
findings". If one selector is missing, the report falls back to the previous
and latest capture. If the selectors are invalid, the context marks change data
unavailable instead of inventing a comparison.

## Review bundle

A bundle is the team-review path that does not require a server, account or
login. Build it with the builder button, the route or the CLI.

### Contents

| File | Purpose |
|---|---|
| `report.html` | Self-contained printable report |
| `report.md` | Markdown copy |
| `report.json` | Redacted report context |
| `report.pdf` | Optional, when `include_pdf` / `--include-pdf` is set |
| `manifest.json` | Report metadata, capture list and SHA-256 for every payload file |
| `manifest.sha256` | SHA-256 of `manifest.json` |
| `SHA256SUMS` | `sha256sum -c`-compatible checksums |
| `README.txt` | What is inside and how to verify it offline |
| `comments.md` | Optional reviewer comments, redacted before inclusion |
| `evidence/capture-*.json` | Redacted Evidence Manifest v2 per capture |

Raw capture bodies are never included. The local database remains the system of
record; the bundle is a portable review artifact.

### Build and verify

```bash
# CLI
python -m app.cli bundle 1 --template technical \
  --var report_date=2026-11-10 \
  --comments review-notes.md \
  --include-pdf \
  -o review.zip

python -m app.cli verify-bundle review.zip
python -m app.cli verify-bundle review.zip --json
```

The HTTP route is a form POST (CSRF token required in the browser):

```text
POST /reports/<program_id>/bundle
fields: template, report_date, include_scope, include_targets,
        include_findings, include_evidence, include_pdf, comments, ...
```

The response is `application/zip`; `X-Breadcrumb-Bundle-Captures` reports how
many capture manifests were included.

### What the verifier checks

- zip readable, non-empty and within entry/size limits;
- no path traversal, absolute paths, Windows drive paths or NUL bytes;
- no duplicate entries, symlinks or encrypted entries;
- required report files and `manifest.json` present;
- `manifest.sha256` matches `manifest.json`;
- every listed payload file exists with the recorded size and SHA-256;
- `SHA256SUMS` matches the payload;
- no unlisted files;
- every capture manifest is version 2 or newer, matches the listed capture id,
  passes its own chain verification and has a redacted-output hash;
- redaction metadata exists; a reveal bundle is valid but produces a warning.

Verification is in-memory. A hostile zip cannot write outside the working
directory because nothing is extracted.

`bundle_sha256` is returned by the builder as metadata for the caller, but it
is not stored inside `manifest.json` to avoid a circular self-hash.

## What is intentionally not here

- No WYSIWYG document editor.
- No remote/custom template upload or marketplace.
- No DOCX writer in 0.7.0.
- No per-user accounts or reviewer login.
- No automatic sending, emailing or uploading of reports.

Those are deliberate scope choices. The template language is a fixed set of
sections plus typed variables; extending it means adding a built-in template and
golden tests, not allowing arbitrary user code.

## Testing and determinism

- `tests/test_phase_c.py` covers all five templates, typed validation, golden
  Markdown snapshots under `tests/golden/phase_c/`, hostile HTML escaping,
  redaction/reveal/custom rules, bundle build/verify/tamper/traversal/reveal,
  integration exports, routes, API and CLI.
- Golden files are regenerated only with `UPDATE_GOLDEN=1`; review the diff
  before committing.
- Reports are deterministic for a fixed `generated_at` and fixture data. The
  change template pins fixture capture timestamps so its labels are stable.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| “Report could not be rendered” | Invalid variable; the page lists field-level errors |
| Empty findings section | Severity floor too high, findings triaged/false-positive, or the program has no findings |
| Empty inventory | No entities, or the selected template does not include inventory |
| PDF download fails | PDF requires reportlab; install requirements and check `breadcrumb doctor` |
| Change report says unavailable | Selectors are invalid or a job snapshot is incomplete |
| Bundle verifier fails | File was modified after creation, or a zip tool rewrote/added an entry |
| Reveal warning | `reveal` was explicitly enabled; treat the bundle as internal-only |

See [REDACTION_GUIDE.md](REDACTION_GUIDE.md) for masking rules and
[INTEGRATION_MAPPINGS.md](INTEGRATION_MAPPINGS.md) for DefectDojo, Ghostwriter,
Dradis, HackerOne and SARIF field mappings.
