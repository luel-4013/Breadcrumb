# Integration mappings

Status: **Phase C, Breadcrumb 0.7.0.** Export-first integrations. Breadcrumb
does not call a remote API to create findings; it writes a local artifact that
you import into the tool you already use. Every exporter reads the same
redacted finding set as the built-in reports.

## Export surfaces at a glance

| Target | Artifact | Route | CLI |
|---|---|---|---|
| HackerOne | Markdown submission | `GET /reports/<id>/h1` or `.../templates/hackerone.md` | `export --format h1`, `render --template hackerone` |
| DefectDojo | Generic Findings Import JSON | `GET /reports/<id>/defectdojo` | `export --format defectdojo` |
| Ghostwriter | Finding JSON | `GET /reports/<id>/ghostwriter` | `export --format ghostwriter` |
| Dradis | Note-format Markdown (`#[Field]#`) | `GET /reports/<id>/dradis.md` | `export --format dradis` |
| SARIF | SARIF 2.1.0 | `GET /reports/<id>/sarif` | `export --format sarif` |
| Generic JSON | Full program/entity/finding context | `GET /reports/<id>/json` | `export --format json` |
| CSV | Flat entity inventory | `GET /reports/<id>/csv` | `export --format csv` |
| Narrative Markdown | Full program report | `GET /reports/<id>/md` | `export --format md` |
| Target list | In-scope hosts, one per line | `GET /reports/<id>/targets.txt` | `export --format targets` |

All routes accept `?reveal=1` and `?include_triaged=1`. Reveal disables
masking; do not use it for a shared artifact. `include_triaged=1` keeps
false-positive findings for an internal review.

False positives and ignored entities are excluded by default everywhere.
`include_triaged` / `--include-triaged` is the only way to put them back.

## HackerOne

### Template report (recommended)

`GET /reports/<id>/templates/hackerone.md` renders the Phase C `hackerone`
template with summary, scope, affected assets and one section per finding.
Variables are documented in [REPORT_COOKBOOK.md](REPORT_COOKBOOK.md).

| Breadcrumb field | HackerOne section |
|---|---|
| Program name | Report title |
| Program scope/out-of-scope | Scope |
| Targets | Affected assets |
| Finding severity | Severity summary and heading |
| Finding title | Finding heading |
| `description` | Description |
| `steps` | Steps to reproduce |
| `impact` | Impact |
| `evidence` | Supporting material (fenced block) |
| `remediation` | Remediation |
| Tags / CVE / CVSS / source tool | Metadata rendered where present |

The report is Markdown, so paste it into the submission form and adjust the
program-specific fields. No HackerOne API token is required and nothing is
uploaded automatically.

### Legacy flat export

`GET /reports/<id>/h1` (CLI `export --format h1`) produces a simpler
submission-oriented Markdown file: title, summary counts, affected assets and
per-finding description/reproduction/impact/evidence/remediation. It has no
template variables. Use the template path when you need classification,
author, engagement reference or a single-finding report.

## DefectDojo

### What Breadcrumb writes

`GET /reports/<id>/defectdojo` returns a JSON object:

```json
{
  "name": "Breadcrumb — Acme",
  "type": "Generic Findings Import",
  "version": "0.8.0",
  "findings": [
    {
      "title": "Exposed admin panel",
      "severity": "High",
      "description": "...",
      "date": "2026-11-10",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "out_of_scope": false,
      "risk_accepted": false,
      "under_review": false,
      "numerical_severity": "S1",
      "unique_id_from_tool": "breadcrumb-1-42",
      "static_finding": false,
      "dynamic_finding": true,
      "service": "Acme",
      "impact": "...",
      "steps_to_reproduce": "...",
      "mitigation": "...",
      "cvssv3": "CVSS:3.1/...",
      "cwe": 306,
      "cve": "CVE-2025-12345",
      "endpoints": ["https://acme.example/admin"],
      "tags": ["verified", "cve"]
    }
  ]
}
```

The object is the shape consumed by the DefectDojo **Generic Findings Import**
parser. It is a JSON document, not a zip. Only fields that the parser accepts
are emitted, so Breadcrumb's internal ids and notes do not leak into the
import.

### Field mapping

| Breadcrumb | DefectDojo field | Notes |
|---|---|---|
| `Finding.title` | `title` | Truncated to 511 characters |
| `Finding.severity` | `severity` | `critical`, `high`, `medium`, `low`, `info` → `Critical`…`Info` |
| severity rank | `numerical_severity` | `S0` (critical) to `S4` (info) |
| `Finding.description` | `description` | Falls back to title; never empty |
| `Finding.created_at` | `date` | `YYYY-MM-DD`; today when absent |
| `Finding.status` / triage | `active`, `false_p`, `under_review` | Resolved/false-positive → inactive |
| verified tags | `verified` | `verified`, `applicability-verified`, `local-nvd` |
| triage verdict | `duplicate` | Always `false`; Breadcrumb does not track duplicate links |
| `Finding.meta.references` / location | `endpoints` | One URI string in a list |
| `Finding.impact` | `impact` | When present |
| `Finding.steps` | `steps_to_reproduce` | When present |
| `Finding.remediation` | `mitigation` | When present |
| `Finding.cvss` | `cvssv3` or `cvssv3_score` | Vector → `cvssv3`; numeric → score |
| `Finding.meta.cwe` | `cwe` | Digits extracted from `CWE-306` |
| `Finding.meta.cve` / title / evidence / tags | `cve` | First `CVE-YYYY-NNNN` match |
| `Finding.rule_id` | `vuln_id_from_tool` | When present |
| `program.id` + `finding.id` | `unique_id_from_tool` | Stable `breadcrumb-<program>-<finding>` id |
| Program name | `service` | Capped at 200 characters |
| Finding tags | `tags` | Capped at 50 |

### Import into DefectDojo

1. In DefectDojo, create or select the product and engagement.
2. Choose **Import Scan** → **Generic Findings Import**.
3. Upload the JSON downloaded from `/reports/<id>/defectdojo`.
4. Run a dry run first if your DefectDojo version supports it, then import.
5. Check the mapping for severity, false positives, endpoints and tags.

If your DefectDojo version expects a bare array rather than the object wrapper,
extract the `findings` key:

```bash
python -m app.cli export 1 --format defectdojo -o defectdojo.json
python - <<'PY'
import json
data = json.load(open("defectdojo.json"))
json.dump(data["findings"], open("findings.json", "w"), indent=2)
PY
```

The exact accepted shape and field set vary by DefectDojo release. The exporter
targets the documented Generic Findings Import vocabulary; validate against
your own DefectDojo test instance before relying on it in a team workflow. A
test-instance import is an operator acceptance check, not something Breadcrumb
performs or claims automatically.

## Ghostwriter

### What Breadcrumb writes

`GET /reports/<id>/ghostwriter` returns:

```json
{
  "format": "breadcrumb.ghostwriter",
  "format_version": 1,
  "generator": {"name": "breadcrumb", "version": "0.8.0"},
  "project": {
    "name": "Acme",
    "platform": "hackerone",
    "scope_in": "...",
    "scope_out": "..."
  },
  "redaction": {"enabled": true, "profile": "default"},
  "findings": [
    {
      "title": "...",
      "severity": "High",
      "finding_type": "Network",
      "description": "...",
      "impact": "...",
      "mitigation": "...",
      "replication_steps": "...",
      "references": "...",
      "affected_entities": ["https://acme.example/admin"],
      "tags": ["verified"],
      "verified": true,
      "status": "open",
      "triage_status": "untriaged",
      "cve": "CVE-2025-12345",
      "cvss": "CVSS:3.1/...",
      "source": "nuclei"
    }
  ]
}
```

### Field mapping

| Breadcrumb | Ghostwriter-oriented field |
|---|---|
| `Finding.title` | `title` |
| `Finding.severity` | `severity` (`Critical`, `High`, `Medium`, `Low`, `Informational`) |
| constant | `finding_type: "Network"` |
| `Finding.description` | `description` |
| `Finding.impact` | `impact` |
| `Finding.remediation` | `mitigation` |
| `Finding.steps` | `replication_steps` |
| `Finding.meta.references` | `references` |
| Finding location | `affected_entities` (one item) |
| `Finding.tags` | `tags` |
| verified tags | `verified` |
| `Finding.status` | `status` |
| triage snapshot | `triage_status` |
| `Finding.meta.cve` / `_finding_cve` | `cve` |
| `Finding.cvss` | `cvss` |
| `Finding.source_tool` | `source` |

Ghostwriter does not publish a single stable file-import schema; its API and
templates are deployment-specific. This artifact is intentionally a
field-rich, documented bridge rather than a claim of one-click import. Map the
fields above in your Ghostwriter template/API integration, or use the Dradis
Markdown export when a note-oriented import is a better fit.

## Dradis

`GET /reports/<id>/dradis.md` (CLI `export --format dradis`) writes note-format
Markdown that Dradis recognizes:

```text
#[Title]#
Acme — Breadcrumb findings

#[Program]#
Acme

#[Platform]#
hackerone

#[Redaction]#
Default-on: auth headers, cookies, tokens and secret values are masked.

#[Title]#
Exposed admin panel

#[Severity]#
High

#[Description]#
...

#[Impact]#
...

#[Replication Steps]#
...

#[Affected Hosts]#
https://acme.example/admin

#[Remediation]#
...

#[Tags]#
verified cve
```

Mapping:

| Breadcrumb | Dradis note field |
|---|---|
| Program name + “Breadcrumb findings” | `Title` (cover note) |
| Program name | `Program` |
| Platform | `Platform` |
| redaction state | `Redaction` (a literal warning string, not evidence) |
| `Finding.title` | `Title` |
| `Finding.severity` | `Severity` (`Critical`…`Info`) |
| `Finding.description` | `Description` |
| `Finding.impact` | `Impact` |
| `Finding.steps` | `Replication Steps` |
| Finding location / affected asset | `Affected Hosts` |
| `Finding.remediation` | `Remediation` |
| `Finding.tags` | `Tags` |

A line inside a value that begins with `#[` is indented so it cannot start a
new Dradis field. Import the file as a note/issue template in Dradis; no API
call is made.

## SARIF

`GET /reports/<id>/sarif` writes SARIF 2.1.0 for GitHub code scanning and other
CI dashboards.

| Breadcrumb | SARIF |
|---|---|
| Program | `run.properties.program` |
| Entity/relationship counts | `run.properties.entity_count`, `relationship_count` |
| Redaction metadata | `run.properties.redaction` |
| `Finding.title` | Rule `name`, `shortDescription.text`, `ruleId` slug |
| `Finding.severity` | `level`: critical/high → `error`, medium → `warning`, low/info → `note` |
| `Finding.description` + impact | Result `message.text` |
| Target or program name | `locations[0].physicalLocation.artifactLocation.uri` |
| `Finding.status`, triage, tags | Result `properties` |
| `Finding.evidence` | `properties.evidence` only when `mask=False`; `null` in masked mode |

Upload example:

```bash
python -m app.cli export 1 --format sarif -o breadcrumb.sarif
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/OWNER/REPO/code-scanning/sarifs \
  -f commit_sha="$GITHUB_SHA" \
  -f ref="refs/heads/main" \
  -f sarif="$(gzip -c breadcrumb.sarif | base64 -w0)"
```

The API shape is GitHub's; Breadcrumb only produces the SARIF file. The
`informationUri` in the SARIF driver is a placeholder because the project has
no canonical public URL yet.

## CSV, JSON and targets.txt

### CSV

One row per entity:

```text
type,value,normalized,parser,confidence,scope_status,occurrences,program_id,target_id,paste_id
```

This is an inventory, not a finding export. Sensitive entity values are masked
by default.

### JSON

The full program context: program, targets, entities (`entities` and
`entities_by_type`), relationships, findings, summary and redaction metadata.
This is the best format for a custom dashboard or a script.

### targets.txt

Unique in-scope host-ish values (`domain`, `subdomain`, `ip`, `url`) plus
target names, one per line, ready for:

```bash
python -m app.cli export 1 --format targets -o targets.txt
httpx -l targets.txt -json -o httpx.json
nuclei -l targets.txt -jsonl -o nuclei.jsonl
```

The list is masked by default; hostnames are not normally affected, but a
`targets` export from a program with secret-shaped values still goes through
the policy.

## Redaction across integrations

Every exporter above runs the default policy. The same limits apply:

- header values, cookies, tokens, URL credentials and known token shapes are
  masked;
- custom report rules do **not** apply to `export` commands (they are a
  template/bundle feature); use the template JSON if you need per-report rules;
- `?reveal=1` / `--reveal` disables masking and is logged only in the artifact
  metadata, not in an audit trail;
- `include_triaged` changes content, not secrecy.

See [REDACTION_GUIDE.md](REDACTION_GUIDE.md) for the full rule list and threat
model.

## Compatibility notes

- **HackerOne:** Markdown only; no API upload, no automatic submission.
- **DefectDojo:** targets the Generic Findings Import vocabulary. Field names
  and wrapper shape vary by release; validate with your instance.
- **Ghostwriter:** bridge JSON, not a guaranteed one-click importer. Map fields
  in your deployment's template or API layer.
- **Dradis:** note-format Markdown with `#[Field]#` blocks; field labels are
  configurable in Dradis if your template differs.
- **SARIF:** 2.1.0 shape; the `informationUri` is a placeholder.
- **No webhooks, Jira, MISP or Elastic adapters are implemented in 0.7.0.**
  The export files are the integration boundary; a later phase may add webhook
  adapters without widening the default data flow.
