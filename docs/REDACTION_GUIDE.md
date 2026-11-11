# Redaction and report security guide

Status: **Phase C, Breadcrumb 0.7.0.** Redaction is on by default for every
structured report, legacy export, manifest and review bundle. `reveal` is the
only switch that disables masking, and it is always explicit.

Redaction is a safety net, not a substitute for review. Read the final artifact
before you send it to a client, program or public disclosure channel.

## Default stance

Breadcrumb assumes reports and manifests may leave the researcher's laptop.
The local database keeps the original evidence, including secrets, because it
is the system of record. Export surfaces are shareable by default:

| Surface | Default | Reveal switch |
|---|---|---|
| Report templates (Markdown/HTML/JSON/PDF) | Masked | `reveal` variable / `--reveal` / `?reveal=1` |
| Review bundle report and evidence manifests | Masked | Same report `reveal` value |
| `GET /reports/<id>/md`, `json`, `html`, `h1`, `csv`, `targets.txt`, `sarif` | Masked | `?reveal=1` |
| `GET /reports/<id>/defectdojo`, `ghostwriter`, `dradis.md` | Masked | `?reveal=1` |
| Evidence manifest exports | Redacted unless `--reveal` | `breadcrumb manifest --reveal` |
| Ledger JSONL export | Preserves stored values for round-trip | Not a redacted report surface |
| Raw capture on disk / SQLite | Unchanged | N/A |

Redaction happens at render time. It does not rewrite stored evidence, and
turning masking on later cannot un-share a file that was already sent.

## Built-in masking

The built-in rules are deliberately conservative: they target known
credential shapes and authentication material rather than every word that looks
random.

| Category | Examples | Replacement |
|---|---|---|
| Sensitive headers | `Authorization: Bearer …`, `Cookie: …`, `Set-Cookie: …`, `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token` | Header name retained, value `[redacted]` |
| Bearer tokens | `Bearer abcdefghijklmnopqrstuvwxyz` | `Bearer [redacted]` |
| Key/value secrets | `api_key=…`, `password=…`, `client_secret=…`, `access_token=…`, `auth_token=…` | Key retained, value `[redacted]` |
| URL query tokens | `?token=…`, `&api_key=…`, `&password=…` | Parameter retained, value `[redacted]` |
| Session identifiers | `session=…`, `sessionid=…`, `PHPSESSID=…`, `csrftoken=…` | Key retained, value `[redacted]` |
| AWS keys | `AKIA…`, `ASIA…` | `[redacted-aws-key]` |
| GitHub tokens | `ghp_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghr_…` | `[redacted-github-token]` |
| Slack tokens | `xoxb-…`, `xoxp-…`, `xoxa-…`, `xoxr-…`, `xoxs-…` | `[redacted-slack-token]` |
| JWTs | Three base64url segments beginning `eyJ` | `[redacted-jwt]` |
| Private keys | PEM `BEGIN … PRIVATE KEY` blocks | `[redacted-private-key]` |
| URL credentials | `https://user:password@host/` | Password replaced, username/host retained |
| Sensitive entity values | Entity types `secret`, `credential`, `jwt` | Short prefix/suffix plus `[masked]` |

Sensitive entity values keep a recognizable fragment so an operator can tell
which secret was found without printing it. For example:

```text
AKIA…LE  [masked]
```

Values shorter than nine characters become `[redacted]` instead of leaking a
large fraction of the secret.

## What is not masked

The defaults do not attempt to hide:

- ordinary hostnames, subdomains, IPs, ports, technologies and URLs without
  userinfo or token query parameters;
- email addresses, names, internal paths and business context;
- password hashes and arbitrary hex/base64 strings in **default** mode;
- secrets stored under an unusual key name that does not match the built-in
  key/value patterns;
- images, binaries or raw capture bodies (raw bodies are not exported).

If any of those are sensitive for a specific engagement, add a custom rule or
use the `strict` profile.

## Strict profile

`redaction_profile=strict` / `--redaction-profile strict` runs the default rules
and then masks long opaque values:

| Pattern | Replacement |
|---|---|
| Hex string of 32+ characters | `[redacted-hex]` |
| Base64-like string of 40+ characters | `[redacted-opaque]` |

Strict mode is opt-in because hashes, IDs and encoded payloads are sometimes
useful evidence. It is appropriate for a client-facing report or a bundle that
will be stored in a shared drive.

## Custom rules

Custom rules are per-report text passed as `redaction_rules` (builder/CLI) or
`redaction_rules` in the JSON/API context. They are **additive**: built-in rules
always run first, and a custom rule cannot switch a built-in rule off.

Syntax, one rule per line:

```text
literal:Project Falcon=Project X
regex:acme-[0-9]+=acme-REDACTED
plain-literal=replacement
# comments and blank lines are ignored
```

- `literal:` uses exact, case-sensitive string replacement.
- `regex:` compiles the pattern (case-insensitive substitution). An invalid
  regex is a validation error, not a silent skip.
- A line without a prefix is treated as a literal rule.
- `=` separates the pattern from the replacement. The first `=` wins; the
  replacement may contain `=`.
- At most 100 rules per report.

Examples:

```text
# Hide a codename that is not secret-shaped
literal:Project Falcon=Project X

# Normalize an internal hostname prefix
regex:corp-[a-z0-9-]+\.example\.net=internal.example.net

# Mask a customer identifier
regex:CUST-[0-9]{6}=CUST-REDACTED
```

### Rule text is never echoed

A custom rule may itself contain the secret it is meant to remove. The report
JSON therefore exposes only the **count** and **kinds** of custom rules:

```json
"redaction": {
  "enabled": true,
  "profile": "default",
  "custom_rules": 2,
  "custom_rule_kinds": ["literal", "regex"],
  "defaults": "auth headers, cookies, tokens, keys, URL credentials, private keys"
}
```

The raw rule text is not included in `variables`, the report body, the bundle
manifest or the verifier summary. Do not assume the rules file is safe to
commit just because the report does not echo it.

## Reveal

`reveal` is an explicit, unsafe request to disable all masking. It is never a
default in a route, CLI command, template, bundle or test fixture except where
the test is specifically checking reveal behavior.

| Surface | How to reveal |
|---|---|
| Builder / report template | Check “Reveal secrets (unsafe)” or send `reveal=1` |
| CLI `render` / `bundle` | `--reveal` |
| Legacy report routes | `?reveal=1` |
| Evidence manifest CLI | `breadcrumb manifest <id> --reveal` |

Reveal behavior:

- default and custom rules are bypassed;
- sensitive entity values are printed in full;
- report JSON marks `redaction.enabled=false` and `profile="none"`;
- a review bundle still verifies, but the verifier emits a warning;
- the bundle README includes a warning near the top.

Do not send a reveal bundle outside the authorized assessment team. Do not
attach it to a HackerOne report, a public ticket or a shared drive.

A reveal request combined with a non-default profile is treated as an error in
`policy_from()` rather than silently choosing one behavior.

## Where redaction is enforced

### Report templates

`app/report_templates.py` builds a single redacted context. Finding text,
entity values, program/target metadata, user-entered report fields, change
items, comments and footer text pass through the policy before rendering.
Markdown and HTML escaping happen after redaction, so a masked value cannot be
reintroduced by an escaping bug.

### Legacy exporters

`app/reporting.py` applies the same default policy to `to_dict`,
`to_markdown`, `to_csv`, `to_targets_txt`, `to_hackerone`, `to_sarif`,
`to_defectdojo`, `to_ghostwriter` and `to_dradis_markdown`. The `mask` argument
defaults to `True`; call sites pass `not request.query_params.get("reveal")` or
the CLI equivalent.

### Review bundles

`app/review_bundle.py`:

- renders all report formats from the redacted context;
- builds each capture's Evidence Manifest v2 with `redact=True`;
- applies custom rules to manifest free text, while leaving integrity hashes
  untouched (hash fields are excluded from textual replacement);
- redacts reviewer comments before writing `comments.md`;
- records redaction metadata in `manifest.json`;
- warns on verification when reveal was used.

### Manifests and doctor

Evidence Manifest v2 redacts command lines and sensitive metadata by default.
`breadcrumb doctor` is read-only; it never prints secret values. See
[MANIFEST_AND_DOCTOR.md](MANIFEST_AND_DOCTOR.md).

## Threat model and limits

Redaction protects against **accidental disclosure in exported artifacts**. It
does not protect against:

- a compromised laptop, malware or someone with access to the SQLite database;
- a reviewer who is authorized to see the report but should not see a
  particular secret (use custom rules or omit the evidence);
- secrets in screenshots or attachments that Breadcrumb did not parse;
- an operator explicitly choosing `reveal`;
- a secret shape the built-in rules do not recognize;
- data already copied into a chat, ticket or email before masking.

The local database remains sensitive. Protect it like any recon evidence store:
full-disk encryption, a locked screen, and backups treated as confidential.

## Audit checklist before sending

1. Use the default profile unless the engagement requires strict.
2. Add custom rules for codenames, customer IDs and internal hostnames.
3. Preview the HTML and read the evidence blocks, not just the summary.
4. Search the downloaded file for known secret prefixes (`AKIA`, `ghp_`,
   `Bearer `, `token=`, `password=`).
5. Prefer a review bundle for a reviewer; it carries manifests and checksums.
6. Run `python -m app.cli verify-bundle review.zip` and confirm `OK`.
7. Confirm the bundle does not show a reveal warning.
8. If a secret leaked, rotate it first, then delete the artifact and rebuild.

Useful commands:

```bash
# Check the report JSON's redaction metadata without opening the report
python -m app.cli render 1 --template technical --format json -o report.json
python - <<'PY'
import json
data = json.load(open("report.json"))
print(data["redaction"])
print("custom rules echoed:", "redaction_rules" in json.dumps(data["variables"]))
PY

# Verify a bundle offline
python -m app.cli verify-bundle review.zip --json

# Check the evidence chain
python -m app.cli verify
```

## Tests

`tests/test_phase_c.py` covers:

- default masking in Markdown, HTML and JSON;
- URL credentials, bearer tokens, auth headers, cookies, key/value secrets and
  AWS keys;
- sensitive entity masking and explicit reveal;
- custom literal/regex rules, additive behavior and non-echoing;
- strict hex masking;
- legacy exporter masking;
- bundle comment redaction and reveal warning;
- hostile HTML/PDF escaping;
- tamper, path traversal and missing-file verification failures.

Run `.venv/bin/python -m pytest -q tests/test_phase_c.py` after changing a
pattern. Add a regression test for every new secret shape.
