# Evidence Manifest v2 and `breadcrumb doctor`

Two Phase A features make the notebook trustworthy: a portable manifest for
each capture, and a read-only diagnostic that explains a broken install before
it wastes a user's afternoon.

## Evidence Manifest v2

Every capture can export a manifest without including the raw artifact:

```bash
python -m app.cli manifest 12 --format json -o capture-12.manifest.json
python -m app.cli manifest 12 --format md   -o capture-12.manifest.md
```

From the UI/API:

```text
GET /pastes/12/manifest.json
GET /pastes/12/manifest.md
GET /api/v1/pastes/12/manifest
```

The manifest contains:

| Section | Contents |
|---|---|
| `generator` | Breadcrumb version and schema version |
| `capture` | Capture id, time, source, tool guess, redacted command, program/target |
| `input` | SHA-256 and byte length; raw input is **not** included |
| `parser` | Parsers, versions, completeness, skipped rows, parsed counts, issues |
| `output` | Entity/finding/relationship counts; full-output SHA-256 and redacted-output SHA-256 |
| `scope` | Program id, scope-in/out SHA-256, scope-status counts |
| `chain` | Sequence, previous capture, previous chain hash, chain hash, link-verifiable flag |
| `warnings` | Parser issue messages |

### Verification

Verify a manifest and the original artifact offline:

```bash
python -m app.cli verify --manifest capture-12.manifest.json \
  --raw httpx.jsonl
```

This checks:

- manifest version;
- `sha256(raw)` equals `input.sha256`;
- the chain hash recomputes from `prev_chain_hash` and the input hash;
- if the predecessor is missing, the link is reported as a recorded gap
  instead of a false tamper alarm.

Verify a capture against its own database state:

```bash
python -m app.cli verify --paste 12
```

Verify the whole hash chain:

```bash
python -m app.cli verify
```

The API equivalent is `GET /api/v1/verify`.

### Redaction

Manifests are redacted by default:

- `command` and `source_meta` strings are masked for authorization headers,
  API keys, tokens, passwords, JWTs, cloud keys, Slack/GitHub tokens, private
  keys and credentials embedded in URLs;
- sensitive `source_meta` keys are replaced with `[redacted]`;
- secret/credential/JWT entity values keep a short recognizable prefix and a
  `[masked]` marker.

Use `--reveal` (CLI) or `?reveal=true` (API/UI) only for an internal copy.
The raw artifact is never embedded in a manifest; the database remains the
system of record.

### What a manifest proves — and what it does not

It proves the input hash, the parser/version/completeness record, the output
hash and the chain position. It does **not** prove the artifact came from a
trusted tool, that a finding is true, or that the operator did not edit the
database before exporting. The hash chain detects after-the-fact changes to
sealed captures; manifests make each capture portable and independently
checkable.

## `breadcrumb doctor`

```bash
python -m app.cli doctor
python -m app.cli doctor --json
curl /api/v1/doctor
```

The command is read-only. It does not create a database, key, directory or
network connection. Checks:

| Check | Failure it prevents |
|---|---|
| `python` | Unsupported interpreter / syntax errors |
| `sqlite` | Old SQLite without reliable upserts |
| `database_directory` | Unwritable parent directory |
| `disk_space` | Import dies halfway through |
| `database_file` | Unreadable or missing database |
| `database_integrity` | Corrupt file |
| `wal_mode` | Unexpected locking behavior |
| `schema_version` | Pending migration / old file |
| `secret_key` | Header-profile ciphertext cannot be decrypted |
| `port` | “Address already in use” on first run |
| `parsers` | Gutted registry / import failure |
| `optional_tools` | Confusing “tool not found” messages (informational only) |

Exit status is `0` when there are no `fail` checks and `1` when there is at
least one. Warnings are actionable but do not fail scripts. Every check carries
a `fix` string suitable for a support reply or a first-run wizard.

### First-run sequence

```bash
python -m app.cli doctor
python -m app.cli demo
python -m app.cli verify
```

If `doctor` is green, `demo` gives a program, five captures, findings, a report
and a manifest in under a minute. If it is not green, the failing check tells
you exactly what to fix before importing real data.
