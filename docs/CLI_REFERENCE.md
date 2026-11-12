# CLI reference

Every command is local. Run `breadcrumb <command> --help` for the exact
options of the installed version. Commands that write call `init_db()` and
apply additive migrations; take a backup before upgrading.

Global:

```bash
breadcrumb --version
breadcrumb version
breadcrumb doctor [--json]
breadcrumb release check [--json]
```

`doctor` is read-only and prints a copy-paste `fix` for failures. `release
check` is the offline release gate: dangerous constructs, credential shapes,
docs links, dependency pins and reference coverage.

## breadcrumb serve

```bash
breadcrumb serve [--host 127.0.0.1] [--port 8787] [--reload]
```

Runs the web UI and `/api/v1`. Keep the loopback default; there is no login.

## breadcrumb ingest

```bash
breadcrumb ingest FILE [--program ID] [--target ID] [--source LABEL]
  [--command CMD] [--source-meta JSON] [--max-entities N]
  [--report-json FILE|-] [--json] [--dry-run]
```

`-` reads stdin. `--dry-run` parses and reports without writing. The report
includes parser versions, completeness, skipped rows, warnings and a hint when
zero entities were produced.

## breadcrumb manifest

```bash
breadcrumb manifest PASTE_ID [--format json|md] [-o FILE] [--reveal]
```

Exports Evidence Manifest v2. Redacted by default; `--reveal` is explicit and
unsafe.

## breadcrumb verify

```bash
breadcrumb verify [--manifest FILE [--raw FILE]] [--paste ID] [--json]
```

With no selector, verifies the whole capture chain. With `--manifest`, verifies
the manifest (and the original artifact when `--raw` is supplied).

## breadcrumb demo

```bash
breadcrumb demo [--json]
```

Seeds the idempotent sample program, findings and report links.

## breadcrumb programs

```bash
breadcrumb programs [--json]
```

Lists programs with counts.

## breadcrumb findings

```bash
breadcrumb findings [--program ID] [--min-severity LEVEL] [--json]
```

Lists findings; false positives are excluded by default where the triage policy
applies.

## breadcrumb gate

```bash
breadcrumb gate [PROGRAM] [--max-severity LEVEL]
```

CI gate. Exits non-zero when a finding at or above the threshold exists.

## breadcrumb export

```bash
breadcrumb export PROGRAM
  [--format md|json|csv|h1|targets|sarif|defectdojo|ghostwriter|dradis]
  [-o FILE] [--reveal]
```

The classic exports. New reports should use `breadcrumb render`; both use the
same snapshot and redaction policy.

## breadcrumb backup

```bash
breadcrumb backup [-o FILE]
```

SQLite online backup. Copy the key file and artifact directory separately; see
[BACKUP_RESTORE_UPGRADE.md](BACKUP_RESTORE_UPGRADE.md).

## breadcrumb watch

```bash
breadcrumb watch FOLDER [--program ID] [--target ID] [--interval SECONDS] [--once]
```

Foreground folder watcher. For durable run history, use `breadcrumb schedule`.

## breadcrumb schedule

```bash
breadcrumb schedule add NAME --source FOLDER [--program ID] [--target ID]
  [--interval SECONDS] [--overlap skip|queue] [--no-move-processed]
breadcrumb schedule list [--json]
breadcrumb schedule show SCHEDULE_ID [--json]
breadcrumb schedule run SCHEDULE_ID [--force]
breadcrumb schedule enable SCHEDULE_ID
breadcrumb schedule disable SCHEDULE_ID
breadcrumb schedule delete SCHEDULE_ID [--yes]
```

Local folders only. A failed file stays in the drop folder; successful files
move to `processed/`. See [AUTOMATION_COOKBOOK.md](AUTOMATION_COOKBOOK.md).

## breadcrumb scheduler

```bash
breadcrumb scheduler [--once] [--poll SECONDS] [--max-runs N]
```

Foreground loop that runs due schedules. It is not a daemon and does not start
at boot.

## breadcrumb parsers

```bash
breadcrumb parsers [--json]
```

Lists built-in and local parser plugins, their contract version and any load
errors. Local plugins execute in-process; only install parsers you trust.

## breadcrumb artifacts

```bash
breadcrumb artifacts list [--program ID] [--target ID] [--finding ID]
  [--entity ID] [--source LABEL] [--q TEXT] [--limit N] [--offset N] [--json]
breadcrumb artifacts import MANIFEST --program ID [--base-dir DIR]
  [--target ID] [--finding ID] [--source LABEL] [--json]
breadcrumb artifacts show ARTIFACT_ID [--json]
breadcrumb artifacts export ARTIFACT_ID -o FILE
breadcrumb artifacts delete ARTIFACT_ID --yes
breadcrumb artifacts manifest [--program ID] [--limit N] [--no-meta] [-o FILE]
```

PNG/JPEG/GIF/WebP only. Images are stored outside SQLite and verified by
SHA-256. See [SCREENSHOT_COOKBOOK.md](SCREENSHOT_COOKBOOK.md).

## breadcrumb worker

```bash
breadcrumb worker [--once] [--poll SECONDS] [--lease SECONDS] [--max-jobs N]
```

Durable native-collector worker. External adapters additionally require
`BREADCRUMB_EXTERNAL_TOOLS=1`. Run one worker per database.

## breadcrumb tools

```bash
breadcrumb tools [--json]
```

Adapter diagnostics: installed, path, version, scope mode and strict policy.

## breadcrumb collect

```bash
breadcrumb collect TARGET [--program ID] [--collector ID] [--params JSON]
  [--header-profile ID] [--priority N] [--run-now]
```

Queues a native collector or opt-in adapter. Scope is checked before any
process starts.

## breadcrumb jobs

```bash
breadcrumb jobs list [--status STATUS] [--limit N] [--json]
breadcrumb jobs show JOB_ID [--json]
breadcrumb jobs cancel JOB_ID
breadcrumb jobs retry JOB_ID
```

## breadcrumb history

```bash
breadcrumb history TARGET [--program ID] [--diff] [--from SNAPSHOT]
  [--to SNAPSHOT] [--json]
```

Target timeline and snapshot diffs.

## breadcrumb report

```bash
breadcrumb report JOB_ID [--format pdf|json|md] [-o FILE] [--include-triaged]
```

Renders a job snapshot (the classic report path).

## breadcrumb render

```bash
breadcrumb render PROGRAM [--template hackerone|executive|technical|recon|change]
  [--format md|markdown|html|json|pdf] [--var KEY=VALUE] [--redaction-profile default|strict]
  [--redaction-rule RULE] [--reveal] [-o FILE]
```

Five built-in templates. Redaction is on by default; custom rules are additive
and cannot disable built-in masking. Screenshots are included only with
`--var include_screenshots=1`.

## breadcrumb bundle

```bash
breadcrumb bundle PROGRAM [--template ...] [--var KEY=VALUE]
  [--redaction-profile default|strict] [--redaction-rule RULE] [--reveal]
  [-o FILE] [--comments FILE] [--include-pdf] [--include-screenshots]
```

Builds a deterministic, offline review zip. `--include-screenshots` includes
image bytes; pixels are not redacted.

## breadcrumb verify-bundle

```bash
breadcrumb verify-bundle FILE [--json]
```

Verifies the zip in memory: checksums, manifest, capture manifests and optional
screenshot hashes. Nothing is extracted.

## breadcrumb report-templates

```bash
breadcrumb report-templates
```

Lists template ids, descriptions and variables.

## breadcrumb diff

```bash
breadcrumb diff LEFT RIGHT [--format md|json] [--json] [-o FILE] [--notify]
```

Selectors: `paste:12`, `target:3`, `program:1`, `job:9`. `--notify` uses the
locally configured notification channels only.

## breadcrumb ledger

```bash
breadcrumb ledger list [QUERY] [--type TYPE] [--limit N] [--offset N] [--json]
breadcrumb ledger show QUERY --type TYPE --value VALUE [--json]
breadcrumb ledger export [QUERY] [--format jsonl|csv] [-o FILE]
breadcrumb ledger views [--kind ledger|diff|graph] [--json]
breadcrumb ledger save-view NAME --kind KIND [--json]
breadcrumb ledger delete-view VIEW_ID
breadcrumb ledger import FILE --program ID [--program-name NAME] [--json]
```

Cross-program memory. JSONL round-trips through the normal ingest path.

## breadcrumb maintenance

```bash
breadcrumb maintenance on [--reason TEXT]
breadcrumb maintenance off
```

Pauses native worker claims during backup, restore or migration. Running jobs
are not silently rewritten.

## breadcrumb import-leadline

```bash
breadcrumb import-leadline --db FILE [--program ID] [--program-name NAME]
  [--manifest FILE] [--dry-run|--verify] [--no-backup] [--no-snapshots]
  [--no-verify] [--report FILE] [--json]
```

One-way importer for the legacy Leadline database. See
[LEADLINE_MERGE_GUIDE.md](LEADLINE_MERGE_GUIDE.md).

## breadcrumb secrets

```bash
breadcrumb secrets rotate
```

Rotates the header-profile encryption key and archives the previous key at
`<key>.old`. Restore the matching key with any backup.

## breadcrumb nvd

```bash
breadcrumb nvd import FILE [--cache FILE] [--replace] [--json]
breadcrumb nvd stats [--cache FILE] [--json]
```

Imports the offline NVD JSON/JSON.GZ cache used for CVE verification.

## breadcrumb release

```bash
breadcrumb release check [--json]
```

Offline release gate. It checks tracked source for `shell=True`/dynamic eval,
credential shapes, broken relative docs links, runtime dependency pins, and
that every top-level CLI command and `/api/v1` route appears in the reference
docs.

## breadcrumb version

```bash
breadcrumb version
```
