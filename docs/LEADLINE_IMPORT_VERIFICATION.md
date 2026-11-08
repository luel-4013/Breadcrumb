# Leadline import — real-data verification (Phase 8)

**Date:** 2026-11-08
**Status:** Verified on a copy of the owner's real Leadline database.
**Command:** `python -m app.cli import-leadline`
**Source:** `<owner's local Leadline folder>/leadline.db` (path redacted)
**Destination:** a temporary copy of `Breadcrumb/breadcrumb.db`

No live database was modified. The source was copied with SQLite's online
backup API before it was read; the destination was a throwaway copy of the live
Breadcrumb database. The real Leadline folder and the live Breadcrumb database
were left untouched.

## What the real source contains

| Table | Rows |
|---|---:|
| `targets` | 2 |
| `scans` | 0 |
| `scan_events` | 0 |
| `findings` | 0 |
| `graph_nodes` | 0 |

Source size: **106,496 bytes**. Source fingerprint (filename + bytes + WAL):
`a0331f521bcc21ddc3f0639c0b82899caffe7ba1287d6f324d348c846c26648a`.
The fingerprint includes the path, so a copy under a different filename has a
different fingerprint; the import check is that it is unchanged before and
after reading.

The two targets are shown with their identifiers redacted for this public
report; the counts and header totals are unchanged:

| Source ID | Name | URL | Shape | Custom headers |
|---:|---|---|---|---|
| 1 | Target 1 (redacted) | `example.com` (redacted) | bare domain | 9 headers |
| 2 | Target 2 (redacted) | private IPv4 (redacted) | IP | 4 headers |

The two header sets are different, so the dry run correctly predicted **two**
encrypted header profiles. The real database has no scans, findings, triage or
graph rows, so those paths are exercised by the synthetic fixture in
`tests/test_phase8.py` rather than by this particular database.

## Dry run

```
source counts: targets=2, scans=0, events=0, findings=0, graph_nodes=0
would import: targets=2, scans=0, events=0, findings=0, graph_nodes=0, header_profiles=2
distinct header sets: 2
destination: no matching program yet
```

The dry run wrote nothing: no program, no rows, no manifest.

## Real import

| Result | Value |
|---|---|
| Program | `#1 Leadline import` (created, platform `leadline`) |
| Targets imported | 2 |
| Header profiles created | 2 |
| Scans / findings / graph entities | 0 |
| Destination backup | `breadcrumb-destination-copy.db.pre-import-20261107-114809.bak` |
| Manifest | `import-manifest.json` (mode `0600`) |
| Source fingerprint after import | unchanged (`a0331f…`) |
| Post-import verification | **OK** |

The destination copy was migrated from schema version 3 to 4 during the
import. Its two pre-existing plaintext header profiles were encrypted with the
new local key as part of normal startup; the imported profiles were written as
`enc:v1:` ciphertext from the start.

## Verification checks

| Check | Result |
|---|---|
| Counts (targets/scans/events/findings/graph) | PASS |
| Triage distribution | PASS (both sides empty) |
| Severity distribution | PASS (both sides empty) |
| Sampled finding fields | PASS (no findings to sample) |
| Header round-trip | PASS — target 1: 9/9 headers; target 2: 4/4 headers |
| Source read-only hash | PASS |

A second import with the same manifest was idempotent:

```
imported: programs=0, targets=0, header_profiles=0, scans=0, ...
skipped:  targets=2
verification: OK
```

## Acceptance script

`scripts/acceptance_phase8.py` was run against the same source and destination
copy. It copies both inputs to a temporary directory, runs the dry run, the
real import, and verification, then checks the source fingerprint and raw
header ciphertext:

```
PASS source_unchanged
PASS import_ok
PASS verification_ok
PASS counts
PASS source_fingerprint_matches_report
PASS headers_encrypted_at_rest
```

## What this proves, and what it does not

**Proven against real data:**

- the source opens read-only and its fingerprint does not change;
- targets, custom headers, timestamps and metadata map correctly;
- header profiles are encrypted at rest and round-trip through decryption;
- the destination backup and manifest are created;
- re-running the import does not duplicate rows;
- post-import verification is clean.

**Not proven by this database:**

- scans, attempts, phases, findings, triage and graph nodes — the real
  database has none. These paths are covered by
  `tests/test_phase8.py::test_import_maps_data_and_builds_snapshots` and the
  other Phase 8 tests, using a synthetic Leadline-shaped database with
  malformed rows, triage states, graph parents and edges.
- a source with a live writer. The importer detects a concurrent change via
  the before/after fingerprint and aborts with instructions.

## Reproduction

```bash
# Always work on copies. Use SQLite's backup API, not cp, when WAL is active.
sqlite3 "/path/to/leadline.db" ".backup '/tmp/leadline-copy.db'"
sqlite3 breadcrumb.db ".backup '/tmp/breadcrumb-copy.db'"
cp breadcrumb.db.key /tmp/breadcrumb-copy.db.key 2>/dev/null || true
cp breadcrumb.db.key.old /tmp/breadcrumb-copy.db.key.old 2>/dev/null || true

.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db \
  --program-name "Leadline import" \
  --manifest /tmp/leadline-import.json \
  --dry-run

BREADCRUMB_DB_PATH=/tmp/breadcrumb-copy.db \
.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db \
  --program-name "Leadline import" \
  --manifest /tmp/leadline-import.json \
  --report /tmp/leadline-import-report.json

BREADCRUMB_DB_PATH=/tmp/breadcrumb-copy.db \
.venv/bin/python -m app.cli import-leadline \
  --db /tmp/leadline-copy.db \
  --manifest /tmp/leadline-import.json \
  --verify
```

The full JSON reports used for this note are reproducible with
`scripts/acceptance_phase8.py --json`.
