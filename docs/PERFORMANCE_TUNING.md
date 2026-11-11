# Performance tuning guide

Breadcrumb is designed for a solo researcher's laptop: one SQLite file, one
process, no cache server. The goal is not benchmark leadership; it is that a
notebook with a year of history still opens, searches and renders a report
without waiting.

Two reproducible scripts cover the two different cost centres:

| Script | Measures | When to run |
|---|---|---|
| `scripts/bench_import.py` | The full ingest path: parse, seal, insert, attribute, annotate. | After changing a parser, ingest, or attribution. |
| `scripts/bench_scale.py` | Read paths on an already-seeded database: Ledger aggregate/filter/search, entity list, deep pagination, query plans. | After changing an index, Ledger query, or UI list. |

Both use a throwaway SQLite database, print JSON with `--json`, and never touch
the real notebook.

```bash
.venv/bin/python scripts/bench_import.py --entities 10000 --json
.venv/bin/python scripts/bench_import.py --entities 100000 --json
.venv/bin/python scripts/bench_scale.py --entities 100000 --json
.venv/bin/python scripts/bench_scale.py --entities 1000000 --json
.venv/bin/python scripts/bench_scale.py --entities 1000000 --keep --json  # inspect the DB
```

`bench_scale.py` exits non-zero if the slowest measured query exceeds
`--target-seconds` (default 2.0) unless `--keep` is set for investigation.

## 1. Recorded baseline

Development laptop: Ryzen 5 5600H, 20 GB RAM, local SSD, Linux, Python 3.12.
Absolute numbers vary with hardware; the ratios and the query plans are the
useful part. These are the Phase D measurements, taken after the schema 7
migration.

### Import (httpx fixture, 5 entities per record)

| Input | Parsed/persisted entities | Time | Throughput | DB size | Completeness | Skipped |
|---|---:|---:|---:|---:|---:|---:|
| 10k | 10,001 | 10.371 s | ~964/s | — | 100% | 0 |
| 100k | 100,001 | 80.913 s | ~1,236/s | 60.99 MB | 100% | 0 |

The 100k run parsed and persisted **100,001** entities with **zero skipped
rows** and **100% completeness**. The earlier Phase A nmap fixture imported
10k entities in 5.954 s (~1,260/s); nmap is cheaper per entity because it emits
fewer derived entities per record. Use the httpx number as the conservative
planning figure.

### Read paths at 1,000,000 entities

Seeded with two programs, four entity types, mixed scope/status/ignored flags,
and 10% shared values. Seeding took 31.273 s; the database was 422.6 MB.

| Query | Time | Rows matched | Notes |
|---|---:|---:|---|
| Ledger filtered (`type:subdomain scope:in status:200`) | 0.760 s | 75,020 | Aggregate + program links, first page of 100 |
| Ledger deep page (`type:url`, offset 900) | 1.395 s | 225,025 | Slowest measured query |
| Ledger search (`q:shared-42`) | 0.771 s | 1 | Substring search over 1M values |
| Entity filter (program 1, type `url`, first 100) | 0.148 s | 125,000 | Indexed count + page |

Slowest query **1.395 s**, within the documented **2.0 s** target at 1M
entities. All four queries are first-page or modest-offset reads; the API
returns `next_offset` rather than trying to serialise the whole result.

### Query plans

```text
ledger_group   SEARCH entity USING INDEX ix_entity_ignored (ignored=?)
               USE TEMP B-TREE FOR GROUP BY
               USE TEMP B-TREE FOR count(DISTINCT)
entity_filter  SEARCH entity USING INDEX ix_entity_program_ignored (program_id=? AND ignored=?)
value_search   SCAN entity USING COVERING INDEX ix_entity_value
```

The aggregate intentionally does not have a covering composite index: adding
`(ignored, type, scope_status, status_code, normalized, program_id)` would
speed one filter shape and slow every write. At 1M rows the temp B-tree is
acceptable. The substring search scans a covering index (no table lookup), which
is why it stays under a second.

## 2. What is indexed

Schema 7 adds read-path indexes for the queries the UI and API actually run:

```text
ix_entity_program_type          (program_id, type)
ix_entity_program_ignored       (program_id, ignored)
ix_entity_program_scope         (program_id, scope_status)
ix_entity_program_status_code   (program_id, status_code)
ix_entity_type_normalized       (type, normalized)
ix_entity_norm_lower            (lower(normalized))
ix_schedule_due                 (enabled, next_run_at)
ix_schedulerun_schedule         (schedule_id, id)
ix_schedulerun_status           (status)
```

Plus the existing capture/finding/job/snapshot/ledger-view indexes. Indexes are
created idempotently at startup after migrations, so an old database upgrades
in place.

There is **no FTS5 table yet**. The measured 1M substring search (0.77 s) meets
the target without one. Add FTS only when a benchmark shows a real regression
(multi-term search, much larger value strings, or a slower disk), and keep the
existing `LIKE` path as the deterministic fallback. Do not add a search server.

## 3. Import tuning

- **One file per tool run.** The normal ingest path seals each capture once;
  a 10k-line file is cheaper than 10k one-line requests.
- **Use bulk for many small files.** `POST /api/v1/pastes/bulk` amortises the
  HTTP and session overhead but is capped at 100 captures per request.
- **Prefer text over re-parsing.** A schedule imports the same bytes once;
  identical content hashes become duplicate captures, not second parses.
- **Keep a capture under 5 MB for the HTTP API** (the raw body cap). CLI
  ingest and folder schedules accept up to 25 MB per file.
- **Avoid `--max-entities` inflation.** The cap exists to protect the UI; it
  does not make parsing faster.
- **Attribute to a program.** Program/target attribution and cross-program
  annotation are part of the measured cost; an unassigned capture is faster but
  less useful. The benchmark includes a program.
- **Do not run two large imports concurrently.** SQLite allows one writer;
  the second waits on the busy timeout. Serialize large batches.

## 4. Read-path tuning

- **Page, do not export everything.** Use `limit`/`offset` and follow
  `next_offset`. Export endpoints stream a file, which is the right tool for a
  full slice.
- **Filter narrowly.** `type:`, `program:`, `scope:`, `status:` and `tag:`
  reduce the aggregate before Python builds asset rows. A bare `/ledger` on a
  1M-row database is the most expensive view.
- **Deep offsets cost more.** Offset 900 was 1.395 s; offset 50,000 will be
  worse. If you routinely page deep, filter first or export JSONL. A keyset
  cursor is a possible future addition, not a 1.x contract change.
- **Saved views** store the filter string, not a materialized result. They are
  cheap to save and re-run with the current data.
- **Keep the database on local disk.** WAL and random reads on a network mount
  are the fastest way to make every query slow and risk corruption.

## 5. Maintenance

SQLite maintains itself for normal use. When the file has grown after large
deletions or many schema changes:

```bash
breadcrumb backup -o before-maintenance.db   # always back up first
.venv/bin/python - <<'PY'
import sqlite3
from app.db import DB_PATH
conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
conn.execute("ANALYZE")
conn.execute("VACUUM")
conn.close()
PY
```

`VACUUM` rewrites the file and needs free disk equal to the database size. It
is not required after ordinary imports. `ANALYZE` refreshes planner statistics
and is safe to run periodically. A backup-encryption path already performs
`wal_checkpoint(TRUNCATE)` + `VACUUM` after re-encrypting secrets.

Operational rules:

- Use `breadcrumb backup` (online backup API + integrity check), never a raw
  copy of a live WAL database.
- Run `breadcrumb maintenance on --reason "..."` before a backup window if a
  worker is active; imports and reads can continue.
- Leave `PRAGMA synchronous=NORMAL`, `journal_mode=WAL`,
  `busy_timeout=30000`, `foreign_keys=ON` and `secure_delete=ON` alone. They
  are chosen for crash safety and secret hygiene, not micro-benchmarks.
- `breadcrumb doctor` reports schema version, integrity, disk and parser
  status. Run it first when performance changes unexpectedly.

## 6. Capacity planning

Rough figures from the 1M seed:

| Entities | Database size | First-page Ledger query (expected) |
|---:|---:|---:|
| 10k | ~4.4 MB | < 0.03 s |
| 100k | ~61 MB (import fixture) | < 0.1 s |
| 1M | ~423 MB | 0.76–1.40 s |

Relationship, finding and capture rows add to this. A year of solo recon is
usually far below 1M entities; if you approach it, archive old programs with a
JSONL export and a fresh database rather than deleting evidence in place.
There is no hard entity limit and no background compaction daemon.

## 7. Regression policy

- `tests/test_benchmarks.py` runs a 1k-entity smoke test of both scripts on
  every suite; it checks completeness and that every read path reports a time.
- The 100k/1M numbers above are release evidence, not a CI gate. CI machines
  are shared and noisy.
- Before changing a parser or an index, run the relevant benchmark and attach
  the JSON to the change. If a query crosses 2 s at 1M, either add a targeted
  index with a query-plan justification or document the accepted regression.
- Completeness and skipped rows are correctness metrics. Never trade them for
  throughput by silently dropping rows.
