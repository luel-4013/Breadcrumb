# Reliability and soak testing

**Harness:** [`scripts/soak.py`](../scripts/soak.py)
**Short smoke date:** 2026-11-12
**Short smoke result:** PASS (40 cycles, 2.7 s)

The harness exercises the local folder schedule path and the durable job queue
in a loop, injecting the failures that a long-running installation would
eventually meet.

## What it does

Each cycle:

1. writes a unique nmap fixture into a local drop folder;
2. runs the schedule through the normal ingest/capture-key path;
3. records files ingested, duplicates and errors.

Periodically it also:

- inserts a schedule run left `running` three hours in the past, then runs the
  schedule again and confirms the old row becomes `stale` instead of forking;
- inserts a job with an expired worker lease, then calls the queue recovery and
  confirms the lease is reclaimed;
- takes a SQLite online backup and runs `PRAGMA integrity_check`;
- at the end, verifies the whole evidence chain.

The harness uses a temporary database and artifact directory by default. No
network, external tool or real recon data is involved.

## Commands

```bash
# Smoke / CI
.venv/bin/python scripts/soak.py --cycles 40

# One hour
.venv/bin/python scripts/soak.py --duration 3600 -o soak-hour.json

# Actual 24-hour acceptance run
.venv/bin/python scripts/soak.py --duration 86400 -o soak-24h.json
```

`--keep` retains the temporary database for inspection. `--backup-every N`
controls the integrity-snapshot interval.

## Short smoke evidence

```json
{
  "cycles": 40,
  "files_ingested": 40,
  "duplicates": 0,
  "entities": 162,
  "pastes": 40,
  "schedule_runs": 50,
  "stale_recoveries": 5,
  "lease_recoveries": 3,
  "backups": 4,
  "integrity": "ok",
  "chain_valid": true,
  "elapsed_seconds": 2.715,
  "errors": [],
  "ok": true
}
```

This is a harness smoke, not the 24-hour acceptance run. A wall-clock 24-hour
run is an operator step because it depends on the machine staying awake and
the database growing for a day. The release notes state that limitation
explicitly.

## Failure modes covered elsewhere

| Failure | Coverage |
|---|---|
| Worker killed mid-job | `tests/test_jobs.py` lease expiry and recovery |
| Cooperative cancellation | `tests/test_jobs.py` cancel test |
| Scheduler crash leaves `running` | This harness; `tests/test_phase_d.py`; Phase F stale-run test |
| Overlapping schedule runs | Phase D overlap tests |
| Database contention | WAL/busy-timeout plus two-worker tests |
| Disk full during artifact write | Phase F test: temp file removed, no row created |
| Bad image bytes | Phase E magic-byte/dimension tests |
| Corrupt artifact after import | Phase E hash-mismatch test |
| Backup while writing | Online backup + integrity test; this harness |
| Chain fork/tamper | Evidence-chain tests and `/api/v1/verify` |
| Broken plugin load | Parser SDK error isolation tests |

## Interpreting a failure

- `integrity != ok`: stop, restore the last known-good backup, and keep the
  failing file for diagnosis.
- `chain_valid == false`: do not edit the chain; restore a backup and report the
  failing capture.
- `errors` non-empty: inspect the cycle and the schedule run detail. A failed
  file stays in the drop folder by design.
- Growing database with no ingested files: check for duplicate content or a
  parser that returns zero entities; read the import report.

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and
[PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md).
