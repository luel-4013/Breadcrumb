#!/usr/bin/env python3
"""Accelerated soak harness for local folder schedules and the job queue.

A real 24-hour soak is a wall-clock test. This harness runs the same loop as
fast as the local machine allows and periodically injects the failure modes a
long run would otherwise only discover by accident:

* a schedule run row left ``running`` after a crash (stale recovery);
* a job lease that expired (worker crash recovery);
* a database backup during writes (integrity snapshot);
* a final evidence-chain verification.

It uses an isolated temporary database by default. No network, no external
tools and no real recon data are required.

Examples::

    python scripts/soak.py --cycles 100
    python scripts/soak.py --duration 3600 -o soak-hour.json
    python scripts/soak.py --duration 86400 -o soak-24h.json

The ``--duration 86400`` invocation is the actual 24-hour acceptance run. The
short runs are smoke tests for the harness itself.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NMAP = """Starting Nmap 7.95
Nmap scan report for soak-{cycle}.example.test (192.0.2.{host})
PORT     STATE SERVICE
443/tcp  open  https
22/tcp   open  ssh
"""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycles", type=int, default=60, help="stop after N cycles")
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="stop after N seconds (0 = use --cycles)",
    )
    parser.add_argument(
        "--backup-every", type=int, default=10, help="integrity backup interval"
    )
    parser.add_argument("-o", "--output", default="", help="write the JSON summary")
    parser.add_argument("--keep", action="store_true", help="keep the temp database")
    args = parser.parse_args(argv)

    tmp = Path(tempfile.mkdtemp(prefix="breadcrumb-soak-"))
    db_path = tmp / "soak.db"
    os.environ["BREADCRUMB_DB_PATH"] = str(db_path)
    os.environ["BREADCRUMB_ARTIFACT_DIR"] = str(tmp / "artifacts")
    os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"
    os.environ.setdefault(
        "BREADCRUMB_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost"
    )
    sys.path.insert(0, str(ROOT))

    from sqlmodel import Session, func, select  # noqa: PLC0415

    from app.db import SCHEMA_VERSION, backup_database, engine, init_db  # noqa: PLC0415
    from app.evidence import verify_chain  # noqa: PLC0415
    from app.jobs import queue  # noqa: PLC0415
    from app.models import (  # noqa: PLC0415
        Entity,
        Paste,
        Program,
        ScanJob,
        Schedule,
        ScheduleRun,
    )
    from app.schedules import create_schedule, run_schedule  # noqa: PLC0415

    init_db()
    drop = tmp / "drop"
    drop.mkdir()
    started = time.monotonic()
    deadline = started + args.duration if args.duration > 0 else None
    max_cycles = max(1, args.cycles)
    summary: dict = {
        "started_at": _utcnow().isoformat(),
        "version_schema": SCHEMA_VERSION,
        "cycles": 0,
        "files_ingested": 0,
        "duplicates": 0,
        "errors": [],
        "stale_recoveries": 0,
        "lease_recoveries": 0,
        "backups": 0,
        "integrity": "unchecked",
        "chain_valid": False,
    }

    with Session(engine) as session:
        program = Program(name=f"soak-{os.getpid()}-{tmp.name[-6:]}")
        session.add(program)
        session.commit()
        session.refresh(program)
        program_id = program.id
        schedule = create_schedule(
            session,
            name=f"soak-schedule-{program_id}",
            source=str(drop),
            program_id=program_id,
            interval_seconds=60,
            overlap_policy="skip",
            move_processed=True,
        )
        schedule_id = schedule.id

    cycle = 0
    while cycle < max_cycles:
        if deadline is not None and time.monotonic() >= deadline:
            break
        cycle += 1
        payload = NMAP.format(cycle=cycle, host=(cycle % 250) + 1)
        if cycle % 3 == 0:
            payload += "# repeat marker keeps the fixture unique\n"
        (drop / f"scan-{cycle:05d}.txt").write_text(payload, encoding="utf-8")

        with Session(engine) as session:
            result = run_schedule(session, schedule_id)
        summary["cycles"] = cycle
        summary["files_ingested"] += int(result.get("files_ingested") or 0)
        summary["duplicates"] += int(result.get("duplicates") or 0)
        if result.get("status") not in {"ok", "partial"}:
            summary["errors"].append(
                f"cycle {cycle}: {result.get('status')} {result.get('error') or ''}"
            )

        if cycle % 7 == 0:
            # Simulate a process that died after creating a running row.
            with Session(engine) as session:
                session.add(
                    ScheduleRun(
                        schedule_id=schedule_id,
                        started_at=_utcnow() - timedelta(hours=3),
                        status="running",
                    )
                )
                session.commit()
            with Session(engine) as session:
                result = run_schedule(session, schedule_id)
            with Session(engine) as session:
                stale = session.exec(
                    select(func.count())
                    .select_from(ScheduleRun)
                    .where(ScheduleRun.status == "stale")
                ).one()
            if stale:
                summary["stale_recoveries"] += 1
            if result.get("status") not in {"ok", "partial"}:
                summary["errors"].append(
                    f"cycle {cycle} stale: {result.get('status')} {result.get('error') or ''}"
                )

        if cycle % 11 == 0:
            # Simulate a worker that stopped renewing a lease.
            with Session(engine) as session:
                job = ScanJob(
                    program_id=program_id,
                    runner="soak-never-run",
                    target="192.0.2.1",
                    status="running",
                    attempts=1,
                    lease_owner="dead-worker",
                    lease_expires_at=_utcnow() - timedelta(minutes=5),
                )
                session.add(job)
                session.commit()
            with Session(engine) as session:
                recovered = queue.recover_expired(session)
            if recovered:
                summary["lease_recoveries"] += 1

        if args.backup_every > 0 and cycle % args.backup_every == 0:
            dest = tmp / f"backup-{cycle:05d}.db"
            backup_database(dest)
            conn = sqlite3.connect(dest)
            try:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    summary["errors"].append(f"cycle {cycle}: backup integrity failed")
            finally:
                conn.close()
            summary["backups"] += 1

    with Session(engine) as session:
        pastes = session.exec(select(func.count()).select_from(Paste)).one()
        entities = session.exec(select(func.count()).select_from(Entity)).one()
        runs = session.exec(select(func.count()).select_from(ScheduleRun)).one()
        chain = verify_chain(session)
    conn = sqlite3.connect(db_path)
    try:
        summary["integrity"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()

    summary.update(
        {
            "finished_at": _utcnow().isoformat(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "pastes": int(pastes or 0),
            "entities": int(entities or 0),
            "schedule_runs": int(runs or 0),
            "chain_valid": bool(chain.get("valid")),
            "database_bytes": db_path.stat().st_size if db_path.exists() else 0,
            "database": str(db_path) if args.keep else "(removed)",
        }
    )
    summary["ok"] = (
        not summary["errors"]
        and summary["integrity"] == "ok"
        and summary["chain_valid"]
        and summary["cycles"] > 0
    )

    text = json.dumps(summary, indent=2, sort_keys=True, default=str)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {output}")
    print(text)
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
