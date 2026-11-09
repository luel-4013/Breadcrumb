#!/usr/bin/env python3
"""Reproducible import benchmark for the Phase A performance baseline.

Examples:

    .venv/bin/python scripts/bench_import.py --entities 10000
    .venv/bin/python scripts/bench_import.py --entities 100000 --json

The benchmark uses a throwaway SQLite database. It measures the full ingest
path (parse, seal, insert, attribution, cross-program annotation) and prints
the entity count, completeness, skipped rows, elapsed time and database size.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _httpx_fixture(entities: int) -> tuple[str, int]:
    # One httpx record yields url + host + ip + port + tech (5 entities).
    records = max(1, entities // 5)
    lines = []
    for i in range(records):
        host = f"h{i}.bench.test"
        ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        lines.append(
            json.dumps(
                {
                    "url": f"https://{host}/",
                    "input": host,
                    "host": ip,
                    "port": 443,
                    "status_code": 200,
                    "title": f"bench {i}",
                    "webserver": "nginx",
                    "tech": ["nginx"],
                }
            )
        )
    return "\n".join(lines) + "\n", records


def _nmap_fixture(entities: int) -> tuple[str, int]:
    # One nmap host yields ip + host + port + service (4 entities).
    hosts = max(1, entities // 4)
    lines = [f"Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-08 10:00 UTC"]
    for i in range(hosts):
        host = f"h{i}.bench.test"
        ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        lines.append(f"Nmap scan report for {host} ({ip})")
        lines.append("PORT    STATE SERVICE VERSION")
        lines.append("443/tcp open  https   nginx 1.24.0")
        lines.append("")
    lines.append("Nmap done: %d IP address scanned in 1.00 seconds" % hosts)
    return "\n".join(lines) + "\n", hosts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Breadcrumb import throughput")
    parser.add_argument("--entities", type=int, default=10000, help="target entity count")
    parser.add_argument("--format", choices=["httpx", "nmap"], default="httpx")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the temporary database")
    args = parser.parse_args(argv)
    if args.entities < 1:
        parser.error("--entities must be positive")

    tmp = tempfile.TemporaryDirectory(prefix="breadcrumb-bench-")
    db_path = Path(tmp.name) / "bench.db"
    os.environ["BREADCRUMB_DB_PATH"] = str(db_path)
    os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"
    sys.path.insert(0, str(ROOT))

    from sqlmodel import Session, select  # noqa: PLC0415

    from app.db import engine, init_db  # noqa: PLC0415
    from app.ingest import IngestRequest, ingest  # noqa: PLC0415
    from app.models import Entity, Program  # noqa: PLC0415

    init_db()
    with Session(engine) as session:
        program = Program(name="Benchmark")
        session.add(program)
        session.commit()
        session.refresh(program)
        program_id = program.id

    text, records = (
        _httpx_fixture(args.entities)
        if args.format == "httpx"
        else _nmap_fixture(args.entities)
    )
    started = time.perf_counter()
    with Session(engine) as session:
        result = ingest(
            session,
            IngestRequest(
                text=text,
                program_id=program_id,
                source="benchmark",
                command=f"bench_import.py --entities {args.entities} --format {args.format}",
                max_entities=max(args.entities * 2, 25000),
            ),
        )
        persisted = len(
            session.exec(select(Entity).where(Entity.program_id == program_id)).all()
        )
        report = result.report
    elapsed = time.perf_counter() - started
    payload = {
        "format": args.format,
        "requested_entities": args.entities,
        "records": records,
        "parsed_entities": report.get("parsed_entities", result.entities),
        "persisted_entities": persisted,
        "findings": report.get("findings", result.findings),
        "skipped_rows": report.get("skipped_rows", result.skipped_rows),
        "completeness": report.get("completeness", result.completeness),
        "seconds": round(elapsed, 3),
        "entities_per_second": round(
            (report.get("parsed_entities", result.entities) or 0) / max(elapsed, 1e-9),
            1,
        ),
        "database_bytes": db_path.stat().st_size if db_path.exists() else 0,
        "database": str(db_path),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"{payload['format']}: {payload['parsed_entities']} parsed entities "
            f"({payload['persisted_entities']} persisted) in {payload['seconds']}s "
            f"= {payload['entities_per_second']}/s; completeness "
            f"{payload['completeness']:.0%}; skipped {payload['skipped_rows']}"
        )
        print(f"database: {payload['database']} ({payload['database_bytes']} bytes)")
    if not args.keep:
        tmp.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
