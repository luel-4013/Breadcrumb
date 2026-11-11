#!/usr/bin/env python3
"""Phase D query-scale benchmark: seed a throwaway database, then measure.

Examples:

    .venv/bin/python scripts/bench_scale.py --entities 10000
    .venv/bin/python scripts/bench_scale.py --entities 1000000 --json
    .venv/bin/python scripts/bench_scale.py --entities 100000 --keep

This is deliberately not an ingest benchmark. ``scripts/bench_import.py``
measures the full import path; this script measures the read paths that matter
when the notebook already holds a large history:

* Ledger aggregate + filter (the cross-program memory view);
* a filtered entity page (the API/UI list);
* a free-text Ledger search;
* deep offset pagination.

Rows are seeded with SQLAlchemy Core in batches, so a 1M run takes seconds to
seed rather than hours of parser work. The temporary database is deleted unless
``--keep`` is passed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BATCH = 10_000


def _seed(engine, entities: int) -> tuple[int, float, int]:
    from sqlalchemy import insert
    from sqlmodel import Session

    from app.models import Entity, Program

    with Session(engine) as session:
        programs = [Program(name="Bench A"), Program(name="Bench B")]
        session.add_all(programs)
        session.commit()
        for program in programs:
            session.refresh(program)
        program_ids = [program.id for program in programs]

    types = ["subdomain", "url", "ip", "port"]
    started = time.perf_counter()
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        for start in range(0, entities, BATCH):
            rows = []
            for index in range(start, min(start + BATCH, entities)):
                # Decouple type from program parity so both programs contain
                # every entity type; otherwise one filter is trivially empty.
                etype = types[(index // 2) % len(types)]
                # 90% unique assets, 10% repeats across the two programs.
                if index % 10:
                    value = f"asset-{index}.bench.test"
                else:
                    value = f"shared-{index % 1000}.bench.test"
                rows.append(
                    {
                        "program_id": program_ids[index % 2],
                        "type": etype,
                        "value": value,
                        "normalized": value.lower(),
                        "confidence": 1.0,
                        "parser": "benchmark",
                        "status": "new",
                        "scope_status": ["in", "out", "unknown"][index % 3],
                        "scope_reason": "bench",
                        "status_code": [200, 403, None][index % 3],
                        "ignored": index % 100 == 0,
                        "verdict": "none",
                        "tags": [],
                        "occurrences": 1 + (index % 5 == 0),
                        "meta": {},
                        "provenance": [],
                        "cross_programs": [],
                        "created_at": now,
                    }
                )
            conn.execute(insert(Entity.__table__), rows)
    return len(program_ids), time.perf_counter() - started, entities


def _time(label: str, fn) -> dict:
    started = time.perf_counter()
    value = fn()
    elapsed = time.perf_counter() - started
    if isinstance(value, dict):
        detail = {
            key: value.get(key)
            for key in ("total", "count", "offset", "limit", "next_offset")
            if key in value
        }
    else:
        detail = {"result": value}
    return {"label": label, "seconds": round(elapsed, 4), **detail}


def _plans(engine) -> list[dict]:
    from sqlalchemy import text

    queries = {
        "ledger_group": (
            "SELECT type, lower(normalized) AS norm, count(DISTINCT program_id) "
            "FROM entity WHERE ignored = 0 AND type = 'subdomain' AND scope_status = 'in' "
            "AND status_code = 200 GROUP BY type, lower(normalized)"
        ),
        "entity_filter": (
            "SELECT id, value FROM entity WHERE ignored = 0 AND program_id = 1 "
            "AND type = 'url' ORDER BY id LIMIT 100"
        ),
        "value_search": (
            "SELECT id FROM entity WHERE lower(value) LIKE '%asset-123%' LIMIT 100"
        ),
    }
    plans = []
    with engine.connect() as conn:
        for name, sql in queries.items():
            rows = conn.execute(text("EXPLAIN QUERY PLAN " + sql)).fetchall()
            plans.append(
                {"query": name, "detail": [str(row[-1]) for row in rows]}
            )
    return plans


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Breadcrumb read paths at scale")
    parser.add_argument("--entities", type=int, default=100_000)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the temporary database")
    parser.add_argument(
        "--target-seconds",
        type=float,
        default=2.0,
        help="documented per-query target (default 2s at 1M)",
    )
    args = parser.parse_args(argv)
    if args.entities < 1:
        parser.error("--entities must be positive")

    tmp = Path(tempfile.mkdtemp(prefix="breadcrumb-scale-"))
    db_path = tmp / "scale.db"
    os.environ["BREADCRUMB_DB_PATH"] = str(db_path)
    os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"
    sys.path.insert(0, str(ROOT))

    from sqlmodel import Session, select

    from app import ledger as ledger_mod
    from app.db import engine, init_db
    from app.models import Entity

    init_db()
    programs, seed_seconds, rows = _seed(engine, args.entities)
    db_bytes = db_path.stat().st_size if db_path.exists() else 0

    def ledger_page(query: str, limit: int = 100, offset: int = 0):
        with Session(engine) as session:
            return ledger_mod.ledger_assets(
                session,
                ledger_mod.parse_query(query),
                limit=limit,
                offset=offset,
            )

    def entity_page(program_id: int, etype: str, limit: int = 100):
        with Session(engine) as session:
            from sqlalchemy import func

            stmt = select(Entity).where(
                Entity.ignored == False,  # noqa: E712
                Entity.program_id == program_id,
                Entity.type == etype,
            ).order_by(Entity.id)
            total = session.exec(
                select(func.count()).select_from(stmt.subquery())
            ).one()
            page = session.exec(stmt.limit(limit)).all()
            return {"total": int(total or 0), "count": len(page), "limit": limit}

    measurements = [
        _time("ledger_filtered", lambda: ledger_page("type:subdomain scope:in status:200")),
        _time("ledger_deep_page", lambda: ledger_page("type:url", limit=100, offset=900)),
        _time("ledger_search", lambda: ledger_page("q:shared-42")),
        _time("entity_filtered", lambda: entity_page(1, "url")),
    ]
    slowest = max(item["seconds"] for item in measurements)
    payload = {
        "entities": rows,
        "programs": programs,
        "seed_seconds": round(seed_seconds, 3),
        "database_bytes": db_bytes,
        "target_seconds": args.target_seconds,
        "slowest_query_seconds": slowest,
        "within_target": slowest <= args.target_seconds,
        "measurements": measurements,
        "query_plans": _plans(engine),
        "database": str(db_path),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"seeded {rows} entities across {programs} programs in "
            f"{seed_seconds:.2f}s ({db_bytes / (1024 * 1024):.1f} MB)"
        )
        for item in measurements:
            print(
                f"  {item['label']:<16} {item['seconds']:.3f}s "
                f"(total {item.get('total', '—')}, count {item.get('count', '—')})"
            )
        print(
            f"slowest {slowest:.3f}s; target {args.target_seconds:.3f}s: "
            f"{'PASS' if payload['within_target'] else 'OVER TARGET'}"
        )
        for plan in payload["query_plans"]:
            print(f"  plan {plan['query']}: {'; '.join(plan['detail'])}")
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if payload["within_target"] or args.keep else 1


if __name__ == "__main__":
    raise SystemExit(main())
