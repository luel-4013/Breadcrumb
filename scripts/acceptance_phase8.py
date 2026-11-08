#!/usr/bin/env python3
"""Phase 8 acceptance: import a Leadline database into a throwaway Breadcrumb DB.

The script never opens the source or destination in place:

* the source is copied to a temporary file before it is read;
* the destination is a fresh temporary database, or a temporary copy of the
  database passed with ``--database``;
* the import runs with its normal backup, maintenance mode, manifest and
  verification path;
* the source fingerprint is compared before and after the run.

Exit code 0 means every check passed. ``--json`` prints the full report.

Usage::

    .venv/bin/python scripts/acceptance_phase8.py \
        --source "/path/to/leadline.db"

    .venv/bin/python scripts/acceptance_phase8.py \
        --source /tmp/leadline-copy.db \
        --database /tmp/breadcrumb-copy.db \
        --keep --json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _copy_sqlite(source: Path, destination: Path) -> None:
    """Use SQLite's online backup API so WAL pages are included."""
    source_connection = sqlite3.connect(str(source), timeout=30.0)
    destination_connection = sqlite3.connect(str(destination))
    try:
        source_connection.backup(destination_connection)
        destination_connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        destination_connection.close()
        source_connection.close()


def _raw_header_check(database: Path, program_id: int) -> dict:
    """Confirm every imported header profile is ciphertext at rest."""
    connection = sqlite3.connect(str(database))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT DISTINCT p.id, p.name, p.headers FROM headerprofile p "
            "JOIN target t ON t.meta LIKE '%leadline_header_profile_id%' "
            "WHERE t.program_id = ? AND p.family = 'leadline'",
            (program_id,),
        ).fetchall()
        checked = []
        for row in rows:
            value = row["headers"] or ""
            checked.append(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "encrypted": str(value).startswith("enc:v1:"),
                }
            )
        return {
            "ok": all(item["encrypted"] for item in checked),
            "profiles": checked,
        }
    finally:
        connection.close()


def _job_check(database: Path, program_id: int) -> dict:
    """Imported jobs must be terminal, single-attempt history rows."""
    connection = sqlite3.connect(str(database))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT id, runner, status, attempts, max_attempts, params "
            "FROM scanjob WHERE program_id = ? ORDER BY id",
            (program_id,),
        ).fetchall()
        jobs = []
        for row in rows:
            try:
                params = json.loads(row["params"] or "{}")
            except ValueError:
                params = {}
            jobs.append(
                {
                    "id": row["id"],
                    "runner": row["runner"],
                    "status": row["status"],
                    "attempts": row["attempts"],
                    "max_attempts": row["max_attempts"],
                    "imported": bool(params.get("imported")),
                }
            )
        ok = all(
            job["runner"] == "leadline.imported"
            and job["status"] in ("done", "failed", "cancelled")
            and job["attempts"] == 1
            and job["max_attempts"] == 1
            and job["imported"]
            for job in jobs
        )
        return {"ok": ok, "jobs": jobs}
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Leadline SQLite database")
    parser.add_argument(
        "--database",
        default="",
        help="Breadcrumb DB to copy for the test (default: a fresh temporary DB)",
    )
    parser.add_argument(
        "--program-name",
        default="",
        help="destination program name (default: unique acceptance name)",
    )
    parser.add_argument("--keep", action="store_true", help="keep the work directory")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    args = parser.parse_args(argv)

    source_input = Path(args.source).expanduser().resolve()
    if not source_input.is_file():
        print(f"source database not found: {source_input}", file=sys.stderr)
        return 2

    workdir = Path(tempfile.mkdtemp(prefix="breadcrumb-phase8-acceptance-"))
    source = workdir / "leadline-source.db"
    destination = workdir / "breadcrumb-destination.db"
    _copy_sqlite(source_input, source)
    if args.database:
        database_input = Path(args.database).expanduser().resolve()
        if not database_input.is_file():
            print(f"destination database not found: {database_input}", file=sys.stderr)
            return 2
        _copy_sqlite(database_input, destination)
        # Encrypted header profiles cannot be read without the key that sits
        # next to the database. Copy it into the throwaway work directory.
        for suffix in (".key", ".key.old"):
            key_source = Path(str(database_input) + suffix)
            if key_source.exists():
                shutil.copy2(key_source, Path(str(destination) + suffix))

    os.environ["BREADCRUMB_DB_PATH"] = str(destination)
    os.environ.setdefault("BREADCRUMB_SKIP_BACKUP", "1")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from app.leadline_import import (  # noqa: PLC0415  (after env setup)
        dry_run,
        import_leadline,
        source_fingerprint,
    )

    program_name = args.program_name.strip() or (
        "Phase 8 acceptance " + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    )
    manifest = workdir / "import-manifest.json"
    before = source_fingerprint(source)

    report: dict = {
        "source": str(source_input),
        "source_copy": str(source),
        "database": str(destination),
        "program_name": program_name,
        "checks": [],
    }

    dry = dry_run(source, program_name=program_name)
    report["dry_run"] = {
        "counts": dry["counts"],
        "would_import": dry["would_import"],
        "triage": dry["triage"],
        "severity": dry["severity"],
        "warnings": dry["warnings"],
        "errors": dry["errors"],
    }
    imported = import_leadline(
        source,
        program_name=program_name,
        manifest_path=manifest,
        backup=True,
        generate_snapshots=True,
        verify=True,
    )
    after = source_fingerprint(source)
    report["import"] = imported
    report["source_fingerprint"] = {"before": before, "after": after}

    checks = report["checks"]

    def check(name: str, ok: bool, detail) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    check(
        "source_unchanged",
        before == after,
        {"before": before[0], "after": after[0]},
    )
    check("import_ok", bool(imported.get("ok")), imported.get("warnings") or [])
    verification = imported.get("verification") or {}
    check("verification_ok", bool(verification.get("ok")), verification.get("checks"))
    expected = dry["would_import"]
    imported_counts = imported["counts"]["imported"]
    check(
        "counts",
        all(
            imported_counts[key] == expected[key]
            for key in ("targets", "scans", "events", "findings")
        )
        and imported_counts["entities"] == expected["graph_nodes"],
        {"expected": expected, "imported": imported_counts},
    )
    check(
        "source_fingerprint_matches_report",
        imported["source"]["sha256"] == before[0],
        {"report": imported["source"]["sha256"], "fingerprint": before[0]},
    )
    if imported_counts["scans"]:
        job_check = _job_check(destination, imported["program"]["id"])
        check("imported_jobs_are_historical", job_check["ok"], job_check)
    header_check = _raw_header_check(destination, imported["program"]["id"])
    check("headers_encrypted_at_rest", header_check["ok"], header_check)

    ok = all(item["ok"] for item in checks)
    report["ok"] = ok
    report["workdir"] = str(workdir)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Phase 8 acceptance: {'PASS' if ok else 'FAIL'}")
        print(f"source: {source_input}")
        print(f"program: #{imported['program']['id']} {imported['program']['name']}")
        print(
            "dry-run: "
            + ", ".join(f"{key}={value}" for key, value in dry["would_import"].items())
        )
        print(
            "imported: "
            + ", ".join(
                f"{key}={value}" for key, value in imported_counts.items()
            )
        )
        for item in checks:
            print(f"  {'PASS' if item['ok'] else 'FAIL'} {item['name']}")
        if imported.get("backup"):
            print(f"backup: {imported['backup']}")
        print(f"manifest: {imported['manifest']}")
        print(f"workdir: {workdir}")

    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
