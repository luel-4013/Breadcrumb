#!/usr/bin/env python3
"""Migration and rollback drill for Breadcrumb release gates.

For each requested release tag, this script:

1. checks the old tag out into a temporary git worktree;
2. creates a database with the old code and seeds a program, target, capture,
   entities and a finding through the old ingest path;
3. copies that database and upgrades the copy with the current code;
4. verifies row counts, schema version and the evidence chain;
5. restores the automatic pre-migration backup and opens it with the old code
   to prove the rollback path.

The source database is never used in place. Run it before tagging a release::

    python scripts/migration_drill.py --ref v0.4.0
    python scripts/migration_drill.py --all -o /tmp/migration-drill.json

``--real-db`` additionally upgrades a copy of an existing database (for
example the ignored ``breadcrumb.db`` in the checkout) and reports integrity
and schema without modifying the original.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

NMAP = """Starting Nmap 7.95
Nmap scan report for legacy.example.test (192.0.2.10)
PORT     STATE SERVICE
443/tcp  open  https
22/tcp   open  ssh
"""

SEED = r"""
import json
import sqlite3

from sqlalchemy import func
from sqlmodel import Session, select

from app.db import DB_PATH, SCHEMA_VERSION, engine, init_db
from app.ingest import IngestRequest, ingest
from app.models import Entity, Finding, Paste, Program, Target

init_db()
name = "legacy-" + __import__("sys").argv[1]
with Session(engine) as session:
    program = Program(name=name, scope_in="192.0.2.0/24")
    session.add(program)
    session.commit()
    session.refresh(program)
    target = Target(program_id=program.id, name="legacy.example.test", kind="domain")
    session.add(target)
    session.commit()
    session.refresh(target)
    finding = Finding(
        program_id=program.id,
        target_id=target.id,
        title="Legacy finding survives migration",
        severity="high",
    )
    session.add(finding)
    session.commit()
    result = ingest(
        session,
        IngestRequest(
            text=%r,
            program_id=program.id,
            target_id=target.id,
            source="migration-drill",
        ),
    )
    counts = {
        "program": session.exec(select(func.count()).select_from(Program)).one(),
        "target": session.exec(select(func.count()).select_from(Target)).one(),
        "paste": session.exec(select(func.count()).select_from(Paste)).one(),
        "entity": session.exec(select(func.count()).select_from(Entity)).one(),
        "finding": session.exec(select(func.count()).select_from(Finding)).one(),
    }
connection = sqlite3.connect(DB_PATH)
try:
    schema = connection.execute("SELECT schema_version FROM appstate WHERE id=1").fetchone()[0]
finally:
    connection.close()
print(json.dumps({
    "name": name,
    "schema": schema,
    "counts": {key: int(value or 0) for key, value in counts.items()},
    "paste_id": result.paste.id,
}))
""" % NMAP

UPGRADE = r"""
import json
import sqlite3

from sqlalchemy import func
from sqlmodel import Session, select

from app.db import DB_PATH, SCHEMA_VERSION, engine, init_db
from app.evidence import verify_chain
from app.models import Entity, Finding, Paste, Program, Target

init_db()
with Session(engine) as session:
    counts = {
        "program": session.exec(select(func.count()).select_from(Program)).one(),
        "target": session.exec(select(func.count()).select_from(Target)).one(),
        "paste": session.exec(select(func.count()).select_from(Paste)).one(),
        "entity": session.exec(select(func.count()).select_from(Entity)).one(),
        "finding": session.exec(select(func.count()).select_from(Finding)).one(),
    }
    chain = verify_chain(session)
connection = sqlite3.connect(DB_PATH)
try:
    schema = connection.execute("SELECT schema_version FROM appstate WHERE id=1").fetchone()[0]
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    connection.close()
print(json.dumps({
    "schema": schema,
    "expected_schema": SCHEMA_VERSION,
    "counts": {key: int(value or 0) for key, value in counts.items()},
    "integrity": integrity,
    "chain_valid": bool(chain.get("valid")),
    "chain_issues": [check for check in chain.get("checks", []) if not check.get("ok")],
}))
"""

ROLLBACK = r"""
import hashlib
import json
import sqlite3

from sqlalchemy import func
from sqlmodel import Session, select

from app.db import DB_PATH, SCHEMA_VERSION, engine, init_db
from app.models import Entity, Finding, Paste, Program, Target

init_db()
with Session(engine) as session:
    counts = {
        "program": session.exec(select(func.count()).select_from(Program)).one(),
        "target": session.exec(select(func.count()).select_from(Target)).one(),
        "paste": session.exec(select(func.count()).select_from(Paste)).one(),
        "entity": session.exec(select(func.count()).select_from(Entity)).one(),
        "finding": session.exec(select(func.count()).select_from(Finding)).one(),
    }
    try:
        from app.evidence import verify_chain

        chain_valid = bool(verify_chain(session).get("valid"))
    except ImportError:
        # v0.4.0 predates app.evidence; recompute the same linear chain locally.
        rows = session.exec(
            select(Paste).where(Paste.chain_hash != None).order_by(Paste.id)
        ).all()
        previous = "genesis"
        chain_valid = True
        for paste in rows:
            content = hashlib.sha256(
                (paste.raw or "").encode("utf-8", errors="replace")
            ).hexdigest()
            expected = hashlib.sha256(
                f"{previous}:{content}".encode("utf-8")
            ).hexdigest()
            if paste.chain_hash != expected:
                chain_valid = False
                break
            previous = paste.chain_hash
connection = sqlite3.connect(DB_PATH)
try:
    schema = connection.execute("SELECT schema_version FROM appstate WHERE id=1").fetchone()[0]
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    connection.close()
print(json.dumps({
    "schema": schema,
    "expected_schema": SCHEMA_VERSION,
    "counts": {key: int(value or 0) for key, value in counts.items()},
    "integrity": integrity,
    "chain_valid": chain_valid,
}))
"""


def _run(command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise RuntimeError(
            f"command did not print a JSON result: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        ) from exc


def _base_env(db_path: Path, pythonpath: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["BREADCRUMB_DB_PATH"] = str(db_path)
    env["PYTHONPATH"] = str(pythonpath)
    env.pop("BREADCRUMB_EXECUTOR", None)
    env.pop("BREADCRUMB_EXTERNAL_TOOLS", None)
    env.pop("BREADCRUMB_SECRET_KEY", None)
    env.pop("BREADCRUMB_SECRET_KEYS", None)
    env["BREADCRUMB_SKIP_BACKUP"] = "1"
    return env


def _git(args: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _counts(path: Path) -> dict:
    connection = sqlite3.connect(path)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        counts = {}
        for table in ("program", "target", "paste", "entity", "finding"):
            if table in tables:
                counts[table] = connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
        return {
            "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
            "counts": counts,
            "schema": (
                connection.execute(
                    "SELECT schema_version FROM appstate WHERE id=1"
                ).fetchone()[0]
                if "appstate" in tables
                else None
            ),
        }
    finally:
        connection.close()


def drill_ref(ref: str, work_root: Path) -> dict:
    worktree = work_root / ("old-" + ref.replace("/", "-"))
    legacy_db = work_root / f"legacy-{ref}.db"
    upgrade_db = work_root / f"upgrade-{ref}.db"
    rollback_db = work_root / f"rollback-{ref}.db"
    record: dict = {"ref": ref, "ok": False, "steps": []}
    _git(["worktree", "add", "--detach", str(worktree), ref])
    try:
        seed = _run(
            [PYTHON, "-c", SEED, ref],
            cwd=worktree,
            env=_base_env(legacy_db, worktree),
        )
        record["seed"] = seed
        record["steps"].append({"seed": "ok"})
        shutil.copy2(legacy_db, upgrade_db)

        env = _base_env(upgrade_db, ROOT)
        env.pop("BREADCRUMB_SKIP_BACKUP", None)
        upgrade = _run([PYTHON, "-c", UPGRADE], cwd=ROOT, env=env)
        record["upgrade"] = upgrade
        backups = sorted(work_root.glob(f"upgrade-{ref}.db.pre-migrate-*.bak"))
        if not backups and seed.get("schema") != upgrade.get("schema"):
            raise RuntimeError("upgrade did not create a pre-migration backup")
        record["pre_migrate_backup"] = str(backups[-1]) if backups else None
        record["migration_required"] = bool(backups)
        record["steps"].append({"upgrade": "ok"})

        rollback_source = backups[-1] if backups else legacy_db
        shutil.copy2(rollback_source, rollback_db)
        rollback = _run(
            [PYTHON, "-c", ROLLBACK],
            cwd=worktree,
            env=_base_env(rollback_db, worktree),
        )
        record["rollback"] = rollback
        record["steps"].append({"rollback": "ok"})

        expected = seed["counts"]
        upgrade_counts = upgrade["counts"]
        rollback_counts = rollback["counts"]
        checks = {
            "upgrade_schema": upgrade["schema"] == upgrade["expected_schema"],
            "upgrade_integrity": upgrade["integrity"] == "ok",
            "upgrade_chain": upgrade["chain_valid"] is True,
            "upgrade_counts": upgrade_counts == expected,
            "rollback_schema": rollback["schema"] == seed["schema"],
            "rollback_integrity": rollback["integrity"] == "ok",
            "rollback_chain": rollback["chain_valid"] is True,
            "rollback_counts": rollback_counts == expected,
        }
        record["checks"] = checks
        record["ok"] = all(checks.values())
        return record
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        shutil.rmtree(worktree, ignore_errors=True)


def drill_real_db(path: Path, work_root: Path) -> dict:
    source = path.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"real database not found: {source}")
    copy_path = work_root / "real-copy.db"
    shutil.copy2(source, copy_path)
    env = _base_env(copy_path, ROOT)
    env.pop("BREADCRUMB_SKIP_BACKUP", None)
    upgrade = _run([PYTHON, "-c", UPGRADE], cwd=ROOT, env=env)
    backups = sorted(work_root.glob("real-copy.db.pre-migrate-*.bak"))
    before = _counts(backups[-1]) if backups else {}
    expected = upgrade.get("counts", {})
    checks = {
        "integrity": upgrade["integrity"] == "ok",
        "schema": upgrade["schema"] == upgrade["expected_schema"],
        "chain": upgrade["chain_valid"] is True,
        "pre_migrate_backup": bool(backups),
        "counts_preserved": upgrade.get("counts") == before.get("counts", expected),
    }
    return {
        "source": str(source),
        "copy": str(copy_path),
        "before": before,
        "upgrade": upgrade,
        "checks": checks,
        "ok": all(checks.values()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", action="append", default=[], help="release tag")
    parser.add_argument("--all", action="store_true", help="drill v0.4.0 through v0.9.0")
    parser.add_argument(
        "--real-db",
        default="",
        help="optional existing database to upgrade on a copy",
    )
    parser.add_argument("-o", "--output", default="", help="write JSON evidence")
    parser.add_argument("--keep", action="store_true", help="keep temporary files")
    args = parser.parse_args(argv)

    refs = list(args.ref)
    if args.all or not refs:
        refs = [f"v0.{minor}.0" for minor in range(4, 10)]
    work_root = Path(tempfile.mkdtemp(prefix="breadcrumb-migration-"))
    summary: dict = {"refs": refs, "drills": [], "ok": True}
    try:
        for ref in refs:
            print(f"drilling {ref}...", file=sys.stderr)
            try:
                record = drill_ref(ref, work_root)
            except Exception as exc:  # noqa: BLE001
                record = {"ref": ref, "ok": False, "error": str(exc)}
            summary["drills"].append(record)
            summary["ok"] = summary["ok"] and bool(record.get("ok"))
        if args.real_db:
            print(f"drilling real database {args.real_db}...", file=sys.stderr)
            try:
                record = drill_real_db(Path(args.real_db), work_root)
            except Exception as exc:  # noqa: BLE001
                record = {"source": args.real_db, "ok": False, "error": str(exc)}
            summary["real_db"] = record
            summary["ok"] = summary["ok"] and bool(record.get("ok"))
    finally:
        if not args.keep:
            shutil.rmtree(work_root, ignore_errors=True)
        else:
            summary["work_root"] = str(work_root)

    text = json.dumps(summary, indent=2, sort_keys=True, default=str)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {output}")
    print(text)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
