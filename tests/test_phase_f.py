"""Phase F: release gate, migration/rollback, reliability and docs coverage."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase-f-")
os.environ.setdefault("BREADCRUMB_DB_PATH", os.path.join(_tmp, "test.db"))
os.environ["BREADCRUMB_ARTIFACT_DIR"] = os.path.join(_tmp, "artifacts")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"
os.environ.setdefault(
    "BREADCRUMB_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost"
)

from sqlmodel import Session, select  # noqa: E402

from app import __version__, artifacts, cli, release  # noqa: E402
from app.db import SCHEMA_VERSION, engine, init_db  # noqa: E402
from app.models import EvidenceArtifact, Program, ScheduleRun  # noqa: E402
from app.schedules import create_schedule, run_schedule  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
init_db()

def _unique_png() -> bytes:
    """A valid PNG whose bytes differ on every call (unique SHA-256)."""

    def chunk(kind: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)

    marker = uuid.uuid4().hex.encode("ascii")
    raw = b"\x00" + bytes((1, 2, 3)) * 2
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 2, 0, 0, 0))
        + chunk(b"tEXt", b"Comment\x00" + marker)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )

TAG = uuid.uuid4().hex[:8]


def _program() -> int:
    with Session(engine) as session:
        program = Program(name=f"phase-f-{TAG}-{uuid.uuid4().hex[:6]}")
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def test_version_schema_and_offline_release_gate():
    assert __version__ == "1.0.0"
    assert SCHEMA_VERSION == 8
    report = release.release_report(ROOT)
    assert report["ok"], {
        name: check
        for name, check in report["checks"].items()
        if not check.get("ok")
    }
    assert report["checks"]["dangerous_code"]["count"] == 0
    assert report["checks"]["secrets"]["count"] == 0
    assert report["checks"]["docs_links"]["count"] == 0
    assert report["checks"]["dependencies"]["runtime_pins"] >= 8
    assert report["checks"]["dependencies"]["ok"] is True


def test_cli_release_check_is_machine_readable(capsys):
    assert cli.main(["release", "check", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["version"] == "1.0.0"
    assert payload["schema_version"] == 8


def test_release_scanner_detects_dangerous_code_and_secrets(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "bad.py").write_text(
        "import subprocess\n"
        "subprocess.run('nmap', shell=True)\n"
        "value = eval('1 + 1')\n",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()
    fake_key = "AKIA" + "Z" * 16
    (tmp_path / "docs" / "leak.md").write_text(
        f"token {fake_key}\n", encoding="utf-8"
    )
    dangerous = release.scan_dangerous_patterns(tmp_path)
    assert {item["pattern"] for item in dangerous} == {"shell_true", "eval"}
    secrets = release.scan_secrets(tmp_path)
    assert len(secrets) == 1
    assert secrets[0]["pattern"] == "aws_access_key"
    assert "AKIAZZZZ" not in json.dumps(secrets)


def test_release_check_rejects_broken_relative_docs_link(tmp_path):
    (tmp_path / "README.md").write_text(
        "[missing](docs/does-not-exist.md)\n", encoding="utf-8"
    )
    broken = release.check_docs_links(tmp_path)
    assert broken and broken[0]["reason"] == "missing"


def test_schema_7_upgrade_creates_phase_e_table():
    db_path = Path(_tmp) / f"schema7-{uuid.uuid4().hex}.db"
    script = r"""
import json
import sqlite3

from app.db import DB_PATH, SCHEMA_VERSION, init_db

init_db()
connection = sqlite3.connect(DB_PATH)
try:
    connection.execute("DROP TABLE evidenceartifact")
    connection.execute("UPDATE appstate SET schema_version=7 WHERE id=1")
    connection.commit()
finally:
    connection.close()

init_db()
connection = sqlite3.connect(DB_PATH)
try:
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='evidenceartifact'"
    ).fetchone()
    index = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='ix_artifact_sha'"
    ).fetchone()
    schema = connection.execute("SELECT schema_version FROM appstate WHERE id=1").fetchone()[0]
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    connection.close()
print(json.dumps({
    "table": bool(table),
    "index": bool(index),
    "schema": schema,
    "expected": SCHEMA_VERSION,
    "integrity": integrity,
}))
"""
    env = os.environ.copy()
    env["BREADCRUMB_DB_PATH"] = str(db_path)
    env["BREADCRUMB_SKIP_BACKUP"] = "1"
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["table"] is True
    assert payload["index"] is True
    assert payload["schema"] == payload["expected"] == 8
    assert payload["integrity"] == "ok"


def test_schedule_stale_run_is_recovered_not_forked(tmp_path):
    program_id = _program()
    drop = tmp_path / "drop"
    drop.mkdir()
    with Session(engine) as session:
        schedule = create_schedule(
            session,
            name=f"phase-f-stale-{TAG}-{uuid.uuid4().hex[:6]}",
            source=str(drop),
            program_id=program_id,
            interval_seconds=60,
        )
        session.add(
            ScheduleRun(
                schedule_id=schedule.id,
                started_at=datetime.now(timezone.utc) - timedelta(hours=3),
                status="running",
            )
        )
        session.commit()
        schedule_id = schedule.id

    (drop / "scan.txt").write_text(
        "Nmap scan report for stale.example.test (192.0.2.44)\n"
        "PORT     STATE SERVICE\n443/tcp  open  https\n",
        encoding="utf-8",
    )
    with Session(engine) as session:
        result = run_schedule(session, schedule_id)
    assert result["status"] == "ok"
    assert result["files_ingested"] == 1
    with Session(engine) as session:
        stale = session.exec(
            select(ScheduleRun)
            .where(ScheduleRun.schedule_id == schedule_id)
            .where(ScheduleRun.status == "stale")
        ).all()
        finished = session.exec(
            select(ScheduleRun)
            .where(ScheduleRun.schedule_id == schedule_id)
            .where(ScheduleRun.status == "ok")
        ).all()
    assert len(stale) == 1
    assert len(finished) == 1


def test_artifact_disk_full_leaves_no_partial_row(monkeypatch):
    program_id = _program()

    def full(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(artifacts.os, "replace", full)
    with Session(engine) as session:
        with pytest.raises(artifacts.ArtifactError) as error:
            artifacts.import_image(session, _unique_png(), program_id=program_id)
        assert "could not write artifact" in str(error.value)
        rows = session.exec(
            select(EvidenceArtifact).where(EvidenceArtifact.program_id == program_id)
        ).all()
        assert rows == []
    leftovers = list(Path(os.environ["BREADCRUMB_ARTIFACT_DIR"]).rglob("*.tmp-*"))
    assert leftovers == []


def test_soak_harness_smoke(tmp_path):
    output = tmp_path / "soak.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "soak.py"),
            "--cycles",
            "3",
            "-o",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["cycles"] == 3
    assert payload["files_ingested"] == 3
    assert payload["integrity"] == "ok"
    assert payload["chain_valid"] is True


def test_migration_and_rollback_drill_from_v040(tmp_path):
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "v0.4.0"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        pytest.skip("v0.4.0 tag is not available in this checkout")
    output = tmp_path / "migration.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "migration_drill.py"),
            "--ref",
            "v0.4.0",
            "-o",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    drill = payload["drills"][0]
    assert drill["ok"] is True
    assert drill["upgrade"]["schema"] == 8
    assert drill["upgrade"]["chain_valid"] is True
    assert drill["upgrade"]["counts"] == drill["seed"]["counts"]
    assert drill["rollback"]["schema"] == drill["seed"]["schema"]
    assert drill["rollback"]["chain_valid"] is True
    assert all(drill["checks"].values())
