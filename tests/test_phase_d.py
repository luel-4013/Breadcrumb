"""Phase D: scheduled folder re-import, local parser SDK, API automation, scale."""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase-d-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import schedules  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.ingest import IngestRequest, ingest  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, Finding, Paste, Program, Schedule, ScheduleRun  # noqa: E402
from app.parsers import REGISTRY, analyze_detailed, parser_catalog  # noqa: E402
from app.parsers import sdk as parser_sdk  # noqa: E402

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

ROOT = Path(__file__).resolve().parent.parent
_counter = 0


def _program(name: str | None = None) -> int:
    global _counter
    _counter += 1
    unique = name or f"phase-d-{_counter}-{os.getpid()}"
    with Session(engine) as session:
        existing = session.exec(select(Program).where(Program.name == unique)).first()
        if existing is not None:
            return existing.id
        program = Program(name=unique)
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def _unique(prefix: str, tmp_path) -> str:
    return f"{prefix}-{tmp_path.name[-8:]}"


HTTPX = '{"url":"https://sched.phase-d.test/","status_code":200,"tech":["nginx"]}\n'
NMAP = """Starting Nmap 7.95
Nmap scan report for nmap.phase-d.test (192.0.2.44)
PORT    STATE SERVICE
443/tcp open  https
"""


# --------------------------------------------------------------- schedule ---
def test_schema_has_schedules_and_runs():
    from app.db import SCHEMA_VERSION

    assert SCHEMA_VERSION >= 7
    with Session(engine) as session:
        assert session.exec(select(Schedule)).all() is not None
        assert session.exec(select(ScheduleRun)).all() is not None


def test_create_schedule_validation(tmp_path):
    folder = tmp_path / "drop"
    folder.mkdir()
    with Session(engine) as session:
        name = _unique("validate", tmp_path)
        schedule = schedules.create_schedule(
            session, name, str(folder), interval_seconds=60
        )
        assert schedule.id is not None
        assert schedule.enabled is True
        assert schedule.next_run_at is not None
        try:
            schedules.create_schedule(session, name, str(folder))
        except ValueError as exc:
            assert "already exists" in str(exc)
        else:
            raise AssertionError("duplicate name accepted")

        for bad in (
            {"name": "missing-folder", "source": str(tmp_path / "nope")},
            {"name": "short-interval", "source": str(folder), "interval_seconds": 1},
            {"name": "bad-policy", "source": str(folder), "overlap_policy": "parallel"},
        ):
            try:
                schedules.create_schedule(session, bad.pop("name"), bad.pop("source"), **bad)
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid schedule accepted: {bad}")


def test_schedule_ingests_moves_and_dedupes(tmp_path):
    folder = tmp_path / "drop"
    folder.mkdir()
    (folder / "httpx.jsonl").write_text(HTTPX, encoding="utf-8")
    (folder / "nmap.txt").write_text(NMAP, encoding="utf-8")
    (folder / ".hidden.txt").write_text("hidden.example\n", encoding="utf-8")
    (folder / "subdir").mkdir()
    (folder / "subdir" / "ignored.txt").write_text("subdir.example\n", encoding="utf-8")

    pid = _program()
    with Session(engine) as session:
        schedule = schedules.create_schedule(
            session,
            _unique("ingest", tmp_path),
            str(folder),
            program_id=pid,
            interval_seconds=60,
        )
        result = schedules.run_schedule(session, schedule.id)

        assert result["status"] == "ok", result
        assert result["files_seen"] == 2
        assert result["files_ingested"] == 2
        assert result["entities"] > 0
        assert result["error"] is None
        assert (folder / "processed" / "httpx.jsonl").exists()
        assert (folder / "processed" / "nmap.txt").exists()
        assert (folder / ".hidden.txt").exists()
        assert (folder / "subdir" / "ignored.txt").exists()

        run = session.get(ScheduleRun, result["id"])
        assert run.status == "ok"
        assert run.finished_at is not None
        assert {item["status"] for item in run.detail["files"]} == {"ingested"}
        schedule = session.get(Schedule, schedule.id)
        assert schedule.last_status == "ok"
        assert schedule.run_count == 1
        assert schedule.next_run_at is not None

        first_paste_count = len(session.exec(select(Paste)).all())
        # Re-drop identical bytes: a duplicate capture, not a new one.
        (folder / "httpx.jsonl").write_text(HTTPX, encoding="utf-8")
        again = schedules.run_schedule(session, schedule.id)
        assert again["status"] == "ok"
        assert again["files_ingested"] == 0
        assert again["detail"]["duplicates"] == 1
        assert len(session.exec(select(Paste)).all()) == first_paste_count


def test_empty_binary_and_oversize_files_are_explained(tmp_path, monkeypatch):
    folder = tmp_path / "mixed"
    folder.mkdir()
    (folder / "good.txt").write_text("good.phase-d.test\n", encoding="utf-8")
    (folder / "empty.txt").write_text("", encoding="utf-8")
    (folder / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00binary")
    pid = _program()
    with Session(engine) as session:
        schedule = schedules.create_schedule(
            session, _unique("mixed", tmp_path), str(folder), program_id=pid
        )
        result = schedules.run_schedule(session, schedule.id)
        assert result["status"] == "partial", result
        assert result["files_ingested"] == 1
        assert any("binary" in error for error in result["detail"]["errors"])
        assert (folder / "processed" / "empty.txt").exists()
        assert (folder / "image.png").exists()  # never silently moved/deleted

        monkeypatch.setattr(schedules, "MAX_FILE_BYTES", 10)
        with Session(engine) as fresh:
            big = schedules.create_schedule(
                fresh, _unique("oversize", tmp_path), str(folder), program_id=pid
            )
            # Remove the binary so only the oversized text remains.
            (folder / "image.png").unlink()
            (folder / "big.txt").write_text("x" * 100, encoding="utf-8")
            over = schedules.run_schedule(fresh, big.id)
        assert over["status"] in ("error", "partial")
        assert any("larger than" in error for error in over["detail"]["errors"])
        assert (folder / "big.txt").exists()


def test_overlap_skip_and_stale_recovery(tmp_path):
    folder = tmp_path / "overlap"
    folder.mkdir()
    (folder / "scan.txt").write_text("overlap.phase-d.test\n", encoding="utf-8")
    pid = _program()
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        schedule = schedules.create_schedule(
            session, _unique("overlap", tmp_path), str(folder), program_id=pid
        )
        running = ScheduleRun(
            schedule_id=schedule.id,
            started_at=now,
            status="running",
        )
        session.add(running)
        session.commit()
        session.refresh(running)

        skipped = schedules.run_schedule(session, schedule.id, now=now)
        assert skipped["status"] == "skipped"

        # A crashed row becomes stale after the horizon; the next run proceeds.
        running.started_at = now - timedelta(hours=2)
        running.status = "running"
        session.add(running)
        session.commit()
        recovered = schedules.run_schedule(session, schedule.id, now=now)
        assert recovered["status"] == "ok", recovered
        session.refresh(running)
        assert running.status == "stale"


def test_run_due_ignores_disabled_and_advances_next_run(tmp_path):
    pid = _program()
    folder_a = tmp_path / "due-a"
    folder_b = tmp_path / "due-b"
    folder_a.mkdir()
    folder_b.mkdir()
    (folder_a / "a.txt").write_text("a.phase-d.test\n", encoding="utf-8")
    (folder_b / "b.txt").write_text("b.phase-d.test\n", encoding="utf-8")
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        enabled = schedules.create_schedule(
            session,
            _unique("due-on", tmp_path),
            str(folder_a),
            program_id=pid,
            interval_seconds=60,
            now=now,
        )
        disabled = schedules.create_schedule(
            session,
            _unique("due-off", tmp_path),
            str(folder_b),
            program_id=pid,
            interval_seconds=60,
            enabled=False,
            now=now,
        )
        # Ensure only the two schedules under test are due in this fixture.
        for other in session.exec(select(Schedule)).all():
            if other.id not in (enabled.id, disabled.id):
                other.enabled = False
                session.add(other)
        session.commit()
        results = schedules.run_due(session, now=now)
        assert any(item["schedule_id"] == enabled.id and item["status"] == "ok" for item in results)
        assert all(item["schedule_id"] != disabled.id for item in results)
        session.refresh(enabled)
        assert enabled.next_run_at > now
        session.refresh(disabled)
        assert disabled.last_status == "never"


def test_schedule_cli_and_api(tmp_path):
    folder = tmp_path / "api-drop"
    folder.mkdir()
    (folder / "httpx.jsonl").write_text(HTTPX, encoding="utf-8")
    pid = _program()
    name = _unique("api", tmp_path)
    r = client.post(
        "/api/v1/schedules",
        json={
            "name": name,
            "source": str(folder),
            "program_id": pid,
            "interval_seconds": 30,
        },
    )
    assert r.status_code == 201, r.text
    schedule_id = r.json()["id"]

    r = client.post(f"/api/v1/schedules/{schedule_id}/run")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["files_ingested"] == 1

    detail = client.get(f"/api/v1/schedules/{schedule_id}")
    assert detail.status_code == 200
    assert detail.json()["runs"][0]["status"] == "ok"

    r = client.patch(
        f"/api/v1/schedules/{schedule_id}",
        json={"interval_seconds": 120, "enabled": False},
    )
    assert r.status_code == 200
    assert r.json()["interval_seconds"] == 120
    assert r.json()["enabled"] is False

    for path in ("/schedules", f"/schedules/{schedule_id}"):
        page = client.get(path)
        assert page.status_code == 200, path
        assert "Folder schedule" in page.text or "Add a schedule" in page.text

    assert client.delete(f"/api/v1/schedules/{schedule_id}").json()["deleted"] is True
    assert client.get(f"/api/v1/schedules/{schedule_id}").status_code == 404


def test_schedule_cli_smoke(tmp_path):
    folder = tmp_path / "cli-drop"
    folder.mkdir()
    (folder / "scan.txt").write_text("cli.phase-d.test\n", encoding="utf-8")
    name = _unique("cli", tmp_path)
    env = dict(os.environ)
    env["BREADCRUMB_SKIP_BACKUP"] = "1"

    add = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "schedule",
            "add",
            name,
            str(folder),
            "--interval",
            "30",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert add.returncode == 0, add.stderr
    listed = subprocess.run(
        [sys.executable, "-m", "app.cli", "schedule", "list", "--json"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert listed.returncode == 0, listed.stderr
    rows = json.loads(listed.stdout)["schedules"]
    assert any(row["name"] == name for row in rows)

    run = subprocess.run(
        [sys.executable, "-m", "app.cli", "schedule", "run", name, "--json"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["status"] == "ok"

    disabled = subprocess.run(
        [sys.executable, "-m", "app.cli", "schedule", "disable", name],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert disabled.returncode == 0, disabled.stderr
    enabled = subprocess.run(
        [sys.executable, "-m", "app.cli", "schedule", "enable", name],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert enabled.returncode == 0, enabled.stderr
    deleted = subprocess.run(
        [sys.executable, "-m", "app.cli", "schedule", "delete", name, "--yes"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert deleted.returncode == 0, deleted.stderr


def test_schedule_form_route(tmp_path):
    folder = tmp_path / "form-drop"
    folder.mkdir()
    name = _unique("form", tmp_path)
    r = client.post(
        "/schedules",
        data={
            "name": name,
            "source": str(folder),
            "interval_seconds": 60,
            "overlap_policy": "skip",
            "move_processed": "on",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    location = r.headers["location"]
    assert "/schedules/" in location
    detail = client.get(location)
    assert detail.status_code == 200
    assert name in detail.text


# ------------------------------------------------------------- parser SDK ---
def test_local_parser_sdk_contract_and_isolation(tmp_path):
    plugin_dir = tmp_path / "parsers"
    plugin_dir.mkdir()
    plugin = plugin_dir / "example_scanner.py"
    plugin.write_text(
        """
from app.parsers.base import Entity, ParseResult, Parser

class ExampleScanner(Parser):
    name = "phase_d_example"
    description = "Phase D test parser"
    parser_version = "7"
    def detect(self, text):
        return 0.99 if "PHASE-D-EXAMPLE" in text else 0.0
    def parse_detailed(self, text):
        result = ParseResult(parser_version=self.parser_version)
        result.entities.append(Entity(type="domain", value="plugin.phase-d.test"))
        result.stats["marker"] = "seen"
        return result

PARSER = ExampleScanner()
PARSER_META = {"author": "test", "homepage": "local"}
""",
        encoding="utf-8",
    )
    broken = plugin_dir / "broken_plugin.py"
    broken.write_text("raise RuntimeError('broken by design')\n", encoding="utf-8")
    # Sort after the valid plugin so the duplicate is rejected, not the reverse.
    duplicate = plugin_dir / "zz_duplicate_name.py"
    duplicate.write_text(
        """
from app.parsers.base import Parser
class Duplicate(Parser):
    name = "phase_d_example"
    def detect(self, text):
        return 0.0
PARSER = Duplicate()
""",
        encoding="utf-8",
    )

    before = list(REGISTRY)
    try:
        loaded = parser_sdk.load_local_parsers(plugin_dir)
        assert [item["name"] for item in loaded] == ["phase_d_example"]
        assert loaded[0]["meta"]["author"] == "test"
        errors = parser_sdk.plugin_errors()
        assert any("broken by design" in item["error"] for item in errors)
        assert any("already registered" in item["error"] for item in errors)

        result = analyze_detailed("PHASE-D-EXAMPLE")
        assert "phase_d_example" in result.parsers
        assert any(entity.value == "plugin.phase-d.test" for entity in result.entities)
        catalog = parser_catalog()
        local = [item for item in catalog if item["name"] == "phase_d_example"]
        assert local and local[0]["source"] == "local"
        assert local[0]["version"] == "7"
    finally:
        REGISTRY[:] = before
        parser_sdk.PLUGINS.clear()
        parser_sdk._LOADED_PATHS.clear()
        parser_sdk.PLUGIN_ERRORS.clear()


def test_parsers_route_and_api():
    for path in ("/parsers", "/api/v1/parsers"):
        response = client.get(path)
        assert response.status_code == 200, path
    payload = client.get("/api/v1/parsers").json()
    assert payload["count"] >= 20
    assert payload["directory"]


# --------------------------------------------------------- API automation ---
def test_paste_capture_key_is_idempotent():
    pid = _program()
    key = f"phase-d-idem-{os.getpid()}"
    body = {"text": HTTPX, "program_id": pid, "capture_key": key}
    first = client.post("/api/v1/pastes", json=body)
    assert first.status_code == 201, first.text
    assert first.json()["duplicate"] is False
    second = client.post("/api/v1/pastes", json=body)
    assert second.status_code == 200, second.text
    assert second.json()["duplicate"] is True
    assert second.json()["paste_id"] == first.json()["paste_id"]

    # Raw-body pipelines can use the header instead of a JSON field.
    header_key = key + "-raw"
    raw = client.post(
        "/api/v1/pastes",
        content=HTTPX.encode("utf-8"),
        headers={"Idempotency-Key": header_key, "Content-Type": "text/plain"},
    )
    assert raw.status_code == 201
    raw_again = client.post(
        "/api/v1/pastes",
        content=HTTPX.encode("utf-8"),
        headers={"Idempotency-Key": header_key, "Content-Type": "text/plain"},
    )
    assert raw_again.status_code == 200
    assert raw_again.json()["duplicate"] is True


def test_bulk_paste_and_findings_pagination():
    pid = _program()
    nuclei = "\n".join(
        json.dumps(
            {
                "template-id": f"phase-d-panel-{index}",
                "matched-at": f"https://paged.phase-d.test/admin{index}",
                "host": "paged.phase-d.test",
                "info": {"name": f"Phase D panel {index}", "severity": "high"},
            }
        )
        for index in (1, 2)
    )
    r = client.post(
        "/api/v1/pastes/bulk",
        json={
            "program_id": pid,
            "captures": [
                {"filename": "nuclei.jsonl", "text": nuclei, "capture_key": f"bulk-{pid}-n"},
                {"filename": "empty", "text": ""},
                {"filename": "httpx.jsonl", "text": HTTPX, "capture_key": f"bulk-{pid}-h"},
            ],
        },
    )
    assert r.status_code == 207, r.text
    payload = r.json()
    assert payload["count"] == 3
    assert payload["ok"] == 2
    assert payload["failed"] == 1

    page = client.get(
        "/api/v1/findings",
        params={"program_id": pid, "limit": 1, "offset": 0},
    )
    assert page.status_code == 200
    body = page.json()
    assert body["total"] >= 1
    assert body["count"] == 1
    assert body["next_offset"] == 1

    filtered = client.get(
        "/api/v1/findings",
        params={"program_id": pid, "min_severity": "critical"},
    )
    assert filtered.json()["total"] == 0


def test_api_rejects_bad_links_and_options():
    r = client.post("/api/v1/pastes", json={"text": "x", "program_id": 999999})
    assert r.status_code == 400
    r = client.post("/api/v1/pastes/bulk", json={"captures": []})
    assert r.status_code == 400
    r = client.post(
        "/api/v1/pastes/bulk",
        json={"captures": [{"text": "x", "program_id": 999999}]},
    )
    assert r.status_code == 207
    assert r.json()["failed"] == 1
    r = client.post(
        "/api/v1/schedules",
        json={"name": "bad", "source": "/does/not/exist"},
    )
    assert r.status_code == 400


def test_scheduler_inline_due_run_is_idempotent(tmp_path):
    folder = tmp_path / "inline"
    folder.mkdir()
    (folder / "scan.txt").write_text("inline.phase-d.test\n", encoding="utf-8")
    with Session(engine) as session:
        schedules.create_schedule(
            session, _unique("inline", tmp_path), str(folder), interval_seconds=60
        )
    runs = schedules.run_forever(once=True)
    assert runs >= 1
