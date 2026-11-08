"""Phase 8: Leadline import, verification, and historical-job behaviour.

The fixture builds a small Leadline-shaped SQLite database with malformed
rows mixed in, so the tests exercise the importer's skip/report paths rather
than only the happy path. Each test imports into a uniquely named program in
the shared pytest database.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase8-")
os.environ.setdefault("BREADCRUMB_DB_PATH", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BREADCRUMB_SKIP_BACKUP", "1")

import pytest  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import history, triage  # noqa: E402
from app.collect import claimable_collector_ids  # noqa: E402
from app.db import DB_PATH, engine, init_db  # noqa: E402
from app.leadline_import import (  # noqa: E402
    IMPORT_RUNNER,
    LeadlineImportError,
    dry_run,
    import_leadline,
    read_source,
    source_fingerprint,
    verify_import,
)
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    Entity,
    Finding,
    HeaderProfile,
    Program,
    Relationship,
    ScanJob,
    ScanPhase,
    Target,
)

init_db()
TAG = uuid.uuid4().hex[:8]
HEADERS = {"Authorization": "Bearer secret-token", "X-Api-Key": "abc123"}


def _unique(prefix: str) -> str:
    return f"{prefix}-{TAG}-{uuid.uuid4().hex[:6]}"


def _make_source(tmp_path: Path) -> Path:
    path = tmp_path / f"leadline-{uuid.uuid4().hex[:8]}.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            url VARCHAR(512) NOT NULL,
            notes TEXT,
            is_active BOOLEAN,
            custom_headers JSON,
            created_at DATETIME,
            updated_at DATETIME
        );
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            target_id INTEGER NOT NULL,
            status VARCHAR(50),
            progress FLOAT,
            current_phase VARCHAR(100),
            started_at DATETIME,
            completed_at DATETIME,
            error_message TEXT,
            evasion_enabled BOOLEAN,
            request_delay FLOAT,
            enable_external_lookups BOOLEAN,
            created_at DATETIME
        );
        CREATE TABLE scan_events (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            phase_name VARCHAR(100) NOT NULL,
            phase_order INTEGER NOT NULL,
            status VARCHAR(50),
            started_at DATETIME,
            completed_at DATETIME,
            result_data JSON,
            findings_count INTEGER,
            error_message TEXT,
            created_at DATETIME
        );
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            finding_type VARCHAR(100) NOT NULL,
            severity VARCHAR(20),
            title VARCHAR(255) NOT NULL,
            description TEXT,
            location VARCHAR(512),
            evidence TEXT,
            remediation TEXT,
            extra_data JSON,
            is_false_positive BOOLEAN,
            triage_status VARCHAR(30),
            triage_note TEXT,
            triaged_at DATETIME,
            created_at DATETIME
        );
        CREATE TABLE graph_nodes (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            node_id VARCHAR(255) NOT NULL,
            node_type VARCHAR(50) NOT NULL,
            label VARCHAR(255) NOT NULL,
            parent_id VARCHAR(255),
            depth INTEGER,
            extra_data JSON,
            created_at DATETIME
        );
        """
    )
    connection.executemany(
        "INSERT INTO targets VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                1,
                "Example",
                "https://example.com",
                "primary",
                1,
                json.dumps(HEADERS),
                "2026-01-01 10:00:00",
                "2026-01-01 10:00:00",
            ),
            (
                2,
                "API",
                "api.example.com:8443",
                None,
                1,
                json.dumps(HEADERS),
                "2026-01-02 10:00:00",
                "2026-01-02 10:00:00",
            ),
            (
                3,
                "Bad scheme",
                "ftp://bad.example",
                None,
                1,
                None,
                "2026-01-03 10:00:00",
                None,
            ),
            (
                4,
                "Old host",
                "old.example.com",
                "retired",
                0,
                None,
                "2026-01-04 10:00:00",
                None,
            ),
        ],
    )
    connection.executemany(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 1, "completed", 100.0, "graph", "2026-01-01 10:00:00", "2026-01-01 10:05:00", None, 1, 0.5, 1, "2026-01-01 09:59:00"),
            (2, 1, "stopped", 40.0, "http", "2026-01-01 11:00:00", "2026-01-01 11:02:00", None, 1, None, 1, "2026-01-01 10:59:00"),
            (3, 2, "failed", 10.0, "dns", "2026-01-02 10:00:00", "2026-01-02 10:01:00", "boom", 1, None, 1, "2026-01-02 09:59:00"),
            (4, 3, "completed", 100.0, "graph", "2026-01-03 10:00:00", "2026-01-03 10:01:00", None, 1, None, 1, "2026-01-03 09:59:00"),
            (5, 99, "running", 5.0, "dns", "2026-01-04 10:00:00", None, None, 1, None, 1, "2026-01-04 09:59:00"),
        ],
    )
    connection.executemany(
        "INSERT INTO scan_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 1, "dns_discovery", 1, "completed", "2026-01-01 10:00:00", "2026-01-01 10:00:10", json.dumps({"records": 2}), 2, None, "2026-01-01 10:00:00"),
            (2, 1, "graph", 12, "completed", "2026-01-01 10:04:00", "2026-01-01 10:05:00", json.dumps({"edges": [{"source": "ep1", "target": "p1", "relationship": "references"}]}), 0, None, "2026-01-01 10:04:00"),
            (3, 2, "http_fingerprinting", 3, "stopped", "2026-01-01 11:00:00", "2026-01-01 11:02:00", json.dumps({"error": "operator stopped"}), 1, None, "2026-01-01 11:00:00"),
            (4, 3, "dns_discovery", 1, "failed", "2026-01-02 10:00:00", "2026-01-02 10:01:00", json.dumps({"error": "boom"}), 0, "boom", "2026-01-02 10:00:00"),
            (5, 4, "dns_discovery", 1, "completed", "2026-01-03 10:00:00", "2026-01-03 10:01:00", None, 0, None, "2026-01-03 10:00:00"),
        ],
    )
    connection.executemany(
        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                1,
                1,
                "xss",
                "High",
                "Reflected XSS",
                "Input is reflected",
                "https://example.com/search",
                "payload reflected",
                "Encode output",
                json.dumps({"cvss": 7.5, "tags": ["web"]}),
                0,
                "open",
                None,
                None,
                "2026-01-01 10:01:00",
            ),
            (
                2,
                1,
                "misconfig",
                "moderate",
                "Missing CSP",
                "No content security policy",
                "https://example.com",
                "header absent",
                None,
                json.dumps({"cve": "CVE-2024-1234"}),
                0,
                "acknowledged",
                "known issue",
                "2026-01-02 12:00:00",
                "2026-01-01 10:02:00",
            ),
            (
                3,
                1,
                "info",
                "informational",
                "Server banner",
                None,
                "https://example.com",
                "server: nginx",
                None,
                json.dumps({"tags": ["fingerprint"]}),
                0,
                "false_positive",
                "expected",
                "2026-01-02 12:00:00",
                "2026-01-01 10:03:00",
            ),
            (
                4,
                2,
                "port",
                "low",
                "Open port",
                None,
                "https://example.com:8443",
                "8443/tcp open",
                None,
                None,
                0,
                "open",
                None,
                None,
                "2026-01-01 11:01:00",
            ),
            (
                5,
                3,
                "dns",
                "medium",
                "Dangling record",
                None,
                "api.example.com",
                "CNAME target missing",
                None,
                None,
                0,
                "open",
                None,
                None,
                "2026-01-02 10:00:30",
            ),
            (
                6,
                4,
                "ignored",
                "high",
                "Malformed scan row",
                None,
                None,
                None,
                None,
                None,
                0,
                "open",
                None,
                None,
                "2026-01-03 10:00:00",
            ),
        ],
    )
    connection.executemany(
        "INSERT INTO graph_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 1, "root", "root", "https://example.com", None, 0, json.dumps({"source": "seed"}), "2026-01-01 10:00:00"),
            (2, 1, "ep1", "endpoint", "https://example.com/search", "root", 1, None, "2026-01-01 10:00:00"),
            (3, 1, "p1", "parameter", "q", "ep1", 2, None, "2026-01-01 10:00:00"),
            (4, 2, "root2", "root", "https://example.com", None, 0, None, "2026-01-01 11:00:00"),
            (5, 3, "api1", "api", "https://api.example.com:8443/v1", None, 0, None, "2026-01-02 10:00:00"),
            (6, 3, "s1", "service", "https", "api1", 1, None, "2026-01-02 10:00:00"),
            (7, 4, "ignored", "root", "https://bad.example", None, 0, None, "2026-01-03 10:00:00"),
        ],
    )
    connection.commit()
    connection.close()
    return path


def _program(name: str) -> Program | None:
    with Session(engine) as session:
        return session.exec(select(Program).where(Program.name == name)).first()


def _program_rows(name: str) -> dict:
    program = _program(name)
    assert program is not None
    with Session(engine) as session:
        targets = session.exec(
            select(Target).where(Target.program_id == program.id)
        ).all()
        jobs = session.exec(
            select(ScanJob).where(ScanJob.program_id == program.id)
        ).all()
        findings = session.exec(
            select(Finding).where(Finding.program_id == program.id)
        ).all()
        entities = session.exec(
            select(Entity).where(Entity.program_id == program.id)
        ).all()
        relationships = session.exec(
            select(Relationship).where(Relationship.program_id == program.id)
        ).all()
        phases = session.exec(
            select(ScanPhase).where(
                ScanPhase.job_id.in_([job.id for job in jobs])
            )
        ).all() if jobs else []
    return {
        "program": program,
        "targets": targets,
        "jobs": jobs,
        "findings": findings,
        "entities": entities,
        "relationships": relationships,
        "phases": phases,
    }


def test_dry_run_reports_counts_without_writing(tmp_path: Path):
    source = _make_source(tmp_path)
    before_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    name = _unique("phase8-dry")

    report = dry_run(source, program_name=name)

    assert report["dry_run"] is True
    assert report["counts"] == {
        "targets": 4,
        "scans": 5,
        "events": 5,
        "findings": 6,
        "graph_nodes": 7,
    }
    assert report["would_import"] == {
        "targets": 3,
        "scans": 3,
        "events": 4,
        "findings": 5,
        "graph_nodes": 6,
        "header_profiles": 1,
    }
    assert report["distinct_header_sets"] == 1
    assert report["triage"] == {"acknowledged": 1, "false_positive": 1, "open": 3}
    assert report["severity"] == {"high": 1, "info": 1, "low": 1, "medium": 2}
    assert report["malformed_targets"][0]["id"] == 3
    assert {item["id"] for item in report["malformed_scans"]} == {4, 5}
    assert report["source"]["sha256"] == source_fingerprint(source)[0]
    assert report["program"]["would_create"] is True
    assert _program(name) is None
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before_hash


def test_cli_dry_run_wires_the_importer(tmp_path: Path):
    source = _make_source(tmp_path)
    name = _unique("phase8-cli")
    env = os.environ.copy()
    env["BREADCRUMB_DB_PATH"] = str(DB_PATH)
    env["BREADCRUMB_SKIP_BACKUP"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "import-leadline",
            "--db",
            str(source),
            "--program-name",
            name,
            "--dry-run",
            "--json",
        ],
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["would_import"]["findings"] == 5


def test_import_maps_data_and_builds_snapshots(tmp_path: Path):
    source = _make_source(tmp_path)
    before_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    name = _unique("phase8-import")
    manifest = tmp_path / "manifest.json"

    result = import_leadline(
        source, program_name=name, manifest_path=manifest, backup=True
    )

    assert result["ok"] is True, result["verification"]
    assert result["program"]["created"] is True
    assert result["counts"]["imported"] == {
        "programs": 1,
        "targets": 3,
        "header_profiles": 1,
        "scans": 3,
        "attempts": 3,
        "events": 4,
        "phases": 4,
        "findings": 5,
        "entities": 6,
        "graph_nodes": 6,
        "relationships": 4,
        "snapshots": 3,
    }
    assert result["counts"]["skipped"] == {
        "targets": 0,
        "scans": 0,
        "findings": 0,
        "entities": 0,
    }
    assert result["backup"] and Path(result["backup"]).exists()
    assert manifest.exists()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before_hash
    assert result["source"]["sha256"] == source_fingerprint(source)[0]

    rows = _program_rows(name)
    assert len(rows["targets"]) == 3
    by_source = {
        target.meta["leadline_source_id"]: target for target in rows["targets"]
    }
    assert by_source[1].kind == "url"
    assert by_source[2].kind == "url"
    assert by_source[4].kind == "domain"
    assert "inactive" in (by_source[4].notes or "")
    assert by_source[1].meta["leadline_headers_hash"]
    assert by_source[1].meta["leadline_header_profile_id"] == by_source[2].meta[
        "leadline_header_profile_id"
    ]

    with Session(engine) as session:
        profile = session.get(
            HeaderProfile, by_source[1].meta["leadline_header_profile_id"]
        )
        assert profile is not None
        assert profile.family == "leadline"
        assert profile.name.startswith("Leadline import ")
        assert profile.headers == HEADERS

        raw = session.connection().exec_driver_sql(
            "SELECT headers FROM headerprofile WHERE family = 'leadline'"
        ).fetchall()
        assert raw
        assert all(str(value).startswith("enc:v1:") for (value,) in raw)

    jobs = {job.params["leadline_source_id"]: job for job in rows["jobs"]}
    assert set(jobs) == {1, 2, 3}
    assert jobs[1].runner == IMPORT_RUNNER
    assert jobs[1].status == "done"
    assert jobs[2].status == "cancelled"
    assert jobs[3].status == "failed"
    assert jobs[1].attempts == 1 and jobs[1].max_attempts == 1
    assert all(job.params["imported"] is True for job in jobs.values())
    assert jobs[1].header_profile_id == by_source[1].meta[
        "leadline_header_profile_id"
    ]
    assert jobs[3].error == "boom"
    assert "stopped" in (jobs[2].error or "")

    findings = {
        finding.meta["leadline_finding_id"]: finding for finding in rows["findings"]
    }
    assert set(findings) == {1, 2, 3, 4, 5}
    assert findings[1].severity == "high"
    assert findings[1].cvss == "7.5"
    assert findings[1].source_tool == "leadline"
    assert findings[1].fingerprint == (
        "leadline:"
        + hashlib.sha256(b"https://example.com|1|1").hexdigest()[:32]
    )
    assert findings[1].meta["leadline_scan_id"] == 1
    assert findings[1].meta["leadline_extra_data"]["tags"] == ["web"]
    assert "leadline-imported" in findings[1].tags
    assert findings[2].severity == "medium"
    assert findings[2].meta["leadline_triage_status"] == "acknowledged"
    assert "CVE-2024-1234" in findings[2].tags
    assert triage.triage_status(findings[1]) == "open"
    assert triage.triage_status(findings[2]) == "acknowledged"
    assert triage.triage_status(findings[3]) == "false_positive"
    assert findings[1].status == "open" and findings[1].verdict == "none"
    assert findings[2].status == "in-progress"
    assert findings[2].verdict == "needs-review"
    assert findings[2].notes == "known issue"
    assert findings[3].status == "wont-fix"
    assert findings[3].verdict == "false-positive"

    entities = {entity.normalized: entity for entity in rows["entities"]}
    assert set(entities) == {
        "leadline:1:root",
        "leadline:1:ep1",
        "leadline:1:p1",
        "leadline:2:root2",
        "leadline:3:api1",
        "leadline:3:s1",
    }
    assert all(entity.parser == "leadline-import" for entity in entities.values())
    assert entities["leadline:1:root"].meta["leadline_node_type"] == "root"
    assert entities["leadline:1:p1"].meta["leadline_parent_id"] == "ep1"

    relationships = {
        (rel.src_value, rel.dst_value, rel.rel_type)
        for rel in rows["relationships"]
    }
    assert ("https://example.com/search", "https://example.com", "part_of") in relationships
    assert ("q", "https://example.com/search", "part_of") in relationships
    assert ("https://example.com/search", "q", "references") in relationships
    assert ("https", "https://api.example.com:8443/v1", "part_of") in relationships
    assert len(relationships) == 4

    phases = {(phase.job_id, phase.name): phase for phase in rows["phases"]}
    graph_phase = phases[(jobs[1].id, "graph")]
    assert graph_phase.stats["entities"] == 3
    assert phases[(jobs[1].id, "dns_discovery")].stats["leadline_status"] == "completed"
    assert phases[(jobs[2].id, "http_fingerprinting")].status == "cancelled"
    assert phases[(jobs[3].id, "dns_discovery")].status == "failed"

    with Session(engine) as session:
        first = history.snapshot_for_job(session, jobs[1].id)
        second = history.snapshot_for_job(session, jobs[2].id)
        third = history.snapshot_for_job(session, jobs[3].id)
        assert first and first.status == "ready"
        assert second and second.status == "ready"
        assert third and third.status == "ready"
        assert first.data["total_finding_count"] == 3
        assert first.data["finding_count"] == 2  # false positive excluded
        assert first.data["entity_counts"] == {"endpoint": 1, "param": 1, "target": 1}
        assert second.data["total_finding_count"] == 1
        assert second.data["finding_count"] == 1
        assert second.data["entity_counts"] == {"target": 1}
        assert third.data["entity_counts"] == {"endpoint": 1, "service": 1}

    verification = verify_import(
        source, program_name=name, manifest_path=manifest
    )
    assert verification["ok"] is True
    assert all(check["ok"] for check in verification["checks"])
    assert verification["counts"]["actual"] == {
        "targets": 3,
        "scans": 3,
        "events": 4,
        "findings": 5,
        "graph_nodes": 6,
    }

    client = TestClient(app)
    response = client.get(f"/jobs/{jobs[1].id}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF")


def test_reimport_is_idempotent(tmp_path: Path):
    source = _make_source(tmp_path)
    name = _unique("phase8-idempotent")
    manifest = tmp_path / "manifest.json"

    first = import_leadline(
        source, program_name=name, manifest_path=manifest, backup=False
    )
    assert first["ok"] is True
    rows_before = _program_rows(name)

    second = import_leadline(
        source, program_name=name, manifest_path=manifest, backup=False
    )
    assert second["ok"] is True
    assert second["program"]["created"] is False
    assert second["counts"]["imported"]["targets"] == 0
    assert second["counts"]["imported"]["scans"] == 0
    assert second["counts"]["imported"]["findings"] == 0
    assert second["counts"]["imported"]["entities"] == 0
    assert second["counts"]["skipped"]["targets"] == 3
    assert second["counts"]["skipped"]["scans"] == 3

    rows_after = _program_rows(name)
    for key in ("targets", "jobs", "findings", "entities", "relationships", "phases"):
        assert len(rows_after[key]) == len(rows_before[key])

    verification = verify_import(
        source, program_name=name, manifest_path=manifest
    )
    assert verification["ok"] is True


def test_imported_jobs_are_historical_and_not_runnable(tmp_path: Path):
    source = _make_source(tmp_path)
    name = _unique("phase8-history")
    manifest = tmp_path / "manifest.json"
    result = import_leadline(
        source,
        program_name=name,
        manifest_path=manifest,
        backup=False,
        generate_snapshots=False,
    )
    assert result["ok"] is True
    rows = _program_rows(name)
    job = next(job for job in rows["jobs"] if job.params["leadline_source_id"] == 1)

    assert IMPORT_RUNNER not in claimable_collector_ids()

    client = TestClient(app)
    retry = client.post(f"/api/v1/jobs/{job.id}/retry")
    assert retry.status_code == 409
    assert "historical" in retry.json()["detail"].lower()

    run = client.post(f"/api/v1/jobs/{job.id}/run")
    assert run.status_code == 409
    assert "historical" in run.json()["detail"].lower()

    page = client.get(f"/jobs/{job.id}")
    assert page.status_code == 200
    assert "imported Leadline scan" in page.text
    assert f"/jobs/{job.id}/retry" not in page.text

    runners = client.get("/runners")
    assert runners.status_code == 200
    assert f"/jobs/{job.id}/retry" not in runners.text
    assert f"/jobs/{job.id}" in runners.text


def test_verification_detects_a_missing_finding(tmp_path: Path):
    source = _make_source(tmp_path)
    name = _unique("phase8-verify")
    manifest = tmp_path / "manifest.json"
    result = import_leadline(
        source,
        program_name=name,
        manifest_path=manifest,
        backup=False,
        generate_snapshots=False,
    )
    assert result["ok"] is True

    with Session(engine) as session:
        finding = session.exec(
            select(Finding).where(Finding.program_id == result["program"]["id"])
        ).first()
        assert finding is not None
        session.delete(finding)
        session.commit()

    verification = verify_import(
        source, program_name=name, manifest_path=manifest
    )
    assert verification["ok"] is False
    counts = next(
        check for check in verification["checks"] if check["name"] == "counts"
    )
    assert counts["ok"] is False
    assert counts["detail"]["actual"]["findings"] == 4


def test_import_rejects_missing_or_non_leadline_sources(tmp_path: Path):
    with pytest.raises(LeadlineImportError):
        read_source(tmp_path / "missing.db")

    other = tmp_path / "other.db"
    connection = sqlite3.connect(other)
    connection.execute("CREATE TABLE unrelated (id INTEGER)")
    connection.commit()
    connection.close()
    with pytest.raises(LeadlineImportError):
        read_source(other)


def test_source_with_no_scan_tables_is_treated_as_empty(tmp_path: Path):
    source = tmp_path / "targets-only.db"
    connection = sqlite3.connect(source)
    connection.execute(
        "CREATE TABLE targets (id INTEGER PRIMARY KEY, name TEXT, url TEXT)"
    )
    connection.execute(
        "INSERT INTO targets (id, name, url) VALUES (1, 'Only', 'only.example.com')"
    )
    connection.commit()
    connection.close()

    report = dry_run(source, program_name=_unique("phase8-empty"))
    assert report["counts"]["targets"] == 1
    assert report["would_import"]["targets"] == 1
    assert report["would_import"]["scans"] == 0
    assert any("scans" in warning for warning in report["warnings"])
