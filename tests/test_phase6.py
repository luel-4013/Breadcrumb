"""Phase 6: history snapshots, diffs, triage, PDF and compatibility.

The tests are local-only. They exercise the real snapshot builder against
rows created in the shared pytest database and the real PDF renderer; no
network access is required.
"""

import json
import os
import tempfile
import uuid
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase6-")
os.environ.setdefault("BREADCRUMB_DB_PATH", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BREADCRUMB_SKIP_BACKUP", "1")

import pytest  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import cli, history, pdf_export, reporting, triage  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.jobs import worker  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    Entity,
    Finding,
    Paste,
    Program,
    ScanJob,
    ScanSnapshot,
    Target,
)

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

TAG = uuid.uuid4().hex[:8]
NUCLEI = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE",'
    '"severity":"critical","tags":["cve","rce"]},"host":"https://snap.example.test",'
    '"matched-at":"https://snap.example.test/api/login"}\n'
)


def _program(scope_in: str = "") -> int:
    with Session(engine) as session:
        program = Program(
            name=f"phase6-{TAG}-{uuid.uuid4().hex[:6]}", scope_in=scope_in
        )
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def _target(program_id: int, name: str, kind: str = "domain") -> int:
    with Session(engine) as session:
        target = Target(program_id=program_id, name=name, kind=kind)
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _job(program_id: int, target: str, runner: str = "fake-echo", **kwargs) -> int:
    with Session(engine) as session:
        job = ScanJob(program_id=program_id, runner=runner, target=target, **kwargs)
        session.add(job)
        session.commit()
        session.refresh(job)
        return job.id


def _paste(program_id: int, job_id: int, target_id: int, raw: str, phase: str = "test") -> int:
    with Session(engine) as session:
        paste = Paste(
            program_id=program_id,
            target_id=target_id,
            job_id=job_id,
            phase=phase,
            source=f"test:{TAG}",
            raw=raw,
        )
        session.add(paste)
        session.commit()
        session.refresh(paste)
        return paste.id


def _finding(
    program_id: int,
    target_id: int,
    paste_id: int,
    title: str,
    severity: str,
    fingerprint: str,
    **kwargs,
) -> int:
    with Session(engine) as session:
        finding = Finding(
            program_id=program_id,
            target_id=target_id,
            paste_id=paste_id,
            title=title,
            severity=severity,
            fingerprint=fingerprint,
            source_tool="test",
            **kwargs,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _entity(
    program_id: int,
    target_id: int,
    paste_id: int,
    etype: str,
    value: str,
    meta: dict | None = None,
    **kwargs,
) -> int:
    with Session(engine) as session:
        entity = Entity(
            program_id=program_id,
            target_id=target_id,
            paste_id=paste_id,
            type=etype,
            value=value,
            normalized=value.lower(),
            meta=meta or {},
            **kwargs,
        )
        session.add(entity)
        session.commit()
        session.refresh(entity)
        return entity.id


def _snapshot(job_id: int) -> ScanSnapshot:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert job is not None
        return history.generate_snapshot(session, job)


# --------------------------------------------------------------- triage ----
def test_triage_mapping_roundtrip():
    finding = Finding(title="triage test")
    triage.apply_triage(finding, "acknowledged", "looking into it")
    assert (finding.status, finding.verdict) == ("in-progress", "needs-review")
    assert triage.triage_status(finding) == "acknowledged"
    assert finding.notes == "looking into it"

    triage.apply_triage(finding, "false_positive")
    assert (finding.status, finding.verdict) == ("wont-fix", "false-positive")
    assert triage.is_false_positive(finding)

    triage.apply_triage(finding, "open")
    assert (finding.status, finding.verdict) == ("open", "none")
    assert triage.triage_status(finding) == "open"

    with pytest.raises(ValueError):
        triage.apply_triage(finding, "not-a-status")


# ------------------------------------------------------- snapshots/diffs ----
def test_snapshot_and_diff_track_target_state():
    pid = _program(scope_in="snap.example.test")
    tid = _target(pid, "snap.example.test")
    first_job = _job(pid, "snap.example.test", status="done")
    first_paste = _paste(pid, first_job, tid, "first capture")
    first_finding = _finding(
        pid, tid, first_paste, "Exposed admin panel", "high", "finding-admin"
    )
    _entity(pid, tid, first_paste, "port", "80/tcp", {"port": 80, "proto": "tcp", "service": "http"})
    _entity(pid, tid, first_paste, "subdomain", "a.snap.example.test")
    _entity(pid, tid, first_paste, "tech", "nginx", {"version": "1.18.0"})

    snapshot1 = _snapshot(first_job)
    assert snapshot1.status == "ready"
    assert snapshot1.target_id == tid
    data1 = snapshot1.data
    assert data1["risk_level"] == "high"
    assert data1["finding_count"] == 1
    assert data1["ports"]["80/tcp"]["service"] == "http"
    assert data1["technologies"] == ["nginx 1.18.0"]
    assert data1["technology_versions"] == {"nginx": "1.18.0"}

    # The next scan no longer sees port 80, adds 443 and a new critical
    # finding, and resolves the first finding.
    with Session(engine) as session:
        session.delete(session.get(Finding, first_finding))
        old_port = session.exec(
            select(Entity).where(
                Entity.target_id == tid, Entity.type == "port", Entity.value == "80/tcp"
            )
        ).first()
        assert old_port is not None
        session.delete(old_port)
        old_tech = session.exec(
            select(Entity).where(
                Entity.target_id == tid, Entity.type == "tech", Entity.value == "nginx"
            )
        ).first()
        assert old_tech is not None
        session.delete(old_tech)
        session.commit()

    second_job = _job(pid, "snap.example.test", status="done")
    second_paste = _paste(pid, second_job, tid, "second capture")
    _finding(pid, tid, second_paste, "Remote code execution", "critical", "finding-rce")
    _finding(
        pid,
        tid,
        second_paste,
        "False alarm",
        "critical",
        "finding-fp",
        status="wont-fix",
        verdict="false-positive",
    )
    _entity(pid, tid, second_paste, "port", "443/tcp", {"port": 443, "proto": "tcp", "service": "https"})
    _entity(pid, tid, second_paste, "subdomain", "b.snap.example.test")
    _entity(pid, tid, second_paste, "tech", "nginx", {"version": "1.25.3"})

    snapshot2 = _snapshot(second_job)
    data2 = snapshot2.data
    assert data2["risk_level"] == "critical"
    assert data2["finding_count"] == 1  # the false positive is not active
    assert data2["total_finding_count"] == 2
    assert data2["findings"]["finding-fp"]["is_false_positive"] is True
    assert data2["risk_score"] > data1["risk_score"]

    diff = history.diff_snapshots(data1, data2)
    assert diff["summary"]["new_findings"] == 1
    assert diff["summary"]["removed_findings"] == 1
    assert diff["summary"]["ports_opened"] == 1
    assert diff["summary"]["ports_closed"] == 1
    assert diff["ports"]["opened"] == ["443/tcp"]
    assert diff["ports"]["closed"] == ["80/tcp"]
    assert diff["summary"]["subdomains_added"] == 1
    assert diff["subdomains"]["added"] == ["b.snap.example.test"]
    assert diff["summary"]["technologies_added"] == 1
    assert diff["summary"]["technologies_removed"] == 1
    assert diff["technologies"]["added"] == ["nginx 1.25.3"]
    assert diff["technologies"]["removed"] == ["nginx 1.18.0"]
    assert diff["technology_versions"]["version_changed"] == [
        {"product": "nginx", "before": "1.18.0", "after": "1.25.3"}
    ]
    assert diff["risk"]["direction"] == "increased"
    assert diff["findings"]["new"][0]["title"] == "Remote code execution"
    assert all(
        item["title"] != "False alarm" for item in diff["findings"]["new"]
    )


def test_worker_generates_snapshot_after_done():
    host = f"worker-{TAG}.example.test"
    pid = _program(scope_in=host)
    tid = _target(pid, host)
    job_id = _job(pid, host, params={"text": host})

    assert worker.run_once(
        worker_id=f"phase6-{TAG}",
        lease_seconds=30,
        job_id=job_id,
        runner_ids=("fake-echo",),
    )

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert job.status == "done"
        assert job.target_id == tid
        assert job.output_paste_id is not None
        snapshot = session.exec(
            select(ScanSnapshot).where(ScanSnapshot.job_id == job_id)
        ).first()
        assert snapshot is not None
        assert snapshot.status == "ready"
        assert snapshot.target_id == tid
        assert snapshot.data["target_id"] == tid


def test_snapshot_failure_does_not_fail_done_job(monkeypatch):
    host = f"snapfail-{TAG}.example.test"
    pid = _program(scope_in=host)
    _target(pid, host)
    job_id = _job(pid, host, params={"text": host})

    def _explode(session, job):
        raise RuntimeError("snapshot builder unavailable")

    monkeypatch.setattr(worker, "generate_snapshot", _explode)
    assert worker.run_once(
        worker_id=f"phase6-fail-{TAG}",
        lease_seconds=30,
        job_id=job_id,
        runner_ids=("fake-echo",),
    )
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert job.status == "done"
        snapshot = session.exec(
            select(ScanSnapshot).where(ScanSnapshot.job_id == job_id)
        ).first()
        assert snapshot is not None
        assert snapshot.status == "pending"
        assert "unavailable" in (snapshot.error or "")


# --------------------------------------------------------------- triage UI ----
def test_triage_route_and_report_false_positive_exclusion():
    pid = _program()
    tid = _target(pid, f"report-{TAG}.example.test")
    job_id = _job(pid, f"report-{TAG}.example.test", status="done")
    paste_id = _paste(pid, job_id, tid, "report capture")
    finding_id = _finding(
        pid, tid, paste_id, "False positive report finding", "high", "report-fp"
    )

    r = client.post(
        f"/findings/{finding_id}/triage",
        data={"triage_status": "false_positive", "triage_note": "tested; not exploitable"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "wont-fix"
        assert finding.verdict == "false-positive"
        assert finding.notes == "tested; not exploitable"

    markdown = client.get(f"/reports/{pid}/md").text
    assert "False positive report finding" not in markdown
    internal = client.get(f"/reports/{pid}/md?include_triaged=1").text
    assert "False positive report finding" in internal

    data = reporting.to_dict(Session(engine), pid)
    assert all(
        item["title"] != "False positive report finding"
        for item in data.get("findings", [])
    )
    internal_data = reporting.to_dict(Session(engine), pid, include_triaged=True)
    assert any(
        item["title"] == "False positive report finding"
        for item in internal_data.get("findings", [])
    )
    assert any(
        item["triage_status"] == "false_positive"
        for item in internal_data.get("findings", [])
    )


# ------------------------------------------------------------------ PDF ----
def test_pdf_export_escapes_hostile_text(tmp_path: Path):
    assert pdf_export._escape("<script>alert(1)</script>&") == (
        "&lt;script&gt;alert(1)&lt;/script&gt;&amp;"
    )
    assert pdf_export.safe_filename("../../etc/passwd") == "etc-passwd"
    assert pdf_export.report_filename("https://app.example.test:8443", 7) == (
        "app.example.test_8443-scan-7.pdf"
    )

    content = pdf_export.generate_report_pdf(
        program_name="Test <Program>",
        target_name="app.example.test",
        target_url="https://app.example.test",
        scan_id=7,
        status="completed",
        summary={
            "total_findings": 1,
            "severity_counts": {"critical": 1},
            "risk_score": 85,
            "risk_level": "critical",
        },
        highlights={
            "technologies": ["nginx <1.25"],
            "security_headers_missing": ["Content-Security-Policy"],
            "open_ports": {"443/tcp": {"service": "https", "version": "TLS <1.3"}},
        },
        findings=[
            {
                "title": "<script>alert('xss')</script>",
                "severity": "critical",
                "description": "A & B < C",
                "evidence": "GET /<img src=x onerror=alert(1)> HTTP/1.1",
                "remediation": "Escape & encode",
                "triage_status": "open",
            }
        ],
    )
    assert content.startswith(b"%PDF")
    assert len(content) > 2000
    output = tmp_path / "report.pdf"
    output.write_bytes(content)
    assert output.stat().st_size == len(content)


# ------------------------------------------------------------ compatibility ----
def test_leadline_compatible_api_end_to_end():
    name = f"compat-{TAG}"
    created = client.post(
        "/api/targets",
        json={"name": name, "url": f"https://compat-{TAG}.example.test"},
    )
    assert created.status_code == 201, created.text
    target = created.json()
    target_id = target["id"]
    assert target["name"] == name
    assert target["url"] == f"https://compat-{TAG}.example.test"

    listed = client.get("/api/targets").json()
    assert any(item["id"] == target_id for item in listed)

    scan = client.post(
        "/api/scans",
        json={"target_id": target_id, "runner": "fake-echo", "params": {"text": NUCLEI}},
    )
    assert scan.status_code == 201, scan.text
    scan_id = scan.json()["id"]
    assert scan.json()["status"] == "pending"

    assert worker.run_once(
        worker_id=f"phase6-compat-{TAG}",
        lease_seconds=30,
        job_id=scan_id,
        runner_ids=("fake-echo",),
    )
    completed = client.get(f"/api/scans/{scan_id}").json()
    assert completed["status"] == "completed"

    events = client.get(f"/api/scans/{scan_id}/events").json()
    assert events and events[0]["scan_id"] == scan_id

    findings = client.get(f"/api/findings?scan_id={scan_id}").json()
    assert findings, findings
    finding = findings[0]
    assert finding["triage_status"] == "open"

    patched = client.patch(
        f"/api/findings/{finding['id']}",
        json={"triage_status": "acknowledged", "triage_note": "reviewing"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["triage_status"] == "acknowledged"
    assert patched.json()["status"] == "in-progress"

    report = client.get(f"/api/reports/{scan_id}")
    assert report.status_code == 200, report.text
    payload = report.json()
    assert payload["scan_id"] == scan_id
    assert "summary" in payload and "highlights" in payload

    exported = client.get(f"/api/reports/{scan_id}/export/json")
    assert exported.status_code == 200
    assert json.loads(exported.text)["scan_id"] == scan_id
    assert "text/markdown" in client.get(
        f"/api/reports/{scan_id}/export/markdown"
    ).headers["content-type"]
    assert "<html" in client.get(f"/api/reports/{scan_id}/export/html").text.lower()
    pdf = client.get(f"/api/reports/{scan_id}/export/pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")

    history_payload = client.get(f"/api/targets/{target_id}/history").json()
    assert history_payload["target"]["id"] == target_id
    assert any(scan["job_id"] == scan_id for scan in history_payload["scans"])


def test_program_and_job_pages_show_history_controls():
    host = f"ui-{TAG}.example.test"
    pid = _program(scope_in=host)
    tid = _target(pid, host)
    job_id = _job(pid, host, params={"text": host})
    assert worker.run_once(
        worker_id=f"phase6-ui-{TAG}",
        lease_seconds=30,
        job_id=job_id,
        runner_ids=("fake-echo",),
    )

    program_page = client.get(f"/programs/{pid}")
    assert program_page.status_code == 200
    assert "Rebuild history snapshots" in program_page.text
    assert f"/targets/{tid}/history" in program_page.text
    assert f"/reports/{pid}/pdf" in program_page.text

    job_page = client.get(f"/jobs/{job_id}")
    assert job_page.status_code == 200
    assert "History snapshot" in job_page.text
    assert f"/jobs/{job_id}/report.pdf" in job_page.text
    assert "Rebuild snapshot" in job_page.text

    history_page = client.get(f"/targets/{tid}/history")
    assert history_page.status_code == 200
    assert "Timeline" in history_page.text

    pdf = client.get(f"/jobs/{job_id}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")


# ------------------------------------------------------------------ CLI ----
def test_cli_jobs_history_and_pdf_report(tmp_path: Path, capsys):
    host = f"cli-{TAG}.example.test"
    pid = _program(scope_in=host)
    tid = _target(pid, host)
    job_id = _job(pid, host, params={"text": host})
    assert worker.run_once(
        worker_id=f"phase6-cli-{TAG}",
        lease_seconds=30,
        job_id=job_id,
        runner_ids=("fake-echo",),
    )

    assert cli.main(["jobs", "list"]) == 0
    assert cli.main(["jobs", "show", str(job_id)]) == 0
    assert cli.main(["history", str(tid)]) == 0
    assert cli.main(["history", str(tid), "--diff"]) == 0
    output = tmp_path / "cli-report.pdf"
    assert cli.main(
        ["report", str(job_id), "--format", "pdf", "-o", str(output)]
    ) == 0
    assert output.read_bytes().startswith(b"%PDF")
    captured = capsys.readouterr()
    assert "wrote" in captured.out
