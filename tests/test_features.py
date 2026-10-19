"""Tests for the requested-feature / improvement additions.

Isolated temp DB; covers path scope, verdicts+tags, findings annotations,
job control, SARIF, bulk API, CI gate, proxy config, CLI, and notify.
"""

import io
import json
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-feat-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_NOTIFY_CONFIG"] = os.path.join(_tmp, "notify.json")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import cli, notify  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, Finding  # noqa: E402
from app.scope import Scope  # noqa: E402

init_db()
client = TestClient(app)

NMAP = ("Nmap scan report for web.acme.test (10.0.0.5)\n"
        "443/tcp open https\n22/tcp open ssh\n")


def _program(name="Feat Program"):
    r = client.post("/programs", data={"name": name}, follow_redirects=False)
    assert r.status_code == 303
    return int(r.headers["location"].rstrip("/").split("/")[-1])


def _ingest(pid, text=NMAP):
    r = client.post("/paste", data={"text": text, "program_id": str(pid)},
                    follow_redirects=False)
    assert r.status_code == 303
    return int(r.headers["location"].split("/pastes/")[1].split("?")[0])


def _entities(pid, type_=None):
    with Session(engine) as s:
        stmt = select(Entity).where(Entity.program_id == pid)
        if type_:
            stmt = stmt.where(Entity.type == type_)
        return s.exec(stmt).all()


# ---------------- path-based scope ----------------


def test_path_scope_rules():
    scope = Scope(scope_in="example.com/admin/*\nhttps://api.example.com/v2")
    assert scope.status("https://example.com/admin/panel", "url") == "in"
    assert scope.status("https://example.com/admin/", "url") == "in"
    assert scope.status("https://example.com/public", "url") == "unknown"
    assert scope.status("https://api.example.com/v2/users", "url") == "in"
    # a plain host still falls back to a suffix rule
    plain = Scope(scope_in="example.com")
    assert plain.status("example.com", "domain") == "in"
    assert plain.status("x.example.com", "subdomain") == "in"


def test_path_scope_in_ui():
    pid = _program("Path Scope")
    r = client.post(f"/programs/{pid}/rebuild", follow_redirects=False)
    assert r.status_code == 303
    _ingest(pid, "https://app.example.com/admin/x\nhttps://app.example.com/pub\n")
    # scope not set on this program -> unknown, but route must not error
    assert client.get(f"/programs/{pid}").status_code == 200


# ---------------- verdicts + tags ----------------


def test_entity_verdict_tags_notes_and_filter():
    pid = _program("Annotate")
    paste_id = _ingest(pid)
    rows = _entities(pid, "port")
    assert rows
    eid = rows[0].id

    r = client.post(
        f"/entities/{eid}/annotate",
        data={"verdict": "false-positive", "tags": "noise, reviewed", "notes": "not real"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(engine) as s:
        e = s.get(Entity, eid)
        assert e.verdict == "false-positive"
        assert e.tags == ["noise", "reviewed"]
        assert e.notes == "not real"

    # filter language
    assert client.get("/entities", params={"q": "verdict:false-positive"}).status_code == 200
    assert client.get("/entities", params={"q": "tag:noise"}).status_code == 200
    found = client.get("/entities", params={"q": "tag:noise"}).text
    assert "false-positive" in found

    # false positives are excluded from exports
    md = client.get(f"/reports/{pid}/md").text
    assert rows[0].value not in md


def test_verdict_quick_route():
    pid = _program("Quick Verdict")
    _ingest(pid)
    eid = _entities(pid, "ip")[0].id
    r = client.post(f"/entities/{eid}/verdict", data={"verdict": "confirmed"},
                    follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        assert s.get(Entity, eid).verdict == "confirmed"


# ---------------- findings annotations + notify hook ----------------


def test_finding_tags_and_notes():
    pid = _program("Findings")
    r = client.post(f"/programs/{pid}/findings",
                    data={"title": "XSS in search", "severity": "high", "tags": "xss, web"},
                    follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        f = s.exec(select(Finding).where(Finding.program_id == pid)).first()
        assert f.tags == ["xss", "web"]
        fid = f.id
    r = client.post(f"/findings/{fid}/annotate",
                    data={"tags": "xss, triaged", "notes": "repro attached"},
                    follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.tags == ["xss", "triaged"]
        assert f.notes == "repro attached"


def test_notify_disabled_is_safe():
    cfg = notify.load_config()
    assert notify.is_configured(cfg) is False
    result = notify.test(cfg)
    assert result["sent"] is False


# ---------------- job control ----------------


def test_job_control_flow():
    pid = _program("Jobs")
    r = client.post("/jobs", data={"runner": "nmap", "target": "10.0.0.0/24",
                                   "program_id": str(pid)}, follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        from app.models import ScanJob
        job = s.exec(select(ScanJob).order_by(ScanJob.id.desc())).first()
        jid = job.id
        assert job.status == "queued"

    assert client.get(f"/jobs/{jid}").status_code == 200

    # API moves it to running + logs
    r = client.post(f"/api/v1/jobs/{jid}/status",
                    json={"status": "running", "log": "scanning..."})
    assert r.status_code == 200

    # cancel
    r = client.post(f"/jobs/{jid}/cancel", follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        from app.models import ScanJob
        assert s.get(ScanJob, jid).status == "cancelled"

    # retry makes a fresh queued clone
    before = client.get("/api/v1/jobs").json()["jobs"]
    r = client.post(f"/jobs/{jid}/retry", follow_redirects=False)
    assert r.status_code == 303
    after = client.get("/api/v1/jobs").json()["jobs"]
    assert len(after) == len(before) + 1

    # clear removes finished jobs
    r = client.post("/jobs/clear", follow_redirects=False)
    assert r.status_code == 303
    remaining = client.get("/api/v1/jobs").json()["jobs"]
    assert all(j["status"] in ("queued", "running") for j in remaining)


def test_bad_job_status_rejected():
    r = client.post("/api/v1/jobs/1/status", json={"status": "exploded"})
    # unknown job -> 404, known -> 400; either way not accepted silently
    assert r.status_code in (400, 404)


# ---------------- exports: SARIF ----------------


def test_sarif_export():
    pid = _program("Sarif")
    client.post(f"/programs/{pid}/findings",
                data={"title": "SQL injection", "severity": "critical"}, follow_redirects=False)
    r = client.get(f"/reports/{pid}/sarif")
    assert r.status_code == 200
    data = json.loads(r.text)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Breadcrumb"
    assert any(res["level"] == "error" for res in run["results"])


# ---------------- bulk API + gate ----------------


def test_bulk_api_and_gate():
    pid = _program("Bulk")
    _ingest(pid)
    ids = [e.id for e in _entities(pid)]
    r = client.post("/api/v1/entities/bulk",
                    json={"action": "tag", "ids": ids, "tag": "bulk"})
    assert r.status_code == 200 and r.json()["changed"] == len(ids)

    r = client.post("/api/v1/entities/bulk",
                    json={"action": "verdict", "ids": ids[:1], "verdict": "false-positive"})
    assert r.status_code == 200

    r = client.post("/api/v1/entities/bulk", json={"action": "nonsense", "ids": ids})
    assert r.status_code == 400

    # gate: no high findings -> pass
    assert client.get(f"/api/v1/gate?program_id={pid}").json()["pass"] is True
    client.post(f"/programs/{pid}/findings",
                data={"title": "RCE", "severity": "critical"}, follow_redirects=False)
    r = client.get(f"/api/v1/gate?program_id={pid}&max_severity=high")
    assert r.status_code == 409
    assert r.json()["pass"] is False


def test_findings_api_severity_filter():
    pid = _program("Filter Find")
    client.post(f"/programs/{pid}/findings",
                data={"title": "Low thing", "severity": "low"}, follow_redirects=False)
    client.post(f"/programs/{pid}/findings",
                data={"title": "High thing", "severity": "high"}, follow_redirects=False)
    low = client.get(f"/api/v1/findings?program_id={pid}&min_severity=low").json()
    high = client.get(f"/api/v1/findings?program_id={pid}&min_severity=high").json()
    assert low["count"] >= 2
    assert all(f["severity"] != "low" for f in high["findings"])


# ---------------- proxy / egress config ----------------


def test_header_profile_proxy_and_curl():
    r = client.post("/api/v1/headers", json={
        "name": "proxied", "family": "chrome-windows",
        "headers": {"X-Test": "1"}, "proxy": "socks5://127.0.0.1:9050", "rate_limit": 5,
    })
    assert r.status_code == 201
    body = r.json()
    assert body["proxy"] == "socks5://127.0.0.1:9050"
    assert "-x 'socks5://127.0.0.1:9050'" in body["curl"]


# ---------------- CLI ----------------


def test_cli_export_and_gate(capsys):
    pid = _program("Cli Program")
    client.post(f"/programs/{pid}/findings",
                data={"title": "CLI finding", "severity": "medium"}, follow_redirects=False)

    out = os.path.join(_tmp, "cli.sarif")
    rc = cli.main(["export", str(pid), "--format", "sarif", "-o", out])
    assert rc == 0
    with open(out) as fh:
        assert json.loads(fh.read())["version"] == "2.1.0"

    rc = cli.main(["export", str(pid), "--format", "targets"])
    assert rc == 0

    # gate with a high threshold passes for a medium finding
    rc = cli.main(["gate", str(pid), "--max-severity", "high"])
    assert rc == 0
    rc = cli.main(["gate", str(pid), "--max-severity", "medium"])
    assert rc == 1

    rc = cli.main(["programs", "--json"])
    assert rc == 0


def test_cli_ingest_stdin(monkeypatch):
    pid = _program("Cli Ingest")
    monkeypatch.setattr("sys.stdin", io.StringIO("cli.example.com\n"))
    rc = cli.main(["ingest", "-", "--program", str(pid)])
    assert rc == 0
    assert _entities(pid)


def test_cli_version(capsys):
    assert cli.main(["version"]) == 0
    assert "breadcrumb" in capsys.readouterr().out
