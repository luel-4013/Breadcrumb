"""ProjectDiscovery pipeline coverage.

The dominant solo-hunter workflow: subfinder | httpx | nuclei. Before these
parsers existed, nuclei output produced zero findings and httpx fingerprints
(status/title/tech/cname) were thrown away.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-pd-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, Finding, Program, Target  # noqa: E402
from app.parsers import REGISTRY, analyze, extract_findings, load_all  # noqa: E402

init_db()
client = TestClient(app)

NUCLEI = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE",'
    '"severity":"critical","tags":["cve","rce"],'
    '"classification":{"cvss-score":10.0}},"host":"https://app.acme.test",'
    '"matched-at":"https://app.acme.test/api/login","matcher-name":"oast"}\n'
    '{"template-id":"exposed-env","info":{"name":"Exposed .env",'
    '"severity":"medium","tags":["exposure"]},"host":"https://app.acme.test",'
    '"matched-at":"https://app.acme.test/.env"}'
)
HTTPX = (
    '{"url":"https://app.acme.test","input":"app.acme.test","status_code":200,'
    '"title":"Admin","tech":["nginx","React"],"cname":["orphan.s3.amazonaws.com"],'
    '"webserver":"nginx","host":"10.0.0.5","port":"443","scheme":"https"}'
)
NAABU = '{"host":"app.acme.test","ip":"10.0.0.5","port":8080}'
MASSCAN = "Discovered open port 443/tcp on 10.0.0.5"


def _program(name, scope_in=""):
    r = client.post("/programs", data={"name": name, "scope_in": scope_in},
                    follow_redirects=False)
    assert r.status_code == 303
    return int(r.headers["location"].rstrip("/").split("/")[-1])


def _ingest(pid, text):
    r = client.post("/paste", data={"text": text, "program_id": str(pid)},
                    follow_redirects=False)
    assert r.status_code == 303
    return int(r.headers["location"].split("/pastes/")[1].split("?")[0])


def _findings(pid):
    with Session(engine) as s:
        return s.exec(select(Finding).where(Finding.program_id == pid)).all()


# ---------------- parser registration ----------------


def test_registry_includes_new_parsers():
    load_all()
    names = {p.name for p in REGISTRY}
    assert {"nuclei", "httpx", "ports"} <= names


# ---------------- nuclei -> findings ----------------


def test_nuclei_emits_findings_with_severity():
    found = extract_findings(NUCLEI)
    titles = {f["title"]: f for f in found}
    assert titles["Apache Log4j RCE"]["severity"] == "critical"
    assert titles["Apache Log4j RCE"]["cvss"] == 10.0
    assert titles["Exposed .env"]["severity"] == "medium"


def test_nuclei_ingest_creates_findings():
    pid = _program("PD Nuclei")
    _ingest(pid, NUCLEI)
    fs = _findings(pid)
    assert {f.title for f in fs} == {"Apache Log4j RCE", "Exposed .env"}
    log4j = next(f for f in fs if f.title == "Apache Log4j RCE")
    assert log4j.severity == "critical"
    assert log4j.fingerprint and log4j.source_tool == "nuclei"


def test_nuclei_reimport_is_idempotent():
    pid = _program("PD Nuclei Dedup")
    _ingest(pid, NUCLEI)
    first = _findings(pid)
    _ingest(pid, NUCLEI)
    again = _findings(pid)
    assert len(first) == len(again) == 2
    # re-import keeps status (does not reopen) and refreshes updated_at
    assert all(f.status == "open" for f in again)


# ---------------- httpx fingerprints + takeover ----------------


def test_httpx_entities_and_tech():
    entities, _rels, parsers, _errs = analyze(HTTPX)
    assert "httpx" in parsers
    types = {e.type for e in entities}
    assert {"tech", "port", "url", "subdomain"} <= types
    tech = sorted(e.value for e in entities if e.type == "tech")
    assert tech == ["React", "nginx"]
    url = next(e for e in entities if e.type == "url")
    assert url.meta["status_code"] == 200
    assert url.meta["title"] == "Admin"


def test_httpx_takeover_candidate_becomes_finding():
    pid = _program("PD Takeover", scope_in="acme.test")
    _ingest(pid, HTTPX)
    fs = _findings(pid)
    takeover = [f for f in fs if "takeover" in f.tags]
    assert takeover, "CNAME to S3 should surface a takeover candidate"
    assert takeover[0].severity == "high"
    assert takeover[0].target_id is not None


# ---------------- port scanners ----------------


def test_naabu_and_masscan_ports():
    for sample, port in ((NAABU, 8080), (MASSCAN, 443)):
        entities, _r, parsers, _e = analyze(sample)
        assert "ports" in parsers
        ports = [e for e in entities if e.type == "port"]
        assert any(e.meta.get("port") == port for e in ports), sample


# ---------------- auto-target from scope ----------------


def test_targets_auto_created_from_scope():
    pid = _program("PD Scope", scope_in="acme.test\n10.0.0.0/24\n!skip.acme.test")
    with Session(engine) as s:
        names = {t.name for t in s.exec(select(Target).where(Target.program_id == pid)).all()}
    assert "acme.test" in names
    assert "10.0.0.0/24" in names
    assert "skip.acme.test" not in names


def test_findings_attributed_to_matching_target():
    pid = _program("PD Attribute", scope_in="acme.test")
    _ingest(pid, NUCLEI)
    with Session(engine) as s:
        target = s.exec(select(Target).where(Target.program_id == pid)).first()
    assert target is not None
    fs = _findings(pid)
    assert fs and all(f.target_id == target.id for f in fs)


# ---------------- program / target CRUD ----------------


def test_program_update_and_delete():
    pid = _program("PD CRUD", scope_in="old.acme.test")
    r = client.post(f"/programs/{pid}/update",
                    data={"name": "PD CRUD Renamed", "scope_in": "new.acme.test"},
                    follow_redirects=False)
    assert r.status_code == 303
    _ingest(pid, NUCLEI)
    with Session(engine) as s:
        assert s.get(Program, pid).name == "PD CRUD Renamed"
    r = client.post(f"/programs/{pid}/delete", follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        assert s.get(Program, pid) is None
        assert s.exec(select(Entity).where(Entity.program_id == pid)).all() == []
        assert s.exec(select(Finding).where(Finding.program_id == pid)).all() == []


def test_target_delete_detaches_entities():
    pid = _program("PD Target Delete", scope_in="acme.test")
    _ingest(pid, NUCLEI)
    with Session(engine) as s:
        target = s.exec(select(Target).where(Target.program_id == pid)).first()
        target_id = target.id
    r = client.post(f"/programs/{pid}/targets/{target_id}/delete", follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        assert s.get(Target, target_id) is None
        still = s.exec(select(Entity).where(Entity.program_id == pid)).all()
    assert still and all(e.target_id is None for e in still)


# ---------------- pipeline generator + drop-folder watch ----------------


def test_pipeline_page_generates_chain():
    pid = _program("PD Pipeline", scope_in="acme.test")
    r = client.get(f"/pipeline?program_id={pid}")
    assert r.status_code == 200
    body = r.text
    assert "subfinder" in body and "nuclei" in body and "httpx" in body
    assert f"--program {pid}" in body


def test_cli_watch_once_ingests_and_moves(tmp_path=None):
    import tempfile

    from app import cli

    folder = tempfile.mkdtemp(prefix="breadcrumb-drop-")
    pid = _program("PD Watch", scope_in="acme.test")
    with open(os.path.join(folder, "nuclei.jsonl"), "w") as fh:
        fh.write(NUCLEI)
    rc = cli.main(["watch", folder, "--program", str(pid), "--once"])
    assert rc == 0
    fs = _findings(pid)
    assert {f.title for f in fs} == {"Apache Log4j RCE", "Exposed .env"}
    assert os.path.exists(os.path.join(folder, "processed", "nuclei.jsonl"))
