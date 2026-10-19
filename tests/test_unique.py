"""Capabilities no competitor offers: cross-program asset memory and
tamper-evident evidence sealing, plus the authoritative takeover DB.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-uniq-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, Finding, Paste  # noqa: E402
from app.takeover import FINGERPRINTS, detect_takeovers  # noqa: E402

init_db()
client = TestClient(app)


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


# ---------------- cross-program memory ----------------


def test_cross_program_memory_flags_repeat_assets():
    a = _program("Uniq Alpha", scope_in="shared.test")
    b = _program("Uniq Beta", scope_in="shared.test")
    _ingest(a, "host1.shared.test\nhost2.shared.test")
    # Before the second ingest, program A entities have no cross-program links.
    with Session(engine) as s:
        first = s.exec(select(Entity).where(Entity.program_id == a,
                                            Entity.value == "host1.shared.test")).first()
    assert first is not None and first.cross_programs == []

    _ingest(b, "host1.shared.test\nhost3.shared.test")
    with Session(engine) as s:
        second = s.exec(select(Entity).where(Entity.program_id == b,
                                             Entity.value == "host1.shared.test")).first()
        uniq = s.exec(select(Entity).where(Entity.program_id == b,
                                           Entity.value == "host3.shared.test")).first()
    assert second is not None and second.cross_programs, "repeat asset should be flagged"
    assert second.cross_programs[0]["name"] == "Uniq Alpha"
    assert uniq is not None and uniq.cross_programs == []


def test_ledger_page_lists_shared_assets():
    a = _program("Uniq Ledger A", scope_in="ledger.test")
    b = _program("Uniq Ledger B", scope_in="ledger.test")
    _ingest(a, "edge.ledger.test")
    _ingest(b, "edge.ledger.test")
    r = client.get("/ledger")
    assert r.status_code == 200
    assert "edge.ledger.test" in r.text
    assert "seen in 2" in r.text


# ---------------- tamper-evident sealing ----------------


def test_captures_are_sealed_and_verify_clean():
    pid = _program("Uniq Seal", scope_in="seal.test")
    _ingest(pid, "a.seal.test")
    _ingest(pid, "b.seal.test")
    r = client.get("/api/v1/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["broken_at"] is None
    assert body["sealed"] >= 2


def test_tampering_breaks_the_chain():
    pid = _program("Uniq Tamper", scope_in="seal.test")
    paste_id = _ingest(pid, "original content seal.test")
    with Session(engine) as s:
        p = s.get(Paste, paste_id)
        assert p.content_sha256 and p.chain_hash
        p.raw = "tampered content seal.test"
        s.add(p)
        s.commit()
    body = client.get("/api/v1/verify").json()
    assert body["valid"] is False
    assert body["broken_at"] == paste_id


# ---------------- authoritative takeover DB ----------------


def test_takeover_db_has_multiple_critical_services():
    assert len(FINGERPRINTS) >= 25
    for needle in ("elasticbeanstalk.com", "s3.amazonaws.com", "ngrok.io"):
        assert needle in FINGERPRINTS


def test_takeover_detects_elasticbeanstalk():

    class _E:
        def __init__(self, value, cname):
            self.type = "subdomain"
            self.value = value
            self.meta = {"cname": cname}

    found = detect_takeovers([_E("app.example.com", "x.us-east-1.elasticbeanstalk.com")])
    assert found and found[0]["severity"] == "high"
    assert "Elastic Beanstalk" in found[0]["title"] or "Elastic Beanstalk" in found[0]["description"]
