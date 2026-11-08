"""Capabilities no competitor offers: cross-program asset memory and
tamper-evident evidence sealing, plus the authoritative takeover DB.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-uniq-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from concurrent.futures import ThreadPoolExecutor  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, func, select  # noqa: E402

from app.db import engine, init_db  # noqa: E402
from app.main import _ingest as ingest_capture  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, EvidenceChain, Finding, Paste  # noqa: E402
from app.takeover import FINGERPRINTS, detect_takeovers  # noqa: E402

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]


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
    assert body["head_ok"] is True
    assert body["length_ok"] is True


def test_migration_backfills_chain_sequence_and_head():
    from sqlalchemy import text

    from app.db import _migrate

    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ux_paste_chain_seq"))
        conn.execute(text("UPDATE paste SET chain_seq = NULL"))
        conn.execute(text("DELETE FROM evidencechain"))
    _migrate()
    with Session(engine) as session:
        sealed = session.exec(
            select(Paste).where(Paste.chain_hash != None).order_by(Paste.id)  # noqa: E711
        ).all()
        assert sealed
        assert [p.chain_seq for p in sealed] == list(range(1, len(sealed) + 1))
        chain = session.get(EvidenceChain, 1)
        assert chain is not None
        assert chain.head_paste_id == sealed[-1].id
        assert chain.length == len(sealed)


def test_chain_is_linear_under_concurrent_ingest():
    pid = _program("Uniq Race", scope_in="race.test")
    with Session(engine) as session:
        base = session.exec(select(func.max(Paste.chain_seq))).one() or 0
        old_head = session.exec(
            select(Paste)
            .where(Paste.chain_hash != None)  # noqa: E711
            .order_by(Paste.id.desc())
            .limit(1)
        ).first()

    def write(index):
        with Session(engine) as session:
            paste = ingest_capture(
                session,
                f"race-{index}.race.test\n",
                pid,
                None,
                "thread",
            )
            return paste.id, paste.chain_seq, paste.prev_paste_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(write, range(16)))
    seqs = sorted(seq for _, seq, _ in rows)
    assert seqs == list(range(base + 1, base + 17))
    assert len({paste_id for paste_id, _, _ in rows}) == 16
    by_seq = {seq: paste_id for paste_id, seq, _ in rows}
    prev_by_seq = {seq: prev for _, seq, prev in rows}
    assert prev_by_seq[base + 1] == (old_head.id if old_head else None)
    for seq in range(base + 2, base + 17):
        assert prev_by_seq[seq] == by_seq[seq - 1]
    body = client.get("/api/v1/verify").json()
    assert body["valid"] is True
    assert body["forks"] == 0
    assert body["sequence_ok"] is True


def test_chain_recovers_after_program_delete():
    doomed = _program("Uniq Delete A", scope_in="delete.test")
    survivor = _program("Uniq Delete B", scope_in="delete.test")
    _ingest(doomed, "doomed.delete.test")
    last = _ingest(survivor, "survivor.delete.test")
    with Session(engine) as session:
        before = session.exec(
            select(func.count()).select_from(Paste).where(Paste.chain_hash != None)  # noqa: E711
        ).one()
    r = client.post(f"/programs/{doomed}/delete", follow_redirects=False)
    assert r.status_code == 303
    body = client.get("/api/v1/verify").json()
    assert body["valid"] is True
    assert body["gaps"] >= 1
    assert body["chain_head"] == last
    assert body["chain_length"] == before - 1
    _ingest(survivor, "after-delete.delete.test")
    body = client.get("/api/v1/verify").json()
    assert body["valid"] is True
    assert body["chain_length"] == before


def test_verify_detects_broken_chain_head():
    with Session(engine) as session:
        chain = session.get(EvidenceChain, 1)
        assert chain is not None
        original = chain.head_paste_id
        chain.head_paste_id = 987654321
        session.add(chain)
        session.commit()
    try:
        body = client.get("/api/v1/verify").json()
        assert body["valid"] is False
        assert body["head_ok"] is False
    finally:
        with Session(engine) as session:
            chain = session.get(EvidenceChain, 1)
            chain.head_paste_id = original
            session.add(chain)
            session.commit()
    assert client.get("/api/v1/verify").json()["valid"] is True


def test_capture_key_is_unique():
    from sqlalchemy.exc import IntegrityError

    with Session(engine) as session:
        session.add(Paste(raw="first key capture", capture_key="same-delivery"))
        session.commit()
    with Session(engine) as session:
        session.add(Paste(raw="second key capture", capture_key="same-delivery"))
        try:
            session.commit()
            raise AssertionError("duplicate capture_key was accepted")
        except IntegrityError:
            session.rollback()


def test_tampering_breaks_the_chain():
    pid = _program("Uniq Tamper", scope_in="seal.test")
    paste_id = _ingest(pid, "original content seal.test")
    with Session(engine) as s:
        p = s.get(Paste, paste_id)
        assert p.content_sha256 and p.chain_hash
        original = p.raw
        p.raw = "tampered content seal.test"
        s.add(p)
        s.commit()
    try:
        body = client.get("/api/v1/verify").json()
        assert body["valid"] is False
        assert body["broken_at"] == paste_id
    finally:
        with Session(engine) as s:
            p = s.get(Paste, paste_id)
            p.raw = original
            s.add(p)
            s.commit()
    assert client.get("/api/v1/verify").json()["valid"] is True


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
