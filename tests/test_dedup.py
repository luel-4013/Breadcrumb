"""Dedup-correctness properties: re-import must never lose or duplicate data.

Regression guard for the DefectDojo failure class (re-import closing valid
findings / resurrecting duplicates). Uses an isolated temp database.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-dedup-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")

from sqlmodel import Session, func, select  # noqa: E402

from app.attribution import consolidate_entities, merge_into_program, rebuild_program  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models import Entity, Paste, Program, Relationship  # noqa: E402
from app.parsers import analyze  # noqa: E402

init_db()

REPORT_A = "Nmap scan report for web.acme.test (10.0.0.5)\n443/tcp open https\n"
REPORT_B = "Nmap scan report for web.acme.test (10.0.0.5)\n443/tcp open https\n22/tcp open ssh\n"


def _fresh_program(name="Dedup"):
    with Session(engine) as s:
        p = Program(name=name)
        s.add(p)
        s.commit()
        s.refresh(p)
        return p.id


def _ingest_raw(pid, text):
    """Mirror _ingest without importing the web layer."""
    from app.attribution import rebuild_program as _rebuild

    entities, rels, _parsers, _errors = analyze(text)
    with Session(engine) as s:
        paste = Paste(program_id=pid, raw=text, parsers=[])
        s.add(paste)
        s.commit()
        s.refresh(paste)
        for e in entities:
            s.add(Entity(paste_id=paste.id, program_id=pid, type=e.type,
                         value=e.value, normalized=e.normalized,
                         confidence=e.confidence, parser=e.parser,
                         meta=e.meta, provenance=[paste.id]))
        for r in rels:
            s.add(Relationship(paste_id=paste.id, program_id=pid,
                               src_value=r.src_value, src_type=r.src_type,
                               dst_value=r.dst_value, dst_type=r.dst_type,
                               rel_type=r.rel_type, source="parser"))
        s.commit()
        pid_out, paste_id = pid, paste.id
    with Session(engine) as s:
        consolidate_entities(s, pid_out)
        if pid_out:
            _rebuild(s, pid_out)
    return paste_id


def _rows(pid):
    with Session(engine) as s:
        return s.exec(select(Entity).where(Entity.program_id == pid)).all()


def _count(pid):
    with Session(engine) as s:
        return s.exec(
            select(func.count()).select_from(Entity).where(Entity.program_id == pid)
        ).one()


def test_reimport_same_report_is_stable():
    """Ingesting the identical report twice: no duplicates, occurrences grow."""
    pid = _fresh_program("Stable")
    _ingest_raw(pid, REPORT_A)
    first = {(e.type, e.value): e.occurrences for e in _rows(pid)}
    _ingest_raw(pid, REPORT_A)
    second = {(e.type, e.value): e.occurrences for e in _rows(pid)}
    assert set(first) == set(second), "re-import must not add or drop keys"
    assert _count(pid) == len(first), "no duplicate rows may appear"
    for key in first:
        assert second[key] >= first[key], f"occurrences must not shrink for {key}"


def test_reimport_superset_keeps_everything():
    """A bigger re-import keeps old rows AND adds new ones (no valid data lost)."""
    pid = _fresh_program("Superset")
    _ingest_raw(pid, REPORT_A)
    before = {(e.type, e.value) for e in _rows(pid)}
    _ingest_raw(pid, REPORT_B)
    after = {(e.type, e.value) for e in _rows(pid)}
    assert before <= after, f"lost on re-import: {before - after}"
    assert ("port", "22/tcp ssh") in after or any(
        t == "port" and "22" in v for t, v in after), "new port must appear"


def test_distinct_values_never_merge():
    pid = _fresh_program("Distinct")
    _ingest_raw(pid, "10.0.0.1\n10.0.0.2\n10.0.0.3\n")
    ips = sorted(e.value for e in _rows(pid) if e.type == "ip")
    assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_cross_program_isolation():
    a = _fresh_program("IsoA")
    b = _fresh_program("IsoB")
    _ingest_raw(a, "shared.example.com\n")
    _ingest_raw(b, "shared.example.com\n")
    assert _count(a) == _count(b)
    with Session(engine) as s:
        rows = s.exec(select(Entity).where(Entity.value == "shared.example.com")).all()
        assert {e.program_id for e in rows} == {a, b}, "same value in two programs stays two rows"


def test_unassigned_dedup_and_provenance():
    _ingest_raw(None, "lonely.example.com\n")
    _ingest_raw(None, "lonely.example.com\n")
    with Session(engine) as s:
        rows = s.exec(
            select(Entity).where(Entity.program_id == None, Entity.value == "lonely.example.com")  # noqa: E711
        ).all()
        assert len(rows) == 1
        assert len(rows[0].provenance or []) == 2, "both pastes must be recorded"


def test_rebuild_is_idempotent():
    pid = _fresh_program("Idem")
    _ingest_raw(pid, REPORT_B + "https://web.acme.test/app\n")
    with Session(engine) as s:
        n0 = _count(pid)
        e0 = s.exec(select(func.count()).select_from(Relationship)
                    .where(Relationship.program_id == pid)).one()
        for _ in range(3):
            rebuild_program(s, pid)
        n1 = _count(pid)
        e1 = s.exec(select(func.count()).select_from(Relationship)
                    .where(Relationship.program_id == pid)).one()
    assert (n0, e0) == (n1, e1), "rebuild must be a fixed point"


def test_merge_into_program_folds_duplicates():
    """Assigning a paste to a program with the same value merges, not dupes."""
    pid = _fresh_program("Merge")
    paste_id = _ingest_raw(None, "fold.example.com\n")
    _ingest_raw(pid, "fold.example.com\n")
    with Session(engine) as s:
        merge_into_program(s, paste_id, pid)
        rows = s.exec(
            select(Entity).where(Entity.program_id == pid, Entity.value == "fold.example.com")
        ).all()
        assert len(rows) == 1
        assert (rows[0].occurrences or 1) >= 2


def test_relationships_survive_consolidation():
    """Edges re-point at survivors; none dangle at deleted rows."""
    pid = _fresh_program("Edges")
    _ingest_raw(pid, REPORT_B)
    with Session(engine) as s:
        ent_ids = {e.id for e in s.exec(select(Entity).where(Entity.program_id == pid)).all()}
        dangling = s.exec(
            select(Relationship).where(Relationship.program_id == pid)
        ).all()
        for rel in dangling:
            for ref in (rel.src_entity_id, rel.dst_entity_id):
                assert ref is None or ref in ent_ids, "edge points at a deleted row"
