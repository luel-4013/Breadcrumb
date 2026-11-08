"""Durable job queue, scope guard, native collectors and migration tests.

These tests exercise the merged execution path end to end. They use unique
program names and never rely on the database being empty, because pytest runs
all modules in one process (and therefore one SQLite file) here.
"""

import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="breadcrumb-jobs-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

import pytest  # noqa: E402,F401  (keeps this module a normal pytest target)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlmodel import Session, func, select  # noqa: E402

from app.collect import PRIVATE_TARGET_WARNING, ScopeGuard, get_collector  # noqa: E402
from app.collect.base import CollectorContext  # noqa: E402
from app.db import engine, init_db, set_maintenance  # noqa: E402
from app.ingest import IngestRequest, ingest  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    Entity,
    Finding,
    HeaderProfile,
    JobAttempt,
    JobEvent,
    Paste,
    Program,
    Relationship,
    ScanJob,
    ScanPhase,
)
from app.scope import Scope  # noqa: E402
from app.jobs import queue, worker  # noqa: E402

init_db()
TAG = uuid.uuid4().hex[:8]


def _program(scope_in="127.0.0.1", name=None) -> int:
    with Session(engine) as session:
        program = Program(name=name or f"jobs-{TAG}-{uuid.uuid4().hex[:6]}", scope_in=scope_in)
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def _job(program_id: int, runner: str, target: str, **kwargs) -> int:
    with Session(engine) as session:
        job = ScanJob(program_id=program_id, runner=runner, target=target, **kwargs)
        session.add(job)
        session.commit()
        session.refresh(job)
        return job.id


def _get_job(job_id: int) -> ScanJob:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert job is not None
        return job


def _finish_claimed(job_id: int) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        attempt = session.exec(
            select(JobAttempt)
            .where(JobAttempt.job_id == job_id, JobAttempt.status == "running")
            .order_by(JobAttempt.id.desc())
        ).first()
        queue.finish(
            session,
            job_id,
            attempt.id if attempt else None,
            "done",
            worker_id=job.lease_owner if job else None,
        )


# ---------------------------------------------------------------- ingest ----
def test_capture_key_is_idempotent_and_does_not_fork_chain():
    pid = _program()
    key = f"test-capture-{TAG}-{uuid.uuid4().hex}"
    text = "Nmap scan report for web.acme.test (10.0.0.5)\n80/tcp open http\n"

    with Session(engine) as session:
        first = ingest(
            session,
            IngestRequest(text=text, program_id=pid, source="test", capture_key=key),
        )
    with Session(engine) as session:
        second = ingest(
            session,
            IngestRequest(text=text, program_id=pid, source="test", capture_key=key),
        )

    assert first.paste.id == second.paste.id
    assert second.duplicate is True
    with Session(engine) as session:
        pastes = session.exec(select(Paste).where(Paste.capture_key == key)).all()
        assert len(pastes) == 1
        n_entities = session.exec(
            select(func.count()).select_from(Entity).where(Entity.paste_id == first.paste.id)
        ).one()
        assert n_entities == first.entities
    assert n_entities > 0


# ------------------------------------------------------------- migration ----
def test_old_database_is_migrated_in_subprocess(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE program (
          id INTEGER PRIMARY KEY, name VARCHAR NOT NULL, platform VARCHAR,
          scope_in TEXT, scope_out TEXT, notes TEXT, ai_summary TEXT,
          ai_model VARCHAR, ai_at DATETIME, created_at DATETIME
        );
        CREATE TABLE paste (
          id INTEGER PRIMARY KEY, program_id INTEGER, target_id INTEGER,
          source VARCHAR NOT NULL, tool_guess VARCHAR, parsers TEXT,
          parse_errors TEXT, ai_analysis TEXT, ai_model VARCHAR, ai_at DATETIME,
          raw TEXT NOT NULL, content_sha256 VARCHAR, chain_hash VARCHAR,
          prev_paste_id INTEGER, created_at DATETIME
        );
        CREATE TABLE scanjob (
          id INTEGER PRIMARY KEY, program_id INTEGER, runner VARCHAR NOT NULL,
          target VARCHAR, status VARCHAR NOT NULL, header_profile_id INTEGER,
          log TEXT, created_at DATETIME, started_at DATETIME, finished_at DATETIME
        );
        INSERT INTO program (id, name, created_at)
          VALUES (1, 'legacy', '2026-01-01 00:00:00');
        INSERT INTO paste
          (id, program_id, source, raw, content_sha256, chain_hash, created_at)
          VALUES (1, 1, 'legacy', 'old capture', 'abc', 'oldhash',
                  '2026-01-01 00:00:00');
        """
    )
    conn.commit()
    conn.close()

    script = r"""
import json
from sqlalchemy import inspect
from sqlmodel import Session
from app.db import engine, get_app_state, init_db

init_db()
insp = inspect(engine)
with Session(engine) as session:
    state = get_app_state(session)
    print(json.dumps({
        "schema_version": state.schema_version,
        "paste_columns": sorted(c["name"] for c in insp.get_columns("paste")),
        "scanjob_columns": sorted(c["name"] for c in insp.get_columns("scanjob")),
    }))
"""
    env = dict(os.environ)
    env.update(
        BREADCRUMB_DB_PATH=str(db_path),
        BREADCRUMB_SKIP_BACKUP="1",
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    import json

    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["schema_version"] == 4
    assert {"chain_seq", "capture_key", "job_id", "attempt_id", "phase"} <= set(
        payload["paste_columns"]
    )
    assert {"params", "priority", "attempts", "max_attempts", "lease_owner"} <= set(
        payload["scanjob_columns"]
    )

    conn = sqlite3.connect(db_path)
    chain_seq = conn.execute("SELECT chain_seq FROM paste WHERE id=1").fetchone()[0]
    head = conn.execute("SELECT head_paste_id, length FROM evidencechain WHERE id=1").fetchone()
    conn.close()
    assert chain_seq == 1
    assert head == (1, 1)


# ----------------------------------------------------------- queue claims ----
def test_concurrent_claims_are_exclusive():
    pid = _program()
    job_ids = [_job(pid, "fake-echo", "127.0.0.1") for _ in range(6)]
    barrier = threading.Barrier(len(job_ids))

    def claim(index: int):
        barrier.wait(timeout=10)
        with Session(engine) as session:
            result = queue.claim_next(
                session,
                worker_id=f"claim-worker-{TAG}-{index}",
                runner_ids=("fake-echo",),
                lease_seconds=30,
            )
            return result.job.id if result else None

    with ThreadPoolExecutor(max_workers=len(job_ids)) as pool:
        claimed = list(pool.map(claim, range(len(job_ids))))

    assert all(job_id is not None for job_id in claimed), claimed
    assert len(set(claimed)) == len(claimed), claimed
    assert set(claimed) == set(job_ids)
    for job_id in job_ids:
        _finish_claimed(job_id)


def test_two_workers_drain_fifty_jobs_without_duplicates():
    pid = _program()
    total = 50
    job_ids = [
        _job(pid, "fake-echo", "127.0.0.1", params={"text": f"drain-{TAG}-{i}.example.test"})
        for i in range(total)
    ]
    errors: list[BaseException] = []

    def drain(worker_id: str) -> None:
        try:
            while worker.run_once(
                worker_id=worker_id,
                lease_seconds=30,
                runner_ids=("fake-echo",),
            ):
                pass
        except BaseException as exc:  # noqa: BLE001  (surface thread failures)
            errors.append(exc)

    threads = [
        threading.Thread(target=drain, args=(f"drain-{TAG}-{i}",))
        for i in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert errors == []
    assert all(not thread.is_alive() for thread in threads)
    with Session(engine) as session:
        jobs = session.exec(select(ScanJob).where(ScanJob.id.in_(job_ids))).all()
        assert len(jobs) == total
        assert {job.status for job in jobs} == {"done"}
        assert all(job.output_paste_id is not None for job in jobs)
        attempts = session.exec(
            select(func.count()).select_from(JobAttempt).where(JobAttempt.job_id.in_(job_ids))
        ).one()
        assert attempts == total
        pastes = session.exec(
            select(func.count()).select_from(Paste).where(Paste.job_id.in_(job_ids))
        ).one()
        assert pastes == total
        duplicates = session.exec(
            select(Paste.capture_key, func.count())
            .where(Paste.job_id.in_(job_ids))
            .group_by(Paste.capture_key)
            .having(func.count() > 1)
        ).all()
        assert duplicates == []


def test_maintenance_pauses_claims():
    pid = _program()
    job_id = _job(pid, "fake-echo", "127.0.0.1")
    set_maintenance(True, "test pause")
    try:
        with Session(engine) as session:
            assert queue.claim_next(
                session,
                worker_id=f"maintenance-{TAG}",
                runner_ids=("fake-echo",),
                job_id=job_id,
            ) is None
    finally:
        set_maintenance(False)
    with Session(engine) as session:
        claim = queue.claim_next(
            session,
            worker_id=f"maintenance-{TAG}",
            runner_ids=("fake-echo",),
            job_id=job_id,
        )
        assert claim is not None
    _finish_claimed(job_id)


def test_retry_backoff_then_failure():
    pid = _program()
    job_id = _job(pid, "fake-echo", "127.0.0.1", max_attempts=2)
    with Session(engine) as session:
        claim = queue.claim_next(
            session,
            worker_id=f"retry-{TAG}",
            runner_ids=("fake-echo",),
            job_id=job_id,
        )
        assert claim is not None
        outcome = queue.retry_or_fail(
            session, job_id, claim.attempt.id, "transient test error",
            worker_id=claim.job.lease_owner,
        )
    assert outcome == "queued"
    job = _get_job(job_id)
    assert job.status == "queued"
    assert job.next_run_at is not None
    assert job.error == "transient test error"
    with Session(engine) as session:
        attempt = session.exec(
            select(JobAttempt).where(JobAttempt.job_id == job_id).order_by(JobAttempt.id.desc())
        ).first()
        assert attempt.status == "failed"

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        job.next_run_at = None
        session.add(job)
        session.commit()
        claim = queue.claim_next(
            session,
            worker_id=f"retry-{TAG}",
            runner_ids=("fake-echo",),
            job_id=job_id,
        )
        assert claim is not None and claim.job.attempts == 2
        outcome = queue.retry_or_fail(
            session, job_id, claim.attempt.id, "final test error",
            worker_id=claim.job.lease_owner,
        )
    assert outcome == "failed"
    job = _get_job(job_id)
    assert job.status == "failed"
    assert job.error == "final test error"


def test_worker_cancellation_is_cooperative():
    pid = _program()
    job_id = _job(
        pid, "fake-cancel", "127.0.0.1", params={"seconds": 8}, max_attempts=1
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            worker.run_once,
            worker_id=f"cancel-{TAG}",
            lease_seconds=5,
            job_id=job_id,
            runner_ids=("fake-cancel",),
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _get_job(job_id).status != "running":
            time.sleep(0.05)
        assert _get_job(job_id).status == "running"
        with Session(engine) as session:
            assert queue.request_cancel(session, job_id) == "cancel-requested"
        future.result(timeout=20)

    job = _get_job(job_id)
    assert job.status == "cancelled"
    assert job.cancel_requested is True
    with Session(engine) as session:
        attempt = session.exec(
            select(JobAttempt).where(JobAttempt.job_id == job_id).order_by(JobAttempt.id.desc())
        ).first()
        assert attempt.status == "cancelled"


def test_expired_lease_is_recovered():
    pid = _program()
    job_id = _job(pid, "fake-echo", "127.0.0.1", max_attempts=2)
    with Session(engine) as session:
        claim = queue.claim_next(
            session,
            worker_id=f"expired-{TAG}",
            runner_ids=("fake-echo",),
            job_id=job_id,
            lease_seconds=5,
        )
        assert claim is not None
        session.add(
            ScanPhase(
                job_id=job_id,
                attempt_id=claim.attempt.id,
                seq=1,
                name="stale",
                status="running",
            )
        )
        job = session.get(ScanJob, job_id)
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.add(job)
        session.commit()

    assert queue.recover_expired() >= 1
    job = _get_job(job_id)
    assert job.status == "queued"
    assert job.lease_owner is None
    assert job.next_run_at is not None
    with Session(engine) as session:
        attempt = session.exec(
            select(JobAttempt).where(JobAttempt.job_id == job_id).order_by(JobAttempt.id.desc())
        ).first()
        assert attempt.status == "lost"
        phase = session.exec(select(ScanPhase).where(ScanPhase.job_id == job_id)).first()
        assert phase.status == "lost"
        assert phase.finished_at is not None
        job = session.get(ScanJob, job_id)
        job.next_run_at = None
        session.add(job)
        session.commit()
        claim = queue.claim_next(
            session,
            worker_id=f"expired-{TAG}",
            runner_ids=("fake-echo",),
            job_id=job_id,
        )
        assert claim is not None
    _finish_claimed(job_id)


def test_job_cannot_finish_done_without_sealed_output():
    pid = _program()
    job_id = _job(pid, "fake-echo", "", params={"text": ""}, max_attempts=1)
    assert worker.run_once(
        worker_id=f"empty-{TAG}",
        lease_seconds=30,
        job_id=job_id,
        runner_ids=("fake-echo",),
    ) is True
    job = _get_job(job_id)
    assert job.status == "failed"
    assert "no sealed output" in (job.error or "")
    with Session(engine) as session:
        assert session.exec(select(Paste).where(Paste.job_id == job_id)).all() == []


def test_worker_once_runs_at_most_one_job():
    pid = _program()
    first = _job(pid, "fake-echo", "127.0.0.1", params={"text": "once-a.example.test"})
    second = _job(pid, "fake-echo", "127.0.0.1", params={"text": "once-b.example.test"})
    assert worker.run_worker(once=True, worker_id=f"once-{TAG}") == 1
    statuses = {job_id: _get_job(job_id).status for job_id in (first, second)}
    assert sorted(statuses.values()) == ["done", "queued"], statuses

    remaining = next(job_id for job_id, status in statuses.items() if status == "queued")
    with Session(engine) as session:
        claim = queue.claim_next(
            session,
            worker_id=f"once-cleanup-{TAG}",
            runner_ids=("fake-echo",),
            job_id=remaining,
        )
        assert claim is not None
    _finish_claimed(remaining)


# ----------------------------------------------------------- scope guard ----
def _fake_resolver(mapping: dict[str, list[str]]):
    def resolve(host, port, family, socktype, proto):  # noqa: ARG001
        addresses = mapping.get(host, [])
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port or 0))
            for address in addresses
        ]

    return resolve


def test_scope_guard_denies_out_unknown_and_blocked_targets():
    guard = ScopeGuard(
        Scope("example.test\ninternal.test", "blocked.example.test"),
        resolver=_fake_resolver(
            {
                "example.test": ["93.184.216.34"],
                "internal.test": ["127.0.0.1"],
                "mixed.test": ["93.184.216.34", "169.254.169.254"],
            }
        ),
    )
    assert guard.check_host("example.test").allowed is True
    assert guard.check_host("blocked.example.test").status == "out"
    assert guard.check_host("blocked.example.test").allowed is False
    assert guard.check_host("unknown.test").status == "unknown"
    assert guard.check_host("unknown.test").allowed is False
    assert guard.check_url("file:///etc/passwd").allowed is False
    assert guard.check_url("https://user:pass@example.test/").allowed is False
    assert guard.check_url("https://example.test:8443/").allowed is True

    private = guard.check_host("internal.test")
    assert private.allowed is True
    assert PRIVATE_TARGET_WARNING in private.warnings

    mixed = ScopeGuard(
        Scope("mixed.test"), resolver=_fake_resolver({"mixed.test": ["93.184.216.34", "169.254.169.254"]})
    ).check_host("mixed.test")
    assert mixed.allowed is False
    assert mixed.blocked_addresses == ("169.254.169.254",)

    metadata = ScopeGuard(Scope("169.254.0.0/16")).check_url(
        "http://169.254.169.254/latest/meta-data/"
    )
    assert metadata.allowed is False
    assert metadata.blocked_addresses == ("169.254.169.254",)

    metadata_host = ScopeGuard(Scope("metadata.google.internal")).check_host(
        "metadata.google.internal"
    )
    assert metadata_host.allowed is False
    assert "metadata" in metadata_host.reason

    empty = ScopeGuard(Scope("")).check_host("example.test")
    assert empty.allowed is False


def test_scope_guard_can_refuse_private_targets():
    guard = ScopeGuard(
        Scope("internal.test"),
        allow_private=False,
        resolver=_fake_resolver({"internal.test": ["10.0.0.5"]}),
    )
    decision = guard.check_host("internal.test")
    assert decision.allowed is False
    assert "private" in decision.reason


# ------------------------------------------------------------ collectors ----
def test_dns_collector_emits_bind_records_and_skips_out_of_scope_names():
    collector = get_collector("leadline-dns")
    assert collector is not None
    ctx = CollectorContext(
        target="127.0.0.1",
        options={"subdomains": "out-of-scope.test"},
        guard=ScopeGuard(Scope("127.0.0.1")),
        job_id=1,
        attempt_id=1,
        worker_id="test",
    )
    result = collector.run(ctx)
    assert len(result.phases) == 1
    phase = result.phases[0]
    assert phase.name == "dns"
    assert "127.0.0.1. 0 IN A 127.0.0.1" in phase.output
    assert phase.error is None
    assert phase.stats["skipped"] == 1


class _LocalHandler(BaseHTTPRequestHandler):
    redirect_to = ""

    def do_GET(self):  # noqa: N802
        if self.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = (
            b"<html><head><title>Local Test</title></head>"
            b"<body>wp-content</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.send_header("X-Powered-By", "PHP")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002
        pass


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_http_native_job_reaches_done_with_sealed_phases():
    _LocalHandler.redirect_to = ""
    server, port = _serve(_LocalHandler)
    try:
        pid = _program(scope_in="127.0.0.1")
        job_id = _job(pid, "leadline-http", f"http://127.0.0.1:{port}/")
        assert worker.run_once(
            worker_id=f"http-{TAG}",
            lease_seconds=30,
            job_id=job_id,
            runner_ids=("leadline-http",),
        ) is True

        job = _get_job(job_id)
        assert job.status == "done"
        assert job.output_paste_id is not None
        assert job.error is None
        with Session(engine) as session:
            attempt = session.exec(
                select(JobAttempt).where(JobAttempt.job_id == job_id).order_by(JobAttempt.id.desc())
            ).first()
            assert attempt.status == "done"
            assert attempt.output_paste_id == job.output_paste_id
            phases = session.exec(
                select(ScanPhase).where(ScanPhase.job_id == job_id).order_by(ScanPhase.seq)
            ).all()
            assert [phase.name for phase in phases] == ["http", "headers"]
            assert all(phase.status == "done" for phase in phases)
            assert all(phase.output_paste_id for phase in phases)
            pastes = session.exec(select(Paste).where(Paste.job_id == job_id)).all()
            assert len(pastes) == 2
            assert all(paste.chain_hash and paste.chain_seq for paste in pastes)
            assert {paste.capture_key for paste in pastes} == {
                f"job:{job_id}:attempt:1:1:http",
                f"job:{job_id}:attempt:1:2:headers",
            }
            types = {
                entity.type
                for entity in session.exec(
                    select(Entity).where(Entity.paste_id.in_([p.id for p in pastes]))
                ).all()
            }
            assert {"url", "ip", "port", "tech", "header"} <= types
            events = session.exec(select(JobEvent).where(JobEvent.job_id == job_id)).all()
            assert any(event.kind == "done" for event in events)
            assert any(event.kind == "scope" for event in events)
    finally:
        server.shutdown()
        server.server_close()


def test_native_http_job_sends_decrypted_header_profile():
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.update({key.lower(): value for key, value in self.headers.items()})
            body = b"<html><head><title>Profile Test</title></head></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: ARG002
            pass

    server, port = _serve(Handler)
    try:
        secret = f"Bearer {uuid.uuid4().hex}"
        pid = _program(scope_in="127.0.0.1")
        with Session(engine) as session:
            profile = HeaderProfile(
                name=f"profile-{TAG}-{uuid.uuid4().hex[:6]}",
                family="curl-minimal",
                headers={"Authorization": secret, "X-Test": "yes"},
                proxy="",
            )
            session.add(profile)
            session.commit()
            session.refresh(profile)
            profile_id = profile.id

        job_id = _job(
            pid,
            "leadline-http",
            f"http://127.0.0.1:{port}/",
            header_profile_id=profile_id,
        )
        assert worker.run_once(
            worker_id=f"profile-{TAG}",
            lease_seconds=30,
            job_id=job_id,
            runner_ids=("leadline-http",),
        ) is True
        assert _get_job(job_id).status == "done"
        assert seen["authorization"] == secret
        assert seen["x-test"] == "yes"

        with engine.connect() as conn:
            raw = conn.execute(
                text("SELECT headers FROM headerprofile WHERE id = :id"),
                {"id": profile_id},
            ).scalar_one()
        assert raw.startswith("enc:v1:")
        assert secret not in raw
    finally:
        server.shutdown()
        server.server_close()


def test_header_secrets_are_redacted_from_job_errors():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: ARG002
            pass

    server, port = _serve(Handler)
    try:
        secret = f"Bearer {uuid.uuid4().hex}"
        injected = f"injected-{uuid.uuid4().hex}"
        pid = _program(scope_in="127.0.0.1")
        with Session(engine) as session:
            profile = HeaderProfile(
                name=f"bad-profile-{TAG}-{uuid.uuid4().hex[:6]}",
                family="curl-minimal",
                headers={
                    "Authorization": secret,
                    "X-Bad": f"broken-{uuid.uuid4().hex}\r\nX-Injected: {injected}",
                },
                proxy="",
            )
            session.add(profile)
            session.commit()
            session.refresh(profile)
            profile_id = profile.id

        job_id = _job(
            pid,
            "leadline-http",
            f"http://127.0.0.1:{port}/",
            header_profile_id=profile_id,
            max_attempts=1,
        )
        assert worker.run_once(
            worker_id=f"bad-header-{TAG}",
            lease_seconds=30,
            job_id=job_id,
            runner_ids=("leadline-http",),
        ) is True
        job = _get_job(job_id)
        assert job.status == "failed"

        with Session(engine) as session:
            attempt = session.exec(
                select(JobAttempt).where(JobAttempt.job_id == job_id)
            ).first()
            phases = session.exec(
                select(ScanPhase).where(ScanPhase.job_id == job_id)
            ).all()
            events = session.exec(
                select(JobEvent).where(JobEvent.job_id == job_id)
            ).all()
            stored = "\n".join(
                filter(
                    None,
                    [
                        job.error or "",
                        attempt.error or "",
                        *[phase.error or "" for phase in phases],
                        *[event.message for event in events],
                        *[
                            str(value)
                            for event in events
                            for value in (event.data or {}).values()
                        ],
                    ],
                )
            )
        assert secret not in stored
        assert injected not in stored
        assert "••••••" in stored
    finally:
        server.shutdown()
        server.server_close()


def test_out_of_scope_redirect_fails_the_job_without_retry():
    _LocalHandler.redirect_to = "http://blocked.example.test/"
    server, port = _serve(_LocalHandler)
    try:
        pid = _program(scope_in="127.0.0.1")
        job_id = _job(pid, "leadline-http", f"http://127.0.0.1:{port}/", max_attempts=3)
        assert worker.run_once(
            worker_id=f"redirect-{TAG}",
            lease_seconds=30,
            job_id=job_id,
            runner_ids=("leadline-http",),
        ) is True
        job = _get_job(job_id)
        assert job.status == "failed"
        assert job.attempts == 1
        assert "scope denied" in (job.error or "").lower()
        with Session(engine) as session:
            assert session.exec(select(Paste).where(Paste.job_id == job_id)).all() == []
    finally:
        server.shutdown()
        server.server_close()


# -------------------------------------------------------------- web/API ----
def test_cli_registers_worker_and_maintenance_commands():
    from app.cli import build_parser

    parser = build_parser()
    worker_args = parser.parse_args(
        ["worker", "--once", "--poll", "0.5", "--lease", "10", "--max-jobs", "1"]
    )
    assert worker_args.func.__name__ == "cmd_worker"
    assert worker_args.once is True
    assert worker_args.poll == 0.5
    assert worker_args.lease == 10
    maint_args = parser.parse_args(["maintenance", "on", "--reason", "backup"])
    assert maint_args.func.__name__ == "cmd_maintenance"
    assert maint_args.action == "on"
    assert maint_args.reason == "backup"


def test_health_job_detail_and_runners_page():
    pid = _program(scope_in="127.0.0.1")
    job_id = _job(pid, "leadline-http", "http://127.0.0.1:9/")
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        data = health.json()
        assert data["status"] == "ok"
        assert data["schema_version"] == data["expected_schema_version"]
        assert data["wal_mode"] == "wal"
        assert data["maintenance"] is False
        assert "queued" in data["jobs"]

        detail = client.get(f"/api/v1/jobs/{job_id}")
        assert detail.status_code == 200
        assert detail.json()["id"] == job_id
        assert detail.json()["attempts"] == []
        assert detail.json()["phases"] == []
        assert detail.json()["events"] == []

        page = client.get(f"/jobs/{job_id}")
        assert page.status_code == 200
        assert "Native collector" in page.text
        assert "Run now" in page.text

        runners = client.get("/runners")
        assert runners.status_code == 200
        assert "Executor mode" in runners.text

        listed = client.get("/api/v1/jobs").json()["jobs"]
        assert any(item["id"] == job_id for item in listed)


def test_api_run_now_starts_a_native_job():
    pid = _program(scope_in="127.0.0.1")
    job_id = _job(pid, "leadline-dns", "127.0.0.1")
    external_id = _job(pid, "rustscan", "127.0.0.1")
    with TestClient(app) as client:
        rejected = client.post(f"/api/v1/jobs/{external_id}/run")
        assert rejected.status_code == 400

        response = client.post(f"/api/v1/jobs/{job_id}/run")
        assert response.status_code == 202
        assert response.json()["status"] == "started"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and _get_job(job_id).status in ("queued", "running"):
            time.sleep(0.05)
    job = _get_job(job_id)
    assert job.status == "done"
    assert job.output_paste_id is not None


def test_manual_rearm_preserves_attempt_numbers_and_clears_cancel():
    from app.main import _arm_native_job

    pid = _program(scope_in="127.0.0.1")
    job_id = _job(
        pid, "leadline-dns", "127.0.0.1",
        status="failed", attempts=3, max_attempts=3,
        cancel_requested=True, error="boom",
    )
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert _arm_native_job(session, job) == "armed"
        assert job.status == "queued"
        assert job.attempts == 3
        assert job.max_attempts == 4
        assert job.cancel_requested is False
        assert job.error is None

    with Session(engine) as session:
        claim = queue.claim_next(
            session,
            worker_id=f"rearm-{TAG}",
            runner_ids=("leadline-dns",),
            job_id=job_id,
        )
        assert claim is not None
        assert claim.attempt.attempt_no == 4
    _finish_claimed(job_id)


def test_job_page_run_now_starts_a_native_job():
    pid = _program(scope_in="127.0.0.1")
    job_id = _job(pid, "leadline-dns", "127.0.0.1")
    with TestClient(app) as client:
        assert client.get(f"/jobs/{job_id}").status_code == 200
        token = client.cookies.get("bc_csrf")
        response = client.post(
            f"/jobs/{job_id}/run",
            headers={"X-CSRF-Token": token},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "started" in response.headers["location"]
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and _get_job(job_id).status in ("queued", "running"):
            time.sleep(0.05)
    assert _get_job(job_id).status == "done"


def test_custom_runner_id_cannot_shadow_a_collector():
    with TestClient(app) as client:
        assert client.get("/runners").status_code == 200
        token = client.cookies.get("bc_csrf")
        response = client.post(
            "/runners/custom",
            data={"runner_id": "fake-echo", "label": "shadow", "example": "fake-echo"},
            headers={"X-CSRF-Token": token},
            follow_redirects=False,
        )
        assert response.status_code == 400


def test_maintenance_state_is_visible_in_health():
    with TestClient(app) as client:
        assert client.get("/health").json()["maintenance"] is False
        set_maintenance(True, "test window")
        try:
            data = client.get("/health").json()
            assert data["maintenance"] is True
            assert data["maintenance_reason"] == "test window"
        finally:
            set_maintenance(False)


# ------------------------------------------------------ native recon v1 ----
class _ReconHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def _send(self, body: bytes, content_type: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):  # noqa: N802
        self._send(b"", "text/html")

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/static/app.js":
            body = (
                b'const API = "/api/v1/users";\n'
                b'fetch("/api/v1/items?user_id=1");\n'
                b'const redirect = "/next";\n'
                b"// CVE-2021-44228\n"
            )
            self._send(body, "application/javascript")
            return
        if path == "/api":
            self._send(b'{"ok": true}', "application/json")
            return
        if path == "/.env":
            self._send(b"SECRET=not-a-real-secret", "text/plain")
            return
        if path == "/search":
            self._send(b"<html><title>Search</title></html>", "text/html")
            return
        if path.startswith("/api/"):
            self._send(b"not found", "text/plain", status=404)
            return
        body = (
            b"<html><head><title>Recon Fixture</title>"
            b'<script src="/static/app.js"></script></head><body>'
            b'<a href="/?id=1">item</a>'
            b'<a href="/.env">env</a>'
            b'<form action="/search" method="get">'
            b'<input name="q" type="text"></form>'
            b"<!-- CVE-2021-44228 -->"
            b"</body></html>"
        )
        self._send(body, "text/html")

    def log_message(self, *args):  # noqa: ARG002
        pass


def test_port_scan_emits_nmap_banner_and_risk_candidate(monkeypatch):
    from app.collect import ports as ports_module

    server, port = _serve(_ReconHandler)
    try:
        monkeypatch.setattr(
            ports_module, "HIGH_RISK_PORTS", ports_module.HIGH_RISK_PORTS | {port}
        )
        ctx = CollectorContext(
            target=f"http://127.0.0.1:{port}/",
            options={"ports": [port], "http_ports": [port]},
            guard=ScopeGuard(Scope("127.0.0.1")),
            job_id=1,
            attempt_id=1,
            worker_id="test",
        )
        result = get_collector("leadline-ports").run(ctx)
        assert result.stats["open"] == 1
        assert result.stats["high_risk"] == 1
        names = [phase.name for phase in result.phases]
        assert names == ["ports", "port-findings"]
        xml = result.phases[0].output
        assert "<nmaprun" in xml
        assert f'portid="{port}"' in xml
        assert "nginx" in xml
        assert 'tunnel="ssl"' not in xml
        finding_lines = [
            line for line in result.phases[1].output.splitlines()
            if line.strip().startswith("{")
        ]
        assert len(finding_lines) == 1
        record = json.loads(finding_lines[0])
        assert record["info"]["severity"] == "medium"
        assert record["matched-at"] == f"127.0.0.1:{port}"
        assert "candidate" in record["info"]["tags"]
    finally:
        server.shutdown()
        server.server_close()


def _serve_tls(handler, tmp_path: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "fixture.local")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("fixture.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / "fixture-cert.pem"
    keyfile = tmp_path / "fixture-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_port_scan_reads_tls_certificate_fields(tmp_path: Path):
    server, port = _serve_tls(_ReconHandler, tmp_path)
    try:
        ctx = CollectorContext(
            target=f"https://127.0.0.1:{port}/",
            options={"ports": [port], "http_ports": [port]},
            guard=ScopeGuard(Scope("127.0.0.1")),
            job_id=1,
            attempt_id=1,
            worker_id="test",
        )
        result = get_collector("leadline-ports").run(ctx)
        assert result.stats["tls"] == 1
        xml = result.phases[0].output
        assert 'tunnel="ssl"' in xml
        assert 'id="ssl-cert"' in xml
        assert "fixture.local" in xml
    finally:
        server.shutdown()
        server.server_close()


def test_recon_preset_runs_twelve_phases_and_seals_evidence():
    from app.collect.recon import PHASE_NAMES

    server, port = _serve(_ReconHandler)
    try:
        pid = _program(scope_in="127.0.0.1")
        job_id = _job(
            pid,
            "leadline-recon",
            f"http://127.0.0.1:{port}/",
            params={
                "ports": [port],
                "http_ports": [port],
                "api_paths": ["/api"],
            },
        )
        assert worker.run_once(
            worker_id=f"recon-{TAG}",
            lease_seconds=60,
            job_id=job_id,
            runner_ids=("leadline-recon",),
        ) is True

        job = _get_job(job_id)
        assert job.status == "done", job.error
        assert job.output_paste_id is not None
        assert job.error is None

        with Session(engine) as session:
            phases = session.exec(
                select(ScanPhase)
                .where(ScanPhase.job_id == job_id)
                .order_by(ScanPhase.seq)
            ).all()
            assert [phase.name for phase in phases] == list(PHASE_NAMES)
            assert all(phase.status == "done" for phase in phases)
            assert all(phase.output_paste_id for phase in phases)

            paste_ids = [phase.output_paste_id for phase in phases]
            assert len(set(paste_ids)) == len(PHASE_NAMES)
            pastes = session.exec(select(Paste).where(Paste.id.in_(paste_ids))).all()
            assert len(pastes) == len(PHASE_NAMES)
            assert all(paste.chain_hash and paste.chain_seq for paste in pastes)

            entities = session.exec(
                select(Entity).where(Entity.paste_id.in_(paste_ids))
            ).all()
            types = {entity.type for entity in entities}
            assert {"url", "param", "tech", "header", "cve", "port"} <= types

            findings = session.exec(
                select(Finding).where(Finding.program_id == pid)
            ).all()
            titles = {finding.title for finding in findings}
            assert any("Missing security header" in title for title in titles)
            assert any("Suspicious parameter" in title for title in titles)
            assert any("Potential security issue" in title for title in titles)
            assert not any("CVE" in title.upper() for title in titles)

            relationships = session.exec(
                select(Relationship).where(Relationship.program_id == pid)
            ).all()
            assert any(rel.rel_type == "has_port" for rel in relationships)

            events = session.exec(
                select(JobEvent).where(JobEvent.job_id == job_id)
            ).all()
            assert any(
                event.kind == "scope"
                and (event.data or {}).get("allowed") is True
                for event in events
            )
            assert any(event.kind == "done" for event in events)
    finally:
        server.shutdown()
        server.server_close()


def test_recon_preset_uses_local_nvd_cache_for_verified_cve_finding(tmp_path: Path):
    from app.collect.nvd import cache_from_payload

    cve = {
        "id": "CVE-2024-4242",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Fixture nginx issue."}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8}, "baseSeverity": "critical"}
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.24.0",
                                "versionEndIncluding": "1.24.0",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    cache_path = tmp_path / "breadcrumb.nvd.json"
    cache_from_payload({"vulnerabilities": [{"cve": cve}]}).save(cache_path)

    server, port = _serve(_ReconHandler)
    try:
        pid = _program(scope_in="127.0.0.1")
        job_id = _job(
            pid,
            "leadline-recon",
            f"http://127.0.0.1:{port}/",
            params={
                "ports": [port],
                "http_ports": [port],
                "api_paths": ["/api"],
                "nvd_cache": str(cache_path),
            },
        )
        assert worker.run_once(
            worker_id=f"recon-cve-{TAG}",
            lease_seconds=60,
            job_id=job_id,
            runner_ids=("leadline-recon",),
        ) is True

        job = _get_job(job_id)
        assert job.status == "done", job.error
        with Session(engine) as session:
            findings = session.exec(
                select(Finding).where(Finding.program_id == pid)
            ).all()
            verified = [
                finding for finding in findings
                if "CVE applies to observed version" in finding.title
            ]
            assert len(verified) == 1
            assert "CVE-2024-4242" in verified[0].title
            assert verified[0].severity == "critical"
            assert "applicability-verified" in (verified[0].tags or [])
    finally:
        server.shutdown()
        server.server_close()


def test_recon_preset_fails_closed_for_out_of_scope_target():
    pid = _program(scope_in="127.0.0.1")
    job_id = _job(
        pid,
        "leadline-recon",
        "http://blocked.example.test/",
        max_attempts=3,
    )
    assert worker.run_once(
        worker_id=f"recon-denied-{TAG}",
        lease_seconds=30,
        job_id=job_id,
        runner_ids=("leadline-recon",),
    ) is True
    job = _get_job(job_id)
    assert job.status == "failed"
    assert job.attempts == 1
    assert "scope denied" in (job.error or "").lower()
    with Session(engine) as session:
        assert session.exec(select(Paste).where(Paste.job_id == job_id)).all() == []
