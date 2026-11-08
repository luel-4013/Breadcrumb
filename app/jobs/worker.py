"""Worker loop and job executor.

The worker claims only jobs whose runner has a registered native collector.
External runners keep the original import-first workflow: they poll the JSON
API, POST their output, and mark the job done.

One lease per attempt, renewed by a small heartbeat thread. Collectors receive
a cancellation event; the executor also checks it between phases. A phase's
output is sealed as a normal Breadcrumb capture, linked to the job, attempt
and phase, with a stable ``capture_key``.

Database discipline: no session (and therefore no SQLite transaction) is kept
open while a collector runs or while an event is being written. Earlier
versions held one session for the whole attempt, which let a phase update and
the heartbeat/event writer block each other on SQLite's write lock. Short
sessions make the lease independent from the scan's runtime.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import uuid
from typing import Callable

from sqlmodel import Session, select

from ..attribution import attribute_target
from ..collect import (
    CollectorContext,
    CollectorError,
    JobCancelled,
    ScopeDenied,
    ScopeGuard,
    claimable_collector_ids,
    get_collector,
)
from ..db import engine
from ..history import generate_snapshot, upsert_snapshot
from ..ingest import IngestRequest, ingest
from ..models import HeaderProfile, JobAttempt, ScanJob, ScanPhase, Target
from ..scope import host_of
from ..secrets_store import redact_values
from . import queue

DEFAULT_LEASE_SECONDS = 120


def new_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


class LeaseKeeper(threading.Thread):
    """Renew a job lease while the collector runs."""

    def __init__(
        self,
        job_id: int,
        worker_id: str,
        lease_seconds: int,
        cancel_event: threading.Event,
        stop_event: threading.Event,
    ):
        super().__init__(name=f"breadcrumb-lease-{job_id}", daemon=True)
        self.job_id = job_id
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.cancel_event = cancel_event
        self.stop_event = stop_event
        self.lost = False

    def run(self) -> None:
        interval = max(1.0, self.lease_seconds / 3.0)
        while not self.stop_event.wait(interval):
            try:
                with Session(engine) as session:
                    owned, cancelled = queue.heartbeat(
                        session,
                        self.job_id,
                        self.worker_id,
                        lease_seconds=self.lease_seconds,
                    )
            except Exception:  # noqa: BLE001  (a transient DB error is not a lost lease)
                continue
            if not owned:
                self.lost = True
                self.cancel_event.set()
                return
            if cancelled:
                self.cancel_event.set()


def _target_id_for(session: Session, job: ScanJob, host: str) -> int | None:
    if not job.program_id:
        return None
    targets = session.exec(select(Target).where(Target.program_id == job.program_id)).all()
    target = attribute_target(host, targets)
    return target.id if target is not None else None


def _phase_key(job_id: int, attempt_no: int, phase_name: str, index: int) -> str:
    return f"job:{job_id}:attempt:{attempt_no}:{index}:{phase_name}"


def _host_for(target: str) -> str:
    target = target or ""
    if "://" in target:
        try:
            return host_of(target, "url")
        except Exception:  # noqa: BLE001
            return target
    return target


def _persist_finish(
    session: Session,
    job_id: int,
    attempt_id: int | None,
    status: str,
    *,
    worker_id: str,
    **kwargs,
) -> str:
    """Finish an attempt and return the status that is actually stored.

    ``queue.finish`` returns ``None`` when the database write lock cannot be
    acquired and returns the unchanged job when this worker's lease is stale.
    Reporting the stored status keeps the executor honest: a lease the worker
    no longer owns is never reported as ``done``.
    """
    job = queue.finish(
        session, job_id, attempt_id, status, worker_id=worker_id, **kwargs
    )
    if job is None:
        return "unknown"
    return job.status


def _snapshot_after_done(job_id: int) -> None:
    """Generate a history snapshot without ever turning a done job into failed.

    The sealed captures are the source of truth. If snapshot generation hits a
    transient error the row is left ``pending`` and can be rebuilt from the
    evidence chain later.
    """
    try:
        with Session(engine) as session:
            job = session.get(ScanJob, job_id)
            if job is None:
                return
            generate_snapshot(session, job)
    except Exception as exc:  # noqa: BLE001
        try:
            with Session(engine) as session:
                job = session.get(ScanJob, job_id)
                if job is not None:
                    upsert_snapshot(session, job, status="pending", error=str(exc))
        except Exception:  # noqa: BLE001  (never let history break scanning)
            pass


def execute_claimed(claim: queue.Claim, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> str:
    """Run one claimed attempt to completion. Returns the final status."""
    job_id = claim.job.id
    attempt_id = claim.attempt.id
    worker_id = claim.job.lease_owner or ""
    cancel_event = threading.Event()
    stop_event = threading.Event()
    keeper = LeaseKeeper(job_id, worker_id, lease_seconds, cancel_event, stop_event)
    keeper.start()
    log_lines: list[str] = []
    last_paste_id: int | None = None
    secret_values: list[str] = []

    def summary_stats() -> dict:
        return {"log": "\n".join(log_lines[-80:])}

    def emit(kind: str, message: str, data: dict | None = None) -> None:
        message = redact_values(message, secret_values)
        log_lines.append(message)
        try:
            with Session(engine) as event_session:
                queue.record_event(
                    event_session, job_id, attempt_id, kind, message, data or {}
                )
        except Exception:  # noqa: BLE001  (progress reporting must not kill a scan)
            pass

    try:
        # Snapshot everything the collector needs, then release the session
        # before any long-running work starts.
        with Session(engine) as session:
            job = session.get(ScanJob, job_id)
            attempt = session.get(JobAttempt, attempt_id)
            if job is None or attempt is None:
                return "missing"

            collector = get_collector(job.runner)
            if collector is None:
                return _persist_finish(
                    session, job.id, attempt.id, "failed",
                    worker_id=worker_id,
                    error=f"no collector or adapter registered for runner {job.runner!r}",
                )

            program_id = job.program_id
            target = job.target or ""
            options = dict(job.params or {})
            attempt_no = int(attempt.attempt_no or 1)

            try:
                guard = ScopeGuard.for_job(session, job)
            except ScopeDenied as exc:
                return _persist_finish(
                    session, job.id, attempt.id, "failed", error=str(exc),
                    worker_id=worker_id, stats=summary_stats(),
                )
            except Exception as exc:  # noqa: BLE001
                return _persist_finish(
                    session, job.id, attempt.id, "failed",
                    error=f"scope guard error: {exc}", worker_id=worker_id,
                )

            profile = (
                session.get(HeaderProfile, job.header_profile_id)
                if job.header_profile_id
                else None
            )
            headers = dict(profile.headers or {}) if profile else {}
            proxy = (profile.proxy or "") if profile else ""
            rate_limit = float(profile.rate_limit or 0) if profile else 0.0
            secret_values.extend(str(value) for value in headers.values() if value)
            if proxy:
                secret_values.append(proxy)
            target_id = _target_id_for(session, job, _host_for(target))
            if target_id is not None and job.target_id is None:
                job.target_id = target_id
                session.add(job)
                session.commit()

        ctx = CollectorContext(
            target=target,
            options=options,
            guard=guard,
            job_id=job_id,
            attempt_id=attempt_id,
            worker_id=worker_id,
            cancel_event=cancel_event,
            headers=headers,
            proxy=proxy,
            rate_limit=rate_limit,
            emit=emit,
        )

        status = "done"
        error_summary: str | None = None
        permanent = False
        result = None
        try:
            ctx.check_cancel()
            emit("phase", f"starting {collector.id} against {target}")
            result = collector.run(ctx)
        except JobCancelled:
            with Session(engine) as session:
                return _persist_finish(
                    session, job_id, attempt_id, "cancelled",
                    error="cancelled by request", worker_id=worker_id,
                    stats=summary_stats(),
                )
        except ScopeDenied as exc:
            status = "failed"
            permanent = True
            error_summary = redact_values(str(exc), secret_values)
            emit("error", error_summary)
        except CollectorError as exc:
            status = "failed"
            permanent = True
            error_summary = redact_values(
                f"{type(exc).__name__}: {exc}", secret_values
            )
            emit("error", error_summary)
        except Exception as exc:  # noqa: BLE001  (collector failures are job failures)
            status = "failed"
            error_summary = redact_values(
                f"{type(exc).__name__}: {exc}", secret_values
            )
            emit("error", error_summary)

        if keeper.lost:
            return "lost"
        if ctx.cancelled():
            with Session(engine) as session:
                return _persist_finish(
                    session, job_id, attempt_id, "cancelled",
                    error="cancelled by request", worker_id=worker_id,
                    stats=summary_stats(),
                )

        phases = list(getattr(result, "phases", []) or []) if result is not None else []
        phase_error = status != "done"
        if not phases and status == "done":
            status = "failed"
            error_summary = "collector returned no phases"
            phase_error = True

        for index, phase in enumerate(phases, 1):
            if ctx.cancelled() or keeper.lost:
                break
            phase_name = phase.name or f"phase-{index}"
            output = phase.output or ""

            # Create the phase row first so a crash still leaves a trace.
            with Session(engine) as session:
                phase_row = ScanPhase(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    seq=index,
                    name=phase_name,
                    status="running",
                    started_at=queue.utcnow(),
                    stats=dict(phase.stats or {}),
                )
                session.add(phase_row)
                session.commit()
                session.refresh(phase_row)
                phase_row_id = phase_row.id

            paste_id: int | None = None
            ingest_error: str | None = None
            ingest_stats: dict = {}
            if output.strip():
                try:
                    with Session(engine) as session:
                        ingest_result = ingest(
                            session,
                            IngestRequest(
                                text=output,
                                program_id=program_id,
                                target_id=target_id,
                                source=f"job:{job_id}:{phase_name}",
                                capture_key=_phase_key(
                                    job_id, attempt_no, phase_name, index
                                ),
                                job_id=job_id,
                                attempt_id=attempt_id,
                                phase=phase_name,
                            ),
                        )
                        paste_id = ingest_result.paste.id
                        last_paste_id = paste_id
                        ingest_stats = {
                            "entities": ingest_result.entities,
                            "findings": ingest_result.findings,
                            "duplicate": ingest_result.duplicate,
                        }
                except Exception as exc:  # noqa: BLE001
                    ingest_error = redact_values(
                        f"{type(exc).__name__}: {exc}", secret_values
                    )

            phase_error_text = redact_values(phase.error or "", secret_values)
            if ingest_error:
                phase_status = "failed"
                phase_error = True
                status = "failed"
                error_summary = f"phase {phase_name} ingest failed: {ingest_error}"
            elif phase_error_text:
                phase_status = "failed"
                phase_error = True
                status = "failed"
                error_summary = error_summary or phase_error_text
            else:
                phase_status = "done"

            with Session(engine) as session:
                row = session.get(ScanPhase, phase_row_id)
                if row is not None:
                    row.status = phase_status
                    row.error = ingest_error or phase_error_text
                    row.output_paste_id = paste_id
                    row.stats = {**(row.stats or {}), **ingest_stats}
                    row.finished_at = queue.utcnow()
                    session.add(row)
                    session.commit()

            if paste_id is not None:
                emit(
                    "phase",
                    f"{phase_name}: sealed capture #{paste_id} "
                    f"({ingest_stats.get('entities', 0)} entities, "
                    f"{ingest_stats.get('findings', 0)} findings)",
                    {"paste_id": paste_id, "phase": phase_name},
                )
            if phase_status == "failed":
                emit("error", f"{phase_name}: {ingest_error or phase_error_text}")

        if keeper.lost:
            return "lost"
        if ctx.cancelled():
            with Session(engine) as session:
                return _persist_finish(
                    session, job_id, attempt_id, "cancelled",
                    error="cancelled by request", worker_id=worker_id,
                    stats=summary_stats(),
                )

        if status == "done" and last_paste_id is None:
            # A done job must point at sealed evidence. An empty collector
            # result is a failure, not a silent success.
            status = "failed"
            phase_error = True
            error_summary = "collector produced no sealed output"

        if phase_error or status != "done":
            with Session(engine) as session:
                if permanent:
                    return _persist_finish(
                        session, job_id, attempt_id, "failed",
                        error=error_summary or "collector failed",
                        worker_id=worker_id, stats=summary_stats(),
                    )
                outcome = queue.retry_or_fail(
                    session, job_id, attempt_id,
                    error_summary or "collector failed",
                    stats=summary_stats(), worker_id=worker_id,
                )
                return outcome

        with Session(engine) as session:
            final = _persist_finish(
                session, job_id, attempt_id, "done",
                output_paste_id=last_paste_id,
                stats=summary_stats(), worker_id=worker_id,
            )
        if final == "done":
            _snapshot_after_done(job_id)
        return final
    finally:
        stop_event.set()
        keeper.join(timeout=2.0)


def run_once(
    *,
    worker_id: str | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    job_id: int | None = None,
    runner_ids: tuple[str, ...] | list[str] | None = None,
) -> bool:
    """Claim and execute at most one job. Returns True if a job was claimed."""
    worker_id = worker_id or new_worker_id()
    ids = tuple(runner_ids) if runner_ids is not None else claimable_collector_ids()
    with Session(engine) as session:
        claim = queue.claim_next(
            session,
            worker_id=worker_id,
            runner_ids=ids,
            lease_seconds=lease_seconds,
            job_id=job_id,
        )
    if claim is None:
        return False
    execute_claimed(claim, lease_seconds=lease_seconds)
    return True


def run_worker(
    once: bool = False,
    poll_interval: float = 2.0,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    max_jobs: int = 0,
    worker_id: str | None = None,
) -> int:
    """Run the native worker loop. ``once`` runs at most one job, then exits.

    ``max_jobs`` caps a longer drain; both are useful for tests and CI.
    """
    worker_id = worker_id or new_worker_id()
    done = 0
    print(
        f"breadcrumb worker {worker_id} "
        f"(collectors: {', '.join(claimable_collector_ids())})"
    )
    while True:
        try:
            worked = run_once(worker_id=worker_id, lease_seconds=lease_seconds)
        except Exception as exc:  # noqa: BLE001  (one bad job must not kill the worker)
            print(f"breadcrumb worker error: {exc}", file=sys.stderr)
            if once:
                break
            try:
                time.sleep(max(0.5, poll_interval))
            except KeyboardInterrupt:
                break
            continue
        if worked:
            done += 1
            if once or (max_jobs and done >= max_jobs):
                break
            continue
        if once:
            break
        try:
            time.sleep(max(0.2, poll_interval))
        except KeyboardInterrupt:
            break
    print(f"breadcrumb worker stopped after {done} job(s)")
    return done


def start_background_worker(
    *, poll_interval: float = 2.0, lease_seconds: int = DEFAULT_LEASE_SECONDS
) -> Callable[[], None]:
    """Start the optional in-process worker (``BREADCRUMB_EXECUTOR=inline``)."""
    stop = threading.Event()

    def loop() -> None:
        worker_id = new_worker_id()
        while not stop.is_set():
            try:
                if not run_once(worker_id=worker_id, lease_seconds=lease_seconds):
                    stop.wait(max(0.5, poll_interval))
            except Exception as exc:  # noqa: BLE001  (never kill the web process)
                print(f"breadcrumb worker error: {exc}", file=sys.stderr)
                stop.wait(max(1.0, poll_interval))

    thread = threading.Thread(target=loop, name="breadcrumb-worker", daemon=True)
    thread.start()

    def _stop() -> None:
        stop.set()

    return _stop
