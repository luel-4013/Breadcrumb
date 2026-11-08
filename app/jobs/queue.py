"""Durable job queue: atomic claim, lease, heartbeat, cancel, retry, recovery.

SQLite is a single-writer database. The queue uses the same rule as the
evidence chain: take ``BEGIN IMMEDIATE`` before inspecting candidates, so two
workers can never claim the same row.

Lifecycle::

    queued --claim--> running --success--> done
       ^                  |
       |                  +--cancel--> cancelled
       +--retry (backoff)-+--error----> queued/failed
                          +--lease lost--> recovery

External runners can still use the JSON status endpoint; native workers only
claim runner ids that have a registered collector.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, select

from ..db import begin_immediate
from ..models import AppState, JobAttempt, JobEvent, ScanJob, ScanPhase


@dataclass
class Claim:
    job: ScanJob
    attempt: JobAttempt


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _backoff_seconds(attempts: int) -> int:
    """5s, 10s, 20s, ... capped at one hour."""
    return min(3600, 5 * (2 ** max(0, int(attempts) - 1)))


def record_event(
    session: Session,
    job_id: int,
    attempt_id: int | None,
    kind: str,
    message: str,
    data: dict | None = None,
) -> JobEvent:
    event = JobEvent(
        job_id=job_id,
        attempt_id=attempt_id,
        kind=kind,
        message=message[:8000],
        data=data or {},
        created_at=utcnow(),
    )
    session.add(event)
    session.commit()
    return event


def _latest_running_attempt(session: Session, job_id: int) -> JobAttempt | None:
    return session.exec(
        select(JobAttempt)
        .where(JobAttempt.job_id == job_id, JobAttempt.status == "running")
        .order_by(JobAttempt.id.desc())
        .limit(1)
    ).first()


def recover_expired_locked(session: Session, now: datetime) -> int:
    """Requeue/fail jobs whose worker stopped renewing its lease.

    Must be called while the caller holds ``BEGIN IMMEDIATE``.
    """
    rows = session.exec(
        select(ScanJob).where(
            ScanJob.status == "running",
            ScanJob.lease_expires_at != None,  # noqa: E711
            ScanJob.lease_expires_at < now,
        )
    ).all()
    recovered = 0
    for job in rows:
        recovered += 1
        attempts = session.exec(
            select(JobAttempt)
            .where(JobAttempt.job_id == job.id, JobAttempt.status == "running")
            .order_by(JobAttempt.id)
        ).all()
        for attempt in attempts:
            attempt.status = "lost"
            attempt.finished_at = now
            attempt.error = "worker lease expired"
            session.add(attempt)
        # A crash can leave a phase row in ``running``. Close it with the
        # attempt so the audit trail never shows a live phase on a lost lease.
        for phase in session.exec(
            select(ScanPhase).where(
                ScanPhase.job_id == job.id,
                ScanPhase.status == "running",
            )
        ).all():
            phase.status = "lost"
            phase.finished_at = now
            phase.error = phase.error or "worker lease expired"
            session.add(phase)
        job.lease_owner = None
        job.lease_expires_at = None
        job.heartbeat_at = now
        if job.cancel_requested:
            job.status = "cancelled"
            job.finished_at = now
            job.error = "cancelled while the worker was unreachable"
            session.add(job)
            session.add(JobEvent(
                job_id=job.id,
                kind="cancelled",
                message=job.error,
                created_at=now,
            ))
            continue
        if int(job.attempts or 0) < int(job.max_attempts or 3):
            job.status = "queued"
            job.next_run_at = now + timedelta(seconds=_backoff_seconds(job.attempts or 1))
            job.error = "worker lease expired; job requeued"
            session.add(job)
            session.add(JobEvent(
                job_id=job.id,
                kind="retry",
                message="worker lease expired; job requeued",
                created_at=now,
            ))
        else:
            job.status = "failed"
            job.finished_at = now
            job.error = "worker lease expired after final attempt"
            session.add(job)
            session.add(JobEvent(
                job_id=job.id,
                kind="failed",
                message=job.error,
                created_at=now,
            ))
    return recovered


def recover_expired(session: Session | None = None) -> int:
    own = session is None
    from ..db import engine

    session = session or Session(engine)
    try:
        try:
            begin_immediate(session)
            count = recover_expired_locked(session, utcnow())
            session.commit()
            return count
        except OperationalError:
            session.rollback()
            return 0
    finally:
        if own:
            session.close()


def claim_next(
    session: Session,
    *,
    worker_id: str,
    runner_ids: tuple[str, ...] | list[str] | None = None,
    lease_seconds: int = 120,
    job_id: int | None = None,
) -> Claim | None:
    """Atomically claim one queued job and create an attempt row."""
    now = utcnow()
    try:
        begin_immediate(session)
    except OperationalError:
        session.rollback()
        return None

    state = session.get(AppState, 1)
    if state is not None and state.maintenance:
        session.commit()
        return None
    if os.environ.get("BREADCRUMB_MAINTENANCE", "").strip().lower() in (
        "1", "true", "yes", "on"
    ):
        session.commit()
        return None

    recover_expired_locked(session, now)

    stmt = select(ScanJob).where(
        ScanJob.status == "queued",
        ScanJob.attempts < ScanJob.max_attempts,
        or_(ScanJob.next_run_at == None, ScanJob.next_run_at <= now),  # noqa: E711
    )
    if runner_ids is not None:
        ids = tuple(runner_ids)
        if not ids:
            session.commit()
            return None
        stmt = stmt.where(ScanJob.runner.in_(ids))
    if job_id is not None:
        stmt = stmt.where(ScanJob.id == job_id)
    stmt = stmt.order_by(ScanJob.priority.desc(), ScanJob.id.asc()).limit(1)
    job = session.exec(stmt).first()
    if job is None:
        session.commit()
        return None

    job.status = "running"
    job.attempts = int(job.attempts or 0) + 1
    job.started_at = job.started_at or now
    job.next_run_at = None
    job.lease_owner = worker_id
    job.lease_expires_at = now + timedelta(seconds=max(5, int(lease_seconds)))
    job.heartbeat_at = now
    job.cancel_requested = False
    job.finished_at = None
    session.add(job)
    session.flush()

    attempt = JobAttempt(
        job_id=job.id,
        attempt_no=job.attempts,
        worker_id=worker_id,
        status="running",
        started_at=now,
        heartbeat_at=now,
    )
    session.add(attempt)
    session.flush()
    session.add(JobEvent(
        job_id=job.id,
        attempt_id=attempt.id,
        kind="claimed",
        message=f"claimed by {worker_id} (attempt {attempt.attempt_no})",
        created_at=now,
    ))
    session.commit()
    session.refresh(job)
    session.refresh(attempt)
    return Claim(job=job, attempt=attempt)


def heartbeat(
    session: Session,
    job_id: int,
    worker_id: str,
    *,
    lease_seconds: int = 120,
) -> tuple[bool, bool]:
    """Renew a lease. Returns ``(still_owned, cancel_requested)``.

    A database lock is *not* returned as "lost": the caller retries on its next
    heartbeat, while the previous lease is still valid for two more intervals.
    Only a missing job, a non-running job, or a different owner is lost.
    """
    now = utcnow()
    begin_immediate(session)
    job = session.get(ScanJob, job_id)
    if job is None or job.status != "running" or job.lease_owner != worker_id:
        session.commit()
        return False, False
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=max(5, int(lease_seconds)))
    session.add(job)
    attempt = _latest_running_attempt(session, job_id)
    if attempt is not None:
        attempt.heartbeat_at = now
        session.add(attempt)
    cancelled = bool(job.cancel_requested)
    session.commit()
    return True, cancelled


def request_cancel(session: Session, job_id: int) -> str | None:
    """Cancel a queued job or ask a leased worker to stop after its current step."""
    now = utcnow()
    try:
        begin_immediate(session)
    except OperationalError:
        session.rollback()
        return None
    job = session.get(ScanJob, job_id)
    if job is None:
        session.commit()
        return None
    if job.status == "queued":
        job.status = "cancelled"
        job.finished_at = now
        job.error = "cancelled before start"
        session.add(job)
        session.add(JobEvent(
            job_id=job.id, kind="cancelled", message=job.error, created_at=now
        ))
        session.commit()
        return "cancelled"
    if job.status == "running":
        if job.lease_owner:
            job.cancel_requested = True
            session.add(job)
            session.add(JobEvent(
                job_id=job.id, kind="cancel-requested",
                message="cancellation requested; worker will stop at the next checkpoint",
                created_at=now,
            ))
            session.commit()
            return "cancel-requested"
        job.status = "cancelled"
        job.finished_at = now
        job.error = "cancelled"
        session.add(job)
        session.add(JobEvent(
            job_id=job.id, kind="cancelled", message=job.error, created_at=now
        ))
        session.commit()
        return "cancelled"
    status = job.status
    session.commit()
    return status


def finish(
    session: Session,
    job_id: int,
    attempt_id: int | None,
    status: str,
    *,
    error: str | None = None,
    output_paste_id: int | None = None,
    stats: dict | None = None,
    worker_id: str | None = None,
) -> ScanJob | None:
    """Finish an attempt with ``done``, ``failed`` or ``cancelled``.

    A stale worker cannot overwrite a job that was recovered and claimed by
    another worker: the attempt must still be running and, when supplied, the
    lease owner must match.
    """
    now = utcnow()
    try:
        begin_immediate(session)
    except OperationalError:
        session.rollback()
        return None
    job = session.get(ScanJob, job_id)
    if job is None:
        session.commit()
        return None
    attempt = session.get(JobAttempt, attempt_id) if attempt_id else None
    if attempt is not None and attempt.status != "running":
        session.commit()
        return job
    if worker_id and job.lease_owner and job.lease_owner != worker_id:
        session.commit()
        return job
    job.status = status
    job.finished_at = now
    job.lease_owner = None
    job.lease_expires_at = None
    job.heartbeat_at = now
    if output_paste_id is not None:
        job.output_paste_id = output_paste_id
    if status == "done":
        job.error = None
        job.cancel_requested = False
    else:
        job.error = error
    if stats and stats.get("log"):
        job.log = str(stats["log"])[:20000]
    session.add(job)
    if attempt is not None:
        attempt.status = status
        attempt.finished_at = now
        attempt.error = error
        attempt.stats = stats or {}
        if output_paste_id is not None:
            attempt.output_paste_id = output_paste_id
        session.add(attempt)
    session.add(JobEvent(
        job_id=job.id,
        attempt_id=attempt_id,
        kind=status,
        message=error or f"job {status}",
        data=stats or {},
        created_at=now,
    ))
    session.commit()
    session.refresh(job)
    return job


def retry_or_fail(
    session: Session,
    job_id: int,
    attempt_id: int | None,
    error: str,
    *,
    stats: dict | None = None,
    worker_id: str | None = None,
) -> str:
    """Requeue with backoff while attempts remain; otherwise fail the job."""
    now = utcnow()
    try:
        begin_immediate(session)
    except OperationalError:
        session.rollback()
        return "unknown"
    job = session.get(ScanJob, job_id)
    if job is None:
        session.commit()
        return "missing"
    attempt = session.get(JobAttempt, attempt_id) if attempt_id else None
    if attempt is not None and attempt.status != "running":
        session.commit()
        return job.status
    if worker_id and job.lease_owner and job.lease_owner != worker_id:
        session.commit()
        return job.status
    if attempt is not None:
        attempt.status = "failed"
        attempt.finished_at = now
        attempt.error = error
        attempt.stats = stats or {}
        session.add(attempt)
    job.lease_owner = None
    job.lease_expires_at = None
    job.heartbeat_at = now
    if stats and stats.get("log"):
        job.log = str(stats["log"])[:20000]
    if int(job.attempts or 0) < int(job.max_attempts or 3):
        job.status = "queued"
        job.next_run_at = now + timedelta(seconds=_backoff_seconds(job.attempts or 1))
        job.error = error
        outcome = "queued"
        kind = "retry"
        message = f"attempt failed; retrying in {_backoff_seconds(job.attempts or 1)}s: {error}"
    else:
        job.status = "failed"
        job.finished_at = now
        job.error = error
        outcome = "failed"
        kind = "failed"
        message = error
    session.add(job)
    session.add(JobEvent(
        job_id=job.id,
        attempt_id=attempt_id,
        kind=kind,
        message=message[:8000],
        data=stats or {},
        created_at=now,
    ))
    session.commit()
    return outcome
