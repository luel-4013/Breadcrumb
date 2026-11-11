"""Folder-based scheduled re-import (Phase D).

A schedule is deliberately boring: one local folder, one interval, and the
normal ingest path. There is no URL fetch, no API pull and no remote agent in
the core. If data lives elsewhere, an external tool fetches it into the folder;
Breadcrumb never needs credentials for a schedule and cannot be pointed at an
internal metadata service.

Design rules:

* Every file is ingested through :func:`app.ingest.ingest`, so capture keys,
  evidence-chain sealing, parser diagnostics and scope classification are the
  same as a manual paste.
* The capture key is derived from the schedule and the file content hash. A
  re-drop of identical bytes is a duplicate, not a new capture.
* A failed read or ingest leaves the file in place; a successful ingest can
  move it to ``processed/``. No file is ever deleted.
* A run writes a :class:`ScheduleRun` row before it starts. A crashed process
  therefore leaves an honest ``running`` row that becomes ``stale`` after a
  bounded horizon instead of wedging the schedule forever.
* Scheduler loops catch per-schedule failures. One broken folder must not stop
  every other schedule.

The SDK and the scheduler both stay local-first: no telemetry, no cloud
scheduler, no background daemon unless the operator runs
``breadcrumb scheduler``.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlmodel import Session, select

from .ingest import IngestRequest, ingest
from .models import Program, Schedule, ScheduleRun, Target

MIN_INTERVAL_SECONDS = 10
MAX_INTERVAL_SECONDS = 30 * 24 * 3600
MAX_FILES_PER_RUN = 200
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ERROR_TEXT = 500
# A run older than this is presumed dead. The interval doubles the horizon for
# deliberately slow schedules, but a run should never take hours.
STALE_RUN_SECONDS = 3600
_IGNORED_SUFFIXES = (".part", ".tmp", ".crdownload", ".swp", ".swx")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _trim(text: str, limit: int = MAX_ERROR_TEXT) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _resolve_folder(source: str) -> Path:
    folder = Path(str(source or "")).expanduser()
    if not folder.is_absolute():
        folder = Path.cwd() / folder
    return folder.resolve()


def _validate_links(
    session: Session, program_id: int | None, target_id: int | None
) -> None:
    program = None
    if program_id is not None:
        program = session.get(Program, program_id)
        if program is None:
            raise ValueError(f"program #{program_id} not found")
    if target_id is not None:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"target #{target_id} not found")
        if program_id is not None and target.program_id not in (None, program_id):
            raise ValueError(
                f"target #{target_id} belongs to program #{target.program_id}, "
                f"not #{program_id}"
            )


def create_schedule(
    session: Session,
    name: str,
    source: str,
    *,
    program_id: int | None = None,
    target_id: int | None = None,
    interval_seconds: int = 300,
    overlap_policy: str = "skip",
    move_processed: bool = True,
    enabled: bool = True,
    now: datetime | None = None,
) -> Schedule:
    """Create a local folder schedule. Validation happens before the write."""
    name = str(name or "").strip()
    if not name:
        raise ValueError("name is required")
    if session.exec(select(Schedule).where(Schedule.name == name)).first():
        raise ValueError(f"schedule {name!r} already exists")
    try:
        interval = int(interval_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("interval_seconds must be an integer") from exc
    if interval < MIN_INTERVAL_SECONDS:
        raise ValueError(f"interval_seconds must be at least {MIN_INTERVAL_SECONDS}")
    if interval > MAX_INTERVAL_SECONDS:
        raise ValueError("interval_seconds must be at most 30 days")
    policy = str(overlap_policy or "skip").lower()
    if policy not in ("skip", "queue"):
        raise ValueError("overlap_policy must be 'skip' or 'queue'")
    folder = _resolve_folder(source)
    if not folder.is_dir():
        raise ValueError(f"folder does not exist: {folder}")
    _validate_links(session, program_id, target_id)

    stamp = _as_utc(now) or utcnow()
    schedule = Schedule(
        name=name,
        kind="folder",
        source=str(folder),
        program_id=program_id,
        target_id=target_id,
        interval_seconds=interval,
        overlap_policy=policy,
        move_processed=bool(move_processed),
        enabled=bool(enabled),
        next_run_at=stamp,
        created_at=stamp,
        updated_at=stamp,
    )
    session.add(schedule)
    session.commit()
    session.refresh(schedule)
    return schedule


def update_schedule(
    session: Session,
    schedule_id: int,
    *,
    now: datetime | None = None,
    **fields,
) -> Schedule:
    """Patch a schedule. Unknown fields are ignored by design (small API)."""
    schedule = session.get(Schedule, schedule_id)
    if schedule is None:
        raise ValueError(f"schedule #{schedule_id} not found")
    stamp = _as_utc(now) or utcnow()

    if "name" in fields:
        name = str(fields["name"] or "").strip()
        if not name:
            raise ValueError("name is required")
        clash = session.exec(
            select(Schedule).where(Schedule.name == name, Schedule.id != schedule.id)
        ).first()
        if clash is not None:
            raise ValueError(f"schedule {name!r} already exists")
        schedule.name = name
    if "source" in fields:
        folder = _resolve_folder(fields["source"])
        if not folder.is_dir():
            raise ValueError(f"folder does not exist: {folder}")
        schedule.source = str(folder)
    if "interval_seconds" in fields:
        try:
            interval = int(fields["interval_seconds"])
        except (TypeError, ValueError) as exc:
            raise ValueError("interval_seconds must be an integer") from exc
        if interval < MIN_INTERVAL_SECONDS or interval > MAX_INTERVAL_SECONDS:
            raise ValueError(
                f"interval_seconds must be between {MIN_INTERVAL_SECONDS} "
                "and 30 days"
            )
        schedule.interval_seconds = interval
    if "overlap_policy" in fields:
        policy = str(fields["overlap_policy"] or "skip").lower()
        if policy not in ("skip", "queue"):
            raise ValueError("overlap_policy must be 'skip' or 'queue'")
        schedule.overlap_policy = policy
    if "move_processed" in fields:
        schedule.move_processed = bool(fields["move_processed"])
    if "program_id" in fields:
        schedule.program_id = (
            None if fields["program_id"] is None else int(fields["program_id"])
        )
    if "target_id" in fields:
        schedule.target_id = (
            None if fields["target_id"] is None else int(fields["target_id"])
        )
    _validate_links(session, schedule.program_id, schedule.target_id)

    if "enabled" in fields:
        was_enabled = bool(schedule.enabled)
        schedule.enabled = bool(fields["enabled"])
        if schedule.enabled and not was_enabled:
            # Re-enabling is a fresh start, not a catch-up storm.
            schedule.next_run_at = stamp
        elif not schedule.enabled:
            schedule.next_run_at = None
    schedule.updated_at = stamp
    session.add(schedule)
    session.commit()
    session.refresh(schedule)
    return schedule


def get_schedule(session: Session, schedule_id: int) -> Schedule | None:
    return session.get(Schedule, schedule_id)


def list_schedules(session: Session, enabled: bool | None = None) -> list[Schedule]:
    stmt = select(Schedule).order_by(Schedule.name)
    if enabled is not None:
        stmt = stmt.where(Schedule.enabled == enabled)
    return list(session.exec(stmt).all())


def delete_schedule(session: Session, schedule_id: int) -> bool:
    schedule = session.get(Schedule, schedule_id)
    if schedule is None:
        return False
    for run in session.exec(
        select(ScheduleRun).where(ScheduleRun.schedule_id == schedule_id)
    ).all():
        session.delete(run)
    session.delete(schedule)
    session.commit()
    return True


def schedule_dict(schedule: Schedule) -> dict:
    return {
        "id": schedule.id,
        "name": schedule.name,
        "kind": schedule.kind,
        "source": schedule.source,
        "program_id": schedule.program_id,
        "target_id": schedule.target_id,
        "interval_seconds": schedule.interval_seconds,
        "overlap_policy": schedule.overlap_policy,
        "move_processed": bool(schedule.move_processed),
        "enabled": bool(schedule.enabled),
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "last_status": schedule.last_status,
        "last_error": schedule.last_error,
        "run_count": schedule.run_count,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
        "updated_at": schedule.updated_at.isoformat() if schedule.updated_at else None,
    }


def run_dict(run: ScheduleRun, *, include_detail: bool = True) -> dict:
    payload = {
        "id": run.id,
        "schedule_id": run.schedule_id,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "status": run.status,
        "files_seen": run.files_seen,
        "files_ingested": run.files_ingested,
        "entities": run.entities,
        "findings": run.findings,
        "error": run.error,
    }
    if include_detail:
        payload["detail"] = dict(run.detail or {})
    return payload


def list_runs(
    session: Session, schedule_id: int | None = None, limit: int = 50
) -> list[ScheduleRun]:
    stmt = select(ScheduleRun).order_by(ScheduleRun.id.desc())
    if schedule_id is not None:
        stmt = stmt.where(ScheduleRun.schedule_id == schedule_id)
    return list(session.exec(stmt.limit(max(1, min(limit, 500)))).all())


@dataclass
class _Sweep:
    folder: str
    files_seen: int = 0
    files_ingested: int = 0
    entities: int = 0
    findings: int = 0
    skipped: int = 0
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    truncated: bool = False

    def file(self, name: str, status: str, **extra) -> None:
        record = {"name": name, "status": status}
        record.update({key: value for key, value in extra.items() if value is not None})
        self.files.append(record)


def _iter_candidates(folder: Path) -> list[Path]:
    entries = sorted(folder.iterdir(), key=lambda path: path.name.lower())
    candidates: list[Path] = []
    for path in entries:
        try:
            if path.is_dir() or path.name.startswith("."):
                continue
        except OSError:
            continue
        if path.name.lower().endswith(_IGNORED_SUFFIXES):
            continue
        candidates.append(path)
    return candidates


def _move_to_processed(path: Path, processed: Path, digest: str) -> Path:
    processed.mkdir(parents=True, exist_ok=True)
    dest = processed / path.name
    if dest.exists():
        dest = processed / f"{path.stem}-{digest[:8]}{path.suffix}"
        counter = 1
        while dest.exists():
            dest = processed / f"{path.stem}-{digest[:8]}-{counter}{path.suffix}"
            counter += 1
    path.rename(dest)
    return dest


def _sweep_folder(session: Session, schedule: Schedule) -> _Sweep:
    folder = Path(schedule.source)
    sweep = _Sweep(folder=str(folder))
    if not folder.is_dir():
        sweep.errors.append(f"folder does not exist: {folder}")
        return sweep
    try:
        candidates = _iter_candidates(folder)
    except OSError as exc:
        sweep.errors.append(f"cannot list folder: {exc}")
        return sweep
    if len(candidates) > MAX_FILES_PER_RUN:
        sweep.truncated = True
        candidates = candidates[:MAX_FILES_PER_RUN]
    sweep.files_seen = len(candidates)
    processed = folder / "processed"

    for path in candidates:
        try:
            stat = path.stat()
        except OSError as exc:
            sweep.errors.append(f"{path.name}: cannot stat: {exc}")
            sweep.file(path.name, "error", error=_trim(str(exc)))
            continue
        if stat.st_size > MAX_FILE_BYTES:
            sweep.skipped += 1
            reason = (
                f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MB; "
                "split or import manually"
            )
            sweep.errors.append(f"{path.name}: {reason}")
            sweep.file(path.name, "skipped", error=reason, bytes=stat.st_size)
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            sweep.errors.append(f"{path.name}: cannot read: {exc}")
            sweep.file(path.name, "error", error=_trim(str(exc)))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if b"\x00" in data[:8192]:
            sweep.skipped += 1
            reason = "binary file; folder schedules ingest text artifacts only"
            sweep.errors.append(f"{path.name}: {reason}")
            sweep.file(path.name, "skipped", error=reason, sha256=digest)
            continue
        text = data.decode("utf-8", errors="replace")
        if not text.strip():
            sweep.skipped += 1
            reason = "empty file"
            sweep.files.append({"name": path.name, "status": "skipped", "error": reason})
            if schedule.move_processed:
                try:
                    _move_to_processed(path, processed, digest)
                except OSError as exc:
                    sweep.errors.append(f"{path.name}: move failed: {exc}")
            continue
        capture_key = f"schedule:{schedule.id}:{digest}"
        try:
            result = ingest(
                session,
                IngestRequest(
                    text=text,
                    program_id=schedule.program_id,
                    target_id=schedule.target_id,
                    source=f"schedule:{schedule.name}",
                    capture_key=capture_key,
                    source_meta={
                        "filename": path.name,
                        "schedule_id": schedule.id,
                        "schedule_name": schedule.name,
                        "sha256": digest,
                        "bytes": len(data),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001  (leave the file; report the reason)
            session.rollback()
            sweep.errors.append(f"{path.name}: ingest failed: {_trim(str(exc))}")
            sweep.file(path.name, "error", error=_trim(str(exc)), sha256=digest)
            continue

        if result.duplicate:
            sweep.duplicates += 1
            sweep.file(
                path.name,
                "duplicate",
                paste_id=result.paste.id,
                sha256=digest,
            )
        else:
            sweep.files_ingested += 1
            sweep.entities += int(result.entities or 0)
            sweep.findings += int(result.findings or 0)
            sweep.file(
                path.name,
                "ingested",
                paste_id=result.paste.id,
                entities=int(result.entities or 0),
                findings=int(result.findings or 0),
                completeness=result.completeness,
                warning=_trim(result.warning) if result.warning else None,
                sha256=digest,
            )
        if schedule.move_processed:
            try:
                _move_to_processed(path, processed, digest)
            except OSError as exc:
                sweep.errors.append(f"{path.name}: move failed: {exc}")

    return sweep


def _claim_run(
    session: Session,
    schedule_id: int,
    now: datetime,
    force: bool = False,
) -> tuple[ScheduleRun | None, Schedule | None, str]:
    """Atomically create a running row, or explain why this run was skipped."""
    schedule = session.get(Schedule, schedule_id)
    if schedule is None:
        return None, None, "schedule not found"
    session.commit()
    from .db import begin_immediate

    begin_immediate(session)
    schedule = session.get(Schedule, schedule_id)
    if schedule is None:
        session.commit()
        return None, None, "schedule not found"
    running = session.exec(
        select(ScheduleRun)
        .where(ScheduleRun.schedule_id == schedule_id)
        .where(ScheduleRun.status == "running")
        .order_by(ScheduleRun.id.desc())
    ).first()
    if running is not None and not force:
        started = _as_utc(running.started_at) or now
        horizon = max(STALE_RUN_SECONDS, int(schedule.interval_seconds or 0) * 2)
        if (now - started).total_seconds() < horizon:
            if schedule.overlap_policy == "skip":
                session.commit()
                return None, schedule, "already running"
        else:
            running.status = "stale"
            running.finished_at = now
            running.error = "run did not finish before the stale horizon"
            session.add(running)
    run = ScheduleRun(schedule_id=schedule_id, started_at=now, status="running")
    session.add(run)
    schedule.last_status = "running"
    schedule.updated_at = now
    session.add(schedule)
    session.commit()
    session.refresh(run)
    session.refresh(schedule)
    return run, schedule, ""


def _record_skipped(
    session: Session, schedule: Schedule, reason: str, now: datetime
) -> ScheduleRun:
    run = ScheduleRun(
        schedule_id=schedule.id,
        started_at=now,
        finished_at=now,
        status="skipped",
        error=reason,
        detail={"reason": reason},
    )
    session.add(run)
    schedule.next_run_at = now + timedelta(
        seconds=max(10, min(int(schedule.interval_seconds or 60), 60))
    )
    schedule.updated_at = now
    session.add(schedule)
    session.commit()
    session.refresh(run)
    return run


def _notify_run(schedule: Schedule, run: ScheduleRun, sweep: _Sweep) -> None:
    """Best-effort notification; a webhook can never fail a scheduled import."""
    if not (sweep.files_ingested or sweep.errors):
        return
    try:
        from . import notify

        config = notify.load_config()
        if not config.get("enabled") or config.get("on_schedule") is False:
            return
        fields = {
            "schedule": schedule.name,
            "folder": schedule.source,
            "captures": sweep.files_ingested,
            "entities": sweep.entities,
            "findings": sweep.findings,
        }
        if sweep.errors:
            notify.send(
                config,
                "schedule.error",
                f"Schedule {schedule.name}: attention needed",
                f"{len(sweep.errors)} problem(s); {sweep.files_ingested} capture(s) imported.",
                fields,
            )
        else:
            notify.send(
                config,
                "schedule.completed",
                f"Schedule {schedule.name}: import complete",
                f"{sweep.files_ingested} new capture(s) imported.",
                fields,
            )
    except Exception:  # noqa: BLE001  (notifications are always best-effort)
        pass


def run_schedule(
    session: Session,
    schedule: int | Schedule,
    *,
    force: bool = False,
    now: datetime | None = None,
) -> dict:
    """Run one schedule now and return a run summary.

    ``force`` starts a run even if another recent run row is still marked
    running. It is a recovery tool, not a way to parallelize imports.
    """
    schedule_id = schedule.id if isinstance(schedule, Schedule) else int(schedule)
    stamp = _as_utc(now) or utcnow()
    run, schedule_row, reason = _claim_run(session, schedule_id, stamp, force=force)
    if run is None or schedule_row is None:
        if schedule_row is not None and reason == "already running":
            skipped = _record_skipped(session, schedule_row, reason, stamp)
            payload = run_dict(skipped, include_detail=False)
            payload.update({"schedule_id": schedule_id, "schedule_name": schedule_row.name})
            return payload
        return {
            "schedule_id": schedule_id,
            "schedule_name": "",
            "status": "error",
            "error": reason,
            "files_seen": 0,
            "files_ingested": 0,
            "entities": 0,
            "findings": 0,
        }

    try:
        sweep = _sweep_folder(session, schedule_row)
    except Exception as exc:  # noqa: BLE001  (record, do not kill the loop)
        session.rollback()
        sweep = _Sweep(folder=schedule_row.source)
        sweep.errors.append(f"run failed: {_trim(str(exc))}")
    finally:
        finished = utcnow() if now is None else _as_utc(now) or utcnow()

    if sweep.errors and not (sweep.files_ingested or sweep.duplicates):
        status = "error"
    elif sweep.errors or sweep.skipped:
        status = "partial"
    else:
        status = "ok"

    run.finished_at = finished
    run.status = status
    run.files_seen = sweep.files_seen
    run.files_ingested = sweep.files_ingested
    run.entities = sweep.entities
    run.findings = sweep.findings
    run.error = _trim(sweep.errors[0]) if sweep.errors else None
    run.detail = {
        "folder": sweep.folder,
        "processed_dir": str(Path(sweep.folder) / "processed"),
        "files": sweep.files,
        "duplicates": sweep.duplicates,
        "skipped": sweep.skipped,
        "errors": [_trim(item) for item in sweep.errors],
        "truncated": sweep.truncated,
        "max_files_per_run": MAX_FILES_PER_RUN,
    }
    schedule_row.last_run_at = finished
    schedule_row.last_status = status
    schedule_row.last_error = run.error
    schedule_row.run_count = int(schedule_row.run_count or 0) + 1
    schedule_row.next_run_at = finished + timedelta(
        seconds=max(MIN_INTERVAL_SECONDS, int(schedule_row.interval_seconds or MIN_INTERVAL_SECONDS))
    )
    schedule_row.updated_at = finished
    session.add(run)
    session.add(schedule_row)
    session.commit()
    session.refresh(run)

    _notify_run(schedule_row, run, sweep)
    payload = run_dict(run)
    payload["schedule_name"] = schedule_row.name
    return payload


def run_due(
    session: Session,
    *,
    now: datetime | None = None,
    limit: int = 20,
) -> list[dict]:
    """Run every enabled schedule whose ``next_run_at`` is due."""
    stamp = _as_utc(now) or utcnow()
    rows = list(
        session.exec(select(Schedule).where(Schedule.enabled == True)).all()  # noqa: E712
    )
    due: list[tuple[datetime, Schedule]] = []
    for schedule in rows:
        due_at = _as_utc(schedule.next_run_at)
        if due_at is None or due_at <= stamp:
            due.append((due_at or stamp, schedule))
    due.sort(key=lambda pair: pair[0])
    results: list[dict] = []
    for _, schedule in due[: max(1, int(limit or 20))]:
        try:
            results.append(run_schedule(session, schedule.id, now=stamp))
        except Exception as exc:  # noqa: BLE001  (one bad schedule cannot stop the rest)
            session.rollback()
            results.append(
                {
                    "schedule_id": schedule.id,
                    "schedule_name": schedule.name,
                    "status": "error",
                    "error": _trim(str(exc)),
                    "files_seen": 0,
                    "files_ingested": 0,
                    "entities": 0,
                    "findings": 0,
                }
            )
    return results


def run_forever(
    *,
    once: bool = False,
    poll_interval: float = 30.0,
    max_runs: int = 0,
    now: datetime | None = None,
) -> int:
    """Scheduler loop used by ``breadcrumb scheduler``. Returns runs executed."""
    from .db import engine, init_db

    init_db()
    executed = 0
    while True:
        with Session(engine) as session:
            results = run_due(session, now=now)
        executed += len(results)
        if once or (max_runs and executed >= max_runs):
            break
        try:
            time.sleep(max(1.0, float(poll_interval or 30.0)))
        except KeyboardInterrupt:
            break
    return executed
