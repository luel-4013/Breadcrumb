import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Text as SAText
from sqlalchemy import cast
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, func, select

from . import (
    __version__,
    ai,
    graph,
    headers_gen,
    history,
    llm,
    notify,
    pdf_export,
    pipeline as pipeline_mod,
    reporting,
    runners,
    triage,
)
from . import ingest as ingest_mod
from .attribution import (
    merge_into_program,
    rebuild_all,
    rebuild_program,
)
from .collect import adapter_ids, adapters_enabled, collector_ids
from .collect.tools import strict_mode
from .compat import router as compat_router
from .db import (
    DB_PATH,
    SCHEMA_VERSION,
    backup_database,
    engine,
    get_app_state,
    get_session,
    init_db,
    restore_database,
)
from .jobs import queue as jobs_queue
from .jobs import run_once as run_native_job
from .models import (
    CustomRunner,
    Entity,
    EvidenceChain,
    Finding,
    HeaderProfile,
    JobAttempt,
    JobEvent,
    Paste,
    Program,
    Relationship,
    RunnerToggle,
    ScanJob,
    ScanPhase,
    ScanSnapshot,
    Target,
)
from .parsers import analyze

APP_VERSION = __version__

BASE = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Lease recovery on start makes crash-left jobs runnable again even before
    # the first worker poll. Claiming also runs recovery, so this is a safety
    # net rather than the only path.
    try:
        jobs_queue.recover_expired()
    except Exception:  # noqa: BLE001  (never block web startup on queue recovery)
        pass
    stop_worker = None
    mode = os.environ.get("BREADCRUMB_EXECUTOR", "off").strip().lower()
    if mode == "inline":
        from .jobs.worker import start_background_worker

        stop_worker = start_background_worker(
            poll_interval=float(os.environ.get("BREADCRUMB_WORKER_POLL", "2") or 2),
        )
    yield
    if stop_worker is not None:
        stop_worker()


app = FastAPI(title="Breadcrumb", lifespan=lifespan)
app.include_router(compat_router)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))


@app.middleware("http")
async def inject_nav(request: Request, call_next):
    try:
        with Session(engine) as session:
            request.state.nav_programs = session.exec(
                select(Program).order_by(Program.name)
            ).all()
            request.state.unassigned_count = session.exec(
                select(func.count()).select_from(Entity).where(Entity.program_id == None)  # noqa: E711
            ).one()
            request.state.maintenance = get_app_state(session)
    except Exception:  # noqa: BLE001  (never let nav break a page)
        request.state.nav_programs = []
        request.state.unassigned_count = 0
        request.state.maintenance = None
    return await call_next(request)


CSRF_COOKIE = "bc_csrf"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
FORM_CONTENT_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")


def _host_key(value: str) -> str:
    """Lowercase a Host/Origin authority and strip its port and IPv6 brackets."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end != -1 else value
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def _allowed_hosts() -> set[str]:
    raw = os.environ.get("BREADCRUMB_ALLOWED_HOSTS", "")
    hosts = {"127.0.0.1", "localhost", "::1"}
    hosts.update(_host_key(part) for part in raw.split(",") if part.strip())
    return hosts


def _host_allowed(value: str) -> bool:
    return _host_key(value) in _allowed_hosts()


def _authority(value: str, default_port: int | None) -> tuple[str, int | None]:
    """Return (lowercase host, port) for a Host/authority value."""
    try:
        parsed = urlparse(f"//{value}")
        return (parsed.hostname or "").lower(), parsed.port or default_port
    except ValueError:
        return "", None


def _boundary_response(message: str, status_code: int = 403) -> PlainTextResponse:
    return PlainTextResponse(message, status_code=status_code)


def _replay_receive(body: bytes):
    """An ASGI receive that replays one buffered request body."""

    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _read_body(receive) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return b"".join(chunks), False
        if message["type"] != "http.request":
            continue
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            return b"".join(chunks), True


class LocalBoundaryMiddleware:
    """Reject DNS-rebinding Host headers and cross-site form posts.

    Breadcrumb is a local, no-auth app. These checks do not add a login; they
    stop a malicious web page (or a rebinding DNS name) from driving the API
    through the user's browser. JSON/curl clients still work because the CSRF
    token requirement applies only to browser form content types.

    This is a pure ASGI middleware, not ``BaseHTTPMiddleware``: form bodies
    must be buffered and replayed so the route's ``Form(...)`` parameters can
    still parse them after the token check.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
        scope.setdefault("state", {})["csrf_token"] = token
        set_cookie = CSRF_COOKIE not in request.cookies

        async def send_wrapper(message):
            if set_cookie and message["type"] == "http.response.start":
                message.setdefault("headers", []).append(
                    (
                        b"set-cookie",
                        f"{CSRF_COOKIE}={token}; Path=/; HttpOnly; SameSite=lax".encode(
                            "latin-1"
                        ),
                    )
                )
            await send(message)

        if not _host_allowed(request.headers.get("host", "")):
            await _boundary_response("Invalid Host header", 400)(
                scope, receive, send_wrapper
            )
            return
        downstream_receive = receive
        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin", "")
            if origin:
                parsed = urlparse(origin)
                if parsed.scheme not in ("http", "https") or not _host_allowed(
                    parsed.netloc
                ):
                    await _boundary_response("Cross-origin request rejected")(
                        scope, receive, send_wrapper
                    )
                    return
            fetch_site = request.headers.get("sec-fetch-site", "")
            if fetch_site and fetch_site not in ("same-origin", "none"):
                await _boundary_response("Cross-site request rejected")(
                    scope, receive, send_wrapper
                )
                return
            content_type = request.headers.get("content-type", "").lower()
            if content_type.startswith(FORM_CONTENT_TYPES):
                supplied = request.headers.get("x-csrf-token", "")
                if not supplied:
                    body, complete = await _read_body(receive)
                    if not complete:
                        await _boundary_response("Incomplete request body", 400)(
                            scope, receive, send_wrapper
                        )
                        return
                    downstream_receive = _replay_receive(body)
                    try:
                        form = await Request(scope, _replay_receive(body)).form()
                    except Exception:  # noqa: BLE001
                        await _boundary_response("Malformed form body", 400)(
                            scope, receive, send_wrapper
                        )
                        return
                    supplied = str(form.get("csrf_token") or "")
                if not supplied or not hmac.compare_digest(supplied, token):
                    await _boundary_response("CSRF token missing or invalid")(
                        scope, receive, send_wrapper
                    )
                    return
        await self.app(scope, downstream_receive, send_wrapper)


app.add_middleware(LocalBoundaryMiddleware)


TYPE_CHOICES = reporting.TYPE_ORDER

ENTITY_VERDICTS = ("none", "confirmed", "needs-review", "false-positive")
JOB_STATUSES = ("queued", "running", "done", "failed", "cancelled")


def parse_tags(raw: str) -> list[str]:
    """Comma/space separated tag input -> ordered unique lowercase tags."""
    parts = re.split(r"[,\s]+", (raw or "").strip())
    seen: list[str] = []
    for part in parts:
        tag = part.strip().lower()
        if tag and tag not in seen:
            seen.append(tag)
    return seen


def _ctx(**extra):
    base = {
        "type_labels": reporting.TYPE_LABELS,
        "edge_labels": graph.EDGE_LABELS,
        "group_entities": reporting.group_entities,
        "app_version": APP_VERSION,
    }
    base.update(extra)
    return base


def _programs(session: Session):
    return session.exec(select(Program).order_by(Program.name)).all()


def _targets(session: Session, program_id=None):
    stmt = select(Target).order_by(Target.name)
    if program_id:
        stmt = stmt.where(Target.program_id == program_id)
    return session.exec(stmt).all()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)):
    programs = _programs(session)
    counts = {}
    for program in programs:
        counts[program.id] = session.exec(
            select(func.count()).select_from(Entity).where(Entity.program_id == program.id)
        ).one()
    recent = session.exec(select(Paste).order_by(Paste.id.desc()).limit(10)).all()
    unassigned = session.exec(
        select(Entity).where(Entity.program_id == None)  # noqa: E711
    ).all()
    type_counts = Counter()
    port_counts = Counter()
    target_counts = Counter()
    interesting = 0
    for row in session.exec(select(Entity.type, Entity.value, Entity.target_id)).all():
        etype, value, target_id = row
        type_counts[etype] += 1
        if etype == "port":
            port_counts[value] += 1
        if etype in ("secret", "credential", "cve", "hash", "jwt"):
            interesting += 1
        if target_id is not None:
            target_counts[target_id] += 1
    busiest = None
    if target_counts:
        top_target_id, top_target_n = target_counts.most_common(1)[0]
        top_target = session.get(Target, top_target_id)
        if top_target is not None:
            busiest = {"name": top_target.name, "count": top_target_n}
    insights = {
        "top_types": type_counts.most_common(5),
        "top_ports": port_counts.most_common(5),
        "interesting": interesting,
        "busiest_target": busiest,
    }
    return templates.TemplateResponse(
        request,
        "index.html",
        _ctx(
            programs=programs,
            counts=counts,
            recent=recent,
            targets=_targets(session),
            unassigned_count=len(unassigned),
            insights=insights,
        ),
    )


@app.post("/programs")
def create_program(
    name: str = Form(...),
    platform: str = Form(""),
    scope_in: str = Form(""),
    scope_out: str = Form(""),
    session: Session = Depends(get_session),
):
    program = Program(
        name=name.strip(),
        platform=platform.strip() or None,
        scope_in=scope_in.strip() or None,
        scope_out=scope_out.strip() or None,
    )
    session.add(program)
    session.commit()
    session.refresh(program)
    _ensure_targets_from_scope(session, program)
    return RedirectResponse(f"/programs/{program.id}", status_code=303)


@app.post("/demo")
def create_demo(session: Session = Depends(get_session)):
    """Seed the sample program from the dashboard (idempotent)."""
    from .demo import run_demo

    result = run_demo(session)
    message = (
        f"Demo ready: {result['entities']} entities, {result['findings']} findings"
    )
    return RedirectResponse(
        f"/programs/{result['program_id']}?msg={quote(message)}", status_code=303
    )


@app.get("/programs/{program_id}", response_class=HTMLResponse)
def program_view(program_id: int, request: Request, session: Session = Depends(get_session)):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    targets = _targets(session, program_id)
    entities = session.exec(
        select(Entity).where(Entity.program_id == program_id).order_by(Entity.type, Entity.value)
    ).all()
    relationships = session.exec(
        select(Relationship).where(Relationship.program_id == program_id).limit(500)
    ).all()
    findings = session.exec(
        select(Finding).where(Finding.program_id == program_id)
    ).all()
    scope_counts = {
        "in": sum(1 for e in entities if e.scope_status == "in"),
        "out": sum(1 for e in entities if e.scope_status == "out"),
        "unknown": sum(1 for e in entities if e.scope_status == "unknown"),
    }
    unattributed = [e for e in entities if e.target_id is None]
    triage_states = {finding.id: triage.triage_status(finding) for finding in findings}
    return templates.TemplateResponse(
        request,
        "program.html",
        _ctx(
            program=program,
            targets=targets,
            groups=reporting.group_entities(entities),
            entities=entities,
            entity_total=len(entities),
            relationships=relationships,
            findings=findings,
            triage_states=triage_states,
            scope_counts=scope_counts,
            unattributed=unattributed,
        ),
    )


@app.post("/programs/{program_id}/rebuild")
def rebuild_view(program_id: int, session: Session = Depends(get_session)):
    if session.get(Program, program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")
    rebuild_program(session, program_id)
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@app.post("/rebuild")
def rebuild_everything(session: Session = Depends(get_session)):
    rebuild_all(session)
    return RedirectResponse("/", status_code=303)


@app.get("/programs/{program_id}/graph", response_class=HTMLResponse)
def program_graph(
    program_id: int,
    request: Request,
    q: str = "",
    node_type: str = "",
    session: Session = Depends(get_session),
):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    targets = session.exec(
        select(Target).where(Target.program_id == program_id).order_by(Target.name)
    ).all()
    all_entities = session.exec(
        select(Entity).where(Entity.program_id == program_id).order_by(Entity.type, Entity.value)
    ).all()
    all_relationships = session.exec(
        select(Relationship).where(Relationship.program_id == program_id)
    ).all()

    query = (q or "").strip().lower()
    node_type = (node_type or "").strip()
    entities = [
        entity for entity in all_entities
        if (not query or query in (entity.value or "").lower())
        and (not node_type or entity.type == node_type)
    ]
    visible_ids = {entity.id for entity in entities if entity.id is not None}
    visible_pairs = {(entity.type, (entity.value or "").lower()) for entity in entities}

    def _edge_visible(relationship) -> bool:
        if relationship.src_entity_id is not None and relationship.dst_entity_id is not None:
            return (
                relationship.src_entity_id in visible_ids
                and relationship.dst_entity_id in visible_ids
            )
        return (
            (relationship.src_type, (relationship.src_value or "").lower()) in visible_pairs
            and (relationship.dst_type, (relationship.dst_value or "").lower()) in visible_pairs
        )

    relationships = [r for r in all_relationships if _edge_visible(r)]
    entity_by_id = {e.id: e for e in entities}
    path_tree = graph.path_tree(entities)
    filter_active = bool(query or node_type)

    by_target: dict = {}
    for entity in entities:
        by_target.setdefault(entity.target_id, []).append(entity)
    groups = []
    for target in targets:
        groups.append(
            {
                "target": target,
                "entities": by_target.get(target.id, []),
                "edges": [r for r in relationships if r.target_id == target.id],
            }
        )
    loose = by_target.get(None, [])
    loose_edges = [r for r in relationships if r.target_id is None]

    def _cluster(label, kind, ents, edges):
        ids = {e.id for e in ents}
        connected = set()
        for r in edges:
            connected.add(r.src_entity_id)
            connected.add(r.dst_entity_id)
        # Cap nodes per cluster so a huge program can't lock up the SVG view.
        ordered = sorted(ents, key=lambda e: (e.id not in connected, (e.value or "").lower()))
        shown = ordered[:MAX_CLUSTER_NODES]
        shown_ids = {e.id for e in shown}
        nodes = [{"id": e.id, "label": e.value, "type": e.type} for e in shown]
        vis = [
            {"s": r.src_entity_id, "d": r.dst_entity_id,
             "label": graph.EDGE_LABELS.get(r.rel_type, r.rel_type)}
            for r in edges
            if r.src_entity_id in shown_ids and r.dst_entity_id in shown_ids
        ]
        return {
            "target": label,
            "kind": kind,
            "nodes": nodes,
            "edges": vis,
            "omitted": max(0, len(ents) - len(shown)),
        }

    clusters = [
        _cluster(g["target"].name, g["target"].kind, g["entities"], g["edges"])
        for g in groups
    ]
    if loose:
        clusters.append(_cluster("Unattributed", "", loose, loose_edges))

    return templates.TemplateResponse(
        request,
        "graph.html",
        _ctx(
            program=program,
            targets=targets,
            groups=groups,
            loose=loose,
            loose_edges=loose_edges,
            edge_count=len(relationships),
            entity_by_id=entity_by_id,
            clusters=clusters,
            q=q,
            node_type=node_type,
            node_types=graph.NODE_TYPES,
            path_tree=path_tree,
            visible_entities=len(entities),
            total_entities=len(all_entities),
            filter_active=filter_active,
        ),
    )


@app.get("/targets/{target_id}/history", response_class=HTMLResponse)
def target_history_view(
    target_id: int,
    request: Request,
    from_scan: int = 0,
    to_scan: int = 0,
    session: Session = Depends(get_session),
):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    try:
        data = history.target_history(session, target_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    program = session.get(Program, target.program_id) if target.program_id else None
    selected_diff = None
    if from_scan and to_scan:
        try:
            selected_diff = history.load_diff(session, target_id, from_scan, to_scan)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    elif data.get("latest_diff"):
        selected_diff = data["latest_diff"]
    return templates.TemplateResponse(
        request,
        "history.html",
        _ctx(
            target=target,
            program=program,
            history=data,
            selected_diff=selected_diff,
            from_scan=from_scan,
            to_scan=to_scan,
        ),
    )


@app.post("/targets/{target_id}/history/rebuild")
def rebuild_target_history(
    target_id: int, session: Session = Depends(get_session)
):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    report = history.rebuild_snapshots(session, target_id=target_id)
    message = (
        f"rebuilt {report['built']} snapshot(s), "
        f"{report['failed']} failed, {report['skipped']} skipped"
    )
    return RedirectResponse(
        f"/targets/{target_id}/history?msg=" + quote(message), status_code=303
    )


@app.post("/programs/{program_id}/snapshots/rebuild")
def rebuild_program_snapshots(
    program_id: int, session: Session = Depends(get_session)
):
    if session.get(Program, program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")
    report = history.rebuild_snapshots(session, program_id=program_id)
    message = (
        f"rebuilt {report['built']} snapshot(s), "
        f"{report['failed']} failed, {report['skipped']} skipped"
    )
    return RedirectResponse(
        f"/programs/{program_id}?msg=" + quote(message), status_code=303
    )


@app.post("/jobs/{job_id}/snapshot/rebuild")
def rebuild_job_snapshot(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        history.generate_snapshot(session, job)
    except Exception as exc:  # noqa: BLE001
        history.upsert_snapshot(session, job, status="pending", error=str(exc))
        raise HTTPException(status_code=500, detail=f"snapshot rebuild failed: {exc}") from exc
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.post("/programs/{program_id}/targets")
def create_target(
    program_id: int,
    name: str = Form(...),
    kind: str = Form("domain"),
    session: Session = Depends(get_session),
):
    session.add(Target(program_id=program_id, name=name.strip(), kind=kind))
    session.commit()
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@app.post("/programs/{program_id}/update")
def update_program(
    program_id: int,
    name: str = Form(""),
    platform: str = Form(""),
    scope_in: str = Form(""),
    scope_out: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    if name.strip():
        program.name = name.strip()
    program.platform = platform.strip() or None
    program.scope_in = scope_in.strip() or None
    program.scope_out = scope_out.strip() or None
    program.notes = notes.strip() or None
    session.add(program)
    session.commit()
    _ensure_targets_from_scope(session, program)
    rebuild_program(session, program_id)
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@app.post("/programs/{program_id}/delete")
def delete_program(program_id: int, session: Session = Depends(get_session)):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    for model in (Finding, Relationship, Entity, Paste, Target, ScanJob):
        for row in session.exec(select(model).where(model.program_id == program_id)).all():
            session.delete(row)
    session.delete(program)
    session.commit()
    _reconcile_chain(session)
    return RedirectResponse("/", status_code=303)


@app.post("/programs/{program_id}/targets/{target_id}/update")
def update_target(
    program_id: int,
    target_id: int,
    name: str = Form(""),
    kind: str = Form(""),
    session: Session = Depends(get_session),
):
    target = session.get(Target, target_id)
    if target is None or target.program_id != program_id:
        raise HTTPException(status_code=404, detail="Target not found")
    if name.strip():
        target.name = name.strip()
    if kind.strip():
        target.kind = kind.strip()
    session.add(target)
    session.commit()
    rebuild_program(session, program_id)
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@app.post("/programs/{program_id}/targets/{target_id}/delete")
def delete_target(
    program_id: int,
    target_id: int,
    session: Session = Depends(get_session),
):
    target = session.get(Target, target_id)
    if target is None or target.program_id != program_id:
        raise HTTPException(status_code=404, detail="Target not found")
    for model in (Entity, Relationship, Finding):
        for row in session.exec(select(model).where(model.target_id == target_id)).all():
            row.target_id = None
            session.add(row)
    session.delete(target)
    session.commit()
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@app.get("/inbox", response_class=HTMLResponse)
def inbox(request: Request, session: Session = Depends(get_session)):
    pastes = session.exec(select(Paste).order_by(Paste.id.desc()).limit(50)).all()
    unassigned = session.exec(
        select(Entity).where(Entity.program_id == None).order_by(Entity.id.desc()).limit(200)  # noqa: E711
    ).all()
    return templates.TemplateResponse(
        request,
        "inbox.html",
        _ctx(
            pastes=pastes,
            groups=reporting.group_entities(unassigned),
            unassigned_count=len(unassigned),
            programs=_programs(session),
            targets=_targets(session),
        ),
    )


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
# Hard ceiling per ingest so a pathological paste can't exhaust disk/RAM.
MAX_ENTITIES_PER_PASTE = 25000
# Nodes drawn per graph cluster; larger sets are summarized, not rendered.
MAX_CLUSTER_NODES = 200


def _ensure_targets_from_scope(session: Session, program: Program) -> int:
    """Auto-create Target rows from a program's in-scope entries.

    Removes the single biggest manual tax in recon notebooks: typing the hosts
    you already wrote down as scope, then hand-attributing every entity.
    """
    from . import scope as scope_mod

    rules = scope_mod.parse_scope(program.scope_in or "")
    existing = {
        t.name.strip().lower()
        for t in session.exec(select(Target).where(Target.program_id == program.id)).all()
    }
    created = 0
    for rule in rules:
        if rule.negate or rule.kind == "path":
            continue
        if rule.kind in {"cidr", "ip"}:
            name, kind = rule.pattern, "ip"
        else:
            name, kind = rule.pattern, "domain"
        if not name or name.lower() in existing:
            continue
        existing.add(name.lower())
        session.add(Target(program_id=program.id, name=name, kind=kind))
        created += 1
    if created:
        session.commit()
    return created


# The ingest path lives in app/ingest.py so the web app, CLI, JSON API and
# native worker all share exactly one evidence/parsing implementation.
_reconcile_chain = ingest_mod._reconcile_chain


def _ingest(
    session: Session,
    text: str,
    pid: int | None,
    tid: int | None,
    source: str,
    capture_key: str | None = None,
    *,
    job_id: int | None = None,
    attempt_id: int | None = None,
    phase: str | None = None,
    command: str | None = None,
    source_meta: dict | None = None,
    max_entities: int | None = None,
) -> Paste:
    """Backward-compatible wrapper used by the existing routes and CLI."""
    result = ingest_mod.ingest(
        session,
        ingest_mod.IngestRequest(
            text=text,
            program_id=pid,
            target_id=tid,
            source=source,
            capture_key=capture_key,
            job_id=job_id,
            attempt_id=attempt_id,
            phase=phase,
            command=command,
            source_meta=source_meta or {},
            # Kept as a module-level constant so tests can monkeypatch it.
            max_entities=max_entities or MAX_ENTITIES_PER_PASTE,
        ),
    )
    return result.paste


@app.post("/paste")
def create_paste(
    text: str = Form(""),
    program_id: str = Form(""),
    target_id: str = Form(""),
    source: str = Form("manual"),
    command: str = Form(""),
    upload: UploadFile | None = File(None),
    session: Session = Depends(get_session),
):
    body = text or ""
    label = source
    source_meta: dict = {}
    if upload is not None and upload.filename:
        raw = upload.file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large (max 5 MB)")
        body = (body + "\n" if body else "") + raw.decode("utf-8", errors="replace")
        label = f"file:{upload.filename}"
        source_meta["filename"] = upload.filename
    if not body.strip():
        return RedirectResponse("/inbox", status_code=303)
    pid = int(program_id) if program_id.strip() else None
    tid = int(target_id) if target_id.strip() else None
    paste = _ingest(
        session,
        body,
        pid,
        tid,
        label,
        command=command.strip() or None,
        source_meta=source_meta,
    )
    n = session.exec(
        select(func.count()).select_from(Entity).where(Entity.paste_id == paste.id)
    ).one()
    n_find = session.exec(
        select(func.count()).select_from(Finding).where(Finding.paste_id == paste.id)
    ).one()
    if n or n_find:
        summary = f"Capture #{paste.id}: {n} entities via {', '.join(paste.parsers or ['?'])}"
    else:
        summary = f"Capture #{paste.id}: no entities detected"
        if paste.parse_errors:
            summary += f" ({len(paste.parse_errors)} parser issue(s) — see capture page)"
        else:
            summary += " (no parser matched — check the format)"
    if n_find:
        summary += f" · {n_find} new finding(s)"
    if paste.parse_errors and n:
        summary += f" · {len(paste.parse_errors)} parser issue(s)"
    return RedirectResponse(f"/pastes/{paste.id}?msg={quote(summary)}", status_code=303)


@app.get("/pastes/{paste_id}", response_class=HTMLResponse)
def paste_view(paste_id: int, request: Request, session: Session = Depends(get_session)):
    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Paste not found")
    entities = session.exec(
        select(Entity).where(Entity.paste_id == paste_id).order_by(Entity.type, Entity.value)
    ).all()
    return templates.TemplateResponse(
        request,
        "paste.html",
        _ctx(
            paste=paste,
            groups=reporting.group_entities(entities),
            programs=_programs(session),
            targets=_targets(session),
        ),
    )


@app.post("/pastes/{paste_id}/assign")
def assign_paste(
    paste_id: int,
    program_id: str = Form(""),
    target_id: str = Form(""),
    session: Session = Depends(get_session),
):
    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Paste not found")
    pid = int(program_id) if program_id.strip() else None
    tid = int(target_id) if target_id.strip() else None
    paste.program_id = pid
    paste.target_id = tid
    session.add(paste)
    for rel in session.exec(select(Relationship).where(Relationship.paste_id == paste_id)).all():
        rel.program_id = pid
        session.add(rel)
    session.commit()
    merge_into_program(session, paste_id, pid)
    if pid:
        rebuild_program(session, pid)
    return RedirectResponse(f"/pastes/{paste_id}", status_code=303)


@app.post("/entities/{entity_id}/delete")
def delete_entity(entity_id: int, session: Session = Depends(get_session)):
    entity = session.get(Entity, entity_id)
    back = "/inbox"
    if entity is not None:
        back = f"/pastes/{entity.paste_id}" if entity.paste_id else "/entities"
        session.delete(entity)
        session.commit()
    return RedirectResponse(back, status_code=303)


@app.post("/entities/{entity_id}/ignore")
def ignore_entity(entity_id: int, session: Session = Depends(get_session)):
    """Noise suppression (ZAP alert-filter style): hide without deleting."""
    entity = session.get(Entity, entity_id)
    back = "/entities"
    if entity is not None:
        entity.ignored = not entity.ignored
        session.add(entity)
        session.commit()
        back = f"/pastes/{entity.paste_id}" if entity.paste_id else "/entities"
    return RedirectResponse(back, status_code=303)


@app.post("/entities/{entity_id}/annotate")
def annotate_entity(
    entity_id: int,
    verdict: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    back: str = Form(""),
    session: Session = Depends(get_session),
):
    """Analyst metadata: verdict (accuracy), tags, private notes."""
    entity = session.get(Entity, entity_id)
    dest = back.strip() or (f"/pastes/{entity.paste_id}" if entity and entity.paste_id else "/entities")
    if entity is None:
        return RedirectResponse(dest, status_code=303)
    if verdict.strip() and verdict.strip() in ENTITY_VERDICTS:
        entity.verdict = verdict.strip()
    entity.tags = parse_tags(tags)
    entity.notes = notes.strip() or None
    session.add(entity)
    session.commit()
    return RedirectResponse(dest, status_code=303)


@app.post("/entities/{entity_id}/verdict")
def set_entity_verdict(
    entity_id: int,
    verdict: str = Form(...),
    back: str = Form(""),
    session: Session = Depends(get_session),
):
    """One-click accuracy verdict (e.g. mark a noisy match as false-positive)."""
    entity = session.get(Entity, entity_id)
    dest = back.strip() or (f"/pastes/{entity.paste_id}" if entity and entity.paste_id else "/entities")
    if entity is not None and verdict.strip() in ENTITY_VERDICTS:
        entity.verdict = verdict.strip()
        session.add(entity)
        session.commit()
    return RedirectResponse(dest, status_code=303)


@app.get("/programs/{program_id}/changes", response_class=HTMLResponse)
def program_changes(program_id: int, request: Request, session: Session = Depends(get_session)):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    changes = reporting.entity_changes(session, program_id)
    return templates.TemplateResponse(
        request,
        "changes.html",
        _ctx(program=program, changes=changes),
    )


@app.post("/programs/{program_id}/changes/notify")
def notify_changes_route(program_id: int, session: Session = Depends(get_session)):
    """Send the latest surface change to the configured notification channels."""
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    changes = reporting.entity_changes(session, program_id)
    result = notify.notify_changes(
        notify.load_config(), program.name, len(changes["added"]), len(changes["removed"])
    )
    if result.get("sent"):
        msg = f"notified {len(result['results'])} channel(s)"
    else:
        msg = f"not sent ({result.get('reason', 'no channels')})"
    return RedirectResponse(
        f"/programs/{program_id}/changes?msg=" + quote(msg), status_code=303
    )


@app.get("/ledger", response_class=HTMLResponse)
def ledger_view(request: Request, session: Session = Depends(get_session)):
    """Cross-program asset memory: assets seen in more than one program."""
    rows = session.exec(
        select(
            Entity.type,
            func.lower(Entity.normalized),
            func.min(Entity.value),
            func.count(func.distinct(Entity.program_id)),
        )
        .where(Entity.program_id != None)  # noqa: E711
        .group_by(Entity.type, func.lower(Entity.normalized))
        .having(func.count(func.distinct(Entity.program_id)) > 1)
        .order_by(func.count(func.distinct(Entity.program_id)).desc())
        .limit(500)
    ).all()
    names = {p.id: p.name for p in session.exec(select(Program)).all()}
    norms = [r[1] for r in rows]
    progs: dict[tuple[str, str], set] = {}
    if norms:
        for t, n, pid in session.exec(
            select(Entity.type, func.lower(Entity.normalized), Entity.program_id)
            .where(Entity.program_id != None, func.lower(Entity.normalized).in_(norms))  # noqa: E711
        ).all():
            progs.setdefault((t, n), set()).add(pid)
    assets = []
    for t, n, value, count in rows:
        ids = sorted(progs.get((t, n), set()))
        assets.append({
            "type": t,
            "value": value,
            "count": count,
            "programs": [{"id": i, "name": names.get(i, f"#{i}")} for i in ids],
        })
    return templates.TemplateResponse(
        request,
        "ledger.html",
        _ctx(assets=assets, program_count=len(names)),
    )


@app.get("/api/v1/verify")
def api_verify(session: Session = Depends(get_session)):
    """Recompute the evidence hash-chain and report integrity (offline).

    Checks each capture's content hash against its stored seal, its chain
    link against the recorded predecessor, the 1-based sequence, and the
    singleton head/length row. Captures removed with a deleted program are
    reported as ``gaps`` (not tampering); legacy unsealed captures are
    reported as ``unsealed``. A duplicate predecessor is a ``fork``.
    """
    from .evidence import verify_chain

    return JSONResponse(verify_chain(session))


@app.get("/pipeline", response_class=HTMLResponse)
def pipeline_view(
    request: Request,
    program_id: int = 0,
    header_profile_id: int = 0,
    session: Session = Depends(get_session),
):
    programs = _programs(session)
    program = session.get(Program, program_id) if program_id else (programs[0] if programs else None)
    targets = (
        session.exec(select(Target).where(Target.program_id == program.id)).all()
        if program else []
    )
    profiles = session.exec(select(HeaderProfile).order_by(HeaderProfile.name)).all()
    header_profile = (
        session.get(HeaderProfile, header_profile_id) if header_profile_id else None
    )
    built = pipeline_mod.build_pipeline(program, targets, header_profile) if program else None
    return templates.TemplateResponse(
        request,
        "pipeline.html",
        _ctx(
            programs=programs,
            program=program,
            targets=targets,
            profiles=profiles,
            header_profile=header_profile,
            built=built,
        ),
    )


@app.get("/runners", response_class=HTMLResponse)
def runners_view(request: Request, session: Session = Depends(get_session)):
    jobs = session.exec(select(ScanJob).order_by(ScanJob.id.desc()).limit(100)).all()
    profiles = session.exec(select(HeaderProfile).order_by(HeaderProfile.name)).all()
    return templates.TemplateResponse(
        request,
        "runners.html",
        _ctx(
            runners=runners.all_runners(session),
            described=runners.describe_all(session),
            jobs=jobs,
            programs=_programs(session),
            profiles=profiles,
            profile_names={p.id: p.name for p in profiles},
            native_ids=set(collector_ids()) | set(adapter_ids()),
            executor_mode=os.environ.get("BREADCRUMB_EXECUTOR", "off").strip().lower(),
            adapters_enabled=adapters_enabled(),
            strict_mode=strict_mode(),
            maintenance=get_app_state(session),
        ),
    )


@app.post("/jobs")
def create_job(
    runner: str = Form(...),
    target: str = Form(""),
    program_id: str = Form(""),
    header_profile_id: str = Form(""),
    params: str = Form(""),
    run_now: str = Form(""),
    session: Session = Depends(get_session),
):
    if runners.find_runner(session, runner) is None:
        raise HTTPException(status_code=400, detail="Unknown runner")
    pid = int(program_id) if program_id.strip() else None
    hpid = int(header_profile_id) if header_profile_id.strip() else None
    if hpid is not None and session.get(HeaderProfile, hpid) is None:
        raise HTTPException(status_code=400, detail="Unknown header profile")
    options: dict = {}
    if params.strip():
        try:
            parsed = json.loads(params)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"params must be JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="params must be a JSON object")
        options = parsed
    target_value = target.strip()
    target_id = None
    if pid is not None and target_value:
        targets = session.exec(select(Target).where(Target.program_id == pid)).all()
        matched = history.attribute_target(history._host_for(target_value), targets)
        target_id = matched.id if matched else None
    job = ScanJob(
        program_id=pid,
        target_id=target_id,
        runner=runner,
        target=target_value,
        status="queued",
        header_profile_id=hpid,
        params=options,
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    selected = runners.find_runner(session, runner)
    if run_now and selected is not None and (selected.native or selected.adapter):
        state = _arm_native_job(session, job)
        if state == "queued":
            _start_native_job(job.id, job.runner)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)
    return RedirectResponse("/runners", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_view(job_id: int, request: Request, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    profile = session.get(HeaderProfile, job.header_profile_id) if job.header_profile_id else None
    program = session.get(Program, job.program_id) if job.program_id else None
    runner = runners.find_runner(session, job.runner)
    curl = headers_gen.to_curl_args(profile.headers or {}, profile.proxy or "") if profile else ""
    attempts = session.exec(
        select(JobAttempt).where(JobAttempt.job_id == job_id).order_by(JobAttempt.attempt_no)
    ).all()
    phases = session.exec(
        select(ScanPhase).where(ScanPhase.job_id == job_id).order_by(ScanPhase.seq)
    ).all()
    events = session.exec(
        select(JobEvent).where(JobEvent.job_id == job_id).order_by(JobEvent.id)
    ).all()
    snapshot = history.snapshot_for_job(session, job_id)
    if snapshot is None and job.status == "done":
        snapshot = history.ensure_snapshot(session, job)
    target = session.get(Target, job.target_id) if job.target_id else None
    return templates.TemplateResponse(
        request,
        "job.html",
        _ctx(
            job=job,
            profile=profile,
            program=program,
            target=target,
            runner=runner,
            curl=curl,
            attempts=attempts,
            phases=phases,
            events=events,
            snapshot=snapshot,
            native=bool(runner and (runner.native or runner.adapter)),
            adapter=bool(runner and runner.adapter),
        ),
    )


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, session: Session = Depends(get_session)):
    """Cancel a queued job or ask a running worker to stop at its next check."""
    outcome = jobs_queue.request_cancel(session, job_id)
    if outcome is None:
        raise HTTPException(status_code=404, detail="Job not found")
    message = {
        "cancelled": f"job #{job_id} cancelled",
        "cancel-requested": f"cancellation requested for job #{job_id}",
    }.get(outcome, f"job #{job_id} is already {outcome}")
    return RedirectResponse("/runners?msg=" + quote(message), status_code=303)


def _is_imported_job(job: ScanJob) -> bool:
    """True for historical rows created by ``breadcrumb import-leadline``."""
    return bool((job.params or {}).get("imported"))


@app.post("/jobs/{job_id}/retry")
def retry_job(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if _is_imported_job(job):
        return RedirectResponse(
            f"/jobs/{job_id}?msg="
            + quote(
                "Imported Leadline jobs are historical and cannot be retried; "
                "queue a new scan instead."
            ),
            status_code=303,
        )
    clone = ScanJob(
        program_id=job.program_id,
        runner=job.runner,
        target=job.target,
        status="queued",
        header_profile_id=job.header_profile_id,
        params=dict(job.params or {}),
        priority=int(job.priority or 0),
        max_attempts=int(job.max_attempts or 3),
    )
    session.add(clone)
    session.commit()
    return RedirectResponse("/runners", status_code=303)


def _arm_native_job(session: Session, job: ScanJob) -> str:
    """Validate a native job and make it claimable.

    Returns ``armed``/``queued`` when the job can run, otherwise the stored
    status. A manual re-run intentionally resets the same row (including the
    attempt count) so a job that exhausted its retries can run again.
    """
    if _is_imported_job(job):
        raise HTTPException(
            status_code=409,
            detail=(
                "Imported Leadline jobs are historical; queue a new scan "
                "instead of re-running this row."
            ),
        )
    runner = runners.find_runner(session, job.runner)
    runnable = set(collector_ids()) | set(adapter_ids())
    if runner is None or not (runner.native or runner.adapter) or job.runner not in runnable:
        raise HTTPException(
            status_code=400, detail="This runner has no native collector or adapter"
        )
    if job.status in ("failed", "cancelled"):
        job.status = "queued"
        job.next_run_at = None
        job.error = None
        job.output_paste_id = None
        job.finished_at = None
        job.cancel_requested = False
        if int(job.attempts or 0) >= int(job.max_attempts or 3):
            # Keep attempt numbers unique and preserve the audit trail; allow
            # exactly one more attempt instead of reusing attempt 1's captures.
            job.max_attempts = int(job.attempts or 0) + 1
        session.add(job)
        session.commit()
        return "armed"
    if job.status != "queued":
        return job.status
    if job.next_run_at is not None or int(job.attempts or 0) >= int(job.max_attempts or 3):
        # "Run now" must bypass retry backoff.
        job.next_run_at = None
        if int(job.attempts or 0) >= int(job.max_attempts or 3):
            job.max_attempts = int(job.attempts or 0) + 1
        session.add(job)
        session.commit()
    return "queued"


def _start_native_job(job_id: int, runner_id: str) -> None:
    """Execute one claimed-by-id job in a background thread."""

    def _run() -> None:
        try:
            run_native_job(
                job_id=job_id,
                runner_ids=(runner_id,),
                worker_id=f"web:{os.getpid()}",
            )
        except Exception as exc:  # noqa: BLE001  (never kill the web process)
            print(f"breadcrumb run-now error for job #{job_id}: {exc}", file=sys.stderr)

    threading.Thread(target=_run, name=f"breadcrumb-run-{job_id}", daemon=True).start()


@app.post("/jobs/{job_id}/run")
def run_job(
    job_id: int,
    session: Session = Depends(get_session),
):
    """Run a native collector now, in a background thread.

    The regular ``breadcrumb worker`` is the durable path; this button is a
    convenience for a single local job. The atomic claim in ``run_once`` means
    the background thread and a standalone worker cannot run it twice.
    """
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    state = _arm_native_job(session, job)
    if state in ("running", "done"):
        return RedirectResponse(
            "/jobs/" + str(job_id) + "?msg=" + quote(f"job #{job_id} is {state}"),
            status_code=303,
        )
    _start_native_job(job.id, job.runner)
    return RedirectResponse(
        "/jobs/" + str(job_id) + "?msg=" + quote(f"job #{job_id} started"),
        status_code=303,
    )


@app.post("/jobs/{job_id}/delete")
def delete_job(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is not None:
        session.delete(job)
        session.commit()
    return RedirectResponse("/runners", status_code=303)


@app.post("/jobs/clear")
def clear_jobs(session: Session = Depends(get_session)):
    """Remove finished/failed/cancelled jobs; keep live ones."""
    rows = session.exec(
        select(ScanJob).where(ScanJob.status.in_(("done", "failed", "cancelled")))
    ).all()
    count = 0
    for job in rows:
        session.delete(job)
        count += 1
    session.commit()
    return RedirectResponse("/runners?msg=" + quote(f"cleared {count} finished job(s)"), status_code=303)


RUNNER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


def _runner_msg(report: list[tuple[str, str]]) -> str:
    return " | ".join(f"[{'OK' if lvl == 'ok' else lvl.upper()}] {msg}" for lvl, msg in report)


@app.post("/runners/toggle")
def toggle_runner(
    runner_id: str = Form(...),
    enabled: str = Form(""),
    session: Session = Depends(get_session),
):
    rid = runner_id.strip()
    if runners.get_runner(rid) is None:
        raise HTTPException(status_code=400, detail="Unknown built-in runner")
    want = enabled.strip().lower() in ("1", "true", "yes", "on")
    row = session.exec(select(RunnerToggle).where(RunnerToggle.runner_id == rid)).first()
    if row is None:
        row = RunnerToggle(runner_id=rid, enabled=want)
    else:
        row.enabled = want
    session.add(row)
    session.commit()
    state = "activated" if want else "deactivated"
    return RedirectResponse(f"/runners?msg={quote(f'{rid} {state}')}", status_code=303)


@app.post("/runners/custom")
def create_custom_runner(
    runner_id: str = Form(...),
    label: str = Form(""),
    description: str = Form(""),
    example: str = Form(""),
    session: Session = Depends(get_session),
):
    rid = runner_id.strip().lower()
    if not RUNNER_ID_RE.match(rid):
        raise HTTPException(
            status_code=400,
            detail="Runner id must be 2-41 chars: lowercase letters, digits, dashes.",
        )
    if runners.get_runner(rid) is not None or rid in collector_ids() or session.exec(
        select(CustomRunner).where(CustomRunner.runner_id == rid)
    ).first():
        raise HTTPException(status_code=400, detail="Runner id already exists")
    session.add(
        CustomRunner(
            runner_id=rid,
            label=label.strip() or rid,
            description=description.strip(),
            example=example.strip(),
        )
    )
    session.commit()
    report = runners.validate_custom(rid, example, session)
    return RedirectResponse(f"/runners?msg={quote(_runner_msg(report))}", status_code=303)


@app.get("/runners/custom/{custom_id}/verify")
def verify_custom_runner(custom_id: int, session: Session = Depends(get_session)):
    custom = session.get(CustomRunner, custom_id)
    if custom is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    report = runners.validate_custom(custom.runner_id, custom.example, session)
    return RedirectResponse(f"/runners?msg={quote(_runner_msg(report))}", status_code=303)


@app.post("/runners/custom/{custom_id}/delete")
def delete_custom_runner(custom_id: int, session: Session = Depends(get_session)):
    custom = session.get(CustomRunner, custom_id)
    if custom is not None:
        session.delete(custom)
        session.commit()
    return RedirectResponse("/runners", status_code=303)


def _profile_or_400(session: Session, raw: str) -> int | None:
    if not raw.strip():
        return None
    try:
        hpid = int(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Bad header_profile_id")
    if session.get(HeaderProfile, hpid) is None:
        raise HTTPException(status_code=400, detail="Unknown header profile")
    return hpid


@app.get("/headers", response_class=HTMLResponse)
def headers_view(request: Request, session: Session = Depends(get_session)):
    profiles = session.exec(select(HeaderProfile).order_by(HeaderProfile.name)).all()
    jobs = session.exec(
        select(ScanJob).where(ScanJob.header_profile_id != None).order_by(ScanJob.id)  # noqa: E711
    ).all()
    usage: dict[int, list] = {}
    for job in jobs:
        usage.setdefault(job.header_profile_id, []).append(job)
    return templates.TemplateResponse(
        request,
        "headers.html",
        _ctx(profiles=profiles, families=headers_gen.BUILDERS, usage=usage),
    )


@app.post("/headers")
def create_header_profile(
    name: str = Form(...),
    family: str = Form("random"),
    custom: str = Form(""),
    proxy: str = Form(""),
    rate_limit: str = Form(""),
    session: Session = Depends(get_session),
):
    profile_name = name.strip()
    if not profile_name:
        raise HTTPException(status_code=400, detail="Name is required")
    try:
        used_family, headers = headers_gen.build_headers(family.strip() or "random")
        custom_headers = headers_gen.parse_custom_headers(custom)
        headers = headers_gen.merge_headers(headers, custom_headers)
        rate = float(rate_limit) if rate_limit.strip() else 0.0
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    profile = HeaderProfile(
        name=profile_name,
        family=used_family,
        user_agent=headers_gen.user_agent_of(headers),
        headers=headers,
        proxy=proxy.strip(),
        rate_limit=max(0.0, rate),
    )
    session.add(profile)
    session.commit()
    return RedirectResponse("/headers", status_code=303)


@app.post("/headers/{profile_id}/egress")
def update_header_egress(
    profile_id: int,
    proxy: str = Form(""),
    rate_limit: str = Form(""),
    session: Session = Depends(get_session),
):
    """Set proxy + rate limit hints attached to scan jobs using this profile."""
    profile = session.get(HeaderProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    profile.proxy = proxy.strip()
    try:
        profile.rate_limit = max(0.0, float(rate_limit)) if rate_limit.strip() else 0.0
    except ValueError:
        raise HTTPException(status_code=400, detail="rate_limit must be a number")
    session.add(profile)
    session.commit()
    return RedirectResponse("/headers", status_code=303)


@app.post("/headers/{profile_id}/randomize")
def randomize_header_profile(profile_id: int, session: Session = Depends(get_session)):
    profile = session.get(HeaderProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    family = profile.family if profile.family in headers_gen.BUILDERS else "random"
    used_family, headers = headers_gen.build_headers(family)
    custom = {k: v for k, v in (profile.headers or {}).items()
              if k.lower() not in {h.lower() for h in headers}}
    headers = headers_gen.merge_headers(headers, custom)
    profile.family = used_family
    profile.user_agent = headers_gen.user_agent_of(headers)
    profile.headers = headers
    session.add(profile)
    session.commit()
    return RedirectResponse("/headers", status_code=303)


@app.post("/headers/{profile_id}/delete")
def delete_header_profile(profile_id: int, session: Session = Depends(get_session)):
    profile = session.get(HeaderProfile, profile_id)
    if profile is not None:
        session.delete(profile)
        session.commit()
    return RedirectResponse("/headers", status_code=303)


@app.post("/entities/{entity_id}/assign")
def assign_entity(
    entity_id: int,
    program_id: str = Form(""),
    target_id: str = Form(""),
    session: Session = Depends(get_session),
):
    entity = session.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    entity.program_id = int(program_id) if program_id.strip() else None
    entity.target_id = int(target_id) if target_id.strip() else None
    session.add(entity)
    session.commit()
    back = f"/pastes/{entity.paste_id}" if entity.paste_id else "/inbox"
    return RedirectResponse(back, status_code=303)


FILTER_KEYS = ("type", "scope", "program", "target", "value", "tag", "verdict")


def parse_entity_filter(q: str):
    """Split a Wireshark-style query into key:value filters + free text.

    Supported keys: type:<entity type>, scope:<in|out|unknown>,
    program:<id or name fragment>, target:<id or name fragment>,
    value:<substring>, tag:<tag>, verdict:<none|confirmed|needs-review|false-positive>.
    Everything else is AND-matched against the value.
    """
    parsed = {"type": None, "scope": None, "program": None, "target": None,
              "value": None, "tag": None, "verdict": None, "text": []}
    for token in (q or "").split():
        if ":" in token:
            key, _, val = token.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key in FILTER_KEYS and val:
                if parsed.get(key) is None:
                    parsed[key] = val
                elif key == "text":
                    parsed["text"].append(token)
                else:
                    parsed["text"].append(token)
                continue
        parsed["text"].append(token)
    return parsed


@app.get("/entities", response_class=HTMLResponse)
def entity_explorer(
    request: Request,
    q: str = "",
    type: str = "",  # noqa: A002
    program_id: str = "",
    verdict: str = "",
    page: int = 1,
    show_ignored: str = "",
    session: Session = Depends(get_session),
):
    stmt = select(Entity).order_by(Entity.type, Entity.value)
    want_ignored = show_ignored.strip().lower() in ("1", "true", "yes", "on")
    if not want_ignored:
        stmt = stmt.where(Entity.ignored == False)  # noqa: E712
    filt = parse_entity_filter(q)
    eff_type = type.strip() or (filt["type"] or "")
    if eff_type:
        stmt = stmt.where(Entity.type == eff_type)
    scope = (filt["scope"] or "").lower()
    if scope in ("in", "out", "unknown"):
        stmt = stmt.where(Entity.scope_status == scope)
    eff_verdict = verdict.strip().lower() or (filt["verdict"] or "").lower()
    if eff_verdict in ENTITY_VERDICTS:
        stmt = stmt.where(Entity.verdict == eff_verdict)
    eff_program = program_id.strip() or (filt["program"] or "")
    if eff_program:
        if eff_program.isdigit():
            stmt = stmt.where(Entity.program_id == int(eff_program))
        else:
            pids = session.exec(
                select(Program.id).where(Program.name.ilike(f"%{eff_program}%"))
            ).all()
            stmt = stmt.where(Entity.program_id.in_(pids) if pids else False)
    target_tok = filt["target"] or ""
    if target_tok:
        if target_tok.isdigit():
            stmt = stmt.where(Entity.target_id == int(target_tok))
        else:
            tids = session.exec(
                select(Target.id).where(Target.name.ilike(f"%{target_tok}%"))
            ).all()
            stmt = stmt.where(Entity.target_id.in_(tids) if tids else False)
    if filt["value"]:
        stmt = stmt.where(Entity.value.ilike(f"%{filt['value']}%"))
    if filt["tag"]:
        stmt = stmt.where(cast(Entity.tags, SAText).like(f'%"{filt["tag"].lower()}"%'))
    if filt["verdict"] and filt["verdict"].lower() in ENTITY_VERDICTS:
        stmt = stmt.where(Entity.verdict == filt["verdict"].lower())
    for token in filt["text"]:
        stmt = stmt.where(Entity.value.ilike(f"%{token}%"))
    total = session.exec(
        select(func.count()).select_from(stmt.subquery())
    ).one()
    per_page = 200
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    entities = session.exec(stmt.offset((page - 1) * per_page).limit(per_page)).all()
    params = {"q": q, "type": type, "program_id": program_id, "verdict": verdict}
    if want_ignored:
        params["show_ignored"] = "1"
    qs = "&".join(f"{k}={quote(v)}" for k, v in params.items() if v)
    return templates.TemplateResponse(
        request,
        "entities.html",
        _ctx(
            groups=reporting.group_entities(entities),
            total=total,
            q=q,
            selected_type=type,
            selected_program=program_id,
            selected_verdict=verdict,
            verdicts=ENTITY_VERDICTS,
            types=TYPE_CHOICES,
            programs=_programs(session),
            page=page,
            pages=pages,
            per_page=per_page,
            qs=qs,
            back=request.url,
            show_ignored=want_ignored,
            ignored_total=session.exec(
                select(func.count()).select_from(Entity).where(Entity.ignored == True)  # noqa: E712
            ).one(),
        ),
    )


@app.get("/reports/{program_id}/md", response_class=PlainTextResponse)
def report_md(program_id: int, request: Request, session: Session = Depends(get_session)):
    text = reporting.to_markdown(
        session,
        program_id,
        mask=not _reveal(request),
        include_triaged=_include_triaged(request),
    )
    if not text:
        raise HTTPException(status_code=404, detail="Program not found")
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}.md"'},
    )


@app.get("/reports/{program_id}/json")
def report_json(program_id: int, request: Request, session: Session = Depends(get_session)):
    data = reporting.to_dict(
        session,
        program_id,
        mask=not _reveal(request),
        include_triaged=_include_triaged(request),
    )
    if not data:
        raise HTTPException(status_code=404, detail="Program not found")
    return JSONResponse(
        data,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}.json"'},
    )


@app.get("/reports/{program_id}/html", response_class=HTMLResponse)
def report_html(program_id: int, request: Request, session: Session = Depends(get_session)):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    reveal = request.query_params.get("reveal") == "1"
    include_triaged = _include_triaged(request)
    _, targets, entities, relationships, findings = reporting.collect(session, program_id)
    findings = reporting.filter_findings(findings, include_triaged)
    if not reveal:
        masked = []
        for e in entities:
            c = Entity.model_validate(e.model_dump())
            c.value = reporting.mask_value(e.type, e.value)
            masked.append(c)
        entities = masked
    summary = {
        "total_findings": len(findings),
        "severity_counts": reporting.severity_counts(findings),
        "verified_cves": sum(
            1 for finding in findings
            if reporting.finding_is_verified(finding) and "cve" in (finding.tags or [])
        ),
        "unverified_cves": 0,
        "endpoints": sum(1 for e in entities if e.type in {"endpoint", "url", "path"}),
        "subdomains": sum(1 for e in entities if e.type == "subdomain"),
        "open_ports": sum(1 for e in entities if e.type == "port"),
        "technologies": sum(1 for e in entities if e.type == "tech"),
        "missing_headers": sum(
            1 for finding in findings if "security-header" in (finding.tags or [])
        ),
        "risk_score": history.compute_risk(findings)[0],
        "risk_level": history.compute_risk(findings)[1],
    }
    return templates.TemplateResponse(
        request,
        "report.html",
        _ctx(
            program=program,
            targets=targets,
            groups=reporting.group_entities(entities),
            relationships=relationships,
            findings=findings,
            summary=summary,
            highlights=reporting.highlights(findings),
            include_triaged=include_triaged,
            masked=not reveal,
        ),
    )


def _reveal(request: Request) -> bool:
    return request.query_params.get("reveal") == "1"


def _include_triaged(request: Request) -> bool:
    return request.query_params.get("include_triaged") == "1"


def _program_pdf_payload(
    session: Session, program_id: int, include_triaged: bool
) -> tuple[Program, dict, dict, list[dict]] | None:
    program = session.get(Program, program_id)
    if program is None:
        return None
    _, targets, entities, _, findings = reporting.collect(session, program_id)
    findings = reporting.filter_findings(findings, include_triaged)
    risk_score, risk_level = history.compute_risk(findings)
    summary = {
        "total_findings": len(findings),
        "severity_counts": reporting.severity_counts(findings),
        "verified_cves": sum(1 for finding in findings if reporting.finding_is_verified(finding)),
        "unverified_cves": 0,
        "endpoints": sum(1 for e in entities if e.type in {"endpoint", "url", "path"}),
        "subdomains": sum(1 for e in entities if e.type == "subdomain"),
        "open_ports": sum(1 for e in entities if e.type == "port"),
        "technologies": sum(1 for e in entities if e.type == "tech"),
        "missing_headers": sum(
            1 for finding in findings if "security-header" in (finding.tags or [])
        ),
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
    highlights = {
        "technologies": sorted({e.value for e in entities if e.type == "tech"})[:100],
        "cdn_waf": [],
        "security_headers_present": [],
        "security_headers_missing": [],
        "resolved_ips": sorted({e.value for e in entities if e.type == "ip"})[:100],
        "hostnames": sorted(
            {e.value for e in entities if e.type in {"domain", "subdomain"}}
        )[:100],
        "subdomains": sorted({e.value for e in entities if e.type == "subdomain"})[:200],
        "open_ports": {
            f"{e.meta.get('port') or e.value}/tcp": {
                "service": e.meta.get("service"),
                "version": e.meta.get("version"),
            }
            for e in entities
            if e.type == "port"
        },
        "discovered_endpoints": sorted(
            {e.value for e in entities if e.type in {"endpoint", "url", "path"}}
        )[:100],
    }
    payload = [history.serialize_finding(finding) for finding in findings]
    return program, summary, highlights, payload


@app.get("/reports/{program_id}/pdf")
def report_pdf(program_id: int, request: Request, session: Session = Depends(get_session)):
    built = _program_pdf_payload(session, program_id, _include_triaged(request))
    if built is None:
        raise HTTPException(status_code=404, detail="Program not found")
    program, summary, highlights, findings = built
    content = pdf_export.generate_report_pdf(
        program_name=program.name,
        target_name=program.name,
        target_url="",
        summary=summary,
        highlights=highlights,
        findings=findings,
    )
    filename = pdf_export.report_filename(program.name, None, "pdf")
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/jobs/{job_id}/report.pdf")
def job_report_pdf(job_id: int, request: Request, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    snapshot = history.ensure_snapshot(session, job)
    if snapshot is None or snapshot.status != "ready":
        raise HTTPException(status_code=409, detail="Snapshot is not ready for this job")
    data = snapshot.data or {}
    include_triaged = _include_triaged(request)
    findings = [
        item
        for item in (data.get("findings") or {}).values()
        if include_triaged or not item.get("is_false_positive")
    ]
    summary = {
        "total_findings": len(findings),
        "severity_counts": data.get("severity_counts") or {},
        "verified_cves": data.get("verified_cves") or 0,
        "unverified_cves": data.get("unverified_cves") or 0,
        "endpoints": len(data.get("endpoints") or []),
        "subdomains": len(data.get("subdomains") or []),
        "open_ports": len(data.get("ports") or {}),
        "technologies": len(data.get("technologies") or []),
        "missing_headers": len(data.get("security_headers_missing") or []),
        "risk_score": data.get("risk_score") or 0,
        "risk_level": data.get("risk_level") or "minimal",
    }
    highlights = {
        "technologies": data.get("technologies") or [],
        "cdn_waf": data.get("cdn_waf") or [],
        "security_headers_present": data.get("security_headers_present") or [],
        "security_headers_missing": data.get("security_headers_missing") or [],
        "resolved_ips": data.get("resolved_ips") or [],
        "hostnames": data.get("hostnames") or [],
        "subdomains": data.get("subdomains") or [],
        "open_ports": data.get("ports") or {},
        "discovered_endpoints": data.get("endpoints") or [],
    }
    program = session.get(Program, job.program_id) if job.program_id else None
    content = pdf_export.generate_report_pdf(
        program_name=program.name if program else "Breadcrumb",
        target_name=data.get("target_name") or job.target,
        target_url=data.get("target_url") or job.target,
        scan_id=job.id,
        status=job.status,
        created_at=job.created_at,
        completed_at=job.finished_at,
        summary=summary,
        highlights=highlights,
        phases=data.get("phases") or [],
        findings=findings,
    )
    filename = pdf_export.report_filename(job.target, job.id, "pdf")
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/reports/{program_id}/csv", response_class=PlainTextResponse)
def report_csv(program_id: int, request: Request, session: Session = Depends(get_session)):
    text = reporting.to_csv(session, program_id, mask=not _reveal(request))
    if not text:
        raise HTTPException(status_code=404, detail="Program not found")
    return PlainTextResponse(
        text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}.csv"'},
    )


@app.get("/reports/{program_id}/targets.txt", response_class=PlainTextResponse)
def report_targets(program_id: int, session: Session = Depends(get_session)):
    text = reporting.targets_txt(session, program_id)
    if session.get(Program, program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}-targets.txt"'},
    )


@app.get("/reports/{program_id}/h1", response_class=PlainTextResponse)
def report_hackerone(
    program_id: int, request: Request, session: Session = Depends(get_session)
):
    text = reporting.to_hackerone(
        session, program_id, include_triaged=_include_triaged(request)
    )
    if not text:
        raise HTTPException(status_code=404, detail="Program not found")
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}-h1.md"'},
    )


@app.get("/reports/{program_id}/sarif")
def report_sarif(program_id: int, request: Request, session: Session = Depends(get_session)):
    """SARIF 2.1.0 for CI/SAST dashboards (e.g. GitHub code scanning upload)."""
    data = reporting.to_sarif(
        session,
        program_id,
        mask=not _reveal(request),
        include_triaged=_include_triaged(request),
    )
    if not data:
        raise HTTPException(status_code=404, detail="Program not found")
    return JSONResponse(
        data,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}.sarif"'},
    )


@app.get("/api/analyze")
def api_analyze(text: str = ""):
    entities, relationships, parsers, errors = analyze(text)
    return {
        "parsers": parsers,
        "errors": errors,
        "warning": "no entities detected" if not entities else "",
        "entities": [
            {"type": e.type, "value": e.value, "confidence": e.confidence, "meta": e.meta}
            for e in entities
        ],
        "relationships": [
            {"src": r.src_value, "rel": r.rel_type, "dst": r.dst_value} for r in relationships
        ],
    }


def _settings_context(config, test_result=None, notify_test=None):
    return _ctx(
        config=config,
        notify_config=notify.load_config(),
        notify_targets=notify.targets(notify.load_config()),
        severities=notify.SEVERITIES,
        task_classes=llm.TASK_CLASSES,
        task_labels=llm.TASK_LABELS,
        test_result=test_result,
        notify_test=notify_test,
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_view(request: Request):
    return templates.TemplateResponse(
        request, "settings.html", _settings_context(llm.load_config())
    )


@app.post("/settings")
async def save_settings(request: Request):
    form = await request.form()
    config = llm.load_config()

    providers = []
    index = 0
    while f"provider_{index}_id" in form:
        base_url = (form.get(f"provider_{index}_base_url") or "").strip()
        providers.append(
            {
                "id": (form.get(f"provider_{index}_id") or "").strip(),
                "label": (form.get(f"provider_{index}_label") or "").strip(),
                "base_url": base_url,
                "api_key": (form.get(f"provider_{index}_api_key") or "").strip(),
                "enabled": form.get(f"provider_{index}_enabled") == "on",
            }
        )
        index += 1
    if providers:
        config["providers"] = providers

    active = (form.get("active_provider") or "").strip()
    if active:
        config["active_provider"] = active
    config["autonomy"] = (form.get("autonomy") or "suggest").strip()
    config["cloud_opt_in"] = form.get("cloud_opt_in") == "on"
    config["routing"] = {
        task: (form.get(f"route_{task}") or "").strip() for task in llm.TASK_CLASSES
    }
    llm.save_config(config)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/test", response_class=HTMLResponse)
async def test_settings(request: Request):
    form = await request.form()
    config = llm.load_config()
    provider = {
        "base_url": (form.get("test_base_url") or "").strip(),
        "api_key": form.get("test_api_key") or "",
    }
    model = (form.get("test_model") or "").strip()
    result = llm.test_connection(provider, model or None)
    return templates.TemplateResponse(request, "settings.html", _settings_context(config, result))


@app.post("/settings/notify")
async def save_notify_settings(request: Request):
    form = await request.form()
    config = notify.load_config()
    config.update(
        {
            "enabled": form.get("notify_enabled") == "on",
            "on_new_findings": form.get("on_new_findings") == "on",
            "on_scope_changes": form.get("on_scope_changes") == "on",
            "min_severity": (form.get("min_severity") or "high").strip(),
            "discord_url": (form.get("discord_url") or "").strip(),
            "slack_url": (form.get("slack_url") or "").strip(),
            "telegram_token": (form.get("telegram_token") or "").strip(),
            "telegram_chat": (form.get("telegram_chat") or "").strip(),
            "webhook_url": (form.get("webhook_url") or "").strip(),
        }
    )
    notify.save_config(config)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/notify/test", response_class=HTMLResponse)
async def test_notify_settings(request: Request):
    form = await request.form()
    config = notify.load_config()
    config.update(
        {
            "enabled": True,
            "discord_url": (form.get("discord_url") or config.get("discord_url") or "").strip(),
            "slack_url": (form.get("slack_url") or config.get("slack_url") or "").strip(),
            "telegram_token": (form.get("telegram_token") or config.get("telegram_token") or "").strip(),
            "telegram_chat": (form.get("telegram_chat") or config.get("telegram_chat") or "").strip(),
            "webhook_url": (form.get("webhook_url") or config.get("webhook_url") or "").strip(),
        }
    )
    result = notify.test(config)
    return templates.TemplateResponse(
        request, "settings.html", _settings_context(llm.load_config(), None, result)
    )


@app.get("/api/llm/models")
def api_llm_models(provider_id: str = "", detailed: int = 0):
    config = llm.load_config()
    provider = llm.get_provider(config, provider_id or None)
    if provider is None:
        return JSONResponse({"ok": False, "error": "no provider"}, status_code=404)
    if detailed:
        return JSONResponse(llm.list_models_detailed(provider))
    try:
        return {"ok": True, "provider": provider.get("id"), "models": llm.list_models(provider)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def _api_csrf(request: Request) -> None:
    """JSON endpoints do not pass through the form CSRF check, so check here."""
    supplied = request.headers.get("x-csrf-token", "")
    token = getattr(request.state, "csrf_token", "")
    if not token or not supplied or not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


@app.post("/api/llm/test")
def api_llm_test(request: Request, payload: dict = Body(...)):
    _api_csrf(request)
    config = llm.load_config()
    provider = llm.get_provider(config, (payload.get("provider") or "").strip() or None)
    if provider is None:
        raise HTTPException(status_code=404, detail="provider not found")
    model = (payload.get("model") or "").strip()
    if not model:
        raise HTTPException(status_code=400, detail="model required")
    try:
        max_tokens = int(payload.get("max_tokens") or 64)
    except (TypeError, ValueError):
        max_tokens = 64
    try:
        timeout = float(payload.get("timeout") or 180)
    except (TypeError, ValueError):
        timeout = 180.0
    timeout = min(600.0, max(30.0, timeout))
    result = llm.test_model(
        provider,
        model,
        max_tokens=min(512, max(8, max_tokens)),
        timeout=timeout,
        auto_fit=bool(payload.get("auto_fit")),
    )
    return JSONResponse(result)


@app.post("/api/llm/routes")
def api_llm_routes(request: Request, payload: dict = Body(...)):
    _api_csrf(request)
    config = llm.load_config()
    task = str(payload.get("task") or "").strip()
    model = str(payload.get("model") or "").strip()
    if not model:
        raise HTTPException(status_code=400, detail="model required")
    if task == "all":
        tasks = list(llm.TASK_CLASSES)
    elif task in llm.TASK_CLASSES:
        tasks = [task]
    else:
        raise HTTPException(status_code=400, detail="unknown task route")
    routing = dict(config.get("routing") or {})
    for name in tasks:
        routing[name] = model
    config["routing"] = routing
    llm.save_config(config)
    return {"ok": True, "routing": routing, "tasks": tasks}


@app.post("/pastes/{paste_id}/analyze")
def analyze_paste_route(paste_id: int, session: Session = Depends(get_session)):
    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Paste not found")
    entities = session.exec(select(Entity).where(Entity.paste_id == paste_id)).all()
    pairs = [(e.type, e.value) for e in entities]
    result = ai.analyze_paste(paste.raw or "", pairs)
    paste.ai_analysis = result
    paste.ai_model = result.get("model")
    paste.ai_at = datetime.now(timezone.utc)
    session.add(paste)
    session.commit()
    return RedirectResponse(f"/pastes/{paste_id}?tab=ai&done=1", status_code=303)


@app.post("/programs/{program_id}/analyze")
def analyze_program_route(program_id: int, session: Session = Depends(get_session)):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    entities = session.exec(select(Entity).where(Entity.program_id == program_id)).all()
    findings = session.exec(select(Finding).where(Finding.program_id == program_id)).all()
    groups = reporting.group_entities(entities)
    result = ai.summarize_program(program, groups, findings)
    program.ai_summary = result.get("text") or f"[error] {result.get('error')}"
    program.ai_model = result.get("model")
    program.ai_at = datetime.now(timezone.utc)
    session.add(program)
    session.commit()
    return RedirectResponse(f"/programs/{program_id}?tab=ai&done=1", status_code=303)


@app.post("/programs/{program_id}/findings")
def create_finding(
    program_id: int,
    title: str = Form(...),
    severity: str = Form("info"),
    target_id: str = Form(""),
    description: str = Form(""),
    tags: str = Form(""),
    session: Session = Depends(get_session),
):
    finding = Finding(
        program_id=program_id,
        target_id=int(target_id) if target_id.strip() else None,
        title=title.strip(),
        severity=severity.strip() or "info",
        description=description.strip() or None,
        tags=parse_tags(tags),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    program = session.get(Program, program_id)
    result = notify.notify_finding(notify.load_config(), finding, program.name if program else "")
    dest = f"/programs/{program_id}?tab=findings"
    if result.get("sent"):
        dest += "&msg=" + quote(f"notified {len(result['results'])} channel(s)")
    return RedirectResponse(dest, status_code=303)


@app.post("/findings/{finding_id}/annotate")
def annotate_finding(
    finding_id: int,
    tags: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    """Analyst triage metadata on a finding (tags + private note)."""
    finding = session.get(Finding, finding_id)
    back = "/"
    if finding is not None:
        finding.tags = parse_tags(tags)
        finding.notes = notes.strip() or None
        finding.updated_at = datetime.now(timezone.utc)
        session.add(finding)
        session.commit()
        back = f"/programs/{finding.program_id}?tab=findings"
    return RedirectResponse(back, status_code=303)


FINDING_STATUSES = ("open", "in-progress", "resolved", "wont-fix")


@app.post("/findings/{finding_id}/triage")
def set_finding_triage(
    finding_id: int,
    triage_status: str = Form(...),
    triage_note: str = Form(""),
    session: Session = Depends(get_session),
):
    """One primary triage control: Open / Acknowledged / False positive."""
    finding = session.get(Finding, finding_id)
    back = "/"
    if finding is not None:
        try:
            triage.apply_triage(finding, triage_status, triage_note)
        except ValueError:
            pass
        else:
            session.add(finding)
            session.commit()
        back = f"/programs/{finding.program_id}?tab=findings"
    return RedirectResponse(back, status_code=303)


@app.post("/findings/{finding_id}/status")
def set_finding_status(
    finding_id: int,
    status: str = Form(...),
    session: Session = Depends(get_session),
):
    finding = session.get(Finding, finding_id)
    back = "/"
    if finding is not None:
        status = status.strip() or "open"
        if status in FINDING_STATUSES:
            finding.status = status
            session.add(finding)
            session.commit()
        back = f"/programs/{finding.program_id}?tab=findings"
    return RedirectResponse(back, status_code=303)


@app.post("/findings/{finding_id}/delete")
def delete_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    back = "/"
    if finding is not None:
        back = f"/programs/{finding.program_id}?tab=findings"
        session.delete(finding)
        session.commit()
    return RedirectResponse(back, status_code=303)


@app.get("/api/search")
def api_search(q: str = "", session: Session = Depends(get_session)):
    query = q.strip()
    results = []
    if query:
        like = f"%{query}%"
        for program in session.exec(select(Program).where(Program.name.ilike(like)).limit(5)).all():
            results.append({"type": "program", "label": program.name, "href": f"/programs/{program.id}"})
        for entity in session.exec(
            select(Entity).where(Entity.value.ilike(like)).order_by(Entity.type).limit(25)
        ).all():
            results.append(
                {
                    "type": entity.type,
                    "label": entity.value,
                    "href": f"/entities?q={quote(entity.value)}",
                    "sub": f"program {entity.program_id}" if entity.program_id else "unassigned",
                }
            )
    else:
        for program in session.exec(select(Program).order_by(Program.name).limit(10)).all():
            results.append({"type": "program", "label": program.name, "href": f"/programs/{program.id}"})
        results.append({"type": "action", "label": "Go to Inbox", "href": "/inbox"})
        results.append({"type": "action", "label": "Open Settings", "href": "/settings"})
    return {"query": query, "results": results}


# ---------------- JSON API v1 (automation: pipe tool output straight in) ----------------

@app.post("/api/v1/pastes", status_code=201)
async def api_create_paste(request: Request, session: Session = Depends(get_session)):
    """Ingest raw tool output as JSON or raw bytes.

    curl -X POST /api/v1/pastes -H 'Content-Type: application/json' \\
      -d '{"text": "...", "program_id": 1}'
    subfinder -d target.com -silent | curl -X POST /api/v1/pastes --data-binary @-
    """
    content_type = request.headers.get("content-type", "")
    program_id = target_id = None
    source = "api"
    command = None
    source_meta: dict = {}
    max_entities = MAX_ENTITIES_PER_PASTE
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid JSON")
        text = payload.get("text", "") or ""
        program_id = payload.get("program_id")
        target_id = payload.get("target_id")
        source = payload.get("source", "api") or "api"
        command = payload.get("command") or None
        source_meta = payload.get("source_meta") or {}
        try:
            max_entities = max(1, int(payload.get("max_entities") or MAX_ENTITIES_PER_PASTE))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="max_entities must be an integer")
    else:
        raw = await request.body()
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Body too large (max 5 MB)")
        text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        raise HTTPException(status_code=400, detail="Empty body")
    paste = _ingest(
        session,
        text,
        program_id,
        target_id,
        source,
        command=command,
        source_meta=source_meta if isinstance(source_meta, dict) else {},
        max_entities=max_entities,
    )
    report = ingest_mod.import_report(session, paste)
    return {
        "paste_id": paste.id,
        "entities": report["entities"],
        "parsers": paste.parsers or [],
        "errors": paste.parse_errors or [],
        "warning": report["warning"],
        "findings": report["findings"],
        "completeness": report["completeness"],
        "skipped_rows": report["skipped_rows"],
        "parser_versions": report["parser_versions"],
        "report_url": f"/api/v1/pastes/{paste.id}/report",
        "manifest_url": f"/api/v1/pastes/{paste.id}/manifest",
    }


@app.get("/api/v1/pastes/{paste_id}/report")
def api_import_report(paste_id: int, session: Session = Depends(get_session)):
    """The machine-readable import report, including why a capture was empty."""
    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return JSONResponse(ingest_mod.import_report(session, paste))


@app.get("/api/v1/pastes/{paste_id}/manifest")
def api_manifest(
    paste_id: int,
    reveal: bool = False,
    session: Session = Depends(get_session),
):
    """Evidence Manifest v2 (redacted by default)."""
    from .manifest import build_manifest

    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    manifest = build_manifest(session, paste, redact=not reveal)
    return JSONResponse(
        manifest,
        headers={
            "Content-Disposition": f'attachment; filename="breadcrumb-{paste_id}-manifest.json"'
        },
    )


@app.get("/pastes/{paste_id}/manifest.json")
def manifest_json_view(
    paste_id: int,
    reveal: bool = False,
    session: Session = Depends(get_session),
):
    from .manifest import build_manifest, manifest_json

    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return PlainTextResponse(
        manifest_json(build_manifest(session, paste, redact=not reveal)),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="breadcrumb-{paste_id}-manifest.json"'
        },
    )


@app.get("/pastes/{paste_id}/manifest.md")
def manifest_md_view(
    paste_id: int,
    reveal: bool = False,
    session: Session = Depends(get_session),
):
    from .manifest import build_manifest, manifest_markdown

    paste = session.get(Paste, paste_id)
    if paste is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return PlainTextResponse(
        manifest_markdown(build_manifest(session, paste, redact=not reveal)),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="breadcrumb-{paste_id}-manifest.md"'
        },
    )


@app.get("/api/v1/doctor")
def api_doctor():
    """Installation/database/parser diagnostics for scripts and support."""
    from .doctor import run_checks

    report = run_checks()
    return JSONResponse(report, status_code=200 if report.get("ok") else 503)


@app.get("/api/v1/entities")
def api_entities(
    program_id: int | None = None,
    type: str | None = None,  # noqa: A002
    q: str = "",
    limit: int = 1000,
    offset: int = 0,
    session: Session = Depends(get_session),
):
    stmt = select(Entity).where(Entity.ignored == False).order_by(Entity.id)  # noqa: E712
    if program_id is not None:
        stmt = stmt.where(Entity.program_id == program_id)
    if type:
        stmt = stmt.where(Entity.type == type)
    if q.strip():
        stmt = stmt.where(Entity.value.ilike(f"%{q.strip()}%"))
    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    page_size = max(1, min(limit, 5000))
    page_offset = max(0, offset)
    rows = session.exec(stmt.offset(page_offset).limit(page_size)).all()
    next_offset = page_offset + len(rows)
    return {
        "count": len(rows),
        "total": int(total or 0),
        "offset": page_offset,
        "limit": page_size,
        "next_offset": next_offset if next_offset < int(total or 0) else None,
        "entities": [
            {"id": e.id, "type": e.type, "value": e.value, "parser": e.parser,
             "scope_status": e.scope_status, "program_id": e.program_id,
             "target_id": e.target_id, "paste_id": e.paste_id, "meta": e.meta}
            for e in rows
        ],
    }


@app.post("/api/v1/entities/bulk")
def api_entities_bulk(payload: dict = Body(...), session: Session = Depends(get_session)):
    """Bulk triage for CI/scripts: ignore, unignore, delete, tag, or set verdict."""
    action = str(payload.get("action", "") or "").lower()
    ids = payload.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list")
    if action not in ("ignore", "unignore", "delete", "tag", "untag", "verdict"):
        raise HTTPException(status_code=400, detail="Bad action")
    tag = str(payload.get("tag", "") or "").strip().lower()
    verdict = str(payload.get("verdict", "") or "").strip().lower()
    if action in ("tag", "untag") and not tag:
        raise HTTPException(status_code=400, detail="tag required")
    if action == "verdict" and verdict not in ENTITY_VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {ENTITY_VERDICTS}")

    changed = 0
    for entity in session.exec(select(Entity).where(Entity.id.in_([int(i) for i in ids]))).all():
        if action == "ignore":
            entity.ignored = True
        elif action == "unignore":
            entity.ignored = False
        elif action == "delete":
            session.delete(entity)
            changed += 1
            continue
        elif action == "tag":
            if tag and tag not in (entity.tags or []):
                entity.tags = (entity.tags or []) + [tag]
        elif action == "untag":
            entity.tags = [t for t in (entity.tags or []) if t != tag]
        elif action == "verdict":
            entity.verdict = verdict
        session.add(entity)
        changed += 1
    session.commit()
    return {"action": action, "changed": changed}


@app.get("/api/v1/findings")
def api_findings(
    program_id: int | None = None,
    min_severity: str = "",
    session: Session = Depends(get_session),
):
    stmt = select(Finding).order_by(Finding.id)
    if program_id is not None:
        stmt = stmt.where(Finding.program_id == program_id)
    rows = session.exec(stmt).all()
    floor = notify.SEVERITY_RANK.get(min_severity.lower()) if min_severity else None
    out = []
    for f in rows:
        if floor is not None and notify.SEVERITY_RANK.get(f.severity, 0) < floor:
            continue
        out.append({
            "id": f.id, "program_id": f.program_id, "title": f.title,
            "severity": f.severity, "status": f.status, "cvss": f.cvss,
            "tags": f.tags or [], "target_id": f.target_id,
        })
    return {"count": len(out), "findings": out}


@app.get("/api/v1/gate")
def api_gate(
    program_id: int | None = None,
    max_severity: str = "high",
    session: Session = Depends(get_session),
):
    """CI gate: fail if any open finding is at/above ``max_severity``.

    curl -f /api/v1/gate?program_id=1&max_severity=high
    """
    threshold = notify.SEVERITY_RANK.get(max_severity.lower(), 3)
    stmt = select(Finding).where(Finding.status != "wont-fix")
    if program_id is not None:
        stmt = stmt.where(Finding.program_id == program_id)
    hits = []
    for f in session.exec(stmt).all():
        if f.status in ("resolved",):
            continue
        if notify.SEVERITY_RANK.get(f.severity, 0) >= threshold:
            hits.append({"id": f.id, "title": f.title, "severity": f.severity, "status": f.status})
    passed = not hits
    return JSONResponse(
        {"pass": passed, "threshold": max_severity, "blocking": hits},
        status_code=200 if passed else 409,
    )


@app.get("/api/v1/programs")
def api_programs(session: Session = Depends(get_session)):
    out = []
    for program in session.exec(select(Program).order_by(Program.name)).all():
        n = session.exec(
            select(func.count()).select_from(Entity).where(Entity.program_id == program.id)
        ).one()
        out.append({"id": program.id, "name": program.name,
                    "platform": program.platform, "entities": n})
    return {"programs": out}


def _job_dict(job: ScanJob) -> dict:
    return {
        "id": job.id,
        "runner": job.runner,
        "target": job.target,
        "status": job.status,
        "program_id": job.program_id,
        "header_profile_id": job.header_profile_id,
        "params": dict(job.params or {}),
        "priority": job.priority,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "next_run_at": job.next_run_at.isoformat() if job.next_run_at else None,
        "output_paste_id": job.output_paste_id,
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@app.get("/api/v1/jobs")
def api_list_jobs(status: str = "", session: Session = Depends(get_session)):
    stmt = select(ScanJob).order_by(ScanJob.id.desc())
    if status.strip():
        stmt = stmt.where(ScanJob.status == status.strip())
    jobs = session.exec(stmt.limit(200)).all()
    names = {
        p.id: p.name
        for p in session.exec(select(HeaderProfile)).all()
    }
    out = []
    for job in jobs:
        item = _job_dict(job)
        item["header_profile_name"] = names.get(job.header_profile_id)
        out.append(item)
    return {"jobs": out}


@app.get("/api/v1/jobs/{job_id}")
def api_get_job(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    attempts = session.exec(
        select(JobAttempt).where(JobAttempt.job_id == job_id).order_by(JobAttempt.attempt_no)
    ).all()
    phases = session.exec(
        select(ScanPhase).where(ScanPhase.job_id == job_id).order_by(ScanPhase.seq)
    ).all()
    events = session.exec(
        select(JobEvent).where(JobEvent.job_id == job_id).order_by(JobEvent.id).limit(1000)
    ).all()
    data = _job_dict(job)
    data.update(
        {
            "attempts": [
                {
                    "id": a.id,
                    "attempt_no": a.attempt_no,
                    "worker_id": a.worker_id,
                    "status": a.status,
                    "started_at": a.started_at.isoformat() if a.started_at else None,
                    "finished_at": a.finished_at.isoformat() if a.finished_at else None,
                    "error": a.error,
                    "output_paste_id": a.output_paste_id,
                    "stats": a.stats or {},
                }
                for a in attempts
            ],
            "phases": [
                {
                    "id": p.id,
                    "seq": p.seq,
                    "name": p.name,
                    "status": p.status,
                    "started_at": p.started_at.isoformat() if p.started_at else None,
                    "finished_at": p.finished_at.isoformat() if p.finished_at else None,
                    "output_paste_id": p.output_paste_id,
                    "stats": p.stats or {},
                    "error": p.error,
                }
                for p in phases
            ],
            "events": [
                {
                    "id": e.id,
                    "kind": e.kind,
                    "message": e.message,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in events
            ],
        }
    )
    return data


@app.post("/api/v1/jobs", status_code=202)
def api_create_job(payload: dict = Body(...), session: Session = Depends(get_session)):
    runner_id = str(payload.get("runner", "") or "")
    if runners.find_runner(session, runner_id) is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown runner. Known: {[r.id for r in runners.all_runners(session)]}",
        )
    hpid = payload.get("header_profile_id")
    if hpid is not None and session.get(HeaderProfile, int(hpid)) is None:
        raise HTTPException(status_code=400, detail="Unknown header profile")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        raise HTTPException(status_code=400, detail="params must be an object")
    try:
        priority = int(payload.get("priority", 0) or 0)
        max_attempts = int(payload.get("max_attempts", 3) or 3)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="priority/max_attempts must be integers")
    job = ScanJob(
        program_id=payload.get("program_id"),
        runner=runner_id,
        target=str(payload.get("target", "") or ""),
        status="queued",
        header_profile_id=int(hpid) if hpid is not None else None,
        params=dict(params),
        priority=priority,
        max_attempts=max(1, max_attempts),
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    native = runner_id in collector_ids()
    adapter = runner_id in adapter_ids()
    if adapter:
        note = (
            "External tool adapter: run it explicitly with "
            f"POST /api/v1/jobs/{job.id}/run, or set BREADCRUMB_EXTERNAL_TOOLS=1 "
            "for the durable worker to claim adapter jobs. "
        )
    elif native:
        note = (
            "Native collector: claim it with `breadcrumb worker` or POST "
            f"/jobs/{job.id}/run. "
        )
    else:
        note = "External runner: POST output to /api/v1/pastes, then update status. "
    return {
        "job_id": job.id,
        "status": "queued",
        "native": native or adapter,
        "adapter": adapter,
        "note": note + "The executor is off by default.",
    }


@app.post("/api/v1/jobs/{job_id}/cancel")
def api_cancel_job(job_id: int, session: Session = Depends(get_session)):
    outcome = jobs_queue.request_cancel(session, job_id)
    if outcome is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "outcome": outcome}


@app.post("/api/v1/jobs/{job_id}/run", status_code=202)
def api_run_job(job_id: int, session: Session = Depends(get_session)):
    """Start a native collector now (the API twin of the job page button)."""
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    state = _arm_native_job(session, job)
    if state in ("running", "done"):
        raise HTTPException(status_code=409, detail=f"job #{job_id} is {state}")
    _start_native_job(job.id, job.runner)
    return {"job_id": job.id, "runner": job.runner, "status": "started"}


@app.post("/api/v1/jobs/{job_id}/retry")
def api_retry_job(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if _is_imported_job(job):
        raise HTTPException(
            status_code=409,
            detail=(
                "Imported Leadline jobs are historical; queue a new scan "
                "instead of retrying this row."
            ),
        )
    clone = ScanJob(
        program_id=job.program_id,
        runner=job.runner,
        target=job.target,
        status="queued",
        header_profile_id=job.header_profile_id,
        params=dict(job.params or {}),
        priority=int(job.priority or 0),
        max_attempts=int(job.max_attempts or 3),
    )
    session.add(clone)
    session.commit()
    session.refresh(clone)
    return {"job_id": clone.id, "status": "queued", "retry_of": job_id}


def _profile_dict(profile: HeaderProfile) -> dict:
    return {
        "id": profile.id,
        "name": profile.name,
        "family": profile.family,
        "user_agent": profile.user_agent,
        "headers": profile.headers or {},
        "proxy": profile.proxy or "",
        "rate_limit": profile.rate_limit or 0.0,
        "curl": headers_gen.to_curl_args(profile.headers or {}, profile.proxy or ""),
    }


@app.get("/api/v1/headers")
def api_list_headers(session: Session = Depends(get_session)):
    profiles = session.exec(select(HeaderProfile).order_by(HeaderProfile.name)).all()
    return {"profiles": [_profile_dict(p) for p in profiles]}


@app.get("/api/v1/headers/{profile_id}")
def api_get_header(profile_id: int, session: Session = Depends(get_session)):
    profile = session.get(HeaderProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _profile_dict(profile)


@app.post("/api/v1/headers", status_code=201)
def api_create_header(payload: dict = Body(...), session: Session = Depends(get_session)):
    name = str(payload.get("name", "") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    family = str(payload.get("family", "random") or "random")
    try:
        used_family, headers = headers_gen.build_headers(family)
        custom = payload.get("headers") or {}
        if isinstance(custom, str):
            custom = headers_gen.parse_custom_headers(custom)
        if not isinstance(custom, dict):
            raise HTTPException(status_code=400, detail="headers must be an object or 'Name: value' text")
        headers = headers_gen.merge_headers(headers, dict(custom))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    profile = HeaderProfile(
        name=name,
        family=used_family,
        user_agent=headers_gen.user_agent_of(headers),
        headers=headers,
        proxy=str(payload.get("proxy", "") or "").strip(),
        rate_limit=max(0.0, float(payload.get("rate_limit", 0) or 0)),
    )
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return _profile_dict(profile)


@app.post("/api/v1/jobs/{job_id}/status")
def api_job_status(job_id: int, payload: dict = Body(...), session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    status = str(payload.get("status", "") or "")
    if status not in JOB_STATUSES:
        raise HTTPException(status_code=400, detail=f"Bad status (one of {JOB_STATUSES})")
    if (
        status == "done"
        and job.runner in collector_ids()
        and job.output_paste_id is None
    ):
        raise HTTPException(
            status_code=400,
            detail="A native job cannot be done without a linked output capture",
        )
    job.status = status
    if status == "running" and job.started_at is None:
        job.started_at = datetime.now(timezone.utc)
    if payload.get("log"):
        job.log = str(payload["log"])[:20000]
    if status in ("done", "failed", "cancelled"):
        job.finished_at = datetime.now(timezone.utc)
    session.add(job)
    session.commit()
    return {"job_id": job.id, "status": job.status}


@app.get("/api/v1/backup")
def api_backup():
    """Download a consistent SQLite snapshot (WAL-safe, integrity-checked)."""
    from fastapi.responses import FileResponse
    from starlette.background import BackgroundTask

    tmpdir = Path(tempfile.mkdtemp(prefix="breadcrumb-backup-"))
    dest = tmpdir / "breadcrumb.db"
    try:
        backup_database(dest)
    except Exception as exc:  # noqa: BLE001
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Backup failed: {exc}") from exc

    def _cleanup() -> None:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

    return FileResponse(
        path=str(dest),
        filename=f"breadcrumb-backup-{datetime.now(timezone.utc):%Y%m%d}.db",
        media_type="application/x-sqlite3",
        background=BackgroundTask(_cleanup),
    )


@app.post("/backup/restore")
def restore_backup(upload: UploadFile = File(...)):
    """Replace the database from an uploaded backup file (validated first)."""
    raw = upload.file.read(100 * 1024 * 1024 + 1)
    if len(raw) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Backup too large (max 100 MB)")
    tmpdir = Path(tempfile.mkdtemp(prefix="breadcrumb-restore-"))
    source = tmpdir / "upload.db"
    try:
        source.write_bytes(raw)
        try:
            restore_database(source)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except sqlite3.DatabaseError as exc:
            raise HTTPException(status_code=400, detail=f"Not a valid SQLite file: {exc}") from exc
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
    return RedirectResponse("/", status_code=303)


@app.get("/health")
def health(session: Session = Depends(get_session)):
    """Liveness + local queue/schema status for the CLI and the UI banner."""
    state = get_app_state(session)
    now = datetime.now(timezone.utc)

    def _count(*where) -> int:
        return int(
            session.exec(select(func.count()).select_from(ScanJob).where(*where)).one() or 0
        )

    try:
        wal_mode = str(session.connection().exec_driver_sql("PRAGMA journal_mode").scalar() or "")
    except Exception:  # noqa: BLE001
        wal_mode = "unknown"
    last_heartbeat = session.exec(select(func.max(JobAttempt.heartbeat_at))).one()
    return {
        "status": "ok",
        "version": APP_VERSION,
        "schema_version": state.schema_version,
        "expected_schema_version": SCHEMA_VERSION,
        "db_path": str(DB_PATH),
        "wal_mode": wal_mode,
        "maintenance": bool(state.maintenance),
        "maintenance_reason": state.maintenance_reason or "",
        "jobs": {
            "queued": _count(ScanJob.status == "queued"),
            "running": _count(ScanJob.status == "running"),
            "done": _count(ScanJob.status == "done"),
            "failed": _count(ScanJob.status == "failed"),
            "cancelled": _count(ScanJob.status == "cancelled"),
        },
        "expired_leases": _count(
            ScanJob.status == "running",
            ScanJob.lease_expires_at != None,  # noqa: E711
            ScanJob.lease_expires_at < now,
        ),
        "last_worker_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
    }