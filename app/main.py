import hashlib
import re
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Text as SAText
from sqlalchemy import cast
from sqlmodel import Session, func, select

from . import __version__, ai, graph, headers_gen, llm, notify, pipeline as pipeline_mod, reporting, runners
from .attribution import (
    consolidate_entities,
    merge_into_program,
    rebuild_all,
    rebuild_program,
)
from .db import DB_PATH, engine, get_session, init_db
from .models import (
    CustomRunner,
    Entity,
    Finding,
    HeaderProfile,
    Paste,
    Program,
    Relationship,
    RunnerToggle,
    ScanJob,
    Target,
)
from .parsers import analyze, extract_findings
from .takeover import detect_takeovers

APP_VERSION = __version__

BASE = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Breadcrumb", lifespan=lifespan)
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
    except Exception:  # noqa: BLE001  (never let nav break a page)
        request.state.nav_programs = []
        request.state.unassigned_count = 0
    return await call_next(request)

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
    session: Session = Depends(get_session),
):
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    targets = session.exec(
        select(Target).where(Target.program_id == program_id).order_by(Target.name)
    ).all()
    entities = session.exec(
        select(Entity).where(Entity.program_id == program_id).order_by(Entity.type, Entity.value)
    ).all()
    relationships = session.exec(
        select(Relationship).where(Relationship.program_id == program_id)
    ).all()
    entity_by_id = {e.id: e for e in entities}

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
        ),
    )


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


def _persist_findings(
    session: Session, pid: int | None, tid: int | None, findings: list[dict], paste_id: int
) -> int:
    """Create Finding rows from parser/takeover output, de-duplicated.

    Re-importing the same tool output must never spray duplicate findings;
    an existing finding keeps its status/notes but refreshes its timestamp.
    """
    if pid is None or not findings:
        return 0
    targets = session.exec(select(Target).where(Target.program_id == pid)).all()
    tmap = {t.name.strip().lower(): t.id for t in targets}

    def _resolve(host: str) -> int | None:
        if not host:
            return None
        host = host.strip().lower().rstrip(".")
        if host in tmap:
            return tmap[host]
        for name, ident in tmap.items():
            if host == name or host.endswith("." + name):
                return ident
        return None

    created = 0
    now = datetime.now(timezone.utc)
    for item in findings:
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        fingerprint = str(item.get("dedup_key") or f"{title}|{item.get('evidence', '')}")
        existing = session.exec(
            select(Finding).where(Finding.program_id == pid, Finding.fingerprint == fingerprint)
        ).first()
        if existing is not None:
            existing.updated_at = now
            session.add(existing)
            continue
        cvss = item.get("cvss")
        target_id = tid if tid is not None else _resolve(str(item.get("target") or ""))
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        session.add(
            Finding(
                program_id=pid,
                target_id=target_id,
                paste_id=paste_id,
                title=title,
                severity=str(item.get("severity") or "info").lower(),
                cvss=str(cvss) if cvss not in (None, "") else None,
                description=item.get("description") or None,
                evidence=item.get("evidence") or None,
                tags=list(tags),
                source_tool=item.get("parser"),
                fingerprint=fingerprint,
                updated_at=now,
            )
        )
        created += 1
    session.commit()
    return created


def _seal_paste(session: Session, raw: str) -> tuple[str, str, int | None]:
    """Compute (content_sha256, chain_hash, prev_paste_id) for a new capture.

    The chain links each capture to the previous one, so the notebook is a
    tamper-evident log: alter any past capture and its hash breaks. A capture's
    predecessor is recorded explicitly, so deleting a program (and its captures)
    shows up as a chain *gap*, not as tampering.
    """
    content = hashlib.sha256((raw or "").encode("utf-8", errors="replace")).hexdigest()
    prev = session.exec(
        select(Paste).where(Paste.chain_hash != None).order_by(Paste.id.desc()).limit(1)  # noqa: E711
    ).first()
    prev_id = prev.id if prev else None
    prev_chain = (prev.chain_hash if prev and prev.chain_hash else "genesis")
    chain = hashlib.sha256(f"{prev_chain}:{content}".encode("utf-8")).hexdigest()
    return content, chain, prev_id


def _annotate_cross_program(session: Session, pid: int | None, paste_id: int) -> int:
    """Tag this capture's entities that were seen in OTHER programs.

    This is Breadcrumb's memory: a subdomain, port, secret or finding you met
    months ago on another engagement is flagged as already-known, with links
    back. Offline, across every program in the notebook.
    """
    if pid is None:
        return 0
    ents = session.exec(select(Entity).where(Entity.paste_id == paste_id)).all()
    if not ents:
        return 0
    norms = sorted({(e.normalized or "").lower() for e in ents if e.normalized})
    if not norms:
        return 0
    names = {p.id: p.name for p in session.exec(select(Program)).all()}
    found: dict[tuple[str, str], dict[int, str]] = {}
    for i in range(0, len(norms), 400):
        chunk = norms[i:i + 400]
        rows = session.exec(
            select(Entity).where(
                Entity.program_id != None,  # noqa: E711
                Entity.program_id != pid,
                func.lower(Entity.normalized).in_(chunk),
            )
        ).all()
        for r in rows:
            found.setdefault((r.type, (r.normalized or "").lower()), {})[r.program_id] = names.get(
                r.program_id, f"#{r.program_id}"
            )
    if not found:
        return 0
    touched = 0
    for e in ents:
        key = (e.type, (e.normalized or "").lower())
        progs = found.get(key)
        if progs:
            e.cross_programs = [{"id": k, "name": v} for k, v in sorted(progs.items())]
            session.add(e)
            touched += 1
    if touched:
        session.commit()
    return touched


def _ingest(session: Session, text: str, pid: int | None, tid: int | None, source: str) -> Paste:
    """Shared ingest path: form pastes, file uploads, and the JSON API."""
    entities, relationships, parsers, errors = analyze(text)
    if len(entities) > MAX_ENTITIES_PER_PASTE:
        errors = errors + [{
            "parser": "*",
            "error": f"truncated at {MAX_ENTITIES_PER_PASTE} entities ({len(entities)} found)",
        }]
        entities = entities[:MAX_ENTITIES_PER_PASTE]
    content_sha, chain_hash, prev_paste_id = _seal_paste(session, text)
    paste = Paste(
        program_id=pid,
        target_id=tid,
        source=source,
        raw=text,
        parsers=parsers,
        parse_errors=errors,
        tool_guess=parsers[0] if parsers else None,
        content_sha256=content_sha,
        chain_hash=chain_hash,
        prev_paste_id=prev_paste_id,
    )
    session.add(paste)
    session.commit()
    session.refresh(paste)
    for entity in entities:
        session.add(
            Entity(
                paste_id=paste.id,
                program_id=pid,
                target_id=tid,
                type=entity.type,
                value=entity.value,
                normalized=entity.normalized,
                confidence=entity.confidence,
                parser=entity.parser,
                meta=entity.meta,
                provenance=[paste.id],
            )
        )
    for rel in relationships:
        session.add(
            Relationship(
                paste_id=paste.id,
                program_id=pid,
                src_value=rel.src_value,
                src_type=rel.src_type,
                dst_value=rel.dst_value,
                dst_type=rel.dst_type,
                rel_type=rel.rel_type,
                source="parser",
            )
        )
    session.commit()
    consolidate_entities(session, pid)
    if pid:
        rebuild_program(session, pid)
    _persist_findings(session, pid, tid, extract_findings(text) + detect_takeovers(entities), paste.id)
    _annotate_cross_program(session, pid, paste.id)
    return paste


@app.post("/paste")
def create_paste(
    text: str = Form(""),
    program_id: str = Form(""),
    target_id: str = Form(""),
    source: str = Form("manual"),
    upload: UploadFile | None = File(None),
    session: Session = Depends(get_session),
):
    body = text or ""
    label = source
    if upload is not None and upload.filename:
        raw = upload.file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large (max 5 MB)")
        body = (body + "\n" if body else "") + raw.decode("utf-8", errors="replace")
        label = f"file:{upload.filename}"
    if not body.strip():
        return RedirectResponse("/inbox", status_code=303)
    pid = int(program_id) if program_id.strip() else None
    tid = int(target_id) if target_id.strip() else None
    paste = _ingest(session, body, pid, tid, label)
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

    Checks each capture's content hash against its stored seal, and its chain
    link against the recorded predecessor. Captures removed with a deleted
    program are reported as ``gaps`` (not tampering); legacy unsealed captures
    are reported as ``unsealed``.
    """
    pastes = session.exec(select(Paste).order_by(Paste.id)).all()
    by_id = {p.id: p for p in pastes}
    broken, unsealed, gaps = None, 0, 0
    for p in pastes:
        if not p.content_sha256 or not p.chain_hash:
            unsealed += 1
            continue
        content = hashlib.sha256((p.raw or "").encode("utf-8", errors="replace")).hexdigest()
        if content != p.content_sha256:
            broken = p.id
            break
        if p.prev_paste_id is None:
            expected = hashlib.sha256(f"genesis:{content}".encode("utf-8")).hexdigest()
        else:
            prev = by_id.get(p.prev_paste_id)
            if prev is None:
                gaps += 1
                continue
            expected = hashlib.sha256(
                f"{prev.chain_hash or 'genesis'}:{content}".encode("utf-8")
            ).hexdigest()
        if expected != p.chain_hash:
            broken = p.id
            break
    return JSONResponse(
        {
            "valid": broken is None,
            "captures": len(pastes),
            "sealed": len(pastes) - unsealed,
            "unsealed": unsealed,
            "gaps": gaps,
            "broken_at": broken,
        }
    )


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
        ),
    )


@app.post("/jobs")
def create_job(
    runner: str = Form(...),
    target: str = Form(""),
    program_id: str = Form(""),
    header_profile_id: str = Form(""),
    session: Session = Depends(get_session),
):
    if runners.find_runner(session, runner) is None:
        raise HTTPException(status_code=400, detail="Unknown runner")
    pid = int(program_id) if program_id.strip() else None
    hpid = int(header_profile_id) if header_profile_id.strip() else None
    if hpid is not None and session.get(HeaderProfile, hpid) is None:
        raise HTTPException(status_code=400, detail="Unknown header profile")
    job = ScanJob(
        program_id=pid,
        runner=runner,
        target=target.strip(),
        status="queued",
        header_profile_id=hpid,
    )
    session.add(job)
    session.commit()
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
    return templates.TemplateResponse(
        request,
        "job.html",
        _ctx(job=job, profile=profile, program=program, runner=runner, curl=curl),
    )


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, session: Session = Depends(get_session)):
    """Flip a job to cancelled; executors should stop on their next poll."""
    job = session.get(ScanJob, job_id)
    if job is not None and job.status in ("queued", "running"):
        job.status = "cancelled"
        job.finished_at = datetime.now(timezone.utc)
        session.add(job)
        session.commit()
    return RedirectResponse("/runners?msg=" + quote(f"job #{job_id} cancelled"), status_code=303)


@app.post("/jobs/{job_id}/retry")
def retry_job(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    clone = ScanJob(
        program_id=job.program_id,
        runner=job.runner,
        target=job.target,
        status="queued",
        header_profile_id=job.header_profile_id,
    )
    session.add(clone)
    session.commit()
    return RedirectResponse("/runners", status_code=303)


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
    if runners.get_runner(rid) is not None or session.exec(
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
    text = reporting.to_markdown(session, program_id, mask=not _reveal(request))
    if not text:
        raise HTTPException(status_code=404, detail="Program not found")
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}.md"'},
    )


@app.get("/reports/{program_id}/json")
def report_json(program_id: int, request: Request, session: Session = Depends(get_session)):
    data = reporting.to_dict(session, program_id, mask=not _reveal(request))
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
    _, targets, entities, relationships, findings = reporting.collect(session, program_id)
    if not reveal:
        masked = []
        for e in entities:
            c = Entity.model_validate(e.model_dump())
            c.value = reporting.mask_value(e.type, e.value)
            masked.append(c)
        entities = masked
    return templates.TemplateResponse(
        request,
        "report.html",
        _ctx(
            program=program,
            targets=targets,
            groups=reporting.group_entities(entities),
            relationships=relationships,
            findings=findings,
            masked=not reveal,
        ),
    )


def _reveal(request: Request) -> bool:
    return request.query_params.get("reveal") == "1"


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
def report_hackerone(program_id: int, session: Session = Depends(get_session)):
    text = reporting.to_hackerone(session, program_id)
    if not text:
        raise HTTPException(status_code=404, detail="Program not found")
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="breadcrumb-{program_id}-h1.md"'},
    )


@app.get("/reports/{program_id}/sarif")
def report_sarif(program_id: int, request: Request, session: Session = Depends(get_session)):
    """SARIF 2.1.0 for CI/SAST dashboards (e.g. GitHub code scanning upload)."""
    data = reporting.to_sarif(session, program_id, mask=not _reveal(request))
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
def api_llm_models(provider_id: str = ""):
    config = llm.load_config()
    provider = llm.get_provider(config, provider_id or None)
    if provider is None:
        return JSONResponse({"ok": False, "error": "no provider"}, status_code=404)
    try:
        return {"ok": True, "provider": provider.get("id"), "models": llm.list_models(provider)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


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
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid JSON")
        text = payload.get("text", "") or ""
        program_id = payload.get("program_id")
        target_id = payload.get("target_id")
        source = payload.get("source", "api") or "api"
    else:
        raw = await request.body()
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Body too large (max 5 MB)")
        text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        raise HTTPException(status_code=400, detail="Empty body")
    paste = _ingest(session, text, program_id, target_id, source)
    count = session.exec(
        select(func.count()).select_from(Entity).where(Entity.paste_id == paste.id)
    ).one()
    return {"paste_id": paste.id, "entities": count, "parsers": paste.parsers or [],
            "errors": paste.parse_errors or [],
            "warning": "no entities detected" if count == 0 else ""}


@app.get("/api/v1/entities")
def api_entities(
    program_id: int | None = None,
    type: str | None = None,  # noqa: A002
    q: str = "",
    limit: int = 1000,
    session: Session = Depends(get_session),
):
    stmt = select(Entity).where(Entity.ignored == False).order_by(Entity.id)  # noqa: E712
    if program_id is not None:
        stmt = stmt.where(Entity.program_id == program_id)
    if type:
        stmt = stmt.where(Entity.type == type)
    if q.strip():
        stmt = stmt.where(Entity.value.ilike(f"%{q.strip()}%"))
    rows = session.exec(stmt.limit(max(1, min(limit, 5000)))).all()
    return {
        "count": len(rows),
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
    return {"jobs": [
        {"id": j.id, "runner": j.runner, "target": j.target, "status": j.status,
         "program_id": j.program_id, "header_profile_id": j.header_profile_id,
         "header_profile_name": names.get(j.header_profile_id),
         "created_at": j.created_at.isoformat() if j.created_at else None}
        for j in jobs
    ]}


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
    job = ScanJob(
        program_id=payload.get("program_id"),
        runner=runner_id,
        target=str(payload.get("target", "") or ""),
        status="queued",
        header_profile_id=int(hpid) if hpid is not None else None,
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return {
        "job_id": job.id,
        "status": "queued",
        "note": "No executor connected yet — POST output to /api/v1/pastes, then update status.",
    }


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
def api_backup(session: Session = Depends(get_session)):  # noqa: ARG001
    """Download the raw SQLite database file."""
    from fastapi.responses import FileResponse

    engine.dispose()
    return FileResponse(
        path=str(DB_PATH),
        filename=f"breadcrumb-backup-{datetime.now(timezone.utc):%Y%m%d}.db",
        media_type="application/x-sqlite3",
    )


@app.post("/backup/restore")
def restore_backup(
    upload: UploadFile = File(...),
    session: Session = Depends(get_session),  # noqa: ARG001
):
    """Replace the database from an uploaded backup file (validated first)."""
    import os
    import shutil
    import sqlite3
    import tempfile

    raw = upload.file.read(100 * 1024 * 1024 + 1)
    if len(raw) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Backup too large (max 100 MB)")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    try:
        tmp.write(raw)
        tmp.close()
        try:
            conn = sqlite3.connect(tmp.name)
            conn.execute("PRAGMA integrity_check").fetchall()
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            conn.close()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"Not a valid SQLite file: {exc}")
        if not {"program", "entity", "paste"} <= tables:
            raise HTTPException(status_code=400, detail="Not a Breadcrumb database")
        engine.dispose()
        shutil.copy(tmp.name, DB_PATH)
        init_db()
    finally:
        os.unlink(tmp.name)
    return RedirectResponse("/", status_code=303)


@app.get("/health")
def health():
    return {"status": "ok", "version": APP_VERSION}