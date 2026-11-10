"""Ledger v2: cross-program asset memory.

The Ledger answers the question a single-engagement scanner cannot: *have I
seen this before?* It aggregates entities by ``(type, normalized)`` across every
program, records first/last sighting, links back to the captures and targets,
and exposes the analyst annotations (verdict, tags, notes) that make memory
useful.

Filters are a small, documented query language::

    type:port scope:in tag:needs-auth seen:other-program program:acme
    status:200 q:admin

The same filter string can be saved as a local view. Exports are JSONL
(round-trips through the normal ingest path) and CSV (for spreadsheets).
"""

from __future__ import annotations

import csv
import io
import json
import shlex
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Text as SAText
from sqlalchemy import cast
from sqlmodel import Session, func, select

from .models import Entity, Paste, Program, SavedView, Target

VIEW_KINDS = {"ledger", "diff", "graph"}
_SEEN_MULTI = {"multi", "other", "other-program", "cross", "seen-before"}
_SEEN_SINGLE = {"single", "one", "only"}


@dataclass
class LedgerFilters:
    types: list[str] = field(default_factory=list)
    scope: str = ""
    tags: list[str] = field(default_factory=list)
    verdict: str = ""
    programs: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    seen: str = ""
    q: str = ""
    sort: str = "last_seen"
    limit: int = 100
    offset: int = 0
    raw: str = ""

    def as_query(self) -> str:
        return self.raw

    def as_dict(self) -> dict:
        return {
            "types": self.types,
            "scope": self.scope,
            "tags": self.tags,
            "verdict": self.verdict,
            "programs": self.programs,
            "status_codes": self.status_codes,
            "seen": self.seen,
            "q": self.q,
            "sort": self.sort,
        }


def _split_values(value: str) -> list[str]:
    return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]


def parse_query(query: str) -> LedgerFilters:
    """Parse the Ledger filter language. Unknown ``key:value`` is free text."""
    filters = LedgerFilters(raw=(query or "").strip())
    try:
        tokens = shlex.split(filters.raw)
    except ValueError:
        tokens = filters.raw.split()
    text: list[str] = []
    for token in tokens:
        key, sep, value = token.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not sep or not value:
            text.append(token)
            continue
        if key in {"type", "types"}:
            filters.types.extend(_split_values(value))
        elif key in {"scope", "status"} and key == "scope":
            if value.lower() in {"in", "out", "unknown"}:
                filters.scope = value.lower()
            else:
                text.append(token)
        elif key in {"tag", "tags"}:
            filters.tags.extend(_split_values(value))
        elif key == "verdict":
            filters.verdict = value.lower()
        elif key in {"program", "programs", "programme"}:
            filters.programs.extend(_split_values(value))
        elif key in {"status", "code", "status_code", "status-code"}:
            for part in _split_values(value):
                try:
                    code = int(part)
                except ValueError:
                    continue
                if 100 <= code <= 599:
                    filters.status_codes.append(code)
        elif key == "seen":
            lowered = value.lower()
            if lowered in _SEEN_MULTI:
                filters.seen = "multi"
            elif lowered in _SEEN_SINGLE:
                filters.seen = "single"
        elif key in {"q", "value", "search"}:
            text.append(value)
        elif key == "sort":
            if value.lower() in {"first_seen", "first-seen"}:
                filters.sort = "first_seen"
            elif value.lower() in {"value", "type"}:
                filters.sort = "value"
            elif value.lower() in {"programs", "program"}:
                filters.sort = "programs"
            elif value.lower() in {"occurrences", "count"}:
                filters.sort = "occurrences"
            else:
                filters.sort = "last_seen"
        else:
            text.append(token)
    filters.q = " ".join(text).strip()
    return filters


def _resolve_programs(session: Session, tokens: list[str]) -> list[int]:
    ids: list[int] = []
    for token in tokens:
        if token.isdigit():
            ids.append(int(token))
            continue
        rows = session.exec(select(Program.id).where(Program.name.ilike(f"%{token}%"))).all()
        ids.extend(int(row) for row in rows if row is not None)
    return sorted(set(ids))


def _base_query(filters: LedgerFilters, program_ids: list[int]):
    norm = func.lower(Entity.normalized)
    stmt = (
        select(
            Entity.type.label("type"),
            norm.label("norm"),
            func.min(Entity.value).label("value"),
            func.min(Entity.created_at).label("first_seen"),
            func.max(Entity.created_at).label("last_seen"),
            func.count(func.distinct(Entity.program_id)).label("program_count"),
            func.sum(Entity.occurrences).label("occurrences"),
            func.max(Entity.confidence).label("confidence"),
        )
        .where(Entity.ignored == False)  # noqa: E712
        .group_by(Entity.type, norm)
    )
    if filters.types:
        stmt = stmt.where(Entity.type.in_(filters.types))
    if filters.scope:
        stmt = stmt.where(Entity.scope_status == filters.scope)
    if filters.verdict:
        stmt = stmt.where(Entity.verdict == filters.verdict)
    if program_ids:
        stmt = stmt.where(Entity.program_id.in_(program_ids))
    if filters.status_codes:
        stmt = stmt.where(Entity.status_code.in_(filters.status_codes))
    for tag in filters.tags:
        stmt = stmt.where(cast(Entity.tags, SAText).like(f'%"{tag.lower()}"%'))
    if filters.q:
        like = f"%{filters.q.lower()}%"
        stmt = stmt.where(
            func.lower(Entity.value).like(like) | func.lower(Entity.normalized).like(like)
        )
    if filters.seen == "multi":
        stmt = stmt.having(func.count(func.distinct(Entity.program_id)) > 1)
    elif filters.seen == "single":
        stmt = stmt.having(func.count(func.distinct(Entity.program_id)) == 1)
    return stmt


def _order(stmt, sort: str):
    if sort == "first_seen":
        return stmt.order_by(func.min(Entity.created_at).asc(), func.min(Entity.value).asc())
    if sort == "value":
        return stmt.order_by(func.min(Entity.value).asc(), Entity.type.asc())
    if sort == "programs":
        return stmt.order_by(
            func.count(func.distinct(Entity.program_id)).desc(),
            func.max(Entity.created_at).desc(),
        )
    if sort == "occurrences":
        return stmt.order_by(func.sum(Entity.occurrences).desc())
    return stmt.order_by(func.max(Entity.created_at).desc(), func.min(Entity.value).asc())


def _iso(value) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


def _details_for(session: Session, keys: list[tuple[str, str]]) -> dict[tuple[str, str], list[Entity]]:
    if not keys:
        return {}
    norms = sorted({norm for _etype, norm in keys})
    rows = session.exec(
        select(Entity).where(
            Entity.ignored == False,  # noqa: E712
            func.lower(Entity.normalized).in_(norms),
        )
    ).all()
    wanted = set(keys)
    grouped: dict[tuple[str, str], list[Entity]] = {}
    for row in rows:
        key = (row.type, (row.normalized or row.value or "").lower())
        if key in wanted:
            grouped.setdefault(key, []).append(row)
    return grouped


def ledger_assets(
    session: Session,
    filters: LedgerFilters | None = None,
    *,
    limit: int | None = None,
    offset: int | None = None,
) -> dict:
    """Return a page of aggregated assets plus totals and filter metadata."""
    filters = filters or LedgerFilters()
    limit = max(1, min(int(limit if limit is not None else filters.limit or 100), 1000))
    offset = max(0, int(offset if offset is not None else filters.offset or 0))
    program_ids = _resolve_programs(session, filters.programs)
    stmt = _base_query(filters, program_ids)
    total = int(
        session.exec(select(func.count()).select_from(stmt.subquery())).one() or 0
    )
    page = session.exec(_order(stmt, filters.sort).offset(offset).limit(limit)).all()
    keys = [(row.type, (row.norm or "").lower()) for row in page]
    grouped = _details_for(session, keys)

    programs = {p.id: p for p in session.exec(select(Program)).all()}
    target_ids = {
        entity.target_id
        for rows in grouped.values()
        for entity in rows
        if entity.target_id is not None
    }
    targets = (
        {
            t.id: t
            for t in session.exec(select(Target).where(Target.id.in_(sorted(target_ids)))).all()
        }
        if target_ids
        else {}
    )
    paste_ids = {
        entity.paste_id
        for rows in grouped.values()
        for entity in rows
        if entity.paste_id is not None
    }
    pastes = (
        {
            p.id: p
            for p in session.exec(select(Paste).where(Paste.id.in_(sorted(paste_ids)))).all()
        }
        if paste_ids
        else {}
    )

    assets: list[dict] = []
    for row in page:
        key = (row.type, (row.norm or "").lower())
        rows = grouped.get(key, [])
        rows.sort(key=lambda entity: (entity.created_at or datetime.min, entity.id or 0))
        programs_seen: dict[int, str] = {}
        targets_seen: dict[int, dict] = {}
        captures_seen: dict[int, dict] = {}
        scope_statuses: set[str] = set()
        scope_reasons: set[str] = set()
        status_codes: set[int] = set()
        verdicts: set[str] = set()
        tags: set[str] = set()
        notes: list[str] = []
        meta: dict = {}
        for entity in rows:
            if entity.program_id is not None:
                programs_seen[entity.program_id] = (
                    programs[entity.program_id].name
                    if entity.program_id in programs
                    else f"#{entity.program_id}"
                )
            if entity.target_id is not None and entity.target_id in targets:
                target = targets[entity.target_id]
                targets_seen[target.id] = {
                    "id": target.id,
                    "name": target.name,
                    "kind": target.kind,
                    "program_id": target.program_id,
                }
            if entity.paste_id is not None and entity.paste_id in pastes:
                paste = pastes[entity.paste_id]
                captures_seen[paste.id] = {
                    "id": paste.id,
                    "source": paste.source,
                    "created_at": _iso(paste.created_at),
                    "program_id": paste.program_id,
                }
            scope_statuses.add(entity.scope_status or "unknown")
            if entity.scope_reason:
                scope_reasons.add(entity.scope_reason)
            if entity.status_code is not None:
                status_codes.add(int(entity.status_code))
            if entity.verdict and entity.verdict != "none":
                verdicts.add(entity.verdict)
            for tag in entity.tags or []:
                if tag:
                    tags.add(str(tag))
            if entity.notes:
                notes.append(str(entity.notes))
            if not meta and entity.meta:
                meta = dict(entity.meta)
        first_seen = min(
            (entity.created_at for entity in rows if entity.created_at), default=None
        )
        last_seen = max(
            (entity.created_at for entity in rows if entity.created_at), default=None
        )
        assets.append(
            {
                "type": row.type,
                "value": row.value,
                "normalized": row.norm,
                "confidence": row.confidence,
                "first_seen": _iso(first_seen),
                "last_seen": _iso(last_seen),
                "program_count": len(programs_seen),
                "occurrences": int(row.occurrences or 0),
                "programs": [
                    {"id": pid, "name": name}
                    for pid, name in sorted(programs_seen.items())
                ],
                "targets": sorted(
                    targets_seen.values(), key=lambda item: (item["name"] or "").lower()
                ),
                "captures": sorted(
                    captures_seen.values(), key=lambda item: item["id"] or 0
                ),
                "scope_statuses": sorted(scope_statuses),
                "scope_reasons": sorted(scope_reasons),
                "status_codes": sorted(status_codes),
                "verdicts": sorted(verdicts),
                "tags": sorted(tags),
                "notes": notes,
                "meta": meta,
                "seen_before": len(programs_seen) > 1,
            }
        )
    return {
        "total": total,
        "count": len(assets),
        "limit": limit,
        "offset": offset,
        "next_offset": offset + len(assets) if offset + len(assets) < total else None,
        "filters": filters.as_dict(),
        "assets": assets,
    }


def asset_timeline(session: Session, etype: str, value: str) -> dict | None:
    """Every sighting of one asset, newest last, with program/capture links."""
    norm = (value or "").strip().lower()
    if not norm:
        return None
    rows = session.exec(
        select(Entity)
        .where(
            Entity.type == etype,
            func.lower(Entity.normalized) == norm,
        )
        .order_by(Entity.created_at, Entity.id)
    ).all()
    if not rows:
        return None
    program_ids = {row.program_id for row in rows if row.program_id is not None}
    target_ids = {row.target_id for row in rows if row.target_id is not None}
    paste_ids = {row.paste_id for row in rows if row.paste_id is not None}
    programs = {
        p.id: p
        for p in session.exec(select(Program).where(Program.id.in_(program_ids))).all()
    } if program_ids else {}
    targets = {
        t.id: t
        for t in session.exec(select(Target).where(Target.id.in_(target_ids))).all()
    } if target_ids else {}
    pastes = {
        p.id: p
        for p in session.exec(select(Paste).where(Paste.id.in_(paste_ids))).all()
    } if paste_ids else {}
    sightings = []
    for row in rows:
        paste = pastes.get(row.paste_id)
        program = programs.get(row.program_id)
        target = targets.get(row.target_id)
        sightings.append(
            {
                "entity_id": row.id,
                "value": row.value,
                "normalized": row.normalized,
                "program": (
                    {"id": program.id, "name": program.name} if program else None
                ),
                "target": (
                    {"id": target.id, "name": target.name, "kind": target.kind}
                    if target
                    else None
                ),
                "capture": (
                    {
                        "id": paste.id,
                        "source": paste.source,
                        "created_at": _iso(paste.created_at),
                        "command": paste.command,
                        "content_sha256": paste.content_sha256,
                    }
                    if paste
                    else None
                ),
                "created_at": _iso(row.created_at),
                "scope_status": row.scope_status,
                "scope_reason": row.scope_reason,
                "status_code": row.status_code,
                "verdict": row.verdict,
                "tags": list(row.tags or []),
                "notes": row.notes,
                "occurrences": row.occurrences,
                "confidence": row.confidence,
                "parser": row.parser,
                "meta": row.meta or {},
            }
        )
    first = rows[0]
    return {
        "type": etype,
        "value": first.value,
        "normalized": norm,
        "sightings": sightings,
        "program_count": len(program_ids),
        "capture_count": len(paste_ids),
        "first_seen": _iso(rows[0].created_at),
        "last_seen": _iso(rows[-1].created_at),
        "seen_before": len(program_ids) > 1,
    }


def ledger_stats(session: Session) -> dict:
    total_entities = int(
        session.exec(
            select(func.count()).select_from(Entity).where(Entity.ignored == False)  # noqa: E712
        ).one()
        or 0
    )
    multi = session.exec(
        select(func.count())
        .select_from(
            select(Entity.type, func.lower(Entity.normalized))
            .where(Entity.program_id != None)  # noqa: E711
            .group_by(Entity.type, func.lower(Entity.normalized))
            .having(func.count(func.distinct(Entity.program_id)) > 1)
            .subquery()
        )
    ).one()
    return {
        "entities": total_entities,
        "programs": int(session.exec(select(func.count()).select_from(Program)).one() or 0),
        "cross_program_assets": int(multi or 0),
        "tags": sorted(
            {
                str(tag)
                for row in session.exec(select(Entity.tags).where(Entity.tags != None)).all()  # noqa: E711
                for tag in (row or [])
                if tag
            }
        ),
    }


def shared_assets(session: Session, program_id: int, limit: int = 100) -> list[dict]:
    """Assets in this program that also appear in other programs.

    This is the graph's "memory" edge: it links a node the analyst is looking
    at now to the same asset seen while working a different program. The query
    is bounded and grouped so a 100k-entity program stays responsive.
    """
    own = session.exec(
        select(Entity.type, func.lower(Entity.normalized))
        .where(Entity.program_id == program_id, Entity.ignored == False)  # noqa: E712
        .group_by(Entity.type, func.lower(Entity.normalized))
    ).all()
    if not own:
        return []
    norms = sorted({row[1] for row in own if row[1]})
    rows = session.exec(
        select(
            Entity.type,
            func.lower(Entity.normalized).label("norm"),
            func.min(Entity.value),
            func.count(func.distinct(Entity.program_id)),
        )
        .where(
            Entity.program_id != None,  # noqa: E711
            Entity.program_id != program_id,
            Entity.ignored == False,  # noqa: E712
            func.lower(Entity.normalized).in_(norms),
        )
        .group_by(Entity.type, func.lower(Entity.normalized))
        .order_by(func.count(func.distinct(Entity.program_id)).desc())
        .limit(max(1, min(int(limit), 500)))
    ).all()
    if not rows:
        return []
    keys = {(row[0], row[1]) for row in rows}
    programs = {p.id: p.name for p in session.exec(select(Program)).all()}
    seen: dict[tuple[str, str], set[int]] = {}
    for etype, norm, pid in session.exec(
        select(Entity.type, func.lower(Entity.normalized), Entity.program_id)
        .where(
            Entity.program_id != None,  # noqa: E711
            Entity.program_id != program_id,
            func.lower(Entity.normalized).in_(norms),
        )
    ).all():
        if (etype, norm) in keys and pid is not None:
            seen.setdefault((etype, norm), set()).add(pid)
    out = []
    for etype, norm, value, count in rows:
        ids = sorted(seen.get((etype, norm), set()))
        out.append(
            {
                "type": etype,
                "value": value,
                "normalized": norm,
                "program_count": int(count or len(ids)),
                "programs": [
                    {"id": pid, "name": programs.get(pid, f"#{pid}")} for pid in ids
                ],
            }
        )
    return out


# --------------------------------------------------------------- exports ----
def assets_to_jsonl(assets: list[dict]) -> str:
    lines = []
    for asset in assets:
        row = {
            "ledger_version": 1,
            "type": asset["type"],
            "value": asset["value"],
            "normalized": asset.get("normalized") or asset["value"],
            "confidence": asset.get("confidence", 1.0),
            "scope_status": (asset.get("scope_statuses") or ["unknown"])[0],
            "status_code": (
                asset["status_codes"][0] if asset.get("status_codes") else None
            ),
            "verdict": (asset.get("verdicts") or ["none"])[0],
            "tags": asset.get("tags") or [],
            "notes": (asset.get("notes") or [None])[0],
            "occurrences": asset.get("occurrences", 1),
            "first_seen": asset.get("first_seen"),
            "last_seen": asset.get("last_seen"),
            "programs": asset.get("programs") or [],
            "targets": asset.get("targets") or [],
            "captures": asset.get("captures") or [],
            "meta": asset.get("meta") or {},
        }
        lines.append(json.dumps(row, sort_keys=True, default=str))
    return "\n".join(lines) + ("\n" if lines else "")


CSV_FIELDS = [
    "type",
    "value",
    "normalized",
    "first_seen",
    "last_seen",
    "program_count",
    "occurrences",
    "scope_statuses",
    "scope_reasons",
    "status_codes",
    "verdicts",
    "tags",
    "programs",
    "targets",
    "captures",
    "seen_before",
]


def assets_to_csv(assets: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for asset in assets:
        writer.writerow(
            {
                "type": asset["type"],
                "value": asset["value"],
                "normalized": asset.get("normalized"),
                "first_seen": asset.get("first_seen"),
                "last_seen": asset.get("last_seen"),
                "program_count": asset.get("program_count"),
                "occurrences": asset.get("occurrences"),
                "scope_statuses": ",".join(asset.get("scope_statuses") or []),
                "scope_reasons": ",".join(asset.get("scope_reasons") or []),
                "status_codes": ",".join(str(c) for c in asset.get("status_codes") or []),
                "verdicts": ",".join(asset.get("verdicts") or []),
                "tags": ",".join(asset.get("tags") or []),
                "programs": ",".join(
                    p.get("name", "") for p in asset.get("programs") or []
                ),
                "targets": ",".join(
                    t.get("name", "") for t in asset.get("targets") or []
                ),
                "captures": ",".join(
                    str(c.get("id")) for c in asset.get("captures") or []
                ),
                "seen_before": asset.get("seen_before"),
            }
        )
    return buffer.getvalue()


# ----------------------------------------------------------- saved views ----
def _validate_kind(kind: str) -> str:
    kind = (kind or "ledger").strip().lower()
    if kind not in VIEW_KINDS:
        raise ValueError(f"view kind must be one of {sorted(VIEW_KINDS)}")
    return kind


def list_views(session: Session, kind: str | None = None) -> list[SavedView]:
    stmt = select(SavedView).order_by(SavedView.kind, SavedView.name)
    if kind:
        stmt = stmt.where(SavedView.kind == _validate_kind(kind))
    return session.exec(stmt).all()


def get_view(session: Session, view_id: int) -> SavedView | None:
    return session.get(SavedView, view_id)


def save_view(
    session: Session,
    name: str,
    kind: str = "ledger",
    query: str = "",
    params: dict | None = None,
) -> SavedView:
    name = (name or "").strip()
    if not name:
        raise ValueError("view name is required")
    kind = _validate_kind(kind)
    existing = session.exec(
        select(SavedView).where(SavedView.kind == kind, SavedView.name == name)
    ).first()
    now = datetime.now().astimezone()
    if existing is None:
        existing = SavedView(
            name=name,
            kind=kind,
            query=(query or "").strip(),
            params=dict(params or {}),
            created_at=now,
            updated_at=now,
        )
    else:
        existing.query = (query or "").strip()
        existing.params = dict(params or {})
        existing.updated_at = now
    session.add(existing)
    session.commit()
    session.refresh(existing)
    return existing


def delete_view(session: Session, view_id: int) -> bool:
    view = session.get(SavedView, view_id)
    if view is None:
        return False
    session.delete(view)
    session.commit()
    return True
