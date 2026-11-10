"""Attribution and consolidation.

This is where raw entities become a coherent picture: every entity is checked
against the program's scope, tied to the most specific target it belongs to,
de-duplicated across pastes (with provenance kept), and linked into the graph.
All of it is deterministic and re-runnable.
"""

import ipaddress

from sqlmodel import Session, select

from .graph import derive_edges
from .models import Entity, Program, Relationship, Target
from .scope import Scope, ScopeDecision, host_of, status_code_of

HOST_LIKE = {"domain", "subdomain", "wildcard", "ip", "cidr"}


def entity_host(entity) -> str:
    """The host a scope/target decision should be based on."""
    etype = entity.type
    value = entity.value or ""
    if etype in HOST_LIKE:
        if etype == "cidr":
            return ""
        return host_of(value, etype)
    if etype == "dns_record":
        return host_of((entity.meta or {}).get("name", ""), "domain")
    if etype in {"url", "path", "param", "port", "secret", "credential", "jwt"}:
        return host_of((entity.meta or {}).get("host", "") or "", etype)
    return ""


def _scope_inputs(entity) -> tuple[str, str, str, int | None]:
    """Return (value, vtype, host, status_code) for a scope decision.

    Paths and params carry their host in meta; reconstructing the URL lets the
    path rules and status filters see the full value instead of a bare host.
    """
    etype = getattr(entity, "type", "") or ""
    meta = getattr(entity, "meta", None) or {}
    code = getattr(entity, "status_code", None)
    if code is None:
        code = status_code_of(getattr(entity, "value", "") or "", etype, meta)
    if etype == "dns_record":
        name = str(meta.get("name") or "")
        return name, "domain", host_of(name, "domain"), code
    if etype in {"path", "param"}:
        value = str(getattr(entity, "value", "") or "")
        host = str(meta.get("host") or "").lower()
        if host and value.startswith("/"):
            return f"https://{host}{value}", "url", host, code
        return value, "path", host, code
    if etype == "port":
        host = str(meta.get("host") or "").lower()
        return str(getattr(entity, "value", "") or ""), "port", host, code
    if etype in {"secret", "credential", "jwt"}:
        host = str(meta.get("host") or "").lower()
        return host or str(getattr(entity, "value", "") or ""), "domain", host, code
    if etype == "http_status":
        url = str(meta.get("url") or meta.get("host") or getattr(entity, "value", "") or "")
        return url, "url", host_of(url, "url"), code
    value = str(getattr(entity, "value", "") or "")
    return value, etype, host_of(value, etype), code


def scope_decision(scope: Scope, entity) -> ScopeDecision:
    value, vtype, host, code = _scope_inputs(entity)
    return scope.explain(value, vtype, status_code=code, host=host)


def classify_scope(scope: Scope, entity) -> str:
    return scope_decision(scope, entity).status


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _target_rule(target: Target):
    name = (target.name or "").strip().lower().rstrip(".")
    if target.kind == "cidr" or "/" in name:
        try:
            return ("cidr", str(len(name)), ipaddress.ip_network(name, strict=False))
        except ValueError:
            return None
    if target.kind == "ip":
        return ("ip", str(len(name)), name)
    if target.kind == "url":
        return ("host", str(len(name)), host_of(name, "url"))
    return ("host", str(len(name)), name)


def attribute_target(host: str, targets: list[Target]):
    """Return the most specific target whose name contains ``host``."""
    if not host:
        return None
    best = None
    best_len = -1
    is_ip = _is_ip(host)
    for target in targets:
        rule = _target_rule(target)
        if rule is None:
            continue
        kind, length, value = rule
        matched = False
        if kind == "cidr" and is_ip:
            try:
                matched = ipaddress.ip_address(host) in value
            except ValueError:
                matched = False
        elif kind == "ip":
            matched = is_ip and host == value
        elif kind == "host" and not is_ip:
            matched = host == value or host.endswith("." + value)
        if matched and int(length) > best_len:
            best, best_len = target, int(length)
    return best


def consolidate_entities(session: Session, program_id) -> int:
    """Merge duplicate entities in a program by (type, normalized).

    Keeps the highest-confidence row, unions provenance, sums occurrences and
    points any relationship that referenced a removed row at the survivor.
    """
    stmt = select(Entity)
    if program_id is None:
        stmt = stmt.where(Entity.program_id == None)  # noqa: E711
    else:
        stmt = stmt.where(Entity.program_id == program_id)
    entities = session.exec(stmt).all()

    groups: dict[tuple[str, str], list[Entity]] = {}
    for entity in entities:
        key = (entity.type, (entity.normalized or entity.value).lower())
        groups.setdefault(key, []).append(entity)

    removed = 0
    for rows in groups.values():
        if len(rows) < 2:
            continue
        rows.sort(key=lambda e: (-e.confidence, e.id or 0))
        keep = rows[0]
        provenance = list(keep.provenance or [])
        meta = dict(keep.meta or {})
        occurrences = keep.occurrences or 1
        for extra in rows[1:]:
            occurrences += extra.occurrences or 1
            for pid in extra.provenance or []:
                if pid not in provenance:
                    provenance.append(pid)
            if keep.status_code is None and extra.status_code is not None:
                keep.status_code = extra.status_code
            for k, v in (extra.meta or {}).items():
                meta.setdefault(k, v)
            for rel in session.exec(
                select(Relationship).where(
                    (Relationship.src_entity_id == extra.id)
                    | (Relationship.dst_entity_id == extra.id)
                )
            ).all():
                if rel.src_entity_id == extra.id:
                    rel.src_entity_id = keep.id
                if rel.dst_entity_id == extra.id:
                    rel.dst_entity_id = keep.id
                session.add(rel)
            session.delete(extra)
            removed += 1
        keep.provenance = provenance
        keep.meta = meta
        keep.occurrences = occurrences
        session.add(keep)
    if removed:
        session.commit()
    return removed


def rebuild_program(session: Session, program_id: int) -> dict:
    """Recompute scope status, target attribution and derived graph edges."""
    program = session.get(Program, program_id)
    if program is None:
        return {}

    scope = Scope(program.scope_in or "", program.scope_out or "")
    targets = session.exec(
        select(Target).where(Target.program_id == program_id)
    ).all()

    consolidate_entities(session, program_id)

    entities = session.exec(
        select(Entity).where(Entity.program_id == program_id)
    ).all()
    entity_by_key: dict[tuple[str, str], Entity] = {}
    target_ids = {t.id for t in targets}
    in_scope = out_scope = unknown = attributed = 0
    reason_counts: dict[str, int] = {}
    for entity in entities:
        decision = scope_decision(scope, entity)
        status = decision.status
        entity.scope_status = status
        entity.scope_reason = decision.reason
        reason_counts[decision.reason] = reason_counts.get(decision.reason, 0) + 1
        if entity.status_code is None:
            entity.status_code = status_code_of(
                entity.value or "", entity.type, entity.meta or {}
            )
        if status == "in":
            in_scope += 1
        elif status == "out":
            out_scope += 1
        else:
            unknown += 1
        matched = attribute_target(entity_host(entity), targets)
        if matched is not None:
            entity.target_id = matched.id
        elif entity.target_id is not None and entity.target_id not in target_ids:
            entity.target_id = None
        if entity.target_id is not None:
            attributed += 1
        session.add(entity)
        entity_by_key[(entity.type, entity.value.lower())] = entity
        entity_by_key[(entity.type, (entity.normalized or entity.value).lower())] = entity
    session.commit()

    stale = session.exec(
        select(Relationship).where(
            Relationship.program_id == program_id,
            Relationship.source == "derived",
        )
    ).all()
    for rel in stale:
        session.delete(rel)
    session.commit()

    edges = derive_edges(entities)
    made = 0
    for edge in edges:
        src = entity_by_key.get((edge.src_type, edge.src_value.lower()))
        dst = entity_by_key.get((edge.dst_type, edge.dst_value.lower()))
        target = None
        if src is not None and src.target_id:
            target = src.target_id
        elif dst is not None:
            target = dst.target_id
        session.add(
            Relationship(
                program_id=program_id,
                target_id=target,
                src_value=edge.src_value,
                src_type=edge.src_type,
                dst_value=edge.dst_value,
                dst_type=edge.dst_type,
                rel_type=edge.rel_type,
                src_entity_id=getattr(src, "id", None),
                dst_entity_id=getattr(dst, "id", None),
                confidence=edge.confidence,
                source="derived",
                meta=edge.meta,
            )
        )
        made += 1
    session.commit()

    return {
        "program_id": program_id,
        "entities": len(entities),
        "in_scope": in_scope,
        "out_scope": out_scope,
        "unknown": unknown,
        "attributed": attributed,
        "derived_edges": made,
        "scope_reasons": reason_counts,
    }


def rebuild_all(session: Session) -> list[dict]:
    stats = []
    for program in session.exec(select(Program)).all():
        stats.append(rebuild_program(session, program.id))
    return stats


def merge_into_program(session: Session, paste_id: int, program_id) -> None:
    """Re-point a paste's entities at a program and fold in duplicates."""
    for entity in session.exec(select(Entity).where(Entity.paste_id == paste_id)).all():
        entity.program_id = program_id
        session.add(entity)
    session.commit()
    if program_id is not None:
        consolidate_entities(session, program_id)
