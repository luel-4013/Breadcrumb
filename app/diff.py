"""Diff v2: compare any two captures, targets, programs, or jobs.

The old history diff compared two scan snapshots for one target. Phase B needs
the same rigor across arbitrary selectors, because the question is usually
broader than "what changed on this host?":

    paste:41   one capture (a tool run)
    target:7   everything attributed to one target
    program:2  the whole program surface
    job:19     one queued/executed scan

Selectors are explicit (``kind:id``) so a typo can never silently compare the
wrong things. Job selectors use the persisted history snapshot, which is the
only state that correctly represents a point-in-time scan; captures, targets
and programs use live entity/finding state. Categories are always the same:
findings, ports, DNS, endpoints, technologies, security headers, and risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlmodel import Session, select

from . import history
from .models import Entity, Finding, Paste, Program, ScanJob, Target

SELECTOR_KINDS = ("paste", "target", "program", "job")
_ALIASES = {"capture": "paste", "scan": "job", "programme": "program"}
MAX_ITEMS = 2000


@dataclass
class Selector:
    kind: str
    id: int
    raw: str
    label: str = ""
    program_id: int | None = None
    target_id: int | None = None
    source: str = ""


@dataclass
class State:
    """A comparable slice of one selector's observed state."""

    selector: Selector
    findings: dict[str, dict] = field(default_factory=dict)
    entities: dict[tuple[str, str], dict] = field(default_factory=dict)
    ports: dict[str, dict] = field(default_factory=dict)
    dns: dict[str, dict] = field(default_factory=dict)
    endpoints: set[str] = field(default_factory=set)
    technologies: set[str] = field(default_factory=set)
    headers: dict[str, str] = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = "minimal"
    entity_based: bool = True

    def summary(self) -> dict:
        return {
            "selector": self.selector.raw,
            "kind": self.selector.kind,
            "id": self.selector.id,
            "label": self.selector.label,
            "program_id": self.selector.program_id,
            "target_id": self.selector.target_id,
            "findings": len(self.findings),
            "entities": len(self.entities),
            "ports": len(self.ports),
            "endpoints": len(self.endpoints),
            "technologies": len(self.technologies),
            "headers": len(self.headers),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def parse_selector(raw: str) -> Selector:
    """Parse ``kind:id``; aliases are accepted, bare ids are not."""
    text = (raw or "").strip().lower()
    if not text:
        raise ValueError("selector is required")
    kind, sep, ident = text.partition(":")
    kind = _ALIASES.get(kind, kind)
    if not sep or kind not in SELECTOR_KINDS:
        raise ValueError(
            f"selector must be one of {', '.join(f'{k}:<id>' for k in SELECTOR_KINDS)}"
        )
    try:
        value = int(ident)
    except (TypeError, ValueError):
        raise ValueError(f"selector id must be an integer: {raw!r}") from None
    if value <= 0:
        raise ValueError(f"selector id must be positive: {raw!r}")
    return Selector(kind=kind, id=value, raw=f"{kind}:{value}")


def resolve_selector(session: Session, raw: str | Selector) -> Selector:
    """Parse and validate a selector against the database, with a label."""
    selector = raw if isinstance(raw, Selector) else parse_selector(raw)
    if selector.kind == "paste":
        row = session.get(Paste, selector.id)
        if row is None:
            raise ValueError(f"capture {selector.id} not found")
        selector.label = f"Capture #{row.id} · {row.source}"
        selector.program_id = row.program_id
        selector.target_id = row.target_id
        selector.source = row.source
        when = _iso(row.created_at)
        if when:
            selector.label += f" · {when[:16].replace('T', ' ')}"
    elif selector.kind == "target":
        row = session.get(Target, selector.id)
        if row is None:
            raise ValueError(f"target {selector.id} not found")
        selector.label = f"Target · {row.name}"
        selector.program_id = row.program_id
        selector.target_id = row.id
        selector.source = row.kind
    elif selector.kind == "program":
        row = session.get(Program, selector.id)
        if row is None:
            raise ValueError(f"program {selector.id} not found")
        selector.label = f"Program · {row.name}"
        selector.program_id = row.id
    else:
        row = session.get(ScanJob, selector.id)
        if row is None:
            raise ValueError(f"job {selector.id} not found")
        selector.label = f"Job #{row.id} · {row.target or row.runner or 'scan'}"
        selector.program_id = row.program_id
        selector.target_id = row.target_id
        selector.source = row.runner or ""
    return selector


def _select_entities(session: Session, selector: Selector) -> list[Entity]:
    if selector.kind == "paste":
        stmt = select(Entity).where(Entity.paste_id == selector.id)
    elif selector.kind == "target":
        stmt = select(Entity).where(Entity.target_id == selector.id)
    elif selector.kind == "program":
        stmt = select(Entity).where(Entity.program_id == selector.id)
    else:
        paste_ids = session.exec(
            select(Paste.id).where(Paste.job_id == selector.id)
        ).all()
        ids = [int(pid) for pid in paste_ids if pid is not None]
        if not ids:
            return []
        stmt = select(Entity).where(Entity.paste_id.in_(ids))
    return session.exec(stmt.order_by(Entity.type, Entity.value)).all()


def _select_findings(session: Session, selector: Selector) -> list[Finding]:
    if selector.kind == "paste":
        stmt = select(Finding).where(Finding.paste_id == selector.id)
    elif selector.kind == "target":
        stmt = select(Finding).where(Finding.target_id == selector.id)
    elif selector.kind == "program":
        stmt = select(Finding).where(Finding.program_id == selector.id)
    else:
        paste_ids = session.exec(
            select(Paste.id).where(Paste.job_id == selector.id)
        ).all()
        ids = [int(pid) for pid in paste_ids if pid is not None]
        if not ids:
            return []
        stmt = select(Finding).where(Finding.paste_id.in_(ids))
    return session.exec(stmt.order_by(Finding.id)).all()


def _select_pastes(session: Session, selector: Selector) -> list[Paste]:
    if selector.kind == "paste":
        row = session.get(Paste, selector.id)
        return [row] if row else []
    if selector.kind == "target":
        return session.exec(select(Paste).where(Paste.target_id == selector.id)).all()
    if selector.kind == "program":
        return session.exec(select(Paste).where(Paste.program_id == selector.id)).all()
    return session.exec(select(Paste).where(Paste.job_id == selector.id)).all()


def _entity_info(entity: Entity) -> dict:
    return {
        "type": entity.type,
        "value": entity.value,
        "normalized": (entity.normalized or entity.value or "").lower(),
        "scope_status": entity.scope_status,
        "scope_reason": entity.scope_reason,
        "status_code": entity.status_code,
        "verdict": entity.verdict,
        "tags": list(entity.tags or []),
        "notes": entity.notes,
        "confidence": entity.confidence,
        "program_id": entity.program_id,
        "target_id": entity.target_id,
        "paste_id": entity.paste_id,
        "meta": dict(entity.meta or {}),
    }


def _ports_from_entities(entities: list[Entity]) -> dict[str, dict]:
    ports: dict[str, dict] = {}
    for entity in entities:
        if entity.type != "port":
            continue
        meta = entity.meta or {}
        port = meta.get("port")
        if port is None:
            text = str(entity.value or "")
            port = text.split("/", 1)[0].split(":", 1)[0]
        proto = str(meta.get("proto") or "tcp").lower()
        key = f"{port}/{proto}"
        ports[key] = {
            "service": meta.get("service") or None,
            "version": meta.get("version") or meta.get("version_guess") or None,
            "banner": (meta.get("banner") or "")[:200] or None,
        }
    return ports


def _dns_from_entities(entities: list[Entity]) -> dict[str, dict]:
    records: dict[str, dict] = {}
    for entity in entities:
        if entity.type != "dns_record":
            continue
        meta = entity.meta or {}
        name = str(meta.get("name") or "").lower()
        rtype = str(meta.get("rtype") or "").upper()
        value = str(meta.get("value") or "")
        if not (name and rtype and value):
            parts = str(entity.value or "").split()
            if len(parts) >= 3:
                name, rtype, value = parts[0].lower(), parts[1].upper(), " ".join(parts[2:])
        key = f"{rtype}|{name}|{value}".strip("|").lower()
        records[key] = {"name": name, "rtype": rtype, "value": value}
    return records


def _tech_from_entities(entities: list[Entity]) -> set[str]:
    labels: set[str] = set()
    for entity in entities:
        if entity.type != "tech":
            continue
        label = str(entity.value or "").strip()
        version = str((entity.meta or {}).get("version") or "").strip()
        if label:
            labels.add(f"{label} {version}".strip())
    return labels


def _state_from_entities(session: Session, selector: Selector) -> State:
    entities = [
        entity
        for entity in _select_entities(session, selector)
        if not entity.ignored
    ]
    findings = _select_findings(session, selector)
    state = State(selector=selector)
    state.entities = {
        (entity.type, (entity.normalized or entity.value or "").lower()): _entity_info(entity)
        for entity in entities
    }
    state.findings = {
        history.finding_key(finding): history.serialize_finding(finding)
        for finding in findings
    }
    state.ports = _ports_from_entities(entities)
    state.dns = _dns_from_entities(entities)
    state.endpoints = {
        str(entity.value)
        for entity in entities
        if entity.type in history.API_PATH_TYPES and entity.value
    }
    state.technologies = _tech_from_entities(entities)
    state.headers = history._response_headers(_select_pastes(session, selector))
    state.risk_score, state.risk_level = history.compute_risk(findings)
    return state


def _state_from_snapshot(session: Session, selector: Selector) -> State:
    job = session.get(ScanJob, selector.id)
    if job is None:
        raise ValueError(f"job {selector.id} not found")
    row = history.ensure_snapshot(session, job)
    if row is None or row.status != "ready" or not row.data:
        raise ValueError(
            f"job {selector.id} has no ready snapshot; run `breadcrumb history` or retry the job"
        )
    data = row.data
    state = State(selector=selector, entity_based=False)
    state.findings = dict(data.get("findings") or {})
    for port, info in (data.get("ports") or {}).items():
        state.ports[str(port)] = dict(info or {})
    for rtype, values in (data.get("dns_records") or {}).items():
        for value in values or []:
            key = f"{rtype}|{value}".lower()
            state.dns[key] = {"name": "", "rtype": str(rtype), "value": value}
    state.endpoints = {str(value) for value in (data.get("endpoints") or [])}
    state.technologies = {str(value) for value in (data.get("technologies") or [])}
    state.headers = dict(data.get("security_headers") or {})
    state.risk_score = int(data.get("risk_score") or 0)
    state.risk_level = str(data.get("risk_level") or "minimal")
    state.entities = {}
    return state


def build_state(session: Session, raw: str | Selector) -> State:
    selector = resolve_selector(session, raw)
    if selector.kind == "job":
        return _state_from_snapshot(session, selector)
    return _state_from_entities(session, selector)


def _diff_sets(before, after) -> dict[str, list]:
    before, after = set(before), set(after)
    return {
        "added": sorted(after - before)[:MAX_ITEMS],
        "removed": sorted(before - after)[:MAX_ITEMS],
    }


def _diff_ports(before: dict, after: dict) -> dict:
    changed = []
    for key in sorted(set(before) & set(after)):
        if before[key] != after[key]:
            changed.append({"port": key, "before": before[key], "after": after[key]})
    return {
        "opened": [
            {"port": key, **after[key]} for key in sorted(set(after) - set(before))
        ][:MAX_ITEMS],
        "closed": [
            {"port": key, **before[key]} for key in sorted(set(before) - set(after))
        ][:MAX_ITEMS],
        "changed": changed[:MAX_ITEMS],
    }


def _diff_headers(before: dict, after: dict) -> dict:
    changed = []
    for name in sorted(set(before) & set(after)):
        if before[name] != after[name]:
            changed.append({"name": name, "before": before[name], "after": after[name]})
    return {
        "added": sorted(set(after) - set(before))[:MAX_ITEMS],
        "removed": sorted(set(before) - set(after))[:MAX_ITEMS],
        "changed": changed[:MAX_ITEMS],
    }


def _diff_findings(before: dict, after: dict) -> dict:
    def active(item: dict) -> bool:
        return not item.get("is_false_positive")

    new = [
        after[key] for key in sorted(set(after) - set(before)) if active(after[key])
    ]
    removed = [
        before[key] for key in sorted(set(before) - set(after)) if active(before[key])
    ]
    changed = []
    still_open = []
    for key in sorted(set(before) & set(after)):
        if not active(after[key]):
            continue
        old, new_item = before[key], after[key]
        changes = []
        for field in (
            "severity",
            "title",
            "status",
            "verdict",
            "triage_status",
            "verified",
        ):
            if old.get(field) != new_item.get(field):
                changes.append(
                    {"field": field, "before": old.get(field), "after": new_item.get(field)}
                )
        if changes:
            changed.append(
                {"key": key, "before": old, "after": new_item, "changes": changes}
            )
        else:
            still_open.append(new_item)
    return {
        "new": new[:MAX_ITEMS],
        "removed": removed[:MAX_ITEMS],
        "changed": changed[:MAX_ITEMS],
        "still_open": still_open[:MAX_ITEMS],
    }


def _diff_entities(before: State, after: State) -> dict:
    if not (before.entity_based and after.entity_based):
        return {"available": False, "added": [], "removed": [], "changed": []}
    added = [
        after.entities[key]
        for key in sorted(set(after.entities) - set(before.entities))
    ]
    removed = [
        before.entities[key]
        for key in sorted(set(before.entities) - set(after.entities))
    ]
    changed = []
    for key in sorted(set(before.entities) & set(after.entities)):
        old, new = before.entities[key], after.entities[key]
        changes = []
        for field in ("scope_status", "scope_reason", "status_code", "verdict", "tags", "notes"):
            if old.get(field) != new.get(field):
                changes.append(
                    {"field": field, "before": old.get(field), "after": new.get(field)}
                )
        if changes:
            changed.append(
                {
                    "key": f"{key[0]}|{key[1]}",
                    "type": key[0],
                    "value": new.get("value") or old.get("value"),
                    "before": old,
                    "after": new,
                    "changes": changes,
                }
            )
    return {
        "available": True,
        "added": added[:MAX_ITEMS],
        "removed": removed[:MAX_ITEMS],
        "changed": changed[:MAX_ITEMS],
    }


def diff_states(before: State, after: State) -> dict:
    findings = _diff_findings(before.findings, after.findings)
    ports = _diff_ports(before.ports, after.ports)
    dns = _diff_sets(before.dns, after.dns)
    dns["added"] = [before.dns.get(key) or after.dns.get(key) for key in dns["added"]]
    dns["removed"] = [before.dns.get(key) or after.dns.get(key) for key in dns["removed"]]
    endpoints = _diff_sets(before.endpoints, after.endpoints)
    technologies = _diff_sets(before.technologies, after.technologies)
    headers = _diff_headers(before.headers, after.headers)
    entities = _diff_entities(before, after)
    risk_delta = after.risk_score - before.risk_score

    summary = {
        "new_findings": len(findings["new"]),
        "removed_findings": len(findings["removed"]),
        "changed_findings": len(findings["changed"]),
        "still_open_findings": len(findings["still_open"]),
        "ports_opened": len(ports["opened"]),
        "ports_closed": len(ports["closed"]),
        "ports_changed": len(ports["changed"]),
        "dns_added": len(dns["added"]),
        "dns_removed": len(dns["removed"]),
        "endpoints_added": len(endpoints["added"]),
        "endpoints_removed": len(endpoints["removed"]),
        "technologies_added": len(technologies["added"]),
        "technologies_removed": len(technologies["removed"]),
        "headers_added": len(headers["added"]),
        "headers_removed": len(headers["removed"]),
        "headers_changed": len(headers["changed"]),
        "entities_added": len(entities["added"]),
        "entities_removed": len(entities["removed"]),
        "entities_changed": len(entities["changed"]),
        "risk_before": before.risk_score,
        "risk_after": after.risk_score,
        "risk_delta": risk_delta,
    }
    summary["has_changes"] = any(
        summary[key]
        for key in (
            "new_findings",
            "removed_findings",
            "changed_findings",
            "ports_opened",
            "ports_closed",
            "ports_changed",
            "dns_added",
            "dns_removed",
            "endpoints_added",
            "endpoints_removed",
            "technologies_added",
            "technologies_removed",
            "headers_added",
            "headers_removed",
            "headers_changed",
            "entities_added",
            "entities_removed",
            "entities_changed",
        )
    ) or risk_delta != 0

    return {
        "left": before.summary(),
        "right": after.summary(),
        "summary": summary,
        "findings": findings,
        "entities": entities,
        "ports": ports,
        "dns": dns,
        "endpoints": endpoints,
        "technologies": technologies,
        "headers": headers,
        "risk": {
            "before": before.risk_score,
            "after": after.risk_score,
            "level_before": before.risk_level,
            "level_after": after.risk_level,
            "delta": risk_delta,
            "direction": (
                "increased" if risk_delta > 0 else "decreased" if risk_delta < 0 else "unchanged"
            ),
        },
    }


def diff_selectors(session: Session, left: str, right: str) -> dict:
    before = build_state(session, left)
    after = build_state(session, right)
    return diff_states(before, after)


def selector_options(session: Session) -> list[dict]:
    """Selector choices for the UI, newest first, already labelled."""
    programs = session.exec(select(Program).order_by(Program.name)).all()
    groups = [
        {
            "label": "Programs",
            "options": [
                {"value": f"program:{p.id}", "label": p.name} for p in programs
            ],
        }
    ]
    pastes = session.exec(select(Paste).order_by(Paste.id.desc()).limit(50)).all()
    groups.append(
        {
            "label": "Recent captures",
            "options": [
                {
                    "value": f"paste:{p.id}",
                    "label": f"#{p.id} · {p.source} · {_iso(p.created_at)[:16].replace('T', ' ')}",
                }
                for p in pastes
            ],
        }
    )
    targets = session.exec(select(Target).order_by(Target.name).limit(200)).all()
    groups.append(
        {
            "label": "Targets",
            "options": [
                {"value": f"target:{t.id}", "label": t.name} for t in targets
            ],
        }
    )
    jobs = session.exec(select(ScanJob).order_by(ScanJob.id.desc()).limit(50)).all()
    groups.append(
        {
            "label": "Jobs",
            "options": [
                {
                    "value": f"job:{j.id}",
                    "label": f"#{j.id} · {j.target or j.runner or 'scan'} · {j.status}",
                }
                for j in jobs
            ],
        }
    )
    return groups


def diff_to_markdown(diff: dict) -> str:
    """Human-readable diff for CLI/export. Stable enough to attach to a report."""
    left = diff["left"]
    right = diff["right"]
    summary = diff["summary"]
    lines = [
        f"# Diff: {left['label']} → {right['label']}",
        "",
        f"- Left: `{left['selector']}` ({left['entities']} entities, {left['findings']} findings)",
        f"- Right: `{right['selector']}` ({right['entities']} entities, {right['findings']} findings)",
        f"- Risk: {summary['risk_before']} → {summary['risk_after']} "
        f"({diff['risk']['direction']}, {summary['risk_delta']:+d})",
        "",
        "## Summary",
        "",
    ]
    for key in (
        "new_findings",
        "removed_findings",
        "changed_findings",
        "still_open_findings",
        "ports_opened",
        "ports_closed",
        "ports_changed",
        "dns_added",
        "dns_removed",
        "endpoints_added",
        "endpoints_removed",
        "technologies_added",
        "technologies_removed",
        "headers_added",
        "headers_removed",
        "headers_changed",
        "entities_added",
        "entities_removed",
        "entities_changed",
    ):
        lines.append(f"- {key.replace('_', ' ')}: {summary.get(key, 0)}")

    def section(title: str, items: list[str]) -> None:
        lines.extend(["", f"## {title}", ""])
        lines.extend(items or ["_None._"])

    section(
        "New findings",
        [
            f"- **{item.get('severity', 'info')}** {item.get('title')} "
            f"({item.get('location') or '—'})"
            for item in diff["findings"]["new"]
        ],
    )
    section(
        "Removed findings",
        [
            f"- **{item.get('severity', 'info')}** {item.get('title')}"
            for item in diff["findings"]["removed"]
        ],
    )
    section(
        "Changed findings",
        [
            f"- {item['key']}: "
            + ", ".join(
                f"{change['field']} {change['before']} → {change['after']}"
                for change in item["changes"]
            )
            for item in diff["findings"]["changed"]
        ],
    )
    section(
        "Ports opened",
        [
            f"- {item['port']} {item.get('service') or ''} {item.get('version') or ''}".rstrip()
            for item in diff["ports"]["opened"]
        ],
    )
    section(
        "Ports closed",
        [f"- {item['port']}" for item in diff["ports"]["closed"]],
    )
    section(
        "Endpoints added",
        [f"- `{value}`" for value in diff["endpoints"]["added"]],
    )
    section(
        "Endpoints removed",
        [f"- `{value}`" for value in diff["endpoints"]["removed"]],
    )
    if diff["entities"]["available"]:
        section(
            "Entities added",
            [
                f"- `{item['type']}` {item['value']}"
                for item in diff["entities"]["added"][:200]
            ],
        )
        section(
            "Entities removed",
            [
                f"- `{item['type']}` {item['value']}"
                for item in diff["entities"]["removed"][:200]
            ],
        )
    return "\n".join(lines) + "\n"
