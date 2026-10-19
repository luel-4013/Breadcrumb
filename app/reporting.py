from datetime import datetime, timezone

from sqlmodel import Session, or_, select

from .models import Entity, Finding, Program, Relationship, Target

# Entity types whose raw values are dangerous to share. Masked in all
# downloadable reports unless reveal=True (UI tables and API stay verbatim).
SENSITIVE_TYPES = {"secret", "credential", "jwt"}


def mask_value(entity_type: str, value: str) -> str:
    if entity_type not in SENSITIVE_TYPES:
        return value
    if len(value) <= 8:
        return "[redacted]"
    return f"{value[:4]}…{value[-2:]}  [masked]"

TYPE_ORDER = [
    "domain", "subdomain", "wildcard", "ip", "cidr", "dns_record",
    "port", "service", "tech", "url", "endpoint", "path", "param",
    "credential", "secret", "jwt", "hash", "cve", "email",
    "header", "cookie", "http_status",
]

TYPE_LABELS = {
    "domain": "Domains",
    "subdomain": "Subdomains",
    "wildcard": "Wildcard Zones",
    "ip": "IP Addresses",
    "cidr": "CIDR Ranges",
    "dns_record": "DNS Records",
    "port": "Ports",
    "service": "Services",
    "tech": "Technologies",
    "url": "URLs",
    "endpoint": "Endpoints",
    "path": "Paths",
    "param": "Parameters",
    "credential": "Credentials",
    "secret": "Secrets",
    "jwt": "JWTs",
    "hash": "Hashes",
    "cve": "CVEs",
    "email": "Emails",
    "header": "Headers",
    "cookie": "Cookies",
    "http_status": "HTTP Statuses",
}


def type_rank(entity_type: str) -> int:
    try:
        return TYPE_ORDER.index(entity_type)
    except ValueError:
        return len(TYPE_ORDER)


def group_entities(entities):
    groups: dict[str, list] = {}
    for entity in entities:
        groups.setdefault(entity.type, []).append(entity)
    for items in groups.values():
        items.sort(key=lambda item: item.value.lower())
    return dict(sorted(groups.items(), key=lambda kv: type_rank(kv[0])))


def collect(session: Session, program_id: int, include_ignored: bool = False):
    program = session.get(Program, program_id)
    targets = session.exec(
        select(Target).where(Target.program_id == program_id).order_by(Target.name)
    ).all()
    stmt = select(Entity).where(Entity.program_id == program_id)
    excluded: set = set()
    if not include_ignored:
        stmt = stmt.where(Entity.ignored == False)  # noqa: E712
        # analyst-marked false positives never pollute a deliverable
        stmt = stmt.where(
            or_(Entity.verdict.is_(None), Entity.verdict != "false-positive")
        )
        excluded = set(
            session.exec(
                select(Entity.type, Entity.value).where(
                    Entity.program_id == program_id,
                    or_(Entity.ignored == True,  # noqa: E712
                        Entity.verdict == "false-positive"),
                )
            ).all()
        )
    entities = session.exec(stmt.order_by(Entity.type, Entity.value)).all()
    relationships = session.exec(
        select(Relationship).where(Relationship.program_id == program_id)
    ).all()
    if excluded:
        relationships = [
            r for r in relationships
            if (r.src_type, r.src_value) not in excluded
            and (r.dst_type, r.dst_value) not in excluded
        ]
    findings = session.exec(
        select(Finding).where(Finding.program_id == program_id)
    ).all()
    return program, targets, entities, relationships, findings


def to_dict(session: Session, program_id: int, mask: bool = True) -> dict:
    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return {}
    show = (lambda t, v: v) if not mask else mask_value
    return {
        "program": {
            "id": program.id,
            "name": program.name,
            "platform": program.platform,
            "scope_in": program.scope_in,
            "scope_out": program.scope_out,
        },
        "targets": [
            {"id": t.id, "name": t.name, "kind": t.kind, "notes": t.notes} for t in targets
        ],
        "entities": [
            {
                "type": e.type,
                "value": show(e.type, e.value),
                "normalized": e.normalized,
                "parser": e.parser,
                "confidence": e.confidence,
                "target_id": e.target_id,
                "verdict": e.verdict,
                "tags": e.tags or [],
                "meta": e.meta,
            }
            for e in entities
        ],
        "entities_by_type": {
            etype: [show(etype, e.value) for e in items]
            for etype, items in group_entities(entities).items()
        },
        "relationships": [
            {
                "src": r.src_value,
                "src_type": r.src_type,
                "rel": r.rel_type,
                "dst": r.dst_value,
                "dst_type": r.dst_type,
            }
            for r in relationships
        ],
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "cvss": f.cvss,
                "description": f.description,
                "steps": f.steps,
                "impact": f.impact,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def to_markdown(session: Session, program_id: int, mask: bool = True) -> str:
    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return ""
    show = (lambda t, v: v) if not mask else mask_value
    lines: list[str] = []
    lines.append(f"# {program.name}")
    lines.append("")
    if program.platform:
        lines.append(f"- **Platform:** {program.platform}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    if mask:
        lines.append("- **Note:** secret/credential/JWT values are masked in this export.")
    lines.append("")

    if program.scope_in or program.scope_out:
        lines.append("## Scope")
        lines.append("")
        if program.scope_in:
            lines.append("**In scope**")
            lines.append("")
            for item in program.scope_in.splitlines():
                if item.strip():
                    lines.append(f"- {item.strip()}")
            lines.append("")
        if program.scope_out:
            lines.append("**Out of scope**")
            lines.append("")
            for item in program.scope_out.splitlines():
                if item.strip():
                    lines.append(f"- {item.strip()}")
            lines.append("")

    if targets:
        lines.append("## Targets")
        lines.append("")
        for target in targets:
            lines.append(f"- `{target.name}` ({target.kind})")
        lines.append("")

    groups = group_entities(entities)
    if groups:
        lines.append("## Findings Data")
        lines.append("")
        for etype, items in groups.items():
            lines.append(f"### {TYPE_LABELS.get(etype, etype.title())} ({len(items)})")
            lines.append("")
            for entity in items:
                detail = ""
                if etype == "port":
                    service = entity.meta.get("service") or ""
                    version = entity.meta.get("version") or ""
                    detail = " ".join(x for x in (service, version) if x)
                    detail = f"  _({detail})_" if detail else ""
                elif etype in {"credential", "secret", "hash"}:
                    kind = entity.meta.get("kind") or entity.meta.get("algo") or ""
                    detail = f"  _({kind})_" if kind else ""
                lines.append(f"- `{show(etype, entity.value)}`{detail}")
            lines.append("")

    if relationships:
        lines.append("## Relationships")
        lines.append("")
        for rel in relationships:
            lines.append(f"- `{rel.src_value}` --{rel.rel_type}--> `{rel.dst_value}`")
        lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        for finding in findings:
            lines.append(f"### [{finding.severity.upper()}] {finding.title}")
            lines.append("")
            if finding.description:
                lines.append(finding.description)
                lines.append("")
            if finding.evidence:
                lines.append("**Evidence**")
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence)
                lines.append("```")
                lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def to_csv(session: Session, program_id: int, mask: bool = True) -> str:
    """Flat entity inventory: type,value,normalized,parser,confidence,scope,occurrences,..."""
    import csv
    import io

    program, _, entities, _, _ = collect(session, program_id)
    if program is None:
        return ""
    show = (lambda t, v: v) if not mask else mask_value
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["type", "value", "normalized", "parser", "confidence",
         "scope_status", "occurrences", "program_id", "target_id", "paste_id"]
    )
    for e in entities:
        writer.writerow(
            [e.type, show(e.type, e.value), e.normalized, e.parser,
             e.confidence, e.scope_status, e.occurrences,
             e.program_id, e.target_id, e.paste_id]
        )
    return buf.getvalue()


def targets_txt(session: Session, program_id: int) -> str:
    """Unique in-scope host-ish values, one per line — ready for `nuclei -l` / `httpx -l`."""
    program, targets, entities, _, _ = collect(session, program_id)
    if program is None:
        return ""
    names = {t.name for t in targets}
    for e in entities:
        if e.scope_status == "in" and e.type in ("domain", "subdomain", "ip", "url"):
            names.add(e.value)
    return "".join(f"{name}\n" for name in sorted(names))


def to_hackerone(session: Session, program_id: int) -> str:
    """Submission-friendly markdown: summary, scope, findings with repro sections, assets."""
    program, targets, entities, _, findings = collect(session, program_id)
    if program is None:
        return ""
    lines: list[str] = []
    lines.append(f"# Security report: {program.name}")
    lines.append("")
    if program.platform:
        lines.append(f"Submitted via {program.platform}.")
        lines.append("")
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(findings, key=lambda f: (rank.get(f.severity, 9), f.title))
    if ordered:
        counts: dict[str, int] = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines.append("## Summary")
        lines.append("")
        lines.append(
            f"{len(ordered)} finding(s): "
            + ", ".join(
                f"{sev} × {n}"
                for sev, n in sorted(counts.items(), key=lambda kv: rank.get(kv[0], 9))
            )
            + "."
        )
        lines.append("")

    if targets:
        lines.append("## Affected assets")
        lines.append("")
        for target in targets:
            lines.append(f"- `{target.name}` ({target.kind})")
        lines.append("")

    for i, finding in enumerate(ordered, 1):
        lines.append(f"## {i}. [{finding.severity.upper()}] {finding.title}")
        lines.append("")
        if finding.description:
            lines.append("### Description")
            lines.append("")
            lines.append(finding.description)
            lines.append("")
        if finding.steps:
            lines.append("### Steps to reproduce")
            lines.append("")
            lines.append(finding.steps)
            lines.append("")
        if finding.impact:
            lines.append("### Impact")
            lines.append("")
            lines.append(finding.impact)
            lines.append("")
        if finding.evidence:
            lines.append("### Supporting material")
            lines.append("")
            lines.append("```")
            lines.append(finding.evidence)
            lines.append("```")
            lines.append("")
        if finding.remediation:
            lines.append("### Remediation")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")

    lines.append("---")
    lines.append(f"Generated by Breadcrumb on {datetime.now(timezone.utc).isoformat()}.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def entity_changes(session: Session, program_id: int):
    """Diff the program's latest capture against everything before it.

    Returns dict with pastes timeline + added/removed (type, value) keys.
    Works without extra tables: entities carry paste_id + created_at.
    """
    from .models import Paste

    pastes = session.exec(
        select(Paste).where(Paste.program_id == program_id).order_by(Paste.id)
    ).all()
    if not pastes:
        return {"pastes": [], "added": [], "removed": [], "latest_id": None}
    latest = pastes[-1]

    def keys_for(paste_ids: list[int]) -> set[tuple[str, str]]:
        if not paste_ids:
            return set()
        rows = session.exec(
            select(Entity.type, Entity.value).where(
                Entity.program_id == program_id,
                Entity.paste_id.in_(paste_ids),
                Entity.ignored == False,  # noqa: E712
                or_(Entity.verdict.is_(None), Entity.verdict != "false-positive"),
            )
        ).all()
        return set(rows)

    before = keys_for([p.id for p in pastes[:-1]])
    now = keys_for([latest.id])
    added = sorted(now - before)
    removed = sorted(before - now)
    timeline = [
        {
            "id": p.id,
            "created_at": p.created_at,
            "parsers": p.parsers or [],
            "source": p.source,
            "entity_count": len(keys_for([p.id])),
        }
        for p in pastes
    ]
    return {
        "pastes": timeline,
        "added": added,
        "removed": removed,
        "latest_id": latest.id,
    }


_SEV_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                 "low": "note", "info": "note"}


def _slug(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in (text or "")]
    slug = "".join(keep).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:60] or "finding"


def to_sarif(session: Session, program_id: int, mask: bool = True) -> dict:
    """SARIF 2.1.0 for CI/SAST dashboards (GitHub code scanning, etc.).

    Findings become results; entity/relationship inventory rides along in
    run.properties so a downstream tool can still see the recon context.
    """
    from . import __version__

    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return {}
    target_names = {t.id: t.name for t in targets}

    rules: dict[str, dict] = {}
    results: list[dict] = []
    level_rank = {"error": 0, "warning": 1, "note": 2}
    for finding in findings:
        rule_id = f"breadcrumb/{_slug(finding.title)}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "defaultConfiguration": {
                    "level": _SEV_TO_LEVEL.get(finding.severity, "note")
                },
                "properties": {"severity": finding.severity, "tags": finding.tags or []},
            },
        )
        location = target_names.get(finding.target_id) or program.name
        message = finding.description or finding.title
        if finding.impact:
            message = f"{message}\n\nImpact: {finding.impact}"
        results.append(
            {
                "ruleId": rule_id,
                "level": _SEV_TO_LEVEL.get(finding.severity, "note"),
                "message": {"text": message},
                "locations": [
                    {"physicalLocation": {
                        "artifactLocation": {"uri": location},
                        "region": {"startLine": 1},
                    }}
                ],
                "properties": {
                    "severity": finding.severity,
                    "status": finding.status,
                    "tags": finding.tags or [],
                    "evidence": finding.evidence if not mask else None,
                },
            }
        )
    results.sort(key=lambda r: level_rank.get(r["level"], 3))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Breadcrumb",
                        "version": __version__,
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "program": {"id": program.id, "name": program.name},
                    "entity_count": len(entities),
                    "relationship_count": len(relationships),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            }
        ],
    }

