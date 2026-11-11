from datetime import datetime, timezone

from sqlmodel import Session, or_, select

from .models import Entity, Finding, Program, Relationship, Target
from .redaction import RedactionPolicy
from .triage import triage_snapshot_fields

# Entity types whose raw values are dangerous to share. Masked in all
# downloadable reports unless reveal=True (UI tables and API stay verbatim).
SENSITIVE_TYPES = {"secret", "credential", "jwt"}


def mask_value(entity_type: str, value: str) -> str:
    if entity_type not in SENSITIVE_TYPES:
        return value
    if len(value) <= 8:
        return "[redacted]"
    return f"{value[:4]}…{value[-2:]}  [masked]"


def _policy(mask: bool) -> RedactionPolicy:
    """Default-on policy shared by every downloadable format.

    ``mask=False`` is the explicit ``reveal`` path. Keeping this in one helper
    means a new exporter cannot quietly ship raw finding text.
    """
    return RedactionPolicy(enabled=mask)

TYPE_ORDER = [
    "domain", "subdomain", "wildcard", "ip", "cidr", "dns_record",
    "port", "service", "tech", "url", "endpoint", "path", "param",
    "credential", "secret", "jwt", "hash", "cve", "email",
    "header", "cookie", "http_status",
]

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}

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


def severity_counts(findings) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.severity or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    ordered = {
        severity: counts[severity]
        for severity in SEVERITY_ORDER
        if counts.get(severity)
    }
    ordered.update(
        {key: value for key, value in counts.items() if key not in ordered}
    )
    return ordered


def finding_is_verified(finding) -> bool:
    tags = {
        str(tag).strip().lower()
        for tag in (getattr(finding, "tags", None) or [])
    }
    return bool(tags & {"applicability-verified", "verified", "local-nvd"})


def filter_findings(findings, include_triaged: bool = False):
    """Drop false-positive findings from deliverables unless explicitly asked.

    Ignored entities are already excluded by ``collect``. This function is the
    single switch the report exporters and PDF use, so an analyst's false
    positive decision cannot silently resurface in a client report.
    """
    if include_triaged:
        return list(findings or [])
    return [
        finding
        for finding in (findings or [])
        if not triage_snapshot_fields(finding)["is_false_positive"]
    ]


def risk_explanation(finding) -> str:
    """One-line, analyst-facing explanation of what a finding's severity means."""
    tags = {
        str(tag).strip().lower()
        for tag in (getattr(finding, "tags", None) or [])
    }
    if finding_is_verified(finding):
        return (
            "Locally verified by CPE/version-range correlation; confirm exposure "
            "and exploitability before submitting."
        )
    if "candidate" in tags:
        return (
            "Candidate pattern/header match only; manual review is required "
            "before treating it as a vulnerability."
        )
    severity = str(getattr(finding, "severity", "info") or "info").lower()
    return {
        "critical": "Remotely exploitable impact with little or no precondition; triage first.",
        "high": "Serious confidentiality, integrity or availability impact; triage early.",
        "medium": "Requires conditions or has limited impact; validate during the engagement.",
        "low": "Defence-in-depth or low-impact observation; fix when practical.",
        "info": "Informational observation; no direct security impact is claimed.",
    }.get(severity, "Unclassified finding; review the evidence before trusting the severity.")


def highlights(findings, limit: int = 5) -> list[dict]:
    """Top findings with a short risk explanation, ordered by severity."""
    ordered = sorted(
        findings or [],
        key=lambda finding: (
            SEVERITY_RANK.get(str(getattr(finding, "severity", "info")).lower(), 99),
            str(getattr(finding, "title", "")).lower(),
        ),
    )
    out: list[dict] = []
    for finding in ordered[: max(0, limit)]:
        out.append(
            {
                "title": finding.title,
                "severity": str(finding.severity or "info").lower(),
                "cvss": finding.cvss,
                "status": finding.status,
                "verified": finding_is_verified(finding),
                "explanation": risk_explanation(finding),
            }
        )
    return out


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


def to_dict(
    session: Session,
    program_id: int,
    mask: bool = True,
    include_triaged: bool = False,
) -> dict:
    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return {}
    findings = filter_findings(findings, include_triaged)
    policy = _policy(mask)
    return {
        "program": {
            "id": program.id,
            "name": policy.text(program.name),
            "platform": policy.text(program.platform or ""),
            "scope_in": policy.text(program.scope_in or ""),
            "scope_out": policy.text(program.scope_out or ""),
        },
        "targets": [
            {
                "id": t.id,
                "name": policy.text(t.name),
                "kind": t.kind,
                "notes": policy.text(t.notes or ""),
            }
            for t in targets
        ],
        "entities": [
            {
                "type": e.type,
                "value": policy.value(e.type, e.value),
                "normalized": policy.value(e.type, e.normalized or ""),
                "parser": e.parser,
                "confidence": e.confidence,
                "target_id": e.target_id,
                "verdict": e.verdict,
                "tags": [policy.text(tag) for tag in (e.tags or [])],
                "meta": policy.dict(e.meta or {}),
            }
            for e in entities
        ],
        "entities_by_type": {
            etype: [policy.value(etype, e.value) for e in items]
            for etype, items in group_entities(entities).items()
        },
        "relationships": [
            {
                "src": policy.value(r.src_type, r.src_value),
                "src_type": r.src_type,
                "rel": r.rel_type,
                "dst": policy.value(r.dst_type, r.dst_value),
                "dst_type": r.dst_type,
            }
            for r in relationships
        ],
        "summary": {
            "findings": len(findings),
            "findings_by_severity": severity_counts(findings),
            "verified_findings": sum(1 for f in findings if finding_is_verified(f)),
        },
        "highlights": [
            {
                **item,
                "title": policy.text(item["title"]),
                "explanation": policy.text(item["explanation"]),
            }
            for item in highlights(findings)
        ],
        "findings": [
            {
                "id": f.id,
                "title": policy.text(f.title),
                "severity": f.severity,
                "status": f.status,
                "verdict": f.verdict,
                **triage_snapshot_fields(f),
                "cvss": policy.text(f.cvss or ""),
                "description": policy.text(f.description or ""),
                "steps": policy.text(f.steps or ""),
                "impact": policy.text(f.impact or ""),
                "evidence": policy.text(f.evidence or ""),
                "remediation": policy.text(f.remediation or ""),
                "tags": [policy.text(tag) for tag in (f.tags or [])],
                "verified": finding_is_verified(f),
            }
            for f in findings
        ],
        "redaction": policy.describe(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def to_markdown(
    session: Session,
    program_id: int,
    mask: bool = True,
    include_triaged: bool = False,
) -> str:
    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return ""
    findings = filter_findings(findings, include_triaged)
    policy = _policy(mask)
    program_name = policy.text(program.name)
    lines: list[str] = []
    lines.append(f"# {program_name}")
    lines.append("")
    if program.platform:
        lines.append(f"- **Platform:** {policy.text(program.platform)}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    if mask:
        lines.append(
            "- **Note:** auth headers, cookies, tokens and secret values are masked "
            "in this export."
        )
    lines.append("")

    if findings:
        counts = severity_counts(findings)
        verified = sum(1 for finding in findings if finding_is_verified(finding))
        lines.append("## Highlights")
        lines.append("")
        summary = ", ".join(
            f"{severity} × {count}" for severity, count in counts.items()
        ) or "none"
        lines.append(f"**Risk summary:** {summary}.")
        if verified:
            lines.append(
                f"**Verified:** {verified} finding(s) passed a local CPE/version "
                "applicability check; the rest still require manual review."
            )
        lines.append("")
        top = highlights(findings)
        for item in top:
            flag = " *(verified)*" if item["verified"] else ""
            lines.append(
                f"- **{item['severity'].upper()}** — {policy.text(item['title'])}{flag}: "
                f"{policy.text(item['explanation'])}"
            )
        if len(findings) > len(top):
            lines.append(f"- …and {len(findings) - len(top)} more in Findings below.")
        lines.append("")

    if program.scope_in or program.scope_out:
        lines.append("## Scope")
        lines.append("")
        if program.scope_in:
            lines.append("**In scope**")
            lines.append("")
            for item in program.scope_in.splitlines():
                if item.strip():
                    lines.append(f"- {policy.text(item.strip())}")
            lines.append("")
        if program.scope_out:
            lines.append("**Out of scope**")
            lines.append("")
            for item in program.scope_out.splitlines():
                if item.strip():
                    lines.append(f"- {policy.text(item.strip())}")
            lines.append("")

    if targets:
        lines.append("## Targets")
        lines.append("")
        for target in targets:
            lines.append(f"- `{policy.text(target.name)}` ({target.kind})")
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
                    detail = f"  _({policy.text(detail)})_" if detail else ""
                elif etype in {"credential", "secret", "hash"}:
                    kind = entity.meta.get("kind") or entity.meta.get("algo") or ""
                    detail = f"  _({policy.text(kind)})_" if kind else ""
                lines.append(f"- `{policy.value(etype, entity.value)}`{detail}")
            lines.append("")

    if relationships:
        lines.append("## Relationships")
        lines.append("")
        for rel in relationships:
            lines.append(
                f"- `{policy.value(rel.src_type, rel.src_value)}` "
                f"--{rel.rel_type}--> `{policy.value(rel.dst_type, rel.dst_value)}`"
            )
        lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        for finding in findings:
            lines.append(
                f"### [{str(finding.severity).upper()}] {policy.text(finding.title)}"
            )
            lines.append("")
            triage = triage_snapshot_fields(finding)
            if triage["triage_status"] != "open":
                lines.append(
                    f"**Triage:** {triage['triage_status'].replace('_', ' ')} "
                    f"(status `{finding.status}`, verdict `{triage['verdict']}`)"
                )
                lines.append("")
            if finding.description:
                lines.append(policy.text(finding.description))
                lines.append("")
            if finding.evidence:
                lines.append("**Evidence**")
                lines.append("")
                lines.append("```")
                lines.append(policy.text(finding.evidence))
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
    policy = _policy(mask)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["type", "value", "normalized", "parser", "confidence",
         "scope_status", "occurrences", "program_id", "target_id", "paste_id"]
    )
    for e in entities:
        writer.writerow(
            [e.type, policy.value(e.type, e.value),
             policy.value(e.type, e.normalized or ""), e.parser,
             e.confidence, e.scope_status, e.occurrences,
             e.program_id, e.target_id, e.paste_id]
        )
    return buf.getvalue()


def targets_txt(session: Session, program_id: int, mask: bool = True) -> str:
    """Unique in-scope host-ish values, one per line — ready for `nuclei -l` / `httpx -l`."""
    program, targets, entities, _, _ = collect(session, program_id)
    if program is None:
        return ""
    policy = _policy(mask)
    names = {policy.text(t.name) for t in targets}
    for e in entities:
        if e.scope_status == "in" and e.type in ("domain", "subdomain", "ip", "url"):
            names.add(policy.value(e.type, e.value))
    return "".join(f"{name}\n" for name in sorted(names))


def to_hackerone(
    session: Session,
    program_id: int,
    include_triaged: bool = False,
    mask: bool = True,
) -> str:
    """Submission-friendly markdown: summary, scope, findings with repro sections, assets."""
    program, targets, entities, _, findings = collect(session, program_id)
    if program is None:
        return ""
    findings = filter_findings(findings, include_triaged)
    policy = _policy(mask)
    lines: list[str] = []
    lines.append(f"# Security report: {policy.text(program.name)}")
    lines.append("")
    if program.platform:
        lines.append(f"Submitted via {policy.text(program.platform)}.")
        lines.append("")
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(
        findings, key=lambda f: (rank.get(str(f.severity).lower(), 9), f.title)
    )
    if ordered:
        counts: dict[str, int] = {}
        for f in ordered:
            severity = str(f.severity).lower()
            counts[severity] = counts.get(severity, 0) + 1
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
            lines.append(f"- `{policy.text(target.name)}` ({target.kind})")
        lines.append("")

    for i, finding in enumerate(ordered, 1):
        lines.append(
            f"## {i}. [{str(finding.severity).upper()}] {policy.text(finding.title)}"
        )
        lines.append("")
        if finding.description:
            lines.append("### Description")
            lines.append("")
            lines.append(policy.text(finding.description))
            lines.append("")
        if finding.steps:
            lines.append("### Steps to reproduce")
            lines.append("")
            lines.append(policy.text(finding.steps))
            lines.append("")
        if finding.impact:
            lines.append("### Impact")
            lines.append("")
            lines.append(policy.text(finding.impact))
            lines.append("")
        if finding.evidence:
            lines.append("### Supporting material")
            lines.append("")
            lines.append("```")
            lines.append(policy.text(finding.evidence))
            lines.append("```")
            lines.append("")
        if finding.remediation:
            lines.append("### Remediation")
            lines.append("")
            lines.append(policy.text(finding.remediation))
            lines.append("")

    lines.append("---")
    lines.append(f"Generated by Breadcrumb on {datetime.now(timezone.utc).isoformat()}.")
    if mask:
        lines.append(
            "Auth headers, cookies, tokens and secret values are masked in this export."
        )
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


def to_sarif(
    session: Session,
    program_id: int,
    mask: bool = True,
    include_triaged: bool = False,
) -> dict:
    """SARIF 2.1.0 for CI/SAST dashboards (GitHub code scanning, etc.).

    Findings become results; entity/relationship inventory rides along in
    run.properties so a downstream tool can still see the recon context.
    """
    from . import __version__

    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return {}
    findings = filter_findings(findings, include_triaged)
    policy = _policy(mask)
    target_names = {t.id: policy.text(t.name) for t in targets}

    rules: dict[str, dict] = {}
    results: list[dict] = []
    level_rank = {"error": 0, "warning": 1, "note": 2}
    for finding in findings:
        safe_title = policy.text(finding.title)
        rule_id = f"breadcrumb/{_slug(safe_title)}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": safe_title,
                "shortDescription": {"text": safe_title},
                "defaultConfiguration": {
                    "level": _SEV_TO_LEVEL.get(str(finding.severity).lower(), "note")
                },
                "properties": {
                    "severity": finding.severity,
                    "tags": [policy.text(tag) for tag in (finding.tags or [])],
                },
            },
        )
        location = target_names.get(finding.target_id) or policy.text(program.name)
        message = policy.text(finding.description or finding.title)
        if finding.impact:
            message = f"{message}\n\nImpact: {policy.text(finding.impact)}"
        results.append(
            {
                "ruleId": rule_id,
                "level": _SEV_TO_LEVEL.get(str(finding.severity).lower(), "note"),
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
                    **triage_snapshot_fields(finding),
                    "tags": [policy.text(tag) for tag in (finding.tags or [])],
                    "evidence": policy.text(finding.evidence or "") if not mask else None,
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
                    "program": {"id": program.id, "name": policy.text(program.name)},
                    "entity_count": len(entities),
                    "relationship_count": len(relationships),
                    "redaction": policy.describe(),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            }
        ],
    }



# --------------------------------------------------------- integrations ----
# The exports below target the importers real teams already run. They consume
# the same redacted finding/entity data as the built-in formats, so enabling an
# integration never widens what leaves the machine.

_DD_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
_DD_NUMERICAL = {
    "critical": "S0",
    "high": "S1",
    "medium": "S2",
    "low": "S3",
    "info": "S4",
}
_GHOSTWRITER_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}


def _finding_location(finding) -> str:
    meta = finding.meta or {}
    for key in ("location", "matched_at", "url", "host"):
        value = meta.get(key)
        if value:
            return str(value)
    evidence = (finding.evidence or "").strip()
    if not evidence:
        return ""
    return (
        evidence.split("  [", 1)[0]
        .split("  ->", 1)[0]
        .splitlines()[0]
        .strip()
    )


def _finding_cve(finding) -> str:
    import re

    meta = finding.meta or {}
    for key in ("cve", "cve_id"):
        if meta.get(key):
            return str(meta[key])
    match = re.search(
        r"\bCVE-\d{4}-\d{4,}\b",
        " ".join(
            [str(finding.title or ""), str(finding.evidence or "")]
            + [str(tag) for tag in (finding.tags or [])]
        ),
    )
    return match.group(0) if match else ""


def _export_findings(session: Session, program_id: int, mask: bool, include_triaged: bool):
    program, targets, entities, relationships, findings = collect(session, program_id)
    if program is None:
        return None, [], []
    policy = _policy(mask)
    findings = filter_findings(findings, include_triaged)

    def sort_key(finding):
        return (
            SEVERITY_RANK.get(str(finding.severity or "info").lower(), 9),
            str(finding.title or "").lower(),
        )

    return program, sorted(findings, key=sort_key), policy


def to_defectdojo(
    session: Session,
    program_id: int,
    mask: bool = True,
    include_triaged: bool = False,
) -> dict:
    """DefectDojo Generic Findings Import JSON.

    This is the object form the ``Generic Findings Import`` parser expects: a
    ``findings`` list plus test metadata. ``endpoints`` is intentionally a list
    of URI strings, which the parser accepts and strips before field
    validation. Only fields the parser allows are emitted.
    """
    from . import __version__

    program, findings, policy = _export_findings(
        session, program_id, mask, include_triaged
    )
    if program is None:
        return {}
    program_name = policy.text(program.name)
    items: list[dict] = []
    for finding in findings:
        severity = str(finding.severity or "info").lower()
        if severity not in _DD_SEVERITY:
            severity = "info"
        triage = triage_snapshot_fields(finding)
        description = policy.text(finding.description or finding.title or "")
        if not description.strip():
            description = "No description was recorded in the Breadcrumb capture."
        item = {
            "title": policy.text(finding.title or "Untitled finding")[:511],
            "severity": _DD_SEVERITY[severity],
            "description": description,
            "date": (
                finding.created_at.date().isoformat()
                if finding.created_at
                else datetime.now(timezone.utc).date().isoformat()
            ),
            "active": triage["triage_status"] not in {"resolved", "false_positive"},
            "verified": finding_is_verified(finding),
            "false_p": bool(triage["is_false_positive"]),
            "duplicate": False,
            "out_of_scope": False,
            "risk_accepted": False,
            "under_review": triage["triage_status"] in {"acknowledged", "needs_review"},
            "numerical_severity": _DD_NUMERICAL[severity],
            "unique_id_from_tool": f"breadcrumb-{program.id}-{finding.id}",
            "static_finding": False,
            "dynamic_finding": True,
            "service": program_name[:200],
        }
        if finding.rule_id:
            item["vuln_id_from_tool"] = policy.text(finding.rule_id)[:200]
        if finding.impact:
            item["impact"] = policy.text(finding.impact)
        if finding.steps:
            item["steps_to_reproduce"] = policy.text(finding.steps)
        if finding.remediation:
            item["mitigation"] = policy.text(finding.remediation)
        if finding.cvss:
            cvss = policy.text(finding.cvss).strip()
            if cvss.upper().startswith("CVSS:"):
                item["cvssv3"] = cvss
            else:
                try:
                    item["cvssv3_score"] = float(cvss)
                except ValueError:
                    item["severity_justification"] = f"CVSS: {cvss}"
        meta = finding.meta or {}
        cwe = meta.get("cwe")
        if cwe is not None:
            import re

            match = re.search(r"\d+", str(cwe))
            if match:
                item["cwe"] = int(match.group(0))
        cve = _finding_cve(finding)
        if cve:
            item["cve"] = policy.text(cve)
        location = policy.text(_finding_location(finding)).strip()
        if location:
            item["endpoints"] = [location]
        tags = [policy.text(tag) for tag in (finding.tags or []) if str(tag).strip()]
        if tags:
            item["tags"] = tags[:50]
        items.append(item)
    return {
        "name": f"Breadcrumb — {program_name}",
        "type": "Generic Findings Import",
        "version": __version__,
        "findings": items,
    }


def to_ghostwriter(
    session: Session,
    program_id: int,
    mask: bool = True,
    include_triaged: bool = False,
) -> dict:
    """Ghostwriter/Dradis-friendly JSON, mapped to their finding vocabulary.

    Ghostwriter imports findings through its API/templates rather than a single
    documented file schema, so this object keeps the field names its models and
    report templates use (title, severity, finding_type, description, impact,
    mitigation, replication_steps, references, affected_entities). Dradis users
    can pair it with :func:`to_dradis_markdown`.
    """
    from . import __version__

    program, findings, policy = _export_findings(
        session, program_id, mask, include_triaged
    )
    if program is None:
        return {}
    items: list[dict] = []
    for finding in findings:
        severity = str(finding.severity or "info").lower()
        if severity not in _GHOSTWRITER_SEVERITY:
            severity = "info"
        triage = triage_snapshot_fields(finding)
        location = policy.text(_finding_location(finding)).strip()
        item = {
            "title": policy.text(finding.title or "Untitled finding"),
            "severity": _GHOSTWRITER_SEVERITY[severity],
            "finding_type": "Network",
            "description": policy.text(finding.description or ""),
            "impact": policy.text(finding.impact or ""),
            "mitigation": policy.text(finding.remediation or ""),
            "replication_steps": policy.text(finding.steps or ""),
            "references": policy.text(str((finding.meta or {}).get("references") or "")),
            "affected_entities": [location] if location else [],
            "tags": [policy.text(tag) for tag in (finding.tags or [])],
            "verified": finding_is_verified(finding),
            "status": finding.status,
            "triage_status": triage["triage_status"],
            "cve": policy.text(_finding_cve(finding)),
            "cvss": policy.text(finding.cvss or ""),
            "source": policy.text(finding.source_tool or ""),
        }
        items.append(item)
    return {
        "format": "breadcrumb.ghostwriter",
        "format_version": 1,
        "generator": {"name": "breadcrumb", "version": __version__},
        "project": {
            "name": policy.text(program.name),
            "platform": policy.text(program.platform or ""),
            "scope_in": policy.text(program.scope_in or ""),
            "scope_out": policy.text(program.scope_out or ""),
        },
        "redaction": policy.describe(),
        "findings": items,
    }


def _dradis_value(value) -> str:
    """Keep a value from starting a new ``#[Field]#`` block in Dradis notes."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    for line in text.split("\n"):
        if line.lstrip().startswith("#["):
            line = " " + line
        lines.append(line)
    return "\n".join(lines).strip()


def to_dradis_markdown(
    session: Session,
    program_id: int,
    mask: bool = True,
    include_triaged: bool = False,
) -> str:
    """Dradis note import: ``#[Field]#`` blocks, one note per finding."""
    return _to_field_markdown(
        session,
        program_id,
        mask=mask,
        include_triaged=include_triaged,
        title_field="Title",
        replication_field="Replication Steps",
        remediation_field="Remediation",
        prefix="Dradis",
    )


def _to_field_markdown(
    session: Session,
    program_id: int,
    *,
    mask: bool,
    include_triaged: bool,
    title_field: str,
    replication_field: str,
    remediation_field: str,
    prefix: str,
) -> str:
    program, findings, policy = _export_findings(
        session, program_id, mask, include_triaged
    )
    if program is None:
        return ""
    lines = [
        f"#[{title_field}]#",
        _dradis_value(f"{policy.text(program.name)} — Breadcrumb findings"),
        "",
        "#[Program]#",
        _dradis_value(policy.text(program.name)),
        "",
        "#[Platform]#",
        _dradis_value(policy.text(program.platform or "")),
        "",
        "#[Redaction]#",
        "Default-on: auth headers, cookies, tokens and secret values are masked."
        if mask
        else "WARNING: masking disabled (reveal).",
        "",
    ]
    for finding in findings:
        severity = str(finding.severity or "info").lower()
        lines += [
            f"#[{title_field}]#",
            _dradis_value(policy.text(finding.title or "Untitled finding")),
            "",
            "#[Severity]#",
            _DD_SEVERITY.get(severity, "Info"),
            "",
            "#[Description]#",
            _dradis_value(policy.text(finding.description or "")),
            "",
            "#[Impact]#",
            _dradis_value(policy.text(finding.impact or "")),
            "",
            f"#[{replication_field}]#",
            _dradis_value(policy.text(finding.steps or "")),
            "",
            "#[Affected Hosts]#",
            _dradis_value(policy.text(_finding_location(finding))),
            "",
            f"#[{remediation_field}]#",
            _dradis_value(policy.text(finding.remediation or "")),
            "",
            "#[Tags]#",
            _dradis_value(" ".join(str(tag) for tag in (finding.tags or []))),
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"
