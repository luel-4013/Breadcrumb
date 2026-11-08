"""Target history: per-job snapshots and scan-to-scan diffs.

A snapshot is the target state observed when a scan finishes, not just the
delta from that job. Diffing two snapshots therefore answers the question an
operator actually asks: "what changed since the previous scan?".

Snapshots are stored in ``ScanSnapshot.data`` and are always rebuildable from
the sealed captures, entities and findings. A failed rebuild never invalidates
the evidence; the snapshot row records ``pending``/``failed`` instead.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlmodel import Session, or_, select

from .attribution import attribute_target
from .collect.security import SECURITY_HEADERS
from .models import (
    Entity,
    Finding,
    Paste,
    Program,
    ScanJob,
    ScanPhase,
    ScanSnapshot,
    Target,
)
from .triage import triage_snapshot_fields

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
TERMINAL_JOB_STATUSES = {"done", "failed", "cancelled"}
DONE_STATUSES = {"done"}
VERIFIED_TAGS = {"applicability-verified", "verified", "local-nvd"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DNS_VALUE_RE = re.compile(
    r"^(?P<name>\S+)\s+(?:\d+\s+)?(?:IN\s+)?"
    r"(?P<rtype>A|AAAA|CNAME|MX|NS|TXT|SOA|PTR|SRV)\s+(?P<value>.+)$",
    re.IGNORECASE,
)
HEADER_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9\-]*):\s*(?P<value>.+)$", re.MULTILINE)
SECURITY_HEADER_NAMES = {info["name"].lower(): info["name"] for info in SECURITY_HEADERS.values()}
API_PATH_TYPES = {"endpoint", "url", "path", "api_endpoint", "api_candidate"}
CAP_LIST = 1000
CAP_TECH = 500
CAP_HEADER_VALUE = 400


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _normalized_title(value: str | None) -> str:
    return " ".join((value or "").lower().split())


def _tags(finding: Finding) -> set[str]:
    return {str(tag).strip().lower() for tag in (finding.tags or [])}


def finding_is_verified(finding: Finding) -> bool:
    return bool(_tags(finding) & VERIFIED_TAGS)


def _cve_id(finding: Finding) -> str:
    for tag in finding.tags or []:
        match = CVE_RE.search(str(tag))
        if match:
            return match.group(0).upper()
    match = CVE_RE.search(f"{finding.title or ''} {finding.evidence or ''}")
    return match.group(0).upper() if match else ""


def finding_key(finding: Finding) -> str:
    """Stable fingerprint: CVE id first, then the stored dedup fingerprint."""
    cve = _cve_id(finding)
    if cve:
        return f"cve:{cve}"
    if finding.fingerprint:
        return str(finding.fingerprint)
    return (
        f"{finding.source_tool or 'finding'}|"
        f"{(finding.evidence or '').strip()}|"
        f"{_normalized_title(finding.title)}"
    )


def is_active_finding(finding: Finding) -> bool:
    """False positives never influence risk, highlights or "new" findings."""
    return not triage_snapshot_fields(finding)["is_false_positive"]


def is_risk_finding(finding: Finding) -> bool:
    """Active, and not an unverified CVE candidate."""
    if not is_active_finding(finding):
        return False
    tags = _tags(finding)
    if "cve" in tags and not (tags & VERIFIED_TAGS):
        return False
    return True


def serialize_finding(finding: Finding) -> dict:
    triage = triage_snapshot_fields(finding)
    return {
        "id": finding.id,
        "key": finding_key(finding),
        "type": finding.source_tool or "finding",
        "severity": str(finding.severity or "info").lower(),
        "title": finding.title,
        "description": (finding.description or "")[:1200],
        "location": _finding_location(finding),
        "evidence": (finding.evidence or "")[:1200],
        "remediation": (finding.remediation or "")[:1200],
        "status": finding.status,
        "verdict": triage["verdict"],
        "triage_status": triage["triage_status"],
        "is_false_positive": triage["is_false_positive"],
        "tags": list(finding.tags or []),
        "verified": finding_is_verified(finding),
        "cve_id": _cve_id(finding) or None,
        "created_at": _iso(finding.created_at),
        "updated_at": _iso(finding.updated_at),
    }


def _finding_location(finding: Finding) -> str:
    evidence = (finding.evidence or "").strip()
    if not evidence:
        return ""
    # Nuclei evidence is "<matched-at>  [matcher: ...]  -> ..."
    return evidence.split("  [", 1)[0].split("  ->", 1)[0].strip()


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if not is_active_finding(finding):
            continue
        severity = str(finding.severity or "info").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def compute_risk(findings: Iterable[Finding]) -> tuple[int, str]:
    """Explainable 0-100 score: highest tier sets the floor, volume nudges.

    False positives and unverified CVE candidates are excluded. A verified
    CVE keeps the severity NVD assigned to it.
    """
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if not is_risk_finding(finding):
            continue
        severity = str(finding.severity or "info").lower()
        if severity in counts:
            counts[severity] += 1

    if counts["critical"]:
        return min(100, 85 + (counts["critical"] - 1) * 3), "critical"
    if counts["high"]:
        return min(84, 60 + (counts["high"] - 1) * 3), "high"
    if counts["medium"]:
        return min(59, 35 + (counts["medium"] - 1) * 2), "medium"
    if counts["low"]:
        return min(34, 15 + (counts["low"] - 1)), "low"
    return 0, "minimal"


def _host_for(target: str) -> str:
    value = (target or "").strip().lower()
    if "://" in value:
        try:
            return (urlsplit(value).hostname or value).rstrip(".")
        except ValueError:
            return value
    return value.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def _resolve_target_id(session: Session, job: ScanJob) -> int | None:
    if job.target_id is not None:
        return job.target_id
    if not job.program_id:
        return None
    targets = session.exec(select(Target).where(Target.program_id == job.program_id)).all()
    matched = attribute_target(_host_for(job.target), targets)
    return matched.id if matched else None


def _job_pastes(session: Session, job_id: int) -> list[Paste]:
    return session.exec(select(Paste).where(Paste.job_id == job_id).order_by(Paste.id)).all()


def _imported_scan_id(job: ScanJob) -> int | None:
    """The Leadline scan ID for an imported job, or ``None`` for live jobs.

    Imported findings and entities carry their source scan in ``meta``. A
    snapshot for an imported job must contain only that scan's observations;
    otherwise every imported snapshot would show the target's cumulative
    state and diffs between scans would be meaningless.
    """
    params = job.params or {}
    if not params.get("imported"):
        return None
    try:
        return int(params.get("leadline_source_id"))
    except (TypeError, ValueError):
        return None


def _filter_imported_rows(rows: Iterable, scan_id: int | None) -> list:
    if scan_id is None:
        return list(rows)
    filtered = []
    for row in rows:
        try:
            row_scan_id = int((row.meta or {}).get("leadline_scan_id"))
        except (TypeError, ValueError):
            continue
        if row_scan_id == scan_id:
            filtered.append(row)
    return filtered


def _snapshot_findings(
    session: Session, job: ScanJob, target_id: int | None, paste_ids: list[int]
) -> list[Finding]:
    if job.program_id is None:
        return []
    stmt = select(Finding).where(Finding.program_id == job.program_id)
    if target_id is not None:
        conditions = [Finding.target_id == target_id]
        if paste_ids:
            conditions.append(
                (Finding.target_id.is_(None)) & (Finding.paste_id.in_(paste_ids))
            )
        stmt = stmt.where(or_(*conditions))
    elif paste_ids:
        stmt = stmt.where(Finding.paste_id.in_(paste_ids))
    else:
        return []
    findings = session.exec(stmt.order_by(Finding.id)).all()
    return _filter_imported_rows(findings, _imported_scan_id(job))


def _snapshot_entities(
    session: Session, job: ScanJob, target_id: int | None, paste_ids: list[int]
) -> list[Entity]:
    if job.program_id is None:
        return []
    stmt = select(Entity).where(Entity.program_id == job.program_id)
    if target_id is not None:
        conditions = [Entity.target_id == target_id]
        if paste_ids:
            conditions.append(
                (Entity.target_id.is_(None)) & (Entity.paste_id.in_(paste_ids))
            )
        stmt = stmt.where(or_(*conditions))
    elif paste_ids:
        stmt = stmt.where(Entity.paste_id.in_(paste_ids))
    else:
        return []
    entities = session.exec(stmt.order_by(Entity.type, Entity.value)).all()
    return _filter_imported_rows(entities, _imported_scan_id(job))


def _active_entities(entities: Iterable[Entity]) -> list[Entity]:
    return [
        entity
        for entity in entities
        if not entity.ignored
        and str(entity.verdict or "none").lower() != "false-positive"
    ]


def _dns_records(entities: Iterable[Entity]) -> dict[str, list[str]]:
    records: dict[str, set[str]] = {}
    for entity in entities:
        if entity.type != "dns_record":
            continue
        match = DNS_VALUE_RE.match(entity.value or "")
        if not match:
            continue
        record_type = match.group("rtype").upper()
        records.setdefault(record_type, set()).add(match.group("value").strip())
    return {
        record_type: sorted(values)[:CAP_LIST]
        for record_type, values in sorted(records.items())
    }


def _ports(entities: Iterable[Entity]) -> dict[str, dict]:
    ports: dict[str, dict] = {}
    for entity in entities:
        if entity.type != "port":
            continue
        meta = entity.meta or {}
        port = meta.get("port")
        if port is None:
            match = re.match(r"(\d+)", entity.value or "")
            port = int(match.group(1)) if match else entity.normalized
        proto = str(meta.get("proto") or "tcp").lower()
        key = f"{port}/{proto}"
        ports[key] = {
            "service": meta.get("service") or None,
            "version": meta.get("version") or meta.get("version_guess") or None,
            "banner": (meta.get("banner") or "")[:200] or None,
            "tls_subject": meta.get("tls_subject"),
            "tls_issuer": meta.get("tls_issuer"),
            "tls_expires": meta.get("tls_expires"),
        }
    return dict(sorted(ports.items(), key=lambda item: _port_sort_key(item[0])))


def _port_sort_key(value: str) -> tuple[int, str]:
    match = re.match(r"(\d+)", str(value))
    return (int(match.group(1)) if match else 0, str(value))


def _technologies(entities: Iterable[Entity], pastes: Iterable[Paste]) -> tuple[list[str], dict[str, str]]:
    labels: set[str] = set()
    versions: dict[str, str] = {}
    for entity in entities:
        if entity.type != "tech":
            continue
        label = str(entity.value or "").strip()
        if not label:
            continue
        version = str((entity.meta or {}).get("version") or "").strip()
        labels.add(f"{label} {version}".strip() if version else label)
        if version:
            versions[label.lower()] = version

    # The HTTP/tech phases preserve precise product/version pairs in their
    # sealed JSONL even when the entity layer only keeps the label.
    for paste in pastes:
        if paste.phase not in ("tech", "http"):
            continue
        for line in (paste.raw or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            values = record.get("tech_versions") if isinstance(record, dict) else None
            for item in values or []:
                if not isinstance(item, dict):
                    continue
                product = str(item.get("product") or "").strip()
                version = str(item.get("version") or "").strip()
                if not product:
                    continue
                labels.add(f"{product} {version}".strip())
                if version:
                    versions[product.lower()] = version
            tech = record.get("tech") if isinstance(record, dict) else None
            if isinstance(tech, str):
                tech = [part.strip() for part in tech.split(",") if part.strip()]
            for item in tech or []:
                label = str(item).strip()
                if label:
                    labels.add(label)

    ordered = sorted(labels)[:CAP_TECH]
    return ordered, dict(sorted(versions.items())[:CAP_TECH])


def _response_headers(pastes: Iterable[Paste]) -> dict[str, str]:
    found: dict[str, str] = {}
    for paste in pastes:
        if paste.phase not in ("headers", "http"):
            continue
        for match in HEADER_RE.finditer(paste.raw or ""):
            name = match.group("name").strip()
            lowered = name.lower()
            canonical = SECURITY_HEADER_NAMES.get(lowered)
            if canonical is None:
                continue
            found.setdefault(canonical, match.group("value").strip()[:CAP_HEADER_VALUE])
    return dict(sorted(found.items()))


def _security_headers(pastes: Iterable[Paste]) -> tuple[dict[str, str], list[str], list[str]]:
    present = _response_headers(pastes)
    present_names = {name.lower() for name in present}
    missing = sorted(
        info["name"]
        for key, info in SECURITY_HEADERS.items()
        if key not in present_names
    )
    return present, sorted(present), missing


def _phase_summary(phases: Iterable[ScanPhase]) -> list[dict]:
    out = []
    for phase in sorted(phases, key=lambda item: (item.seq or 0, item.id or 0)):
        stats = phase.stats or {}
        out.append(
            {
                "phase_name": phase.name,
                "phase_order": phase.seq,
                "status": phase.status,
                "findings_count": int(stats.get("findings") or 0),
                "entities_count": int(stats.get("entities") or 0),
                "started_at": _iso(phase.started_at),
                "completed_at": _iso(phase.finished_at),
                "error_message": phase.error,
                "data": stats or None,
            }
        )
    return out


def _duration(started: Any, finished: Any) -> int | None:
    if not started or not finished:
        return None
    try:
        return max(0, int((finished - started).total_seconds()))
    except TypeError:
        return None


def _jsonl_endpoints(pastes: Iterable[Paste]) -> set[str]:
    urls: set[str] = set()
    for paste in pastes:
        for line in (paste.raw or "").splitlines():
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            for key in ("url", "final_url", "final-url", "endpoint", "path"):
                value = record.get(key)
                if isinstance(value, str) and value:
                    urls.add(value[:500])
    return urls


def build_snapshot(session: Session, job: ScanJob | int) -> dict:
    """Build (but do not persist) the target-state snapshot for one job."""
    if isinstance(job, int):
        loaded = session.get(ScanJob, job)
        if loaded is None:
            raise ValueError(f"job {job} not found")
        job = loaded

    target_id = _resolve_target_id(session, job)
    pastes = _job_pastes(session, job.id)
    paste_ids = [paste.id for paste in pastes]
    findings = _snapshot_findings(session, job, target_id, paste_ids)
    entities = _active_entities(_snapshot_entities(session, job, target_id, paste_ids))

    active = [finding for finding in findings if is_active_finding(finding)]
    scores = severity_counts(findings)
    risk_score, risk_level = compute_risk(findings)

    subdomains = sorted({entity.value for entity in entities if entity.type == "subdomain"})
    hostnames = sorted(
        {
            entity.value
            for entity in entities
            if entity.type in ("domain", "subdomain")
        }
    )
    resolved_ips = sorted({entity.value for entity in entities if entity.type == "ip"})
    endpoints: set[str] = set()
    for entity in entities:
        if entity.type in API_PATH_TYPES and entity.value:
            endpoints.add(entity.value)
    endpoints.update(_jsonl_endpoints(pastes))

    technologies, technology_versions = _technologies(entities, pastes)
    headers, present_headers, missing_headers = _security_headers(pastes)
    cdn_waf = sorted(
        {
            entity.value
            for entity in entities
            if entity.type == "tech"
            and str(entity.value or "").lower() in {"cloudflare", "akamai", "fastly", "cloudfront", "sucuri", "imperva", "azure front door"}
        }
    )

    phases = session.exec(
        select(ScanPhase).where(ScanPhase.job_id == job.id).order_by(ScanPhase.seq)
    ).all()
    entity_counts: dict[str, int] = {}
    for entity in entities:
        entity_counts[entity.type] = entity_counts.get(entity.type, 0) + 1

    serialized = {}
    for finding in sorted(findings, key=lambda item: (SEVERITY_RANK.get(str(item.severity or "info").lower(), 99), item.id or 0)):
        item = serialize_finding(finding)
        serialized[item["key"]] = item

    verified_cves = sum(
        1 for finding in findings if finding_is_verified(finding) and _cve_id(finding)
    )
    unverified_cves = sum(
        1
        for finding in findings
        if _cve_id(finding) and not finding_is_verified(finding)
    )

    program = session.get(Program, job.program_id) if job.program_id else None
    target = session.get(Target, target_id) if target_id else None
    return {
        "job_id": job.id,
        "program_id": job.program_id,
        "program_name": program.name if program else None,
        "target_id": target_id,
        "target_name": target.name if target else (job.target or ""),
        "target_url": job.target or (target.name if target else ""),
        "runner": job.runner,
        "status": job.status,
        "error_message": job.error,
        "created_at": _iso(job.created_at),
        "started_at": _iso(job.started_at),
        "completed_at": _iso(job.finished_at),
        "duration_seconds": _duration(job.started_at, job.finished_at),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_counts": scores,
        "finding_count": len(active),
        "total_finding_count": len(findings),
        "verified_cves": verified_cves,
        "unverified_cves": unverified_cves,
        "findings": serialized,
        "endpoints": sorted(endpoints)[:CAP_LIST],
        "resolved_ips": resolved_ips[:CAP_LIST],
        "hostnames": hostnames[:CAP_LIST],
        "subdomains": subdomains[:CAP_LIST],
        "dns_records": _dns_records(entities),
        "whois": {},
        "dnssec_enabled": None,
        "ip_reputation": None,
        "ports": _ports(entities),
        "technologies": technologies,
        "technology_versions": technology_versions,
        "cdn_waf": cdn_waf,
        "security_headers": headers,
        "security_headers_present": present_headers,
        "security_headers_missing": missing_headers,
        "entity_counts": dict(sorted(entity_counts.items())),
        "phases": _phase_summary(phases),
    }


def upsert_snapshot(
    session: Session,
    job: ScanJob | int,
    *,
    data: dict | None = None,
    status: str = "ready",
    error: str | None = None,
) -> ScanSnapshot:
    """Create or replace the snapshot row for ``job`` (one row per job)."""
    if isinstance(job, int):
        loaded = session.get(ScanJob, job)
        if loaded is None:
            raise ValueError(f"job {job} not found")
        job = loaded
    row = session.exec(select(ScanSnapshot).where(ScanSnapshot.job_id == job.id)).first()
    if row is None:
        row = ScanSnapshot(job_id=job.id)
    row.program_id = job.program_id
    row.target_id = data.get("target_id") if data else _resolve_target_id(session, job)
    row.status = status
    row.error = (error or "")[:2000] or None
    if data is not None:
        row.data = data
        row.risk_score = int(data.get("risk_score") or 0)
        row.risk_level = str(data.get("risk_level") or "minimal")
        row.finding_count = int(data.get("finding_count") or 0)
    row.updated_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def generate_snapshot(session: Session, job: ScanJob | int) -> ScanSnapshot:
    """Build and persist a ready snapshot. Raises on a genuine build failure."""
    data = build_snapshot(session, job)
    return upsert_snapshot(session, job, data=data, status="ready")


def snapshot_for_job(session: Session, job_id: int) -> ScanSnapshot | None:
    return session.exec(select(ScanSnapshot).where(ScanSnapshot.job_id == job_id)).first()


def ensure_snapshot(session: Session, job: ScanJob) -> ScanSnapshot | None:
    """Return a snapshot, rebuilding terminal jobs that do not have one yet."""
    row = snapshot_for_job(session, job.id)
    if row is not None and row.status == "ready":
        return row
    if job.status not in TERMINAL_JOB_STATUSES:
        return row
    try:
        return generate_snapshot(session, job)
    except Exception as exc:  # noqa: BLE001  (history is rebuildable)
        return upsert_snapshot(session, job, status="failed", error=str(exc))


def rebuild_snapshots(
    session: Session,
    *,
    program_id: int | None = None,
    target_id: int | None = None,
    include_failed: bool = False,
) -> dict:
    """Rebuild every terminal job's snapshot, optionally scoped."""
    stmt = select(ScanJob)
    if program_id is not None:
        stmt = stmt.where(ScanJob.program_id == program_id)
    if target_id is not None:
        stmt = stmt.where(ScanJob.target_id == target_id)
    jobs = session.exec(stmt.order_by(ScanJob.id)).all()
    statuses = TERMINAL_JOB_STATUSES if include_failed else DONE_STATUSES
    built = failed = skipped = 0
    for job in jobs:
        if job.status not in statuses:
            skipped += 1
            continue
        try:
            generate_snapshot(session, job)
            built += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            upsert_snapshot(session, job, status="failed", error=str(exc))
    return {"built": built, "failed": failed, "skipped": skipped}


def _snapshot_summary(snapshot: dict) -> dict:
    keys = (
        "job_id", "target_id", "target_name", "target_url", "runner", "status",
        "created_at", "started_at", "completed_at", "duration_seconds",
        "risk_score", "risk_level", "severity_counts", "finding_count",
        "total_finding_count", "verified_cves", "unverified_cves",
        "error_message",
    )
    return {key: snapshot.get(key) for key in keys}


def _diff_sets(previous: Iterable[str], current: Iterable[str]) -> dict[str, list[str]]:
    before, after = set(previous), set(current)
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def _diff_ports(previous: dict, current: dict) -> dict:
    before, after = set(previous), set(current)
    changed = []
    for port in sorted(before & after, key=_port_sort_key):
        if previous[port] != current[port]:
            changed.append({"port": port, "before": previous[port], "after": current[port]})
    return {
        "opened": sorted(after - before, key=_port_sort_key),
        "closed": sorted(before - after, key=_port_sort_key),
        "changed": changed,
    }


def _diff_dns(previous: dict, current: dict) -> dict:
    added: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    for record_type in set(previous) | set(current):
        change = _diff_sets(previous.get(record_type, []), current.get(record_type, []))
        if change["added"]:
            added[record_type] = change["added"]
        if change["removed"]:
            removed[record_type] = change["removed"]
    return {"added": added, "removed": removed}


def _diff_technologies(previous: dict, current: dict) -> dict:
    before, after = previous or {}, current or {}
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = []
    for product in sorted(set(before) & set(after)):
        if before[product] != after[product]:
            changed.append(
                {"product": product, "before": before[product], "after": after[product]}
            )
    return {"added": added, "removed": removed, "version_changed": changed}


def _diff_headers(previous: dict, current: dict) -> dict:
    before, after = previous or {}, current or {}
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = []
    for name in sorted(set(before) & set(after)):
        if before[name] != after[name]:
            changed.append({"name": name, "before": before[name], "after": after[name]})
    return {"added": added, "removed": removed, "changed": changed}


def diff_snapshots(previous: dict, current: dict) -> dict:
    previous_findings = previous.get("findings") or {}
    current_findings = current.get("findings") or {}

    def active(items: Iterable[dict]) -> list[dict]:
        return [item for item in items if not item.get("is_false_positive")]

    new_findings = active(
        current_findings[key]
        for key in sorted(set(current_findings) - set(previous_findings))
    )
    removed_findings = active(
        previous_findings[key]
        for key in sorted(set(previous_findings) - set(current_findings))
    )

    changed_findings = []
    for key in sorted(set(previous_findings) & set(current_findings)):
        before, after = previous_findings[key], current_findings[key]
        changes = []
        for field in ("severity", "title", "triage_status", "status", "verdict", "verified"):
            if before.get(field) != after.get(field):
                changes.append(
                    {"field": field, "before": before.get(field), "after": after.get(field)}
                )
        if changes:
            changed_findings.append(
                {"key": key, "before": before, "after": after, "changes": changes}
            )

    ports = _diff_ports(previous.get("ports") or {}, current.get("ports") or {})
    endpoints = _diff_sets(previous.get("endpoints") or [], current.get("endpoints") or [])
    ips = _diff_sets(previous.get("resolved_ips") or [], current.get("resolved_ips") or [])
    subdomains = _diff_sets(previous.get("subdomains") or [], current.get("subdomains") or [])
    technologies = _diff_sets(
        previous.get("technologies") or [], current.get("technologies") or []
    )
    cdn_waf = _diff_sets(previous.get("cdn_waf") or [], current.get("cdn_waf") or [])
    headers = _diff_headers(
        previous.get("security_headers") or {}, current.get("security_headers") or {}
    )
    tech_versions = _diff_technologies(
        previous.get("technology_versions") or {},
        current.get("technology_versions") or {},
    )

    summary = {
        "new_findings": len(new_findings),
        "removed_findings": len(removed_findings),
        "changed_findings": len(changed_findings),
        "ports_opened": len(ports["opened"]),
        "ports_closed": len(ports["closed"]),
        "ports_changed": len(ports["changed"]),
        "endpoints_added": len(endpoints["added"]),
        "endpoints_removed": len(endpoints["removed"]),
        "ips_added": len(ips["added"]),
        "ips_removed": len(ips["removed"]),
        "subdomains_added": len(subdomains["added"]),
        "subdomains_removed": len(subdomains["removed"]),
        "technologies_added": len(technologies["added"]),
        "technologies_removed": len(technologies["removed"]),
        "technology_versions_changed": len(tech_versions["version_changed"]),
        "headers_added": len(headers["added"]),
        "headers_removed": len(headers["removed"]),
        "risk_delta": int(current.get("risk_score") or 0) - int(previous.get("risk_score") or 0),
    }

    return {
        "from_scan": _snapshot_summary(previous),
        "to_scan": _snapshot_summary(current),
        "summary": summary,
        "findings": {
            "new": new_findings,
            "removed": removed_findings,
            "changed": changed_findings,
        },
        "endpoints": endpoints,
        "ports": ports,
        "resolved_ips": ips,
        "subdomains": subdomains,
        "technologies": technologies,
        "technology_versions": tech_versions,
        "cdn_waf": cdn_waf,
        "dns_records": _diff_dns(
            previous.get("dns_records") or {}, current.get("dns_records") or {}
        ),
        "whois": {
            field: {
                "before": (previous.get("whois") or {}).get(field),
                "after": (current.get("whois") or {}).get(field),
            }
            for field in set(previous.get("whois") or {}) | set(current.get("whois") or {})
            if (previous.get("whois") or {}).get(field) != (current.get("whois") or {}).get(field)
        },
        "headers": headers,
        "dnssec": {
            "before": previous.get("dnssec_enabled"),
            "after": current.get("dnssec_enabled"),
            "changed": previous.get("dnssec_enabled") != current.get("dnssec_enabled"),
        },
        "risk": {
            "before": previous.get("risk_score"),
            "after": current.get("risk_score"),
            "level_before": previous.get("risk_level"),
            "level_after": current.get("risk_level"),
            "changed": previous.get("risk_score") != current.get("risk_score"),
            "direction": (
                "increased"
                if int(current.get("risk_score") or 0) > int(previous.get("risk_score") or 0)
                else "decreased"
                if int(current.get("risk_score") or 0) < int(previous.get("risk_score") or 0)
                else "unchanged"
            ),
        },
    }


def _job_matches_target(job: ScanJob, target: Target) -> bool:
    if job.target_id is not None:
        return job.target_id == target.id
    host = _host_for(job.target)
    name = (target.name or "").strip().lower().rstrip(".")
    if not host or not name:
        return False
    if target.kind == "url":
        return _host_for(target.name) == host
    return host == name or host.endswith("." + name)


def jobs_for_target(session: Session, target: Target) -> list[ScanJob]:
    jobs = session.exec(
        select(ScanJob)
        .where(
            or_(
                ScanJob.target_id == target.id,
                (ScanJob.program_id == target.program_id) & (ScanJob.target_id.is_(None)),
            )
        )
        .order_by(ScanJob.created_at, ScanJob.id)
    ).all()
    return [job for job in jobs if _job_matches_target(job, target)]


def target_history(session: Session, target_id: int) -> dict:
    target = session.get(Target, target_id)
    if target is None:
        raise ValueError("target not found")
    program = session.get(Program, target.program_id) if target.program_id else None
    jobs = jobs_for_target(session, target)
    snapshots: list[tuple[ScanJob, dict]] = []
    previous_done: dict | None = None
    timeline = []
    latest_diff = None

    for job in jobs:
        row = ensure_snapshot(session, job)
        if row is None or row.status != "ready":
            timeline.append(
                {
                    "job_id": job.id,
                    "status": job.status,
                    "risk_score": row.risk_score if row else None,
                    "risk_level": row.risk_level if row else None,
                    "snapshot_status": row.status if row else "missing",
                    "error_message": job.error,
                    "changes": None,
                }
            )
            continue
        data = row.data or {}
        changes = None
        if job.status in DONE_STATUSES and previous_done is not None:
            changes = diff_snapshots(previous_done, data)["summary"]
        timeline.append(
            {
                **_snapshot_summary(data),
                "snapshot_status": row.status,
                "changes": changes,
            }
        )
        if job.status in DONE_STATUSES:
            snapshots.append((job, data))
            previous_done = data

    if len(snapshots) >= 2:
        latest_diff = diff_snapshots(snapshots[-2][1], snapshots[-1][1])

    return {
        "target": {
            "id": target.id,
            "program_id": target.program_id,
            "program_name": program.name if program else None,
            "name": target.name,
            "url": target.name,
            "kind": target.kind,
            "notes": target.notes,
            "is_active": True,
            "created_at": _iso(target.created_at),
            "updated_at": None,
            "custom_headers": [],
        },
        "scans": timeline,
        "latest_diff": latest_diff,
        "totals": {
            "scans": len(jobs),
            "completed": sum(1 for job in jobs if job.status == "done"),
            "failed": sum(1 for job in jobs if job.status == "failed"),
            "latest_scan_id": jobs[-1].id if jobs else None,
            "first_scan_at": _iso(jobs[0].created_at) if jobs else None,
            "latest_scan_at": _iso(jobs[-1].created_at) if jobs else None,
        },
    }


def load_diff(
    session: Session, target_id: int, from_job_id: int, to_job_id: int
) -> dict:
    target = session.get(Target, target_id)
    if target is None:
        raise ValueError("target not found")
    snaps = {}
    for job_id in (from_job_id, to_job_id):
        job = session.get(ScanJob, job_id)
        if job is None or not _job_matches_target(job, target):
            raise ValueError("Both jobs must exist and belong to this target")
        row = ensure_snapshot(session, job)
        if row is None or row.status != "ready":
            raise ValueError(f"job {job_id} has no ready snapshot")
        snaps[job_id] = row.data or {}
    return diff_snapshots(snaps[from_job_id], snaps[to_job_id])
