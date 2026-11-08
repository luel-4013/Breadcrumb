"""Leadline-compatible API surface.

This is a translation layer, not a second source of truth. Every read comes
from Breadcrumb's Program/Target/ScanJob/Finding rows and every write goes
through the same ingest/queue paths as the web UI.

The paths match Leadline's ``/api/targets``, ``/api/scans``, ``/api/findings``
and ``/api/reports``. Breadcrumb's own JSON API stays at ``/api/v1``.
"""

from __future__ import annotations

import html
import json
import os
import threading
from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response
from sqlmodel import Session, select

from . import history, pdf_export, reporting, triage
from .db import get_session
from .jobs import queue as jobs_queue
from .models import Entity, Finding, Paste, Program, ScanJob, ScanPhase, Target

router = APIRouter(prefix="/api", tags=["leadline-compat"])

STATUS_TO_LEADLINE = {
    "queued": "pending",
    "running": "running",
    "done": "completed",
    "failed": "failed",
    "cancelled": "stopped",
}
TERMINAL = {"done", "failed", "cancelled"}


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else (str(value) if value else None)


def _target_url(target: Target) -> str:
    return target.name or ""


def _target_response(session: Session, target: Target) -> dict:
    program = session.get(Program, target.program_id) if target.program_id else None
    return {
        "id": target.id,
        "name": program.name if program else target.name,
        "url": _target_url(target),
        "notes": target.notes,
        "is_active": True,
        "custom_headers": {},
        "created_at": target.created_at,
        "updated_at": None,
        "program_id": target.program_id,
        "kind": target.kind,
    }


def _find_or_create_program(session: Session, name: str) -> Program:
    program = session.exec(select(Program).where(Program.name == name)).first()
    if program is None:
        program = Program(name=name)
        session.add(program)
        session.commit()
        session.refresh(program)
    return program


def _host_of(value: str) -> str:
    if "://" in value:
        try:
            return (urlsplit(value).hostname or value).lower().rstrip(".")
        except ValueError:
            return value
    return value.strip().lower().rstrip(".")


# ---------------------------------------------------------------- targets ----
@router.get("/targets")
def list_targets(session: Session = Depends(get_session)):
    rows = session.exec(select(Target).order_by(Target.id)).all()
    return [_target_response(session, target) for target in rows]


@router.post("/targets", status_code=201)
def create_target(payload: dict = Body(...), session: Session = Depends(get_session)):
    name = str(payload.get("name") or "").strip()
    url = str(payload.get("url") or "").strip()
    if not name or not url:
        raise HTTPException(status_code=422, detail="name and url are required")
    program = _find_or_create_program(session, name)
    target = Target(
        program_id=program.id,
        name=url,
        kind="url",
        notes=payload.get("notes"),
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return _target_response(session, target)


@router.get("/targets/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return _target_response(session, target)


@router.put("/targets/{target_id}")
def update_target(
    target_id: int, payload: dict = Body(...), session: Session = Depends(get_session)
):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    program = session.get(Program, target.program_id) if target.program_id else None
    if payload.get("name") is not None and program is not None:
        program.name = str(payload["name"]).strip() or program.name
        session.add(program)
    if payload.get("url") is not None:
        target.name = str(payload["url"]).strip() or target.name
    if "notes" in payload:
        target.notes = payload.get("notes")
    session.add(target)
    session.commit()
    session.refresh(target)
    return _target_response(session, target)


@router.delete("/targets/{target_id}", status_code=204)
def delete_target(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    for model in (Entity, Finding):
        for row in session.exec(select(model).where(model.target_id == target_id)).all():
            row.target_id = None
            session.add(row)
    for job in session.exec(select(ScanJob).where(ScanJob.target_id == target_id)).all():
        job.target_id = None
        session.add(job)
    session.delete(target)
    session.commit()
    return Response(status_code=204)


@router.get("/targets/{target_id}/history")
def target_history(target_id: int, session: Session = Depends(get_session)):
    try:
        return history.target_history(session, target_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/targets/{target_id}/history/diff")
def target_diff(
    target_id: int,
    from_scan_id: int = Query(..., ge=1),
    to_scan_id: int = Query(..., ge=1),
    session: Session = Depends(get_session),
):
    try:
        return history.load_diff(session, target_id, from_scan_id, to_scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ------------------------------------------------------------------ scans ----
def _scan_progress(session: Session, job: ScanJob) -> float:
    phases = session.exec(select(ScanPhase).where(ScanPhase.job_id == job.id)).all()
    if not phases:
        return 100.0 if job.status == "done" else 0.0
    done = sum(1 for phase in phases if phase.status in ("done", "failed", "cancelled"))
    return round((done / len(phases)) * 100, 1)


def _scan_response(session: Session, job: ScanJob) -> dict:
    phases = session.exec(
        select(ScanPhase).where(ScanPhase.job_id == job.id).order_by(ScanPhase.seq)
    ).all()
    current = next((phase.name for phase in phases if phase.status == "running"), None)
    if current is None and job.status == "done" and phases:
        current = phases[-1].name
    return {
        "id": job.id,
        "target_id": job.target_id,
        "status": STATUS_TO_LEADLINE.get(job.status, job.status),
        "progress": _scan_progress(session, job),
        "current_phase": current,
        "started_at": job.started_at,
        "completed_at": job.finished_at,
        "error_message": job.error,
        "evasion_enabled": bool((job.params or {}).get("evasion_enabled", False)),
        "request_delay": (job.params or {}).get("request_delay"),
        "enable_external_lookups": bool(
            (job.params or {}).get("enable_external_lookups", False)
        ),
        "created_at": job.created_at,
        "runner": job.runner,
        "target": job.target,
    }


@router.get("/scans")
def list_scans(session: Session = Depends(get_session)):
    jobs = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc())).all()
    return [_scan_response(session, job) for job in jobs]


@router.post("/scans", status_code=201)
def create_scan(payload: dict = Body(...), session: Session = Depends(get_session)):
    target_id = payload.get("target_id")
    if not isinstance(target_id, int):
        raise HTTPException(status_code=422, detail="target_id is required")
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    params = dict(payload.get("params") or {})
    params.setdefault("evasion_enabled", bool(payload.get("evasion_enabled", True)))
    if payload.get("request_delay") is not None:
        params["request_delay"] = payload["request_delay"]
    params.setdefault(
        "enable_external_lookups", bool(payload.get("enable_external_lookups", True))
    )
    job = ScanJob(
        program_id=target.program_id,
        target_id=target.id,
        runner=str(payload.get("runner") or "leadline-recon"),
        target=target.name,
        status="queued",
        params=params,
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return _scan_response(session, job)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_response(session, job)


@router.post("/scans/{scan_id}/start")
def start_scan(scan_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.status != "queued":
        raise HTTPException(
            status_code=400,
            detail=(
                "Only pending scans can be started. "
                f"This scan is '{STATUS_TO_LEADLINE.get(job.status, job.status)}'; "
                "create a new scan to run it again."
            ),
        )
    job.next_run_at = None
    session.add(job)
    session.commit()
    mode = os.environ.get("BREADCRUMB_EXECUTOR", "off").strip().lower()
    if mode == "inline":
        from .jobs import run_once as run_native_job

        def _run() -> None:
            try:
                run_native_job(job_id=scan_id, runner_ids=(job.runner,))
            except Exception:  # noqa: BLE001  (compat start must not kill the web process)
                pass

        threading.Thread(
            target=_run, name=f"breadcrumb-compat-{scan_id}", daemon=True
        ).start()
    return _scan_response(session, job)


@router.post("/scans/{scan_id}/stop")
def stop_scan(scan_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="Scan is not running")
    jobs_queue.request_cancel(session, scan_id)
    session.refresh(job)
    return _scan_response(session, job)


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.status in ("queued", "running"):
        raise HTTPException(status_code=400, detail="Stop the scan before deleting it")
    session.delete(job)
    session.commit()
    return Response(status_code=204)


@router.get("/scans/{scan_id}/events")
def scan_events(scan_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    phases = session.exec(
        select(ScanPhase).where(ScanPhase.job_id == scan_id).order_by(ScanPhase.seq)
    ).all()
    events = []
    for phase in phases:
        events.append(
            {
                "id": f"phase-{phase.id}",
                "scan_id": scan_id,
                "phase_name": phase.name,
                "phase_order": phase.seq,
                "status": phase.status,
                "started_at": phase.started_at,
                "completed_at": phase.finished_at,
                "result_data": phase.stats or {},
                "error_message": phase.error,
                "created_at": phase.started_at,
            }
        )
    return events


# --------------------------------------------------------------- findings ----
def _scan_findings(session: Session, scan_id: int) -> list[Finding]:
    job = session.get(ScanJob, scan_id)
    if job is None:
        return []
    paste_ids = session.exec(select(Paste.id).where(Paste.job_id == scan_id)).all()
    rows = []
    if paste_ids:
        rows = session.exec(
            select(Finding).where(Finding.paste_id.in_(paste_ids)).order_by(Finding.id)
        ).all()
    if not rows:
        snapshot = history.ensure_snapshot(session, job)
        if snapshot is not None and snapshot.status == "ready":
            ids = [
                int(item["id"])
                for item in (snapshot.data or {}).get("findings", {}).values()
                if item.get("id")
            ]
            if ids:
                rows = session.exec(
                    select(Finding).where(Finding.id.in_(ids)).order_by(Finding.id)
                ).all()
    return rows


def _finding_response(finding: Finding, scan_id: int | None = None) -> dict:
    triage_fields = triage.triage_snapshot_fields(finding)
    return {
        "id": finding.id,
        "scan_id": scan_id,
        "finding_type": finding.source_tool or "finding",
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "location": history._finding_location(finding),
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "extra_data": {
            "tags": finding.tags or [],
            "cvss": finding.cvss,
            "verified": reporting.finding_is_verified(finding),
            "fingerprint": finding.fingerprint,
        },
        "is_false_positive": triage_fields["is_false_positive"],
        "triage_status": triage_fields["triage_status"],
        "triage_note": finding.notes,
        "triaged_at": finding.updated_at,
        "status": finding.status,
        "verdict": triage_fields["verdict"],
        "created_at": finding.created_at,
    }


@router.get("/findings")
def list_findings(
    scan_id: int | None = Query(None, ge=1),
    target_id: int | None = Query(None, ge=1),
    program_id: int | None = Query(None, ge=1),
    severity: str = "",
    triage_status: str = "",
    session: Session = Depends(get_session),
):
    if scan_id is not None:
        rows = _scan_findings(session, scan_id)
    else:
        stmt = select(Finding).order_by(Finding.id)
        if target_id is not None:
            stmt = stmt.where(Finding.target_id == target_id)
        if program_id is not None:
            stmt = stmt.where(Finding.program_id == program_id)
        rows = session.exec(stmt).all()
    if severity:
        rows = [row for row in rows if str(row.severity).lower() == severity.lower()]
    if triage_status:
        rows = [
            row for row in rows
            if triage.triage_status(row) == triage_status.lower()
        ]
    return [_finding_response(row, scan_id) for row in rows]


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_response(finding)


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: int, payload: dict = Body(...), session: Session = Depends(get_session)
):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    note = payload.get("triage_note")
    if payload.get("triage_status") is not None:
        try:
            triage.apply_triage(finding, str(payload["triage_status"]), note)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif payload.get("is_false_positive") is not None:
        triage.apply_triage(
            finding,
            "false_positive" if payload["is_false_positive"] else "open",
            note,
        )
    elif note is not None:
        finding.notes = str(note)[:2000] or None
        finding.updated_at = datetime.now().astimezone()
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return _finding_response(finding)


# ---------------------------------------------------------------- reports ----
def _report_summary(data: dict) -> dict:
    findings = [
        item for item in (data.get("findings") or {}).values()
        if not item.get("is_false_positive")
    ]
    severity = data.get("severity_counts") or {}
    ports = data.get("ports") or {}
    return {
        "total_endpoints": len(data.get("endpoints") or []),
        "api_routes": 0,
        "api_candidates": 0,
        "authentication_mechanisms": 0,
        "debug_interfaces": 0,
        "suspicious_parameters": 0,
        "possible_vulns": len(findings),
        "missing_controls": len(data.get("security_headers_missing") or []),
        "open_ports_found": len(ports),
        "high_risk_ports": 0,
        "cves_found": (data.get("verified_cves") or 0) + (data.get("unverified_cves") or 0),
        "critical_cves": severity.get("critical", 0),
        "verified_cves": data.get("verified_cves") or 0,
        "risk_score": data.get("risk_score") or 0,
        "risk_level": data.get("risk_level") or "minimal",
    }


def _report_highlights(data: dict) -> dict:
    return {
        "technologies": data.get("technologies") or [],
        "cdn_waf": data.get("cdn_waf") or [],
        "response_headers": None,
        "security_headers_present": data.get("security_headers_present") or [],
        "security_headers_missing": data.get("security_headers_missing") or [],
        "dns_records": data.get("dns_records") or {},
        "resolved_ips": data.get("resolved_ips") or [],
        "hostnames": data.get("hostnames") or [],
        "whois": data.get("whois") or {},
        "geolocation": None,
        "open_ports": data.get("ports") or {},
        "subdomains": data.get("subdomains") or [],
        "dnssec_enabled": data.get("dnssec_enabled"),
        "ip_reputation": data.get("ip_reputation"),
        "discovered_endpoints": data.get("endpoints") or [],
        "api_documentation": [],
        "url_parameters": [],
        "cve_matches": [],
        "cve_lookup_note": None,
        "cve_lookup_errors": [],
    }


def _report_payload(session: Session, scan_id: int) -> tuple[ScanJob, dict]:
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    snapshot = history.ensure_snapshot(session, job)
    if snapshot is None or snapshot.status != "ready":
        raise HTTPException(status_code=409, detail="Report snapshot is not ready")
    return job, snapshot.data or {}


@router.get("/reports/{scan_id}")
def get_report(scan_id: int, session: Session = Depends(get_session)):
    job, data = _report_payload(session, scan_id)
    return {
        "scan_id": job.id,
        "target_name": data.get("target_name") or job.target,
        "target_url": data.get("target_url") or job.target,
        "status": STATUS_TO_LEADLINE.get(job.status, job.status),
        "summary": _report_summary(data),
        "highlights": _report_highlights(data),
        "phases": data.get("phases") or [],
        "endpoints": (data.get("endpoints") or [])[:100],
        "created_at": job.created_at,
        "completed_at": job.finished_at,
    }


@router.get("/reports/{scan_id}/export/json")
def export_json(scan_id: int, session: Session = Depends(get_session)):
    job, data = _report_payload(session, scan_id)
    payload = get_report(scan_id, session)
    payload["findings"] = [
        item for item in (data.get("findings") or {}).values()
        if not item.get("is_false_positive")
    ]
    return Response(
        content=json.dumps(payload, default=str, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{pdf_export.report_filename(job.target, job.id, "json")}"'
            )
        },
    )


def _markdown(job: ScanJob, data: dict) -> str:
    summary = _report_summary(data)
    lines = [
        f"# Breadcrumb report: {data.get('target_name') or job.target}",
        "",
        f"- Scan: #{job.id}",
        f"- Status: {STATUS_TO_LEADLINE.get(job.status, job.status)}",
        f"- Risk: {summary['risk_score']} ({summary['risk_level']})",
        f"- Findings: {summary['possible_vulns']}",
        "",
        "## Findings",
        "",
    ]
    findings = [
        item for item in (data.get("findings") or {}).values()
        if not item.get("is_false_positive")
    ]
    if not findings:
        lines.append("No active findings.")
    for finding in findings:
        lines.append(f"### [{finding.get('severity', 'info').upper()}] {finding.get('title')}")
        lines.append("")
        if finding.get("description"):
            lines.append(str(finding["description"]))
            lines.append("")
        if finding.get("evidence"):
            lines.append("```")
            lines.append(str(finding["evidence"]))
            lines.append("```")
            lines.append("")
        if finding.get("remediation"):
            lines.append(f"**Remediation:** {finding['remediation']}")
            lines.append("")
    lines.append("---")
    lines.append("Generated by Breadcrumb for authorized security assessments only.")
    return "\n".join(lines).rstrip() + "\n"


@router.get("/reports/{scan_id}/export/markdown")
def export_markdown(scan_id: int, session: Session = Depends(get_session)):
    job, data = _report_payload(session, scan_id)
    return Response(
        content=_markdown(job, data),
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{pdf_export.report_filename(job.target, job.id, "md")}"'
            )
        },
    )


@router.get("/reports/{scan_id}/export/html")
def export_html(scan_id: int, session: Session = Depends(get_session)):
    job, data = _report_payload(session, scan_id)
    summary = _report_summary(data)
    findings = [
        item for item in (data.get("findings") or {}).values()
        if not item.get("is_false_positive")
    ]
    rows = "".join(
        f"<tr><td>{html.escape(str(item.get('severity', 'info')))}</td>"
        f"<td>{html.escape(str(item.get('title') or ''))}</td>"
        f"<td>{html.escape(str(item.get('location') or ''))}</td></tr>"
        for item in findings
    )
    page = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Breadcrumb report - {html.escape(job.target or '')}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;color:#111827}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #e5e7eb;padding:.4rem;text-align:left}}</style>
</head><body><h1>Breadcrumb report</h1>
<p><strong>Target:</strong> {html.escape(job.target or '')}<br>
<strong>Scan:</strong> #{job.id} · {html.escape(STATUS_TO_LEADLINE.get(job.status, job.status))}<br>
<strong>Risk:</strong> {summary['risk_score']} ({html.escape(str(summary['risk_level']))})</p>
<table><thead><tr><th>Severity</th><th>Title</th><th>Location</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="color:#b91c1c"><strong>CONFIDENTIAL.</strong> Authorized recipients only.</p>
</body></html>"""
    return Response(
        content=page,
        media_type="text/html",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{pdf_export.report_filename(job.target, job.id, "html")}"'
            )
        },
    )


@router.get("/reports/{scan_id}/export/pdf")
def export_pdf(scan_id: int, session: Session = Depends(get_session)):
    job, data = _report_payload(session, scan_id)
    findings = [
        item for item in (data.get("findings") or {}).values()
        if not item.get("is_false_positive")
    ]
    program = session.get(Program, job.program_id) if job.program_id else None
    summary = {
        **_report_summary(data),
        "total_findings": len(findings),
        "severity_counts": data.get("severity_counts") or {},
        "endpoints": len(data.get("endpoints") or []),
        "subdomains": len(data.get("subdomains") or []),
        "open_ports": len(data.get("ports") or {}),
        "technologies": len(data.get("technologies") or []),
        "missing_headers": len(data.get("security_headers_missing") or []),
    }
    content = pdf_export.generate_report_pdf(
        program_name=program.name if program else "Breadcrumb",
        target_name=data.get("target_name") or job.target,
        target_url=data.get("target_url") or job.target,
        scan_id=job.id,
        status=STATUS_TO_LEADLINE.get(job.status, job.status),
        created_at=job.created_at,
        completed_at=job.finished_at,
        summary=summary,
        highlights=_report_highlights(data),
        phases=data.get("phases") or [],
        findings=findings,
    )
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{pdf_export.report_filename(job.target, job.id, "pdf")}"'
            )
        },
    )
