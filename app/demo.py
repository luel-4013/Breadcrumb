"""One-command sample program: the five-minute first report.

The demo is intentionally idempotent. Re-running it returns the same captures
instead of duplicating evidence, so it is safe to use as a smoke test.
"""

from __future__ import annotations

from pathlib import Path

from sqlmodel import Session, select

from .ingest import IngestRequest, ingest
from .models import Entity, Finding, Program, Target

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_data"
DEMO_PROGRAM = "Breadcrumb Demo"
DEMO_VERSION = "v1"

SAMPLES = (
    ("acme_nmap.txt", "nmap -sV -oN acme_nmap.txt app.demo.breadcrumb.test"),
    ("acme_httpx.jsonl", "httpx -json -l hosts.txt -o acme_httpx.jsonl"),
    ("acme_nuclei.jsonl", "nuclei -jsonl -l urls.txt -o acme_nuclei.jsonl"),
    ("acme_bbot.jsonl", "bbot -t demo.breadcrumb.test -f json -o acme_bbot.jsonl"),
    ("acme_amass.json", "amass enum -json acme_amass.json -d demo.breadcrumb.test"),
)

SCOPE_IN = "\n".join(
    (
        "demo.breadcrumb.test",
        "*.demo.breadcrumb.test",
        "192.0.2.0/24",
    )
)


def _ensure_program(session: Session) -> Program:
    program = session.exec(select(Program).where(Program.name == DEMO_PROGRAM)).first()
    if program is None:
        program = Program(
            name=DEMO_PROGRAM,
            platform="demo",
            scope_in=SCOPE_IN,
            notes="Seeded sample data for the Breadcrumb first-run workflow.",
        )
        session.add(program)
        session.commit()
        session.refresh(program)
    return program


def _ensure_targets(session: Session, program: Program) -> None:
    existing = {
        (target.name or "").strip().lower()
        for target in session.exec(select(Target).where(Target.program_id == program.id)).all()
    }
    for name, kind in (
        ("demo.breadcrumb.test", "domain"),
        ("app.demo.breadcrumb.test", "domain"),
        ("api.demo.breadcrumb.test", "domain"),
        ("staging.demo.breadcrumb.test", "domain"),
    ):
        if name in existing:
            continue
        session.add(Target(program_id=program.id, name=name, kind=kind))
    session.commit()


def run_demo(session: Session) -> dict:
    """Create (or reuse) the demo program and ingest the sample captures."""
    program = _ensure_program(session)
    _ensure_targets(session, program)
    captures = []
    for filename, command in SAMPLES:
        path = SAMPLE_DIR / filename
        text = path.read_text(encoding="utf-8")
        result = ingest(
            session,
            IngestRequest(
                text=text,
                program_id=program.id,
                source=f"demo:{filename}",
                capture_key=f"demo:{DEMO_VERSION}:{filename}",
                command=command,
                source_meta={
                    "sample": True,
                    "filename": filename,
                    "tool_version": "sample",
                },
            ),
        )
        captures.append(
            {
                "file": filename,
                "paste_id": result.paste.id,
                "entities": result.entities,
                "parsed_entities": result.report.get("parsed_entities", result.entities),
                "findings": result.findings,
                "completeness": result.completeness,
                "duplicate": result.duplicate,
                "issues": len(result.parse_errors),
            }
        )
    entity_count = len(
        session.exec(select(Entity).where(Entity.program_id == program.id)).all()
    )
    finding_count = len(
        session.exec(select(Finding).where(Finding.program_id == program.id)).all()
    )
    return {
        "program_id": program.id,
        "program_name": program.name,
        "captures": captures,
        "entities": entity_count,
        "findings": finding_count,
        "report_url": f"/reports/{program.id}/html",
        "manifest_url": f"/pastes/{captures[0]['paste_id']}/manifest.json" if captures else "",
    }
