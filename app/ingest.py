"""The single ingest path for every capture.

Before this module existed, ``app.main._ingest`` sealed a capture and then
committed entities, findings and attribution in four separate transactions.
That worked for a single browser tab, but a worker retrying a delivery could
leave a sealed capture with no parsed entities.

This module keeps the same observable behavior while making the capture,
its chain link, and the first round of entities/relationships one
``BEGIN IMMEDIATE`` transaction. Post-processing (dedup, attribution,
findings, cross-program memory) stays re-runnable and idempotent.

``capture_key`` is the worker's delivery idempotency key. If the same key is
presented twice, the existing capture is returned instead of sealing a
duplicate. The evidence chain formula is unchanged:
``sha256(f"{prev_chain or 'genesis'}:{content}")``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, func, select

from .attribution import consolidate_entities, rebuild_program
from .db import begin_immediate
from .models import Entity, EvidenceChain, Finding, Paste, Relationship, Target
from .parsers import analyze_detailed
from .takeover import detect_takeovers

# Hard ceiling per ingest so a pathological paste can't exhaust disk/RAM.
MAX_ENTITIES_PER_PASTE = 25000


@dataclass(frozen=True)
class IngestRequest:
    """Everything the ingest path needs, whether from a browser or worker."""

    text: str
    program_id: int | None = None
    target_id: int | None = None
    source: str = "manual"
    capture_key: str | None = None
    job_id: int | None = None
    attempt_id: int | None = None
    phase: str | None = None
    max_entities: int = MAX_ENTITIES_PER_PASTE
    # Import provenance. ``command`` is the exact command that produced the
    # artifact (redacted in manifests), ``source_meta`` holds filename/tool
    # version/URL and other non-secret context.
    command: str | None = None
    source_meta: dict = field(default_factory=dict)


@dataclass
class IngestResult:
    paste: Paste
    entities: int = 0
    findings: int = 0
    duplicate: bool = False
    warning: str = ""
    parse_errors: list = field(default_factory=list)
    completeness: float = 1.0
    skipped_rows: int = 0
    parser_versions: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)


def _reconcile_chain(session: Session, *, commit: bool = True) -> EvidenceChain:
    """Point the singleton chain row at the last surviving sealed capture."""
    last = session.exec(
        select(Paste)
        .where(Paste.chain_hash != None)  # noqa: E711
        .order_by(Paste.chain_seq.desc(), Paste.id.desc())
        .limit(1)
    ).first()
    length = session.exec(
        select(func.count()).select_from(Paste).where(Paste.chain_hash != None)  # noqa: E711
    ).one()
    chain = session.get(EvidenceChain, 1)
    if chain is None:
        chain = EvidenceChain(id=1)
    chain.head_paste_id = last.id if last else None
    chain.length = int(length)
    chain.updated_at = datetime.now(timezone.utc)
    session.add(chain)
    if commit:
        session.commit()
    else:
        session.flush()
    return chain


def _seal_paste(
    session: Session, raw: str
) -> tuple[str, str, int | None, int, EvidenceChain]:
    """Compute the next capture's seal while the caller holds the write lock.

    The chain links each capture to the previous one, so the notebook is a
    tamper-evident log: alter any past capture and its hash breaks. A capture's
    predecessor is recorded explicitly, so deleting a program (and its captures)
    shows up as a chain *gap*, not as tampering.
    """
    content = hashlib.sha256((raw or "").encode("utf-8", errors="replace")).hexdigest()
    chain = session.get(EvidenceChain, 1)
    prev = (
        session.get(Paste, chain.head_paste_id)
        if chain is not None and chain.head_paste_id is not None
        else None
    )
    if (
        chain is None
        or (chain.head_paste_id is not None and prev is None)
        or (prev is not None and not prev.chain_hash)
    ):
        # Recovery after a deleted head (or a restored legacy file). The
        # caller's BEGIN IMMEDIATE is still held because this helper does not
        # commit.
        chain = _reconcile_chain(session, commit=False)
        prev = (
            session.get(Paste, chain.head_paste_id)
            if chain.head_paste_id is not None
            else None
        )
    prev_id = prev.id if prev else None
    prev_chain = (prev.chain_hash if prev and prev.chain_hash else "genesis")
    chain_hash = hashlib.sha256(f"{prev_chain}:{content}".encode("utf-8")).hexdigest()
    # Sequence numbers may have gaps after a program deletion; the chain
    # *length* counts surviving sealed captures, while the next sequence is
    # one past the head's sequence.
    seq = (
        int(prev.chain_seq) + 1
        if prev is not None and prev.chain_seq is not None
        else 1
    )
    return content, chain_hash, prev_id, seq, chain


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
    from .models import Program

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


def _existing_capture(session: Session, capture_key: str | None) -> Paste | None:
    if not capture_key:
        return None
    return session.exec(select(Paste).where(Paste.capture_key == capture_key)).first()


def import_report(session: Session, paste: Paste) -> dict:
    """The machine-readable story of one import.

    Every import produces this report, including a zero-entity import. The
    report is deliberately explicit about *why* a capture produced nothing:
    a parser that matched but emitted no rows is a different failure from no
    parser matching at all.
    """
    entity_count = int(
        session.exec(
            select(func.count()).select_from(Entity).where(Entity.paste_id == paste.id)
        ).one()
        or 0
    )
    finding_count = int(
        session.exec(
            select(func.count()).select_from(Finding).where(Finding.paste_id == paste.id)
        ).one()
        or 0
    )
    relationship_count = int(
        session.exec(
            select(func.count()).select_from(Relationship).where(Relationship.paste_id == paste.id)
        ).one()
        or 0
    )
    issues = list(paste.parse_errors or [])
    parsers = list(paste.parsers or [])
    stats = dict(paste.import_stats or {})
    parsed_entities = int(stats.get("parsed_entities", entity_count) or 0)
    parsed_findings = int(stats.get("parsed_findings", finding_count) or 0)
    empty = not entity_count and not finding_count
    # Cross-capture consolidation can merge every row from a re-import into
    # records that already exist. That is a successful import, not an empty
    # one, so it must not raise the zero-entity warning.
    consolidated = empty and (parsed_entities > 0 or parsed_findings > 0)
    warning = "no entities detected" if empty and not consolidated else ""
    hint = ""
    if warning and not parsers:
        hint = (
            "No parser matched this input. Check the format with "
            "`python -m app.cli doctor`, or see docs/IMPORT_COOKBOOK.md."
        )
    elif warning:
        hint = (
            "Parsers matched but produced no entities. Read the issues below; "
            "the input may be truncated, malformed, or a tool version we do "
            "not recognize yet."
        )
    elif consolidated:
        hint = (
            "Parsed rows were merged into entities or findings that already "
            "existed in this program. The capture is still sealed; see the "
            "parsed counts above."
        )
    return {
        "report_version": 1,
        "paste_id": paste.id,
        "program_id": paste.program_id,
        "target_id": paste.target_id,
        "source": paste.source,
        "command": paste.command,
        "source_meta": paste.source_meta or {},
        "created_at": paste.created_at.isoformat() if paste.created_at else None,
        "parsers": parsers,
        "parser_versions": paste.parser_versions or {},
        "tool_guess": paste.tool_guess,
        "entities": entity_count,
        "relationships": relationship_count,
        "findings": finding_count,
        # Parsed counts are recorded at import time, before cross-capture
        # consolidation merges duplicate Entity rows. This is the honest
        # "what did the parser see" number; ``entities`` is "what survives".
        "parsed_entities": parsed_entities,
        "parsed_relationships": int(stats.get("parsed_relationships", relationship_count) or 0),
        "parsed_findings": parsed_findings,
        "truncated_entities": int(stats.get("truncated_entities", 0) or 0),
        "skipped_rows": int(paste.skipped_rows or 0),
        "completeness": float(paste.completeness if paste.completeness is not None else 1.0),
        "consolidated": consolidated,
        "issues": issues,
        "warning": warning,
        "hint": hint,
        "content_sha256": paste.content_sha256,
        "chain_hash": paste.chain_hash,
        "chain_seq": paste.chain_seq,
    }


def _result_for(session: Session, paste: Paste, *, duplicate: bool) -> IngestResult:
    report = import_report(session, paste)
    return IngestResult(
        paste=paste,
        entities=report["entities"],
        findings=report["findings"],
        duplicate=duplicate,
        warning=report["warning"],
        parse_errors=list(paste.parse_errors or []),
        completeness=report["completeness"],
        skipped_rows=report["skipped_rows"],
        parser_versions=dict(paste.parser_versions or {}),
        report=report,
    )


def ingest(session: Session, request: IngestRequest) -> IngestResult:
    """Seal one capture and parse it into entities, relationships and findings.

    The same function serves the browser form, file upload, JSON API, CLI and
    native collectors. Callers that retry should pass a stable ``capture_key``;
    a duplicate delivery returns the original capture without touching the
    chain.
    """
    text = request.text or ""
    existing = _existing_capture(session, request.capture_key)
    if existing is not None:
        return _result_for(session, existing, duplicate=True)

    analysis = analyze_detailed(text)
    entities = analysis.entities
    relationships = analysis.relationships
    parsers = analysis.parsers
    errors = list(analysis.errors)
    skipped_rows = int(analysis.skipped_rows or 0)
    completeness = float(analysis.completeness)
    parser_versions = dict(analysis.parser_versions)
    parsed_findings = list(analysis.findings)
    parsed_entities = len(entities)
    parsed_relationships = len(relationships)
    parsed_findings_count = len(parsed_findings)
    truncated = 0
    max_entities = max(1, int(request.max_entities or MAX_ENTITIES_PER_PASTE))
    if len(entities) > max_entities:
        original_count = len(entities)
        errors.append(
            {
                "parser": "*",
                "code": "truncated",
                "message": f"truncated at {max_entities} entities ({original_count} found)",
                "error": f"truncated at {max_entities} entities ({original_count} found)",
                "line": None,
                "detail": {"kept": max_entities, "found": original_count},
            }
        )
        entities = entities[:max_entities]
        truncated = original_count - max_entities
        completeness = round(min(completeness, max_entities / max(1, original_count)), 4)

    paste: Paste | None = None
    for attempt in range(3):
        try:
            begin_immediate(session)
            content_sha, chain_hash, prev_paste_id, chain_seq, chain = _seal_paste(
                session, text
            )
            paste = Paste(
                program_id=request.program_id,
                target_id=request.target_id,
                job_id=request.job_id,
                attempt_id=request.attempt_id,
                phase=request.phase,
                source=request.source,
                raw=text,
                parsers=parsers,
                parse_errors=errors,
                tool_guess=parsers[0] if parsers else None,
                content_sha256=content_sha,
                chain_hash=chain_hash,
                prev_paste_id=prev_paste_id,
                chain_seq=chain_seq,
                capture_key=request.capture_key,
                completeness=completeness,
                skipped_rows=skipped_rows,
                parser_versions=parser_versions,
                import_stats={
                    "parsed_entities": parsed_entities,
                    "parsed_relationships": parsed_relationships,
                    "parsed_findings": parsed_findings_count,
                    "truncated_entities": truncated,
                },
                command=request.command,
                source_meta=dict(request.source_meta or {}),
            )
            session.add(paste)
            session.flush()  # assign the id before moving the chain head
            chain.head_paste_id = paste.id
            chain.length = int(chain.length or 0) + 1
            chain.updated_at = datetime.now(timezone.utc)
            session.add(chain)
            for entity in entities:
                session.add(
                    Entity(
                        paste_id=paste.id,
                        program_id=request.program_id,
                        target_id=request.target_id,
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
                        program_id=request.program_id,
                        src_value=rel.src_value,
                        src_type=rel.src_type,
                        dst_value=rel.dst_value,
                        dst_type=rel.dst_type,
                        rel_type=rel.rel_type,
                        source="parser",
                    )
                )
            session.commit()
            break
        except IntegrityError:
            # A stale head (manual edit/restore) made a sibling capture, or a
            # concurrent delivery won the capture_key race. Roll back, return
            # the existing delivery if we can find it, otherwise reconcile
            # and seal again. Unique indexes reject the fork.
            session.rollback()
            existing = _existing_capture(session, request.capture_key)
            if existing is not None:
                return _result_for(session, existing, duplicate=True)
            if attempt == 2:
                raise
            _reconcile_chain(session)
    assert paste is not None and paste.id is not None
    session.refresh(paste)

    consolidate_entities(session, request.program_id)
    if request.program_id:
        rebuild_program(session, request.program_id)
    _persist_findings(
        session,
        request.program_id,
        request.target_id,
        parsed_findings + detect_takeovers(entities),
        paste.id,
    )
    _annotate_cross_program(session, request.program_id, paste.id)
    return _result_for(session, paste, duplicate=False)


# Compatibility alias for code that imported the old private helper.
_begin_immediate = begin_immediate
