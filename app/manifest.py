"""Evidence Manifest v2.

A manifest is the portable, offline-checkable description of one capture:
what produced it, when, with which parser version, how complete the parse was,
which scope decision applied, where it sits in the hash chain, and hashes of
the input and normalized output. Raw evidence stays local by default.

Two hashes are recorded for the output:

* ``output.sha256`` hashes the full parsed output as stored in the database.
  It proves the data without exposing secrets.
* ``output.redacted_sha256`` hashes the redacted view included in a shared
  manifest, so a reviewer can verify what they received.

The manifest does not replace the hash chain. It is a signed-by-hash summary
that can be checked with nothing but the manifest and, for input verification,
the original artifact.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from sqlmodel import Session, select

from . import __version__
from .db import SCHEMA_VERSION
from .models import Entity, Finding, Paste, Program, Relationship, Target
from .redaction import redact_command, redact_dict, redact_text, redact_value

MANIFEST_VERSION = 2


def canonical_json(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="replace")).hexdigest()


def sha256_json(value) -> str:
    return sha256_text(canonical_json(value))


def _entity_payload(entity: Entity, *, redact: bool) -> dict:
    value = redact_value(entity.type, entity.value, enabled=redact)
    normalized = redact_value(entity.type, entity.normalized or "", enabled=redact)
    return {
        "id": entity.id,
        "type": entity.type,
        "value": value,
        "normalized": normalized,
        "confidence": entity.confidence,
        "parser": entity.parser,
        "scope_status": entity.scope_status,
        "target_id": entity.target_id,
        "occurrences": entity.occurrences,
        "ignored": bool(entity.ignored),
        "verdict": entity.verdict,
        "tags": list(entity.tags or []),
    }


def _finding_payload(finding: Finding, *, redact: bool) -> dict:
    def maybe(value):
        return redact_text(value) if redact and value else value

    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "cvss": finding.cvss,
        "description": maybe(finding.description),
        "evidence": maybe(finding.evidence),
        "remediation": maybe(finding.remediation),
        "tags": list(finding.tags or []),
        "fingerprint": finding.fingerprint,
        "source_tool": finding.source_tool,
        "target_id": finding.target_id,
        "verdict": finding.verdict,
    }


def _relationship_payload(rel: Relationship, *, redact: bool) -> dict:
    return {
        "src": redact_text(rel.src_value) if redact else rel.src_value,
        "src_type": rel.src_type,
        "dst": redact_text(rel.dst_value) if redact else rel.dst_value,
        "dst_type": rel.dst_type,
        "rel_type": rel.rel_type,
        "confidence": rel.confidence,
    }


def _output_payload(session: Session, paste: Paste, *, redact: bool) -> dict:
    entities = session.exec(
        select(Entity).where(Entity.paste_id == paste.id).order_by(Entity.id)
    ).all()
    findings = session.exec(
        select(Finding).where(Finding.paste_id == paste.id).order_by(Finding.id)
    ).all()
    relationships = session.exec(
        select(Relationship).where(Relationship.paste_id == paste.id).order_by(Relationship.id)
    ).all()
    return {
        "entities": [_entity_payload(item, redact=redact) for item in entities],
        "findings": [_finding_payload(item, redact=redact) for item in findings],
        "relationships": [_relationship_payload(item, redact=redact) for item in relationships],
    }


def build_manifest(session: Session, paste: Paste, *, redact: bool = True) -> dict:
    """Build a deterministic manifest for one capture."""
    program = session.get(Program, paste.program_id) if paste.program_id else None
    target = session.get(Target, paste.target_id) if paste.target_id else None
    raw = paste.raw or ""
    input_sha = paste.content_sha256 or sha256_text(raw)

    prev = session.get(Paste, paste.prev_paste_id) if paste.prev_paste_id else None
    prev_chain_hash = prev.chain_hash if prev is not None else None
    link_verifiable = paste.prev_paste_id is None or prev is not None

    full = _output_payload(session, paste, redact=False)
    redacted = _output_payload(session, paste, redact=True)
    full_sha = sha256_json(full)
    redacted_sha = sha256_json(redacted)

    scope_in = (program.scope_in or "") if program else ""
    scope_out = (program.scope_out or "") if program else ""
    status_counts: dict[str, int] = {}
    for item in full["entities"]:
        key = str(item.get("scope_status") or "unknown")
        status_counts[key] = status_counts.get(key, 0) + 1

    issues = list(paste.parse_errors or [])
    warnings = []
    for issue in issues:
        if isinstance(issue, dict):
            warnings.append(str(issue.get("message") or issue.get("error") or issue))
        else:
            warnings.append(str(issue))

    return {
        "manifest_version": MANIFEST_VERSION,
        "generator": {
            "name": "breadcrumb",
            "version": __version__,
            "schema_version": SCHEMA_VERSION,
        },
        "capture": {
            "id": paste.id,
            "created_at": (
                paste.created_at.isoformat()
                if isinstance(paste.created_at, datetime)
                else str(paste.created_at or "")
            ),
            "source": paste.source,
            "tool": paste.tool_guess,
            "command": redact_command(paste.command) if redact else paste.command,
            "source_meta": redact_dict(paste.source_meta or {}, enabled=redact),
            "program": {"id": program.id, "name": program.name} if program else None,
            "target": {"id": target.id, "name": target.name, "kind": target.kind}
            if target
            else None,
        },
        "input": {
            "sha256": input_sha,
            "bytes": len(raw.encode("utf-8", errors="replace")),
            "raw_included": False,
        },
        "parser": {
            "parsers": list(paste.parsers or []),
            "versions": dict(paste.parser_versions or {}),
            "completeness": float(paste.completeness if paste.completeness is not None else 1.0),
            "skipped_rows": int(paste.skipped_rows or 0),
            "parsed_entities": int((paste.import_stats or {}).get("parsed_entities", 0) or 0),
            "parsed_findings": int((paste.import_stats or {}).get("parsed_findings", 0) or 0),
            "truncated_entities": int((paste.import_stats or {}).get("truncated_entities", 0) or 0),
            "issues": issues,
        },
        "output": {
            "entities": len(full["entities"]),
            "findings": len(full["findings"]),
            "relationships": len(full["relationships"]),
            "sha256": full_sha,
            "redacted_sha256": redacted_sha,
            "redaction": "default" if redact else "none",
        },
        "scope": {
            "program_id": program.id if program else None,
            "in_sha256": sha256_text(scope_in),
            "out_sha256": sha256_text(scope_out),
            "status_counts": status_counts,
        },
        "chain": {
            "prev_paste_id": paste.prev_paste_id,
            "prev_chain_hash": prev_chain_hash,
            "chain_hash": paste.chain_hash,
            "chain_seq": paste.chain_seq,
            "link_verifiable": link_verifiable,
        },
        "warnings": warnings,
    }


def manifest_json(manifest: dict, *, indent: int = 2) -> str:
    return json.dumps(manifest, indent=indent, sort_keys=True, default=str) + "\n"


def manifest_markdown(manifest: dict) -> str:
    capture = manifest.get("capture") or {}
    parser = manifest.get("parser") or {}
    output = manifest.get("output") or {}
    chain = manifest.get("chain") or {}
    scope = manifest.get("scope") or {}
    lines = [
        "# Breadcrumb evidence manifest",
        "",
        f"- **Manifest version:** {manifest.get('manifest_version')}",
        f"- **Generator:** {(manifest.get('generator') or {}).get('name')} "
        f"{(manifest.get('generator') or {}).get('version')}",
        f"- **Capture:** #{capture.get('id')} ({capture.get('source') or 'unknown source'})",
        f"- **Created:** {capture.get('created_at')}",
        f"- **Tool:** {capture.get('tool') or 'unknown'}",
    ]
    if capture.get("command"):
        lines.append(f"- **Command:** `{capture['command']}`")
    program = capture.get("program") or {}
    if program:
        lines.append(f"- **Program:** {program.get('name')} (#{program.get('id')})")
    lines += [
        "",
        "## Input",
        "",
        f"- **SHA-256:** `{manifest.get('input', {}).get('sha256')}`",
        f"- **Bytes:** {manifest.get('input', {}).get('bytes')}",
        "- Raw input is **not** included in this manifest.",
        "",
        "## Parser",
        "",
        f"- **Parsers:** {', '.join(parser.get('parsers') or []) or 'none'}",
        f"- **Versions:** {json.dumps(parser.get('versions') or {}, sort_keys=True)}",
        f"- **Completeness:** {parser.get('completeness')}",
        f"- **Skipped rows:** {parser.get('skipped_rows')}",
        "",
        "## Output",
        "",
        f"- **Entities:** {output.get('entities')}",
        f"- **Findings:** {output.get('findings')}",
        f"- **Relationships:** {output.get('relationships')}",
        f"- **Full output SHA-256:** `{output.get('sha256')}`",
        f"- **Redacted output SHA-256:** `{output.get('redacted_sha256')}`",
        "",
        "## Scope",
        "",
        f"- **Program id:** {scope.get('program_id')}",
        f"- **Scope-in SHA-256:** `{scope.get('in_sha256')}`",
        f"- **Scope-out SHA-256:** `{scope.get('out_sha256')}`",
        f"- **Status counts:** {json.dumps(scope.get('status_counts') or {}, sort_keys=True)}",
        "",
        "## Chain",
        "",
        f"- **Sequence:** {chain.get('chain_seq')}",
        f"- **Previous capture:** {chain.get('prev_paste_id')}",
        f"- **Previous chain hash:** `{chain.get('prev_chain_hash')}`",
        f"- **Chain hash:** `{chain.get('chain_hash')}`",
        f"- **Link verifiable:** {chain.get('link_verifiable')}",
        "",
    ]
    warnings = manifest.get("warnings") or []
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    lines.append("Verify offline with `python -m app.cli verify --manifest <this file>`.")
    return "\n".join(lines).rstrip() + "\n"


def verify_manifest_data(manifest: dict, *, raw: str | None = None) -> dict:
    """Verify a manifest without a database (input and chain checks)."""
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    check(
        "manifest_version",
        int(manifest.get("manifest_version") or 0) == MANIFEST_VERSION,
        f"expected {MANIFEST_VERSION}",
    )
    input_sha = (manifest.get("input") or {}).get("sha256")
    if raw is not None:
        actual = sha256_text(raw)
        check("input_sha256", actual == input_sha, f"actual {actual}")
    chain = manifest.get("chain") or {}
    prev = chain.get("prev_chain_hash")
    stored = chain.get("chain_hash")
    if input_sha and stored:
        if chain.get("prev_paste_id") is None:
            expected = sha256_text(f"genesis:{input_sha}")
            check("chain_hash", expected == stored, f"expected {expected}")
        elif prev:
            expected = sha256_text(f"{prev}:{input_sha}")
            check("chain_hash", expected == stored, f"expected {expected}")
        else:
            check("chain_hash", True, "predecessor missing; link is a recorded gap")
    else:
        check("chain_hash", False, "manifest has no input/chain hash")
    return {
        "valid": all(item["ok"] for item in checks),
        "checks": checks,
    }


def verify_paste_manifest(session: Session, paste: Paste, manifest: dict | None = None) -> dict:
    """Verify a stored capture against a manifest (or its freshly built form)."""
    expected = build_manifest(session, paste, redact=False)
    if manifest is None:
        manifest = expected
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    check(
        "manifest_version",
        int(manifest.get("manifest_version") or 0) == MANIFEST_VERSION,
        f"expected {MANIFEST_VERSION}",
    )
    check(
        "input_sha256",
        (manifest.get("input") or {}).get("sha256")
        == (expected.get("input") or {}).get("sha256"),
    )
    check(
        "chain_hash",
        (manifest.get("chain") or {}).get("chain_hash")
        == (expected.get("chain") or {}).get("chain_hash"),
    )
    check(
        "output_sha256",
        (manifest.get("output") or {}).get("sha256")
        == (expected.get("output") or {}).get("sha256"),
    )
    check(
        "capture_id",
        (manifest.get("capture") or {}).get("id") == paste.id,
    )
    return {
        "valid": all(item["ok"] for item in checks),
        "paste_id": paste.id,
        "checks": checks,
    }
