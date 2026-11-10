"""Import a Breadcrumb Ledger JSONL export.

The Ledger is the product's memory. Exporting a slice must not be a one-way
door, so this parser reads the exact rows produced by ``ledger.assets_to_jsonl``
and turns them back into entities through the normal ingest path. Analyst
annotations (verdict, tags, notes), observed status codes, and provenance
metadata survive the round trip; scope is recomputed for the destination
program rather than trusted from the file.

Detection is deliberately conservative: generic JSONL from a scanner must keep
going to its own parser. A row only claims this parser when it carries the
``ledger_version`` marker, or when it has the full asset shape produced by an
export (``type`` + ``value`` + at least one Ledger provenance field).
"""

from __future__ import annotations

import json

from . import register
from .base import Entity, Parser, ParserIssue, ParseResult
from .jsonl import jsonl_issues
from .tool_json import strip_comments

VERDICTS = {"none", "confirmed", "false-positive", "needs-review"}
PROVENANCE_FIELDS = {"first_seen", "last_seen", "programs", "captures", "targets", "seen_before"}


def _rows(text: str) -> list[dict]:
    body = strip_comments(text or "").strip()
    if not body:
        return []
    try:
        value = json.loads(body)
    except (ValueError, TypeError):
        rows = []
        for line in body.splitlines():
            stripped = line.strip().rstrip(",")
            if not stripped.startswith("{"):
                continue
            try:
                item = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []


@register
class LedgerJSONLParser(Parser):
    name = "ledger_jsonl"
    description = "Breadcrumb Ledger JSONL export (round-trip import)"
    parser_version = "1"

    def detect(self, text: str) -> float:
        rows = _rows(text)
        if not rows:
            return 0.0
        if any("ledger_version" in row for row in rows):
            return 7.0
        full = sum(
            1
            for row in rows
            if row.get("type")
            and row.get("value")
            and PROVENANCE_FIELDS & set(row)
        )
        if full == len(rows):
            return 4.0
        return 0.0

    def parse_detailed(self, text: str) -> ParseResult:
        rows = _rows(text)
        entities: list[Entity] = []
        issues: list[ParserIssue] = []
        skipped = 0
        for index, row in enumerate(rows, 1):
            etype = str(row.get("type") or "").strip()
            value = str(row.get("value") or "").strip()
            if not etype or not value:
                skipped += 1
                issues.append(
                    ParserIssue(
                        parser=self.name,
                        code="skipped_row",
                        message=f"row {index}: missing type or value",
                        line=index,
                    )
                )
                continue
            meta = dict(row.get("meta") or {})
            for key in (
                "ledger_version",
                "scope_status",
                "scope_reason",
                "first_seen",
                "last_seen",
                "programs",
                "targets",
                "captures",
                "occurrences",
                "seen_before",
            ):
                if key in row and row[key] not in (None, "", []):
                    meta[f"ledger_{key}"] = row[key]
            code = row.get("status_code")
            try:
                status_code = int(code) if code not in (None, "") else None
            except (TypeError, ValueError):
                status_code = None
            if status_code is not None and not (100 <= status_code <= 599):
                status_code = None
            verdict = str(row.get("verdict") or "none").strip().lower()
            if verdict not in VERDICTS:
                verdict = "none"
            tags = row.get("tags") or []
            if isinstance(tags, str):
                tags = [part.strip() for part in tags.split(",") if part.strip()]
            tags = [str(tag) for tag in tags if tag]
            try:
                confidence = float(row.get("confidence", 1.0))
            except (TypeError, ValueError):
                confidence = 1.0
            entities.append(
                Entity(
                    type=etype,
                    value=value,
                    normalized=str(row.get("normalized") or value),
                    confidence=max(0.0, min(1.0, confidence)),
                    meta=meta,
                    status_code=status_code,
                    tags=tags,
                    verdict=verdict,
                    notes=str(row.get("notes") or ""),
                )
            )
        extra_issues, invalid_rows = jsonl_issues(text, self.name)
        issues.extend(extra_issues)
        skipped += invalid_rows
        return ParseResult(
            entities=entities,
            issues=issues,
            skipped_rows=skipped,
            parser_version=self.parser_version,
            stats={"rows": len(rows), "entities": len(entities)},
        )
