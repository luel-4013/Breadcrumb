"""JSONL diagnostics shared by the tool-output parsers.

Tool output is not always valid JSONL: a scan can be interrupted, a wrapper can
print a warning between records, or a version upgrade can change the shape.
The parsers stay tolerant, but the import report must show what was skipped
instead of silently dropping rows.
"""

from __future__ import annotations

import json

from .base import ParserIssue
from .tool_json import strip_comments


def jsonl_issues(text: str, parser: str) -> tuple[list[ParserIssue], int]:
    """Return issues for lines that look like JSON objects but do not parse.

    Non-JSON lines (comments, progress banners, blank lines) are intentionally
    ignored: they are not data rows. A line beginning with ``{`` is a data row
    attempt and a parse failure is reported.

    A valid single JSON document (object or array) is not diagnosed line by
    line; pretty-printed JSON would otherwise look like truncated JSONL.
    """
    body = strip_comments(text or "").strip()
    if body:
        try:
            json.loads(body)
            return [], 0
        except (ValueError, TypeError):
            pass
    issues: list[ParserIssue] = []
    skipped = 0
    for line_no, line in enumerate((text or "").splitlines(), 1):
        stripped = line.strip().rstrip(",")
        if not stripped.startswith("{"):
            continue
        try:
            json.loads(stripped)
        except (ValueError, TypeError) as exc:
            skipped += 1
            issues.append(
                ParserIssue(
                    parser=parser,
                    code="skipped_row",
                    message=f"line {line_no}: invalid JSON ({exc})",
                    line=line_no,
                )
            )
    return issues, skipped
