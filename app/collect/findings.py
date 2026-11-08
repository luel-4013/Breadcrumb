"""Helpers for emitting findings through Breadcrumb's existing nuclei parser.

Native collectors never write to the database directly. When a phase discovers
a candidate finding it emits ProjectDiscovery-compatible nuclei JSONL; the
normal ingest path parses it, de-duplicates it, and seals it with the capture.
Every native finding is deliberately tagged ``candidate`` -- pattern matches
are leads for manual review, not confirmed vulnerabilities.
"""

from __future__ import annotations

import json


def nuclei_record(
    *,
    template_id: str,
    name: str,
    severity: str = "info",
    matched_at: str = "",
    description: str = "",
    tags: list[str] | None = None,
    matcher: str = "",
    extracted: list[str] | None = None,
    host: str = "",
    port: int | None = None,
    extra: dict | None = None,
) -> dict:
    """One nuclei-shaped finding record.

    ``matched_at`` is what the nuclei parser uses for the finding location and
    for host/URL/port entities. ``extra`` is copied into the record for
    context such as the originating collector and observed evidence.
    """
    record: dict = {
        "template-id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "description": description,
            "tags": list(tags or ["native", "candidate"]),
        },
        "type": "native",
        "matched-at": matched_at,
        "matcher-name": matcher,
        "extracted-results": list(extracted or []),
        "host": host or matched_at,
    }
    if port is not None:
        record["port"] = int(port)
    if extra:
        record.update(extra)
    return record


def nuclei_jsonl(records: list[dict], *, header: str = "") -> str:
    """Serialize records with an optional human-readable comment header."""
    lines: list[str] = []
    if header:
        lines.extend(f"# {line}" for line in header.splitlines())
    for record in records:
        lines.append(json.dumps(record, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")
