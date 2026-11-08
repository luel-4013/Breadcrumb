"""Tolerant JSON/JSONL helpers for external-tool output.

Adapters may prepend a small ``#`` comment block with the scope decision to an
artifact. These helpers ignore comment lines and accept either one JSON
document (object or array) or newline-delimited objects, so the same parser
works with stdout and with a tool that writes a file.
"""

import json


def strip_comments(text: str) -> str:
    return "\n".join(
        line for line in (text or "").splitlines()
        if not line.lstrip().startswith("#")
    )


def iter_json_values(text: str):
    """Yield JSON objects from an object, array, or JSONL document."""
    body = strip_comments(text).strip()
    if not body:
        return
    try:
        value = json.loads(body)
    except (ValueError, TypeError):
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(item, list):
                for entry in item:
                    if isinstance(entry, dict):
                        yield entry
            elif isinstance(item, dict):
                yield item
        return
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item
    elif isinstance(value, dict):
        yield value


def add_unique(entities, seen, entity) -> None:
    key = (entity.type, entity.normalized.lower())
    if key in seen:
        return
    seen.add(key)
    entities.append(entity)
