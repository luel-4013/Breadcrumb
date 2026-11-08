"""Dalfox JSON/JSONL XSS results.

Dalfox can emit a JSON array or JSONL. Every record is a lead: the adapter and
parser never label it "confirmed", and the finding carries a ``candidate`` tag
so it stays distinguishable from verified evidence.
"""

from urllib.parse import urlparse

from . import register
from .base import Entity, Parser
from .tool_json import add_unique, iter_json_values

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _severity(value) -> str:
    text = str(value or "").strip().lower()
    return text if text in _SEVERITIES else "high"


def _records(text):
    for obj in iter_json_values(text):
        if (
            "type" in obj
            and any(key in obj for key in ("payload", "evidence", "inject_type", "message"))
        ) or ("severity" in obj and "message" in obj):
            yield obj


@register
class DalfoxParser(Parser):
    name = "dalfox"
    description = "Dalfox JSON/JSONL XSS candidate results"

    def detect(self, text):
        score = 0.0
        for item in _records(text):
            score += 3.0
            if item.get("payload") or item.get("evidence"):
                score += 1.0
            if score >= 8.0:
                break
        return score

    def _target_url(self, item) -> str:
        for key in ("url", "target", "data", "location"):
            value = str(item.get(key) or "").strip()
            if value.startswith(("http://", "https://")):
                return value
        return ""

    def parse(self, text):
        entities, rels = [], []
        seen = set()
        for item in _records(text):
            url = self._target_url(item)
            if not url:
                continue
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            add_unique(
                entities,
                seen,
                Entity(
                    type="url",
                    value=url,
                    normalized=url,
                    meta={
                        "from": "dalfox",
                        "inject_type": item.get("inject_type") or "",
                        "method": item.get("method") or "",
                    },
                    confidence=0.85,
                ),
            )
            host = (parsed.hostname or "").strip().lower()
            if host:
                add_unique(
                    entities,
                    seen,
                    Entity(
                        type="subdomain" if host.count(".") > 1 else "domain",
                        value=host,
                        normalized=host,
                        meta={"from": "dalfox"},
                        confidence=0.8,
                    ),
                )
            if parsed.path and parsed.path != "/":
                add_unique(
                    entities,
                    seen,
                    Entity(
                        type="path",
                        value=parsed.path,
                        normalized=parsed.path,
                        meta={"host": host},
                        confidence=0.6,
                    ),
                )
            for key in ("param", "parameter"):
                name = str(item.get(key) or "").strip()
                if name:
                    add_unique(
                        entities,
                        seen,
                        Entity(
                            type="param",
                            value=name,
                            normalized=name,
                            meta={"host": host, "path": parsed.path},
                            confidence=0.6,
                        ),
                    )
        return entities, rels

    def findings(self, text):
        out = []
        for item in _records(text):
            url = self._target_url(item)
            if not url:
                continue
            try:
                host = (urlparse(url).hostname or "").strip().lower()
            except ValueError:
                host = ""
            kind = str(item.get("inject_type") or item.get("type") or "xss").strip()
            payload = str(item.get("payload") or "").strip()
            evidence = str(item.get("evidence") or item.get("message") or "").strip()
            if payload:
                evidence = (evidence + "  -> " + payload).strip()
            out.append(
                {
                    "title": f"XSS candidate ({kind})",
                    "severity": _severity(item.get("severity")),
                    "description": str(item.get("message") or "").strip(),
                    "evidence": evidence or url,
                    "tags": ["xss", "dalfox", "candidate"],
                    "target": host,
                    "dedup_key": (
                        f"dalfox|{kind}|{url}|{item.get('method', '')}|{payload}"
                    ),
                }
            )
        return out
