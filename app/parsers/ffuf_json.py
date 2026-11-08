"""ffuf JSON content-discovery results.

ffuf writes one JSON document with a ``results`` array (``-of json -o file``).
Each result carries the fuzzed input, the resulting URL, status, length and
redirect target. Those are normal URL/path/host entities, not findings: a
200 response is a lead for manual review, not a vulnerability.
"""

from urllib.parse import urlparse

from . import register
from .base import Entity, Parser
from .tool_json import add_unique, iter_json_values


def _host_type(host: str) -> str:
    return "subdomain" if host.count(".") > 1 else "domain"


@register
class FfufParser(Parser):
    name = "ffuf"
    description = "ffuf JSON content-discovery results"

    def _results(self, text):
        for obj in iter_json_values(text):
            results = obj.get("results")
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        yield item
            elif "status" in obj and ("url" in obj or "input" in obj):
                yield obj

    def detect(self, text):
        score = 0.0
        for item in self._results(text):
            score += 2.0
            if "status" in item and ("url" in item or "input" in item):
                score += 1.0
            if score >= 6.0:
                break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen = set()
        for item in self._results(text):
            url = str(item.get("url") or "").strip()
            if not url:
                value = item.get("input")
                if isinstance(value, dict):
                    url = str(value.get("FUZZ") or "").strip()
            if not url:
                continue
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            meta = {
                "status_code": item.get("status"),
                "content_length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "content_type": item.get("content-type") or item.get("content_type") or "",
                "redirect": item.get("redirectlocation") or item.get("redirect_location") or "",
                "from": "ffuf",
            }
            meta = {k: v for k, v in meta.items() if v not in (None, "", [])}
            add_unique(
                entities,
                seen,
                Entity(type="url", value=url, normalized=url, meta=meta, confidence=0.9),
            )
            host = (parsed.hostname or "").strip().lower()
            if host:
                add_unique(
                    entities,
                    seen,
                    Entity(
                        type=_host_type(host),
                        value=host,
                        normalized=host,
                        meta={"from": "ffuf"},
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
                        meta={"host": host, "status_code": item.get("status")},
                        confidence=0.7,
                    ),
                )
            if parsed.port:
                add_unique(
                    entities,
                    seen,
                    Entity(
                        type="port",
                        value=str(parsed.port),
                        normalized=f"{host}:{parsed.port}",
                        meta={"host": host, "port": parsed.port, "service": parsed.scheme},
                        confidence=0.6,
                    ),
                )
        return entities, rels
