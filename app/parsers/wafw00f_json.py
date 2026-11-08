"""wafw00f JSON output.

The tool reports whether a WAF was detected and, when it was, the product and
manufacturer. That is a technology observation, not a vulnerability finding.
"""

from urllib.parse import urlparse

from . import register
from .base import Entity, Parser
from .tool_json import add_unique, iter_json_values


def _records(text):
    for obj in iter_json_values(text):
        if "url" in obj and any(
            key in obj for key in ("detected", "firewall", "waf", "manufacturer")
        ):
            yield obj


@register
class Wafw00fParser(Parser):
    name = "wafw00f"
    description = "wafw00f JSON WAF fingerprint results"

    def detect(self, text):
        score = 0.0
        for _item in _records(text):
            score += 3.0
            if score >= 6.0:
                break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen = set()
        for item in _records(text):
            url = str(item.get("url") or "").strip()
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
                    meta={"from": "wafw00f"},
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
                        meta={"from": "wafw00f"},
                        confidence=0.8,
                    ),
                )
            detected = bool(item.get("detected"))
            name = str(item.get("firewall") or item.get("waf") or "").strip()
            if detected and name:
                add_unique(
                    entities,
                    seen,
                    Entity(
                        type="tech",
                        value=name,
                        normalized=name.lower(),
                        meta={
                            "from": "wafw00f",
                            "host": host,
                            "manufacturer": item.get("manufacturer") or "",
                        },
                        confidence=0.8,
                    ),
                )
        return entities, rels
