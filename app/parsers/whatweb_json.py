"""WhatWeb JSON fingerprint output.

WhatWeb's ``--log-json`` output is an array of records with a ``plugins``
object. Each plugin name becomes a ``tech`` entity; version arrays are kept in
the entity metadata so CVE correlation can use them.
"""

from urllib.parse import urlparse

from . import register
from .base import Entity, Parser
from .tool_json import add_unique, iter_json_values


def _records(text):
    for obj in iter_json_values(text):
        if isinstance(obj.get("plugins"), dict) and (
            "target" in obj or "url" in obj
        ):
            yield obj


def _first(value) -> str:
    if isinstance(value, list):
        return str(value[0]).strip() if value else ""
    return str(value or "").strip()


@register
class WhatWebParser(Parser):
    name = "whatweb"
    description = "WhatWeb JSON technology fingerprints"

    def detect(self, text):
        score = 0.0
        for _item in _records(text):
            score += 4.0
            if score >= 8.0:
                break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen = set()
        for item in _records(text):
            url = str(item.get("target") or item.get("url") or "").strip()
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
                    meta={"from": "whatweb", "status_code": item.get("http_status")},
                    confidence=0.9,
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
                        meta={"from": "whatweb"},
                        confidence=0.8,
                    ),
                )
            for name, info in (item.get("plugins") or {}).items():
                if not isinstance(info, dict):
                    info = {}
                version = _first(info.get("version"))
                meta = {"from": "whatweb", "host": host}
                if version:
                    meta["version"] = version
                string = _first(info.get("string"))
                if string:
                    meta["string"] = string
                add_unique(
                    entities,
                    seen,
                    Entity(
                        type="tech",
                        value=str(name),
                        normalized=str(name).lower(),
                        meta=meta,
                        confidence=0.75,
                    ),
                )
        return entities, rels
