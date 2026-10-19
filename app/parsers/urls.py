import re
from urllib.parse import parse_qs, urlparse

from . import register
from .base import Entity, Parser

URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>\]\)\},]+")


@register
class URLParser(Parser):
    name = "url"
    description = "URLs, paths and query parameters"

    def detect(self, text):
        return min(len(URL_RE.findall(text)), 5.0)

    def parse(self, text):
        entities = []
        seen = set()
        for raw in URL_RE.findall(text):
            url = raw.rstrip(".,);]")
            if url in seen:
                continue
            seen.add(url)
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            entities.append(
                Entity(
                    type="url",
                    value=url,
                    normalized=url,
                    meta={
                        "scheme": parsed.scheme,
                        "host": parsed.hostname,
                        "port": parsed.port,
                        "path": parsed.path,
                    },
                    confidence=0.9,
                )
            )
            if parsed.path and parsed.path != "/":
                entities.append(
                    Entity(
                        type="path",
                        value=parsed.path,
                        normalized=parsed.path,
                        meta={"host": parsed.hostname},
                        confidence=0.6,
                    )
                )
            for key in parse_qs(parsed.query).keys():
                entities.append(
                    Entity(
                        type="param",
                        value=key,
                        normalized=key,
                        meta={"host": parsed.hostname, "path": parsed.path},
                        confidence=0.5,
                    )
                )
        return entities, []
