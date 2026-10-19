import re

from . import register
from .base import Entity, Parser

REQ_RE = re.compile(
    r"^(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(?P<path>\S+)\s+HTTP/\d\.\d",
    re.MULTILINE,
)
RESP_RE = re.compile(r"^HTTP/\d\.\d\s+(?P<status>\d{3})\s*(?P<reason>.*)$", re.MULTILINE)
HEADER_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9\-]*):\s*(?P<value>.+)$", re.MULTILINE)

_INTERESTING = {
    "server", "x-powered-by", "location", "set-cookie", "x-frame-options",
    "content-security-policy", "access-control-allow-origin", "x-aspnet-version",
    "x-generator", "via", "x-backend-server",
}


@register
class HTTPParser(Parser):
    name = "http"
    description = "raw HTTP request/response dumps"

    def detect(self, text):
        score = 0.0
        if REQ_RE.search(text):
            score += 2.5
        if RESP_RE.search(text):
            score += 2.0
        return score

    def parse(self, text):
        entities = []
        for match in REQ_RE.finditer(text):
            method, path = match.group("method"), match.group("path")
            entities.append(
                Entity(
                    type="endpoint",
                    value=f"{method} {path}",
                    normalized=f"{method} {path}",
                    meta={"method": method, "path": path},
                    confidence=0.8,
                )
            )
            if "://" in path:
                entities.append(Entity(type="url", value=path, normalized=path, confidence=0.5))
        for match in RESP_RE.finditer(text):
            entities.append(
                Entity(
                    type="http_status",
                    value=match.group("status"),
                    normalized=match.group("status"),
                    confidence=0.6,
                )
            )
        for match in HEADER_RE.finditer(text):
            name = match.group("name").lower()
            value = match.group("value").strip()
            if name in _INTERESTING:
                entities.append(
                    Entity(
                        type="header",
                        value=f"{name}: {value}",
                        normalized=f"{name}:{value.lower()}",
                        meta={"name": name, "value": value},
                        confidence=0.7,
                    )
                )
            if name == "set-cookie":
                cookie = value.split("=", 1)[0].strip()
                if cookie:
                    entities.append(
                        Entity(
                            type="cookie",
                            value=cookie,
                            normalized=cookie,
                            meta={"raw": value},
                            confidence=0.6,
                        )
                    )
        return entities, []
