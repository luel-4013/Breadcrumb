import re

from . import register
from .base import Entity, Parser

WILDCARD_RE = re.compile(r"\*\.(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}")
DOMAIN_RE = re.compile(
    r"(?<![\w.@-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}(?![\w.@-])"
)

_FAKE_TLDS = {
    "html", "htm", "php", "asp", "aspx", "jsp", "js", "css", "txt", "json", "xml",
    "png", "jpg", "jpeg", "gif", "pdf", "svg", "ico", "woff", "woff2", "ttf", "otf",
    "map", "sh", "py", "rb", "pl", "exe", "dll", "so", "zip", "tar", "gz", "bz2",
    "7z", "rar", "log", "conf", "ini", "yml", "yaml", "md", "doc", "docx", "xls",
    "xlsx", "csv", "bak", "sql", "env", "old", "tmp", "swp", "lock", "min", "local",
}


@register
class HostParser(Parser):
    name = "host"
    description = "domains, subdomains and wildcard zones"

    def detect(self, text):
        return min(len(DOMAIN_RE.findall(text)), 5.0) + len(WILDCARD_RE.findall(text))

    def parse(self, text):
        entities = []
        seen = set()
        for wildcard in WILDCARD_RE.findall(text):
            key = wildcard.lower()
            if key in seen:
                continue
            seen.add(key)
            entities.append(
                Entity(
                    type="wildcard",
                    value=wildcard,
                    normalized=key,
                    meta={"zone": wildcard[2:]},
                    confidence=0.9,
                )
            )
        for domain in DOMAIN_RE.findall(text):
            key = domain.lower()
            if key in seen:
                continue
            tld = domain.rsplit(".", 1)[-1].lower()
            if tld in _FAKE_TLDS:
                continue
            parts = domain.split(".")
            if len(parts) < 2:
                continue
            seen.add(key)
            entities.append(
                Entity(
                    type="subdomain" if len(parts) > 2 else "domain",
                    value=domain,
                    normalized=key,
                    meta={"zone": ".".join(parts[-2:])},
                    confidence=0.7,
                )
            )
        return entities, []
