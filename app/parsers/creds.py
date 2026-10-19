import re

from . import register
from .base import Entity, Parser

LABEL_PAIR_RE = re.compile(
    r"(?i)\b(?:user(?:name)?|login|uid)\b\s*[:=]\s*(\S+)\s+"
    r"(?:pass(?:word)?|pwd)\b\s*[:=]\s*(\S+)"
)
HYDRA_RE = re.compile(
    r"(?i)host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
)
USERPASS_RE = re.compile(r"(?m)^\s*([A-Za-z0-9._@+\-]{2,64})\s*:\s*([^\s:]{4,64})\s*$")
EMAIL_LIKE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

_HEADER_NAMES = {
    "server", "date", "content-type", "content-length", "connection", "location",
    "cache-control", "x-powered-by", "set-cookie", "host", "user-agent", "accept",
    "referer", "etag", "vary", "allow", "expires", "pragma", "transfer-encoding",
    "content-encoding", "x-frame-options", "strict-transport-security",
    "content-security-policy", "via", "age", "warning", "upgrade",
}


@register
class CredParser(Parser):
    name = "cred"
    description = "username/password pairs"

    def detect(self, text):
        labeled = len(LABEL_PAIR_RE.findall(text)) + len(HYDRA_RE.findall(text))
        if labeled:
            return min(labeled, 5.0) + 1.0
        lines = [line for line in text.splitlines() if line.strip()]
        matches = [line for line in lines if USERPASS_RE.match(line) and not self._looks_like_header(line)]
        if matches:
            return 0.5 + min(len(matches), 2)
        return 0.0

    def _looks_like_header(self, line):
        name = line.split(":", 1)[0].strip().lower()
        return name in _HEADER_NAMES

    def _add(self, entities, seen, user, password, host=None, confidence=0.7):
        key = (user.lower(), password)
        if key in seen:
            return
        seen.add(key)
        entities.append(
            Entity(
                type="credential",
                value=f"{user}:{password}",
                normalized=f"{user}:{password}",
                meta={"username": user, "password": password, "host": host},
                confidence=confidence,
            )
        )

    def parse(self, text):
        entities = []
        seen = set()
        for match in LABEL_PAIR_RE.finditer(text):
            self._add(entities, seen, match.group(1), match.group(2))
        for match in HYDRA_RE.finditer(text):
            self._add(entities, seen, match.group(2), match.group(3), host=match.group(1))
        for match in USERPASS_RE.finditer(text):
            line = match.group(0)
            user, password = match.group(1), match.group(2)
            if "://" in line or EMAIL_LIKE.fullmatch(password):
                continue
            if self._looks_like_header(line):
                continue
            self._add(entities, seen, user, password, confidence=0.4)
        return entities, []
