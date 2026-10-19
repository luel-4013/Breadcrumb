import re

from . import register
from .base import Entity, Parser

PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 0.95),
    (
        "aws_secret_key",
        re.compile(r"(?i)aws.{0,20}?(?:secret|key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        0.8,
    ),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), 0.95),
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 0.9),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), 0.9),
    ("stripe_key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"), 0.9),
    (
        "private_key",
        re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"),
        0.95,
    ),
]

GENERIC_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|passwd|password|access[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9\-_./+=]{8,})['\"]?"
)


@register
class SecretParser(Parser):
    name = "secret"
    description = "API keys, tokens and other leaked secrets"

    def detect(self, text):
        hits = sum(len(rx.findall(text)) for _kind, rx, _conf in PATTERNS)
        hits += len(GENERIC_RE.findall(text))
        return min(hits, 6.0)

    def parse(self, text):
        entities = []
        seen = set()

        def add(value, kind, label, confidence):
            value = value.strip().strip("'\"")
            key = (value, kind)
            if key in seen or not value:
                return
            seen.add(key)
            entities.append(
                Entity(
                    type="secret",
                    value=value,
                    normalized=value,
                    meta={"kind": kind, "label": label},
                    confidence=confidence,
                )
            )

        for kind, regex, confidence in PATTERNS:
            for match in regex.finditer(text):
                add(match.group(1), kind, kind, confidence)
        for match in GENERIC_RE.finditer(text):
            add(match.group(2), "generic", match.group(1).lower(), 0.5)

        return entities, []
