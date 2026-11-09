"""Secret redaction for manifests, reports, and review bundles.

The rule is simple: evidence exports are shareable by default. Raw captures
stay in the local database; exported manifests contain hashes and redacted
metadata unless the operator explicitly asks for unredacted output.

This module is intentionally conservative. It masks known token shapes and
key/value secrets, not arbitrary words that happen to contain "token".
"""

from __future__ import annotations

import re

SENSITIVE_ENTITY_TYPES = {"secret", "credential", "jwt"}

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)([^\s,;\"']+)"
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(
            r"(?i)\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
            r"client[_-]?secret|password|passwd|pwd|secret)\s*[:=]\s*)"
            r"([^\s,;\"']+)"
        ),
        r"\1[redacted]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[redacted-aws-key]"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "[redacted-aws-key]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[redacted-github-token]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[redacted-slack-token]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[redacted-jwt]"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[redacted-private-key]",
    ),
    (
        re.compile(
            r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)"
        ),
        r"\1[redacted]\3",
    ),
]


def redact_text(text: str) -> str:
    """Mask known secret shapes in free text (commands, logs, evidence)."""
    value = str(text or "")
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def redact_command(command: str | None) -> str | None:
    if command is None:
        return None
    return redact_text(command)


def redact_value(entity_type: str, value: str, *, enabled: bool = True) -> str:
    """Mask a sensitive entity value while keeping a recognizable prefix."""
    if not enabled or entity_type not in SENSITIVE_ENTITY_TYPES:
        return redact_text(value) if enabled else value
    raw = str(value or "")
    if len(raw) <= 8:
        return "[redacted]"
    return f"{raw[:4]}…{raw[-2:]}  [masked]"


_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "set-cookie",
    "private_key",
}


def _sensitive_key(key) -> bool:
    normalized = str(key or "").strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or any(
        part in normalized for part in ("password", "secret", "token", "api_key", "apikey")
    )


def redact_dict(value, *, enabled: bool = True):
    """Recursively redact strings and sensitive key/value pairs."""
    if not enabled:
        return value
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if _sensitive_key(key) and value[key] not in (None, "")
                else redact_dict(item, enabled=enabled)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_dict(item, enabled=enabled) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
