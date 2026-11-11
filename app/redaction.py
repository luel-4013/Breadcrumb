"""Secret redaction for reports, manifests, and review bundles.

The rule is simple: evidence exports are shareable by default. Raw captures
stay in the local database; exported reports and manifests contain redacted
text unless the operator explicitly asks for unredacted output.

This module is intentionally conservative. It masks known token shapes,
authentication headers, cookies, URL credentials and key/value secrets, not
arbitrary words that happen to contain "token". Operators can add per-report
rules (literal or regular-expression replacements) without weakening the
built-in defaults.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SENSITIVE_ENTITY_TYPES = {"secret", "credential", "jwt"}

# Header names whose entire value is sensitive. The value after the colon is
# replaced, the header name is kept so a reviewer can see what was present.
_SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
)

_HEADER_PATTERNS = [
    (
        re.compile(
            rf"(?im)^([ \t]*(?:{'|'.join(re.escape(h) for h in _SENSITIVE_HEADERS)})"
            r"[ \t]*:[ \t]*)([^\r\n]*)"
        ),
        r"\1[redacted]",
    ),
    # Headers can also appear inline in evidence such as
    # "GET / HTTP/1.1  Authorization: Bearer ...".
    (
        re.compile(
            rf"(?i)\b((?:{'|'.join(re.escape(h) for h in _SENSITIVE_HEADERS)})"
            r"[ \t]*:[ \t]*)([^\r\n]+)"
        ),
        r"\1[redacted]",
    ),
]

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    *_HEADER_PATTERNS,
    (
        re.compile(
            r"(?i)\b(bearer[ \t]+)([A-Za-z0-9._~+/=-]{12,})"
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(
            r"(?i)\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
            r"client[_-]?secret|password|passwd|pwd|secret|auth[_-]?token)"
            r"\s*[:=]\s*)"
            r"([^\s,;\"'&]+)"
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(
            r"(?i)([?&](?:token|access_token|refresh_token|id_token|api_key|"
            r"apikey|password|passwd|secret|auth)=)([^&\s#]+)"
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(
            r"(?i)\b((?:session|sessionid|phpsessid|jsessionid|csrftoken|"
            r"xsrf-token)=)([^;\s,]+)"
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

# Strict mode additionally masks long opaque values that are not necessarily
# recognizable as a known token shape. It is opt-in because hashes and IDs are
# sometimes useful evidence.
_STRICT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[redacted-hex]"),
    (
        re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
        "[redacted-opaque]",
    ),
]

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
    "session",
    "sessionid",
    "phpsessid",
    "jsessionid",
}


def redact_text(text: str, *, strict: bool = False) -> str:
    """Mask known secret shapes in free text (commands, logs, evidence)."""
    value = str(text or "")
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    if strict:
        for pattern, replacement in _STRICT_PATTERNS:
            value = pattern.sub(replacement, value)
    return value


def redact_command(command: str | None) -> str | None:
    if command is None:
        return None
    return redact_text(command)


def redact_value(entity_type: str, value: str, *, enabled: bool = True) -> str:
    """Mask a sensitive entity value while keeping a recognizable prefix."""
    if not enabled:
        return value
    if entity_type in SENSITIVE_ENTITY_TYPES:
        raw = str(value or "")
        if len(raw) <= 8:
            return "[redacted]"
        return f"{raw[:4]}…{raw[-2:]}  [masked]"
    return redact_text(value)


def _sensitive_key(key) -> bool:
    normalized = str(key or "").strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or any(
        part in normalized for part in ("password", "secret", "token", "api_key", "apikey")
    )


def redact_dict(value, *, enabled: bool = True, strict: bool = False):
    """Recursively redact strings and sensitive key/value pairs."""
    if not enabled:
        return value
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if _sensitive_key(key) and value[key] not in (None, "")
                else redact_dict(item, enabled=enabled, strict=strict)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_dict(item, enabled=enabled, strict=strict) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_dict(item, enabled=enabled, strict=strict) for item in value)
    if isinstance(value, str):
        return redact_text(value, strict=strict)
    return value


@dataclass(frozen=True)
class RedactionRule:
    """A user-provided per-report replacement rule."""

    kind: str  # literal | regex
    pattern: str
    replacement: str
    raw: str = ""
    _compiled: re.Pattern[str] | None = field(default=None, compare=False, repr=False)

    def apply(self, text: str) -> str:
        if not text:
            return text
        if self.kind == "literal":
            return text.replace(self.pattern, self.replacement)
        compiled = self._compiled or re.compile(self.pattern, re.IGNORECASE)
        return compiled.sub(self.replacement, text)


def parse_redaction_rules(text: str | None, *, limit: int = 100) -> list[RedactionRule]:
    """Parse per-report rules.

    Accepted forms (one per line, ``#`` comments ignored)::

        literal:project-codename=Project X
        regex:(?i)acme-internal=acme-public
        plain-literal=replacement

    The built-in redaction patterns always run first. Custom rules can only
    replace what remains; they cannot disable a built-in rule.
    """
    rules: list[RedactionRule] = []
    for line_number, line in enumerate(str(text or "").splitlines(), 1):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        kind = "literal"
        body = raw
        if raw.lower().startswith("literal:"):
            body = raw.split(":", 1)[1]
        elif raw.lower().startswith("regex:"):
            kind = "regex"
            body = raw.split(":", 1)[1]
        if "=" not in body:
            raise ValueError(
                f"redaction rule line {line_number} must be literal:text=replacement "
                f"or regex:pattern=replacement"
            )
        pattern, replacement = body.split("=", 1)
        pattern = pattern.strip()
        if not pattern:
            raise ValueError(f"redaction rule line {line_number} has an empty pattern")
        compiled = None
        if kind == "regex":
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"redaction rule line {line_number} has an invalid regex: {exc}"
                ) from exc
        rules.append(
            RedactionRule(
                kind=kind,
                pattern=pattern,
                replacement=replacement.strip(),
                raw=raw,
                _compiled=compiled,
            )
        )
        if len(rules) > limit:
            raise ValueError(f"at most {limit} custom redaction rules are allowed")
    return rules


class RedactionPolicy:
    """Default-on redaction with optional per-report rules and strict mode."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        profile: str = "default",
        rules: list[RedactionRule] | tuple[RedactionRule, ...] = (),
    ) -> None:
        profile = (profile or "default").strip().lower()
        if profile not in {"default", "strict", "none"}:
            raise ValueError("redaction profile must be default, strict, or none")
        self.enabled = bool(enabled) and profile != "none"
        self.profile = profile
        self.rules = tuple(rules or ())

    @property
    def strict(self) -> bool:
        return self.profile == "strict"

    def text(self, value) -> str:
        text = "" if value is None else str(value)
        if not self.enabled:
            return text
        text = redact_text(text, strict=self.strict)
        for rule in self.rules:
            text = rule.apply(text)
        return text

    def value(self, entity_type: str, value) -> str:
        text = "" if value is None else str(value)
        if not self.enabled:
            return text
        if entity_type in SENSITIVE_ENTITY_TYPES:
            raw = text
            if len(raw) <= 8:
                text = "[redacted]"
            else:
                text = f"{raw[:4]}…{raw[-2:]}  [masked]"
            for rule in self.rules:
                text = rule.apply(text)
            return text
        return self.text(text)

    def dict(self, value):
        if not self.enabled:
            return value
        if isinstance(value, dict):
            return {
                key: (
                    "[redacted]"
                    if _sensitive_key(key) and value[key] not in (None, "")
                    else self.dict(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.dict(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.dict(item) for item in value)
        if isinstance(value, str):
            return self.text(value)
        return value

    def describe(self) -> dict:
        return {
            "enabled": self.enabled,
            "profile": self.profile if self.enabled else "none",
            "custom_rules": len(self.rules),
            "custom_rule_kinds": sorted({rule.kind for rule in self.rules}),
            "defaults": "auth headers, cookies, tokens, keys, URL credentials, private keys",
        }


def policy_from(
    *,
    reveal: bool = False,
    profile: str = "default",
    rules_text: str | None = None,
) -> RedactionPolicy:
    """Build a policy from request/CLI flags.

    Reveal is explicit and disables all masking. A reveal request with a
    non-default profile is treated as an error rather than silently ignored.
    """
    rules = parse_redaction_rules(rules_text)
    if reveal:
        return RedactionPolicy(enabled=False, profile="none", rules=())
    return RedactionPolicy(enabled=True, profile=profile, rules=rules)
