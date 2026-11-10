"""Scope parsing and matching.

Bug-bounty programs describe what you may touch as a text blob (one entry per
line). This module turns that blob into rules and answers a single question:
"is this value in scope, out of scope, or unknown?"

Supported entry shapes::

    example.com            # apex + every subdomain (suffix match)
    *.example.com          # subdomains only (not the apex)
    .example.com           # explicit suffix
    api.example.com        # suffix match (apex + subdomains)
    10.0.0.0/24            # CIDR range
    10.0.0.5               # single IP
    https://app.example.com/login   # a URL -> its host is used
    example.com/admin/*    # URL path prefix (path rule)
    https://api.example.com/v2     # host + path prefix
    !internal.example.com  # leading ! or - negates (treated as out-of-scope)

Any non-IP, non-CIDR entry is treated as a domain-suffix rule. Bare domains
match subdomains on purpose: recon data is overwhelmingly subdomains, and an
over-inclusive scope is easy to correct by hand. Entries that carry a path
(``host/path``) become *path rules*: they only match URLs/endpoints/paths under
that prefix, so you can scope ``example.com/admin`` without excluding the whole
host.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_COMMENT_RE = re.compile(r"\s+#.*$")
_STATUS_RE = re.compile(r"\s+status:([0-9,\s]+)$", re.IGNORECASE)


@dataclass
class ScopeRule:
    pattern: str
    kind: str  # cidr | ip | domain | wildcard | exact | path
    negate: bool = False
    network: object = None  # ipaddress network when kind == cidr/ip
    host: str = ""          # host part of a path rule
    path: str = ""          # path prefix of a path rule (leading slash)
    status_codes: frozenset[int] | None = None  # optional HTTP status filter

    def describe(self) -> str:
        prefix = "!" if self.negate else ""
        if self.kind == "path":
            base = f"{prefix}{self.host}{self.path}"
        else:
            base = f"{prefix}{self.pattern}"
        if self.status_codes:
            base += " status:" + ",".join(str(code) for code in sorted(self.status_codes))
        return base


@dataclass
class ScopeDecision:
    """An explainable scope verdict.

    ``reason`` is a stable code so the UI/API can group decisions without
    parsing prose. ``rule`` is the exact program-scope line that decided it.
    """

    status: str  # in | out | unknown
    reason: str
    rule: str | None = None
    rule_kind: str | None = None
    status_code: int | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "rule": self.rule,
            "rule_kind": self.rule_kind,
            "status_code": self.status_code,
            "detail": self.detail,
        }


def _strip_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line).strip()


def _split_host_path(token: str) -> tuple[str, str]:
    """Split 'host/path' into ('host', '/path'). Empty path when absent."""
    if "/" not in token:
        return token, ""
    host, _, rest = token.partition("/")
    path = "/" + rest if rest else "/"
    return host, path


def _parse_status_filter(token: str) -> tuple[str, frozenset[int] | None]:
    """Split a trailing ``status:200,204`` filter from a scope entry."""
    match = _STATUS_RE.search(token)
    if not match:
        return token, None
    codes: set[int] = set()
    for part in match.group(1).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            code = int(part)
        except ValueError:
            continue
        if 100 <= code <= 599:
            codes.add(code)
    return token[: match.start()].strip(), frozenset(codes) if codes else None


def classify(token: str) -> ScopeRule:
    token = token.strip()
    negate = token.startswith(("!", "-"))
    if negate:
        token = token[1:].strip()
    token, status_codes = _parse_status_filter(token)

    host = token
    path = ""
    if "://" in token:
        parsed = urlparse(token)
        host = (parsed.hostname or parsed.path.split("/")[0]).strip()
        path = parsed.path or ""
    else:
        # CIDR must be recognized before path-splitting, otherwise
        # "10.0.0.0/24" is mangled into host "10.0.0.0" + path "/24".
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                return ScopeRule(f"{net}", "cidr", negate, net)
            except ValueError:
                pass
        host, path = _split_host_path(token)

    host = host.rstrip("/").strip().lower()
    path = path.rstrip().strip()
    if status_codes and not path:
        # "example.com status:200" is a host-wide URL status filter.
        path = "/"

    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
            return ScopeRule(f"{net}", "cidr", negate, net)
        except ValueError:
            pass

    try:
        ip = ipaddress.ip_address(host)
        return ScopeRule(str(ip), "ip", negate, ip)
    except ValueError:
        pass

    if path and (path != "/" or status_codes):
        # path rule: scope only URLs/paths under this prefix on this host
        pattern = host[2:] if host.startswith("*.") else host.lstrip(".")
        return ScopeRule(
            f"{pattern}{path}", "path", negate, None, pattern, path, status_codes
        )

    if host.startswith("*."):
        return ScopeRule(host[2:], "wildcard", negate)
    if host.startswith("."):
        return ScopeRule(host[1:], "domain", negate)
    if host.count(".") >= 1 or host.isdigit() is False:
        # domain suffix by default; a bare non-ip token still suffix-matches
        return ScopeRule(host, "domain", negate)
    return ScopeRule(host, "exact", negate)


def parse_severity_overrides(text: str) -> dict[str, str]:
    """Parse ``rule-id=severity`` lines into a validated mapping."""
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = _strip_comment(raw)
        if not line or line.startswith("#") or "=" not in line:
            continue
        rule, _, severity = line.partition("=")
        rule = rule.strip()
        severity = severity.strip().lower()
        if rule and severity in {"critical", "high", "medium", "low", "info"}:
            out[rule] = severity
    return out


def format_severity_overrides(mapping: dict | None) -> str:
    return "\n".join(
        f"{rule}={severity}"
        for rule, severity in sorted((mapping or {}).items())
        if severity in {"critical", "high", "medium", "low", "info"}
    )


def parse_scope(text: str) -> list[ScopeRule]:
    rules: list[ScopeRule] = []
    for raw in (text or "").splitlines():
        line = _strip_comment(raw)
        if not line or line.startswith("#"):
            continue
        try:
            rules.append(classify(line))
        except Exception:
            continue
    return rules


def host_of(value: str, vtype: str = "") -> str:
    """Best-effort extraction of a hostname/IP from an entity value."""
    if not value:
        return ""
    val = value.strip()
    if vtype == "url" or "://" in val:
        try:
            parsed = urlparse(val if "://" in val else f"//{val}")
            if parsed.hostname:
                return parsed.hostname.lower().rstrip(".")
        except ValueError:
            return ""
    if vtype == "port" and ":" in val:
        val = val.split(":", 1)[0]
    if vtype == "dns_record":
        return ""
    return val.lower().strip().rstrip(".")


def path_of(value: str, vtype: str = "") -> str:
    """Best-effort URL path for path-scope matching (leading slash, no query)."""
    if not value:
        return ""
    val = value.strip()
    if vtype in {"url", "endpoint", "path"} or "://" in val:
        try:
            parsed = urlparse(val if "://" in val else f"//{val}")
            return parsed.path or "/"
        except ValueError:
            return ""
    if val.startswith("/"):
        return val.split("?", 1)[0].split("#", 1)[0]
    return ""


def _rule_base_matches(rule: ScopeRule, host: str, value: str = "", vtype: str = "") -> bool:
    if not host:
        return False
    if rule.kind in {"cidr", "ip"}:
        try:
            candidate = ipaddress.ip_address(host)
        except ValueError:
            return False
        if rule.kind == "ip":
            return candidate == rule.network
        return candidate in rule.network
    if rule.kind == "exact":
        return host == rule.pattern
    if rule.kind == "wildcard":
        return host.endswith("." + rule.pattern) and host != rule.pattern
    if rule.kind == "path":
        host_ok = host == rule.host or host.endswith("." + rule.host)
        if not host_ok:
            return False
        prefix = rule.path.rstrip("*")
        return path_of(value, vtype).startswith(prefix)
    # domain: apex or any subdomain
    return host == rule.pattern or host.endswith("." + rule.pattern)


def _rule_matches(
    rule: ScopeRule,
    host: str,
    value: str = "",
    vtype: str = "",
    status_code: int | None = None,
) -> bool:
    if not _rule_base_matches(rule, host, value, vtype):
        return False
    if rule.status_codes is None:
        return True
    if status_code is None:
        return False
    return status_code in rule.status_codes


def _eval_rules(
    rules: list[ScopeRule],
    host: str,
    value: str,
    vtype: str,
    status_code: int | None,
) -> tuple[str, ScopeRule | None]:
    """Return (result, rule) where result is match/status_mismatch/status_unknown/no_match."""
    blocked: tuple[str, ScopeRule] | None = None
    for rule in rules:
        if not _rule_base_matches(rule, host, value, vtype):
            continue
        if rule.status_codes is not None:
            if status_code is None:
                blocked = blocked or ("status_unknown", rule)
                continue
            if status_code not in rule.status_codes:
                blocked = blocked or ("status_mismatch", rule)
                continue
        return "match", rule
    return blocked or ("no_match", None)


def status_code_of(value: str, vtype: str = "", meta: dict | None = None) -> int | None:
    """Best-effort HTTP status code for an entity, never inferred from a host."""
    meta = meta or {}
    for key in ("status_code", "status", "http_status", "code", "status-code"):
        raw = meta.get(key)
        if raw in (None, ""):
            continue
        try:
            code = int(str(raw).strip())
        except (TypeError, ValueError):
            continue
        if 100 <= code <= 599:
            return code
    # Only parse a bare status value. Never infer a status from digits in a
    # URL path: /404 is a page, not evidence of an HTTP 404 response.
    if vtype == "http_status":
        match = re.search(r"\b([1-5]\d\d)\b", str(value or ""))
        if match:
            return int(match.group(1))
    return None


class Scope:
    """Combined in/out scope from a program, with negation folded in."""

    def __init__(self, scope_in: str = "", scope_out: str = ""):
        in_rules = parse_scope(scope_in)
        out_rules = parse_scope(scope_out)

        self.in_positive = [r for r in in_rules if not r.negate]
        self.in_negative = [r for r in in_rules if r.negate]
        self.out_positive = [r for r in out_rules if not r.negate]
        self.out_negative = [r for r in out_rules if r.negate]

    @property
    def is_empty(self) -> bool:
        return not (self.in_positive or self.in_negative or self.out_positive or self.out_negative)

    def _any(
        self,
        rules,
        host: str,
        value: str = "",
        vtype: str = "",
        status_code: int | None = None,
    ) -> bool:
        return any(
            _rule_matches(rule, host, value, vtype, status_code) for rule in rules
        )

    def explain(
        self,
        value: str,
        vtype: str = "",
        status_code: int | None = None,
        host: str | None = None,
    ) -> ScopeDecision:
        """Explain a scope decision with the exact rule that made it.

        Precedence: explicit out-of-scope rules, negated in-scope rules,
        re-includes in the out list, then positive in-scope rules. Status
        filters only decide values whose HTTP status is known; otherwise the
        decision is ``status_unknown`` (never a silent drop).
        """
        host = (host if host is not None else host_of(value, vtype)) or ""
        code = status_code if status_code is not None else status_code_of(value, vtype)
        if not host:
            return ScopeDecision("unknown", "no_host", status_code=code)
        if self.is_empty:
            return ScopeDecision("unknown", "no_scope", status_code=code)

        result, rule = _eval_rules(self.out_positive, host, value, vtype, code)
        if result == "match" and rule is not None:
            return ScopeDecision(
                "out", "out_rule", rule.describe(), rule.kind, code
            )
        result, rule = _eval_rules(self.in_negative, host, value, vtype, code)
        if result == "match" and rule is not None:
            return ScopeDecision(
                "out", "in_negated", rule.describe(), rule.kind, code
            )
        result, rule = _eval_rules(self.out_negative, host, value, vtype, code)
        if result == "match" and rule is not None:
            return ScopeDecision(
                "in", "re_included", rule.describe(), rule.kind, code
            )

        result, rule = _eval_rules(self.in_positive, host, value, vtype, code)
        if result == "match" and rule is not None:
            return ScopeDecision("in", "in_rule", rule.describe(), rule.kind, code)
        if result == "status_mismatch" and rule is not None:
            return ScopeDecision(
                "out",
                "status_filter",
                rule.describe(),
                rule.kind,
                code,
                {"allowed": sorted(rule.status_codes or [])},
            )
        if result == "status_unknown" and rule is not None:
            return ScopeDecision(
                "unknown",
                "status_unknown",
                rule.describe(),
                rule.kind,
                code,
                {"allowed": sorted(rule.status_codes or [])},
            )
        return ScopeDecision("unknown", "no_match", status_code=code)

    def status(
        self,
        value: str,
        vtype: str = "",
        status_code: int | None = None,
        host: str | None = None,
    ) -> str:
        """Return 'in', 'out', or 'unknown' for a value."""
        return self.explain(value, vtype, status_code=status_code, host=host).status

    def matches(self, value: str, vtype: str = "", status_code: int | None = None) -> bool:
        return self.status(value, vtype, status_code=status_code) == "in"
