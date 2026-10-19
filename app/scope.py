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
from dataclasses import dataclass
from urllib.parse import urlparse

_COMMENT_RE = re.compile(r"\s+#.*$")


@dataclass
class ScopeRule:
    pattern: str
    kind: str  # cidr | ip | domain | wildcard | exact | path
    negate: bool = False
    network: object = None  # ipaddress network when kind == cidr/ip
    host: str = ""          # host part of a path rule
    path: str = ""          # path prefix of a path rule (leading slash)

    def describe(self) -> str:
        prefix = "!" if self.negate else ""
        if self.kind == "path":
            return f"{prefix}{self.host}{self.path}"
        return f"{prefix}{self.pattern}"


def _strip_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line).strip()


def _split_host_path(token: str) -> tuple[str, str]:
    """Split 'host/path' into ('host', '/path'). Empty path when absent."""
    if "/" not in token:
        return token, ""
    host, _, rest = token.partition("/")
    path = "/" + rest if rest else "/"
    return host, path


def classify(token: str) -> ScopeRule:
    token = token.strip()
    negate = token.startswith(("!", "-"))
    if negate:
        token = token[1:].strip()

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

    if path and path != "/":
        # path rule: scope only URLs/paths under this prefix on this host
        base_kind = "domain"
        pattern = host[2:] if host.startswith("*.") else host.lstrip(".")
        return ScopeRule(f"{pattern}{path}", "path", negate, None, pattern, path)

    if host.startswith("*."):
        return ScopeRule(host[2:], "wildcard", negate)
    if host.startswith("."):
        return ScopeRule(host[1:], "domain", negate)
    if host.count(".") >= 1 or host.isdigit() is False:
        # domain suffix by default; a bare non-ip token still suffix-matches
        return ScopeRule(host, "domain", negate)
    return ScopeRule(host, "exact", negate)


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


def _rule_matches(rule: ScopeRule, host: str, value: str = "", vtype: str = "") -> bool:
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

    def _any(self, rules, host: str, value: str = "", vtype: str = "") -> bool:
        return any(_rule_matches(rule, host, value, vtype) for rule in rules)

    def status(self, value: str, vtype: str = "") -> str:
        """Return 'in', 'out', or 'unknown' for a value."""
        host = host_of(value, vtype)
        if not host:
            return "unknown"

        # explicit exclusions always win
        if self._any(self.out_positive, host, value, vtype):
            return "out"
        if self._any(self.in_negative, host, value, vtype):
            return "out"
        # negation inside the out list acts as a re-include
        if self.out_negative and self._any(self.out_negative, host, value, vtype):
            return "in"

        if self._any(self.in_positive, host, value, vtype):
            return "in"
        return "unknown"

    def matches(self, value: str, vtype: str = "") -> bool:
        return self.status(value, vtype) == "in"
