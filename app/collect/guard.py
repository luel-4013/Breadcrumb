"""Fail-closed scope guard for every native collector connection.

Breadcrumb's existing ``Scope`` answers in/out/unknown for imported data.
This module is the enforcement boundary: it resolves the target, classifies
the resulting addresses, and refuses to let a collector connect unless the
host is explicitly in scope.

Policy (owner decisions recorded in ``docs/LEADLINE_PARITY_MATRIX.md``):

* in-scope public targets: allowed;
* private/loopback targets: allowed with a visible warning;
* link-local addresses and cloud metadata endpoints: always blocked;
* unknown/out-of-scope targets: blocked (fail closed);
* every URL redirect is checked again before the next connection.

The collector must use the returned ``addresses`` for its connection (pinned
resolution) so a DNS answer cannot change between the check and the socket.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..models import Program
from ..scope import Scope, host_of

PRIVATE_TARGET_WARNING = (
    "Private/loopback target allowed by policy. Only scan systems you own or "
    "have written authorization to test."
)

# Always blocked, even when the program's scope includes them. 169.254/16 is
# the cloud metadata range on AWS/GCP/Azure/OpenStack; fe80::/10 is IPv6
# link-local; multicast/unspecified are never legitimate scan targets.
HARD_BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
    # Individual metadata endpoints outside 169.254/16.
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud
    ipaddress.ip_network("192.0.0.192/32"),      # Oracle Cloud
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IMDSv6
)

HARD_BLOCKED_HOSTS = frozenset({
    "metadata",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
    "instance-data.ec2.internal",
})

# Private/loopback ranges used for the visible warning and the
# BREADCRUMB_ALLOW_PRIVATE_TARGETS switch. Kept explicit so a CIDR target is
# classified without resolving every address.
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


def _truthy_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _mapped(ip):
    """Return the IPv4 address behind an IPv4-mapped IPv6 address."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return None


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    status: str                 # in | out | unknown
    host: str
    reason: str
    value: str = ""
    addresses: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    blocked_addresses: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "status": self.status,
            "host": self.host,
            "reason": self.reason,
            "addresses": list(self.addresses),
            "warnings": list(self.warnings),
            "blocked_addresses": list(self.blocked_addresses),
        }


class ScopeDenied(RuntimeError):
    """Raised by collectors before a connection is attempted."""

    def __init__(self, decision: ScopeDecision):
        self.decision = decision
        super().__init__(
            f"scope denied for {decision.host or decision.value}: {decision.reason}"
        )


@dataclass
class ScopeGuard:
    scope: Scope
    program_id: int | None = None
    allow_private: bool = field(
        default_factory=lambda: _truthy_env("BREADCRUMB_ALLOW_PRIVATE_TARGETS", True)
    )
    resolver: object = socket.getaddrinfo

    @classmethod
    def for_job(cls, session, job) -> "ScopeGuard":
        """Build a guard for a job, or raise if the job has no usable program."""
        if job.program_id is None:
            decision = ScopeDecision(
                False, "unknown", job.target or "", "job has no program; scope cannot be enforced"
            )
            raise ScopeDenied(decision)
        program = session.get(Program, job.program_id)
        if program is None:
            decision = ScopeDecision(
                False, "unknown", job.target or "",
                f"program #{job.program_id} no longer exists",
            )
            raise ScopeDenied(decision)
        return cls(
            scope=Scope(program.scope_in or "", program.scope_out or ""),
            program_id=program.id,
        )

    def _resolve(self, host: str, port: int | None) -> tuple[list[str], str | None]:
        try:
            infos = self.resolver(
                host, port or 0, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP
            )
        except (socket.gaierror, OSError, UnicodeError) as exc:
            return [], str(exc)
        addresses: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        return addresses, None

    def _classify(self, address: str) -> tuple[str, str]:
        """Return ('ok'|'private'|'hard', reason)."""
        ip = _as_ip(address)
        if ip is None:
            return "hard", f"unparseable address {address!r}"
        candidates = [ip]
        mapped = _mapped(ip)
        if mapped is not None:
            candidates.append(mapped)
        for candidate in candidates:
            if any(candidate in network for network in HARD_BLOCKED_NETWORKS):
                return "hard", f"link-local/metadata address blocked ({candidate})"
            if candidate.is_unspecified:
                return "hard", f"unspecified address blocked ({candidate})"
            if candidate.is_multicast or candidate.is_link_local:
                return "hard", f"link-local/multicast address blocked ({candidate})"
        if any(candidate.is_private or candidate.is_loopback for candidate in candidates):
            return "private", PRIVATE_TARGET_WARNING
        return "ok", ""

    def _check(
        self,
        host: str,
        *,
        value: str = "",
        vtype: str = "domain",
        port: int | None = None,
    ) -> ScopeDecision:
        host = (host or "").strip().strip("[]").lower().rstrip(".")
        value = value or host
        if not host:
            return ScopeDecision(False, "unknown", "", "empty host")
        if host in HARD_BLOCKED_HOSTS:
            return ScopeDecision(
                False, "out", host, "cloud metadata hostname is always blocked",
                value=value, blocked_addresses=(host,),
            )
        if self.scope.is_empty:
            return ScopeDecision(
                False, "unknown", host,
                "program has no in-scope entries; add scope before scanning",
                value=value,
            )
        status = self.scope.status(value if "://" in value else host, vtype)
        if status == "out":
            return ScopeDecision(False, "out", host, "target is explicitly out of scope", value=value)
        if status != "in":
            return ScopeDecision(
                False, "unknown", host, "target is not listed in the program's in-scope entries",
                value=value,
            )

        literal = _as_ip(host)
        if literal is not None:
            addresses = [str(literal)]
            error = None
        else:
            addresses, error = self._resolve(host, port)
        if error:
            return ScopeDecision(
                False, status, host, f"DNS resolution failed: {error}", value=value
            )
        if not addresses:
            return ScopeDecision(
                False, status, host, "target did not resolve to any address", value=value
            )

        warnings: list[str] = []
        blocked: list[str] = []
        for address in addresses:
            kind, reason = self._classify(address)
            if kind == "hard":
                blocked.append(address)
            elif kind == "private" and reason not in warnings:
                warnings.append(reason)
        if blocked:
            return ScopeDecision(
                False, status, host,
                f"resolved to a blocked address: {', '.join(blocked)}",
                value=value, addresses=tuple(addresses),
                warnings=tuple(warnings), blocked_addresses=tuple(blocked),
            )
        if warnings and not self.allow_private:
            return ScopeDecision(
                False, status, host,
                "target resolves to a private/loopback address and private targets are disabled",
                value=value, addresses=tuple(addresses), warnings=tuple(warnings),
            )
        return ScopeDecision(
            True, status, host, "in scope", value=value,
            addresses=tuple(addresses), warnings=tuple(warnings),
        )

    def check_host(self, host: str, *, port: int | None = None) -> ScopeDecision:
        value = (host or "").strip()
        if "://" in value:
            return self.check_url(value)
        literal = _as_ip(value)
        return self._check(
            value, value=value, vtype="ip" if literal is not None else "domain", port=port
        )

    def check_network(self, value: str) -> ScopeDecision:
        """Check an IP/CIDR target that will be passed to a port scanner.

        The whole range must be inside an in-scope CIDR (or every address in a
        small range must be individually in scope). Any overlap with an
        excluded or hard-blocked range fails closed.
        """
        raw = (value or "").strip()
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return ScopeDecision(
                False, "unknown", raw, "not an IP or CIDR target", value=raw
            )
        if self.scope.is_empty:
            return ScopeDecision(
                False, "unknown", str(network),
                "program has no in-scope entries; add scope before scanning",
                value=raw,
            )
        for blocked in HARD_BLOCKED_NETWORKS:
            if network.version == blocked.version and network.overlaps(blocked):
                return ScopeDecision(
                    False, "out", str(network),
                    f"range overlaps a blocked address range ({blocked})",
                    value=raw, blocked_addresses=(str(blocked),),
                )
        for rule in (*self.scope.out_positive, *self.scope.in_negative):
            if rule.kind not in ("cidr", "ip"):
                continue
            if rule.kind == "cidr":
                rule_network = rule.network
            else:
                rule_network = ipaddress.ip_network(rule.network)
            if network.version == rule_network.version and network.overlaps(rule_network):
                return ScopeDecision(
                    False, "out", str(network),
                    f"range overlaps an excluded range ({rule.describe()})",
                    value=raw,
                )

        contained = False
        for rule in self.scope.in_positive:
            if rule.kind == "cidr":
                if network.version == rule.network.version and network.subnet_of(rule.network):
                    contained = True
                    break
            elif rule.kind == "ip":
                if (
                    network.num_addresses == 1
                    and network.network_address == rule.network
                ):
                    contained = True
                    break
        if not contained and network.num_addresses <= 4096:
            contained = all(
                self.scope.status(str(address), "ip") == "in"
                for address in network
            )
        if not contained:
            return ScopeDecision(
                False, "unknown", str(network),
                "range is not fully contained in an in-scope CIDR",
                value=raw,
            )

        warnings: list[str] = []
        if any(
            network.version == private.version and network.overlaps(private)
            for private in PRIVATE_NETWORKS
        ):
            if not self.allow_private:
                return ScopeDecision(
                    False, "in", str(network),
                    "range is private/loopback and private targets are disabled",
                    value=raw, warnings=(PRIVATE_TARGET_WARNING,),
                )
            warnings.append(PRIVATE_TARGET_WARNING)
        return ScopeDecision(
            True, "in", str(network), "in scope", value=raw,
            addresses=(str(network.network_address), str(network.broadcast_address)),
            warnings=tuple(warnings),
        )

    def check_url(self, url: str) -> ScopeDecision:
        try:
            parsed = urlsplit((url or "").strip())
        except ValueError:
            return ScopeDecision(False, "unknown", "", "malformed URL", value=url)
        if parsed.scheme.lower() not in ("http", "https"):
            return ScopeDecision(
                False, "unknown", parsed.hostname or "",
                f"unsupported scheme {parsed.scheme!r}; only http/https are allowed",
                value=url,
            )
        if parsed.username or parsed.password:
            return ScopeDecision(
                False, "unknown", parsed.hostname or "",
                "URLs with embedded credentials are not allowed",
                value=url,
            )
        try:
            port = parsed.port
        except ValueError:
            return ScopeDecision(False, "unknown", parsed.hostname or "", "invalid port", value=url)
        host = parsed.hostname or host_of(url, "url")
        return self._check(host, value=url, vtype="url", port=port)

    def require_host(self, host: str, *, port: int | None = None) -> ScopeDecision:
        decision = self.check_host(host, port=port)
        if not decision.allowed:
            raise ScopeDenied(decision)
        return decision

    def require_url(self, url: str) -> ScopeDecision:
        decision = self.check_url(url)
        if not decision.allowed:
            raise ScopeDenied(decision)
        return decision
