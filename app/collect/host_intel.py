"""Native host-intel collector (offline subset).

Breadcrumb is offline-first, and the standard library exposes only address
resolution and canonical-name hints -- not MX/NS/TXT/SOA queries. This phase
therefore records the sources it can answer locally (A/AAAA, CNAME, reverse
PTR) and states plainly which external sources were not queried.

Output is BIND-style zone text, so Breadcrumb's existing DNS parser creates
``dns_record`` entities. Scope is checked before any name is resolved.
"""

from __future__ import annotations

import socket

from ..scope import host_of
from .base import (
    Collector,
    CollectorContext,
    CollectorResult,
    PhaseOutput,
    register,
    require_no_proxy,
)


def clean_host(target: str) -> str:
    raw = (target or "").strip()
    if "://" in raw:
        from urllib.parse import urlsplit

        return (urlsplit(raw).hostname or "").strip().lower().rstrip(".")
    if raw.startswith("["):
        return raw[1:].split("]", 1)[0].strip().lower()
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    return host_of(raw, "url" if "/" in raw else "domain").strip().lower().rstrip(".")


def collect_host_intel(ctx: CollectorContext, host: str | None = None) -> tuple[str, dict]:
    """Return (zone text, stats) for the offline host-intel subset."""
    host = (host or clean_host(ctx.target)).strip().lower().rstrip(".")
    if not host:
        return "", {"status": "skipped", "reason": "empty host"}

    ctx.check_cancel()
    decision = ctx.check_host(host)
    addresses = list(decision.addresses)
    lines = [
        f"; Native host intel for {host}",
        "; Offline sources: system resolver + reverse DNS. "
        "MX/NS/TXT/SOA, WHOIS/RDAP, CT and ASN/geo were not queried.",
    ]
    stats = {
        "host": host,
        "addresses": len(addresses),
        "ptr": 0,
        "cname": 0,
        "sources_skipped": [
            "MX", "NS", "TXT", "SOA", "WHOIS/RDAP", "CT", "DNSSEC", "ASN/geo",
        ],
    }

    for address in addresses:
        rtype = "AAAA" if ":" in address else "A"
        lines.append(f"{host}. 0 IN {rtype} {address}")
        try:
            ptr, aliases, _more = socket.gethostbyaddr(address)
        except (socket.herror, socket.gaierror, OSError):
            continue
        ptr = (ptr or "").strip().lower().rstrip(".")
        if not ptr:
            continue
        stats["ptr"] += 1
        lines.append(f"{address}. 0 IN PTR {ptr}.")
        for alias in aliases[:10]:
            alias = alias.strip().lower().rstrip(".")
            if alias and alias != ptr:
                lines.append(f"{alias}. 0 IN PTR {ptr}.")

    try:
        canonical, aliases, _ips = socket.gethostbyname_ex(host)
        canonical = (canonical or "").strip().lower().rstrip(".")
        if canonical and canonical != host:
            stats["cname"] = 1
            lines.append(f"{host}. 0 IN CNAME {canonical}.")
            for alias in aliases[:20]:
                alias = alias.strip().lower().rstrip(".")
                if alias and alias not in {host, canonical}:
                    lines.append(f"{alias}. 0 IN CNAME {canonical}.")
    except (socket.gaierror, OSError):
        pass

    if len(lines) <= 2:
        stats["status"] = "empty"
    else:
        stats["status"] = "ok"
    ctx.emit_event(
        "phase",
        f"host intel: {stats['addresses']} address(es), "
        f"{stats['ptr']} PTR, {stats['cname']} CNAME hint(s)",
        **stats,
    )
    return "\n".join(lines) + "\n", stats


@register
class HostIntelCollector(Collector):
    id = "leadline-host-intel"
    label = "Native host intel"
    description = "A/AAAA, CNAME and reverse-DNS evidence; external sources are opt-in."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        require_no_proxy(ctx)
        output, stats = collect_host_intel(ctx)
        return CollectorResult([PhaseOutput("host_intel", output, stats)], stats)
