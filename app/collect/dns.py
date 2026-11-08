"""Native DNS discovery collector.

Uses only the standard library: ``getaddrinfo`` for A/AAAA and
``gethostbyname_ex`` for the canonical name/CNAME hint. Output is BIND-style
zone text, which Breadcrumb's existing ``dns`` parser already understands, so
the result becomes normal graph entities instead of a private format.

Scope is enforced for the target *and* every optional subdomain before any
name is resolved. Resolved addresses come from the guard's pinned decision.
"""

from __future__ import annotations

import socket
from urllib.parse import urlsplit

from ..scope import host_of
from .base import (
    Collector,
    CollectorContext,
    CollectorResult,
    PhaseOutput,
    register,
    require_no_proxy,
)


def _clean_target(target: str) -> str:
    target = (target or "").strip()
    if "://" in target:
        return (urlsplit(target).hostname or "").strip().lower().rstrip(".")
    return host_of(target, "url" if "/" in target else "domain").strip().lower().rstrip(".")


def _option_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = value.replace(",", " ").split()
    out: list[str] = []
    for item in value:
        name = str(item).strip().lower().rstrip(".")
        if name and name not in out:
            out.append(name)
    return out


def _record_lines(name: str, addresses: list[str]) -> list[str]:
    lines = []
    seen = set()
    for address in addresses:
        if address in seen:
            continue
        seen.add(address)
        rtype = "AAAA" if ":" in address else "A"
        lines.append(f"{name}. 0 IN {rtype} {address}")
    return lines


@register
class DNSCollector(Collector):
    id = "leadline-dns"
    label = "Native DNS"
    description = "A/AAAA/CNAME discovery with scope guard (stdlib, no external binary)."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        require_no_proxy(ctx)
        target = _clean_target(ctx.target)
        if not target:
            return CollectorResult([
                PhaseOutput("dns", error="empty DNS target")
            ])

        ctx.check_cancel()
        ctx.emit_event("phase", f"resolving {target}")
        decision = ctx.check_host(target)
        addresses = list(decision.addresses)
        lines = _record_lines(target, addresses)
        stats = {"target": target, "addresses": len(addresses), "names": 1, "skipped": 0}

        # A canonical-name hint is useful for takeover detection. This is a
        # name lookup, not a connection, so it cannot bypass the socket rule.
        try:
            canonical, _aliases, _ips = socket.gethostbyname_ex(target)
            canonical = canonical.strip().lower().rstrip(".")
            if canonical and canonical != target:
                lines.append(f"{target}. 0 IN CNAME {canonical}.")
                stats["canonical"] = canonical
        except (socket.gaierror, OSError):
            pass

        subdomains = _option_list(ctx.options.get("subdomains"))[:200]
        for index, name in enumerate(subdomains):
            ctx.check_cancel()
            try:
                sub_decision = ctx.check_host(name)
            except Exception as exc:  # noqa: BLE001  (one out-of-scope name is not fatal)
                stats["skipped"] += 1
                ctx.emit_event("warning", f"skipping {name}: {exc}")
                continue
            stats["names"] += 1
            lines.extend(_record_lines(name, list(sub_decision.addresses)))
            try:
                canonical, _aliases, _ips = socket.gethostbyname_ex(name)
                canonical = canonical.strip().lower().rstrip(".")
                if canonical and canonical != name:
                    lines.append(f"{name}. 0 IN CNAME {canonical}.")
            except (socket.gaierror, OSError):
                pass
            if ctx.rate_limit and index + 1 < len(subdomains):
                ctx.sleep(1.0 / ctx.rate_limit)

        output = "\n".join(lines) + ("\n" if lines else "")
        error = None if addresses else f"{target} did not resolve to any address"
        ctx.emit_event(
            "phase",
            f"dns: {stats['names']} name(s), {len(lines)} record(s)"
            + (f", {stats['skipped']} skipped" if stats["skipped"] else ""),
            **stats,
        )
        return CollectorResult([PhaseOutput("dns", output, stats, error)], stats)
