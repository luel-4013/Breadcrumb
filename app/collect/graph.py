"""Graph-observation phase.

Breadcrumb's graph is built by the existing parsers: nmap XML creates
``host -> ip`` and ``host -> port`` edges, while httpx JSONL creates
``host -> ip``/``host -> cname`` edges. This phase emits one compact nmap XML
summary of everything the recon run observed, reinforcing those edges and
sealing a human-readable graph snapshot as evidence.

It performs no new connections when the orchestrator supplies state. The
standalone collector resolves the target and probes it through the normal
scope-pinned HTTP path.
"""

from __future__ import annotations

import xml.sax.saxutils as saxutils
from dataclasses import dataclass

from .base import (
    Collector,
    CollectorContext,
    CollectorResult,
    JobCancelled,
    PhaseOutput,
    register,
    require_no_proxy,
)
from .guard import ScopeDenied
from .host_intel import clean_host
from .http import _probe_targets
from .ports import OpenPort


@dataclass
class GraphResult:
    output: str
    stats: dict


def _attr(value: object) -> str:
    return saxutils.quoteattr(str(value))[1:-1]


def graph_observation(
    *,
    host: str,
    addresses: list[str],
    ports: list | None = None,
    urls: list[str] | None = None,
) -> GraphResult:
    host = (host or "").strip().lower().rstrip(".")
    addresses = [item for item in addresses if item]
    ports = ports or []
    urls = [item for item in (urls or []) if item]

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<nmaprun scanner="breadcrumb-graph" args="graph observations {_attr(host)}">',
        "<host>",
        '<status state="up" reason="observed"/>',
    ]
    if addresses:
        lines.append(
            f'<address addr="{_attr(addresses[0])}" '
            f'addrtype="{"ipv6" if ":" in addresses[0] else "ipv4"}"/>'
        )
    lines.extend(["<hostnames>"])
    if host:
        lines.append(f'<hostname name="{_attr(host)}" type="user"/>')
    lines.extend(["</hostnames>", "<ports>"])
    for item in ports:
        port = getattr(item, "port", None) or (item.get("port") if isinstance(item, dict) else None)
        service = getattr(item, "service", "") or (item.get("service", "") if isinstance(item, dict) else "")
        if not port:
            continue
        lines.extend([
            f'<port protocol="tcp" portid="{int(port)}">',
            '<state state="open" reason="observed"/>',
            f'<service name="{_attr(service or "unknown")}"/>',
            "</port>",
        ])
    lines.extend(["</ports>"])
    for url in urls:
        lines.append(f'<script id="observed-url" output="{_attr(url)}"/>')
    for address in addresses[1:]:
        lines.append(f'<script id="observed-address" output="{_attr(address)}"/>')
    lines.extend(["</host>", "</nmaprun>"])

    stats = {
        "hosts": 1 if host else 0,
        "addresses": len(addresses),
        "ports": len(ports),
        "urls": len(urls),
        "edges": (1 if host and addresses else 0) + len(ports),
    }
    return GraphResult(output="\n".join(lines) + "\n", stats=stats)


@register
class GraphCollector(Collector):
    id = "leadline-graph"
    label = "Native graph observations"
    description = "Emit observed host/IP/port edges in nmap XML for Breadcrumb's graph."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        try:
            require_no_proxy(ctx)
            host = clean_host(ctx.target)
            decision = ctx.check_host(host)
            urls: list[str] = []
            ports: list[OpenPort] = []
            try:
                probes, _errors, _stats = _probe_targets(ctx)
                for probe in probes:
                    if probe.final_url not in urls:
                        urls.append(probe.final_url)
                    if probe.port:
                        ports.append(OpenPort(port=probe.port, service=probe.scheme, tls=probe.scheme == "https"))
            except (JobCancelled, ScopeDenied):
                raise
            except Exception:  # noqa: BLE001  (DNS/IP-only targets may not answer HTTP)
                pass
            result = graph_observation(
                host=host,
                addresses=list(decision.addresses),
                ports=ports,
                urls=urls,
            )
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            return CollectorResult(
                [PhaseOutput("graph", "", {"status": "failed"}, str(exc))]
            )
        return CollectorResult([PhaseOutput("graph", result.output, result.stats)], result.stats)
