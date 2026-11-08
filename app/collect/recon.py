"""The ``leadline-recon`` preset: twelve phases in Leadline's order.

One job runs DNS, host intel, ports/TLS, HTTP, tech, JavaScript, params,
security headers, API discovery, vulnerability candidates, CVE correlation and
graph observations. Each phase is returned as a separate ``PhaseOutput`` and
therefore sealed as its own Breadcrumb capture by the normal executor.

Phases share fetched artifacts (one HTTP fetch feeds tech/headers/JS/params/API)
and never write to the database directly. Scope denials and cancellation are
fatal; an optional analysis failure is recorded as a skipped phase so a partial
recon still preserves the evidence it did collect.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .api import APIResult, discover_api
from .base import (
    Collector,
    CollectorContext,
    CollectorResult,
    JobCancelled,
    PhaseOutput,
    register,
    require_no_proxy,
)
from .cve import CVEResult, collect_cves
from .dns import DNSCollector
from .graph import GraphResult, graph_observation
from .guard import ScopeDenied
from .host_intel import clean_host, collect_host_intel
from .http import Probe, _probe_targets
from .js import JavaScriptResult, analyze_javascript
from .params import ParamResult, discover_params
from .ports import PortScanResult, _port_list, scan_ports
from .security import analyze_security_headers
from .vulns import VulnResult, vuln_result

PHASE_NAMES = (
    "dns", "host_intel", "ports", "http", "tech", "js",
    "params", "headers", "api", "vulns", "cve", "graph",
)


@dataclass
class ReconState:
    target: str
    host: str
    addresses: list[str] = field(default_factory=list)
    probes: list[Probe] = field(default_factory=list)
    base_url: str = ""
    page_url: str = ""
    html: str = ""
    technologies: list[dict] = field(default_factory=list)
    port_result: PortScanResult | None = None
    js: JavaScriptResult | None = None
    params: ParamResult | None = None
    header_analysis: dict = field(default_factory=dict)
    api: APIResult | None = None
    vulns: VulnResult | None = None
    cve: CVEResult | None = None
    graph: GraphResult | None = None


def _skipped(name: str, reason: str) -> PhaseOutput:
    return PhaseOutput(
        name,
        f"# {name} skipped: {reason}\n",
        {"status": "skipped", "reason": reason},
    )


def _target_port(target: str) -> int | None:
    if "://" not in (target or ""):
        return None
    try:
        return urlsplit(target).port
    except ValueError:
        return None


def _httpx_jsonl(probes: list[Probe], host: str) -> str:
    lines = []
    for probe in probes:
        input_host = urlsplit(probe.url).hostname or host
        lines.append(json.dumps(probe.as_httpx(input_host), sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")


def _tech_values(probes: list[Probe], host: str) -> list[dict]:
    """Collect product/version observations without duplicating a product.

    ``tech_versions`` is the precise list emitted by ``Probe.as_httpx``. Older
    or third-party records may only carry plain ``tech`` labels, so both are
    merged and the versioned form wins.
    """
    values: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(product: str, version: str = "", source: str = "", confidence: str = "") -> None:
        product = str(product or "").strip()
        version = str(version or "").strip()
        if not product:
            return
        key = (product.lower(), version)
        if key in seen:
            return
        seen.add(key)
        values.append(
            {
                "product": product,
                "version": version,
                "source": source,
                "confidence": confidence,
            }
        )

    for probe in probes:
        record = probe.as_httpx(host)
        versioned = record.get("tech_versions") or []
        versioned_products = {
            str(item.get("product") or "").strip().lower()
            for item in versioned
            if isinstance(item, dict)
        }
        for item in versioned:
            if isinstance(item, dict):
                add(
                    item.get("product", ""),
                    item.get("version", ""),
                    item.get("source", ""),
                    item.get("confidence", ""),
                )
        for value in record.get("tech") or []:
            if str(value or "").strip().lower() not in versioned_products:
                add(value)
        server = str(record.get("webserver") or "").strip()
        if server and not record.get("tech"):
            add(server)
    return values


def _graph_urls(state: ReconState) -> list[str]:
    urls: list[str] = []
    for value in [state.page_url, *[probe.final_url for probe in state.probes]]:
        if value and value not in urls:
            urls.append(value)
    for result in (state.js, state.api):
        if result is None:
            continue
        for value in getattr(result, "endpoints", []) or []:
            if value not in urls:
                urls.append(value)
    return urls


@register
class ReconCollector(Collector):
    id = "leadline-recon"
    label = "Leadline recon (12 phases)"
    description = (
        "DNS, host intel, ports/TLS, HTTP, tech, JS, params, headers, API, "
        "vuln candidates, CVE candidates and graph observations."
    )
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        require_no_proxy(ctx)
        host = clean_host(ctx.target)
        if not host:
            return CollectorResult(
                [PhaseOutput("dns", "", {"status": "failed"}, "empty recon target")]
            )

        state = ReconState(target=ctx.target, host=host)
        phases: list[PhaseOutput] = []

        # 1. DNS. A resolution failure is fatal because later phases need the
        # guard's pinned addresses.
        ctx.check_cancel()
        dns_phase = DNSCollector().run(ctx).phases[0]
        phases.append(dns_phase)
        if dns_phase.error:
            return CollectorResult(phases, dns_phase.stats)

        # The DNS phase already resolved the host; repeat the guard call so the
        # orchestrator has the pinned addresses without trusting parsed text.
        decision = ctx.check_host(host)
        state.addresses = list(decision.addresses)

        # 2. Host intel (offline subset).
        ctx.check_cancel()
        intel_output, intel_stats = collect_host_intel(ctx, host)
        phases.append(PhaseOutput("host_intel", intel_output, intel_stats))

        # 3. Ports, banners, TLS. If the target URL names a port, scan just
        # that port unless the job explicitly supplied a port list.
        ctx.check_cancel()
        explicit_ports = ctx.options.get("ports")
        selected_ports = _port_list(explicit_ports) if explicit_ports else None
        if selected_ports is None and _target_port(ctx.target):
            selected_ports = [_target_port(ctx.target)]
        try:
            state.port_result = scan_ports(ctx, host=host, ports=selected_ports)
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            phases.append(
                PhaseOutput("ports", "", {"status": "failed"}, str(exc))
            )
            return CollectorResult(phases, {"phases": len(phases)})
        phases.append(
            PhaseOutput("ports", state.port_result.xml, dict(state.port_result.stats))
        )

        # 4. HTTP. One fetch feeds the rest of the web phases.
        ctx.check_cancel()
        probes, http_errors, http_stats = _probe_targets(ctx)
        state.probes = probes
        if probes:
            state.page_url = max(probes, key=lambda item: len(item.body)).final_url or probes[0].url
            parsed = urlsplit(state.page_url)
            state.base_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
            state.html = max(probes, key=lambda item: len(item.body)).body.decode(
                "utf-8", errors="replace"
            )
            phases.append(
                PhaseOutput("http", _httpx_jsonl(probes, host), dict(http_stats))
            )
        else:
            http_error = "; ".join(http_errors) or "no HTTP response"
            phases.append(PhaseOutput("http", "", dict(http_stats), http_error))

        # 5. Technology fingerprints from the HTTP artifacts.
        ctx.check_cancel()
        technologies = _tech_values(probes, host)
        state.technologies = technologies
        if probes:
            tech_lines = [
                json.dumps(probe.as_httpx(host), sort_keys=True) for probe in probes
            ]
            tech_output = (
                "# Technologies observed from HTTP headers and response bodies.\n"
                + "\n".join(tech_lines) + "\n"
            )
            phases.append(
                PhaseOutput("tech", tech_output, {"technologies": len(technologies)})
            )
        else:
            phases.append(_skipped("tech", "no HTTP response"))

        # 6. JavaScript analysis (same-origin, never executed).
        ctx.check_cancel()
        if state.base_url and state.html:
            try:
                state.js = analyze_javascript(
                    ctx,
                    base_url=state.base_url,
                    page_url=state.page_url,
                    html=state.html,
                )
                phases.append(PhaseOutput("js", state.js.output, state.js.stats))
            except (JobCancelled, ScopeDenied):
                raise
            except Exception as exc:  # noqa: BLE001
                phases.append(_skipped("js", str(exc)))
        else:
            phases.append(_skipped("js", "no HTML page"))

        # 7. Parameters from HTML and JavaScript references.
        ctx.check_cancel()
        if state.base_url and state.html:
            try:
                state.params = discover_params(
                    state.html,
                    state.base_url,
                    page_url=state.page_url,
                    js_params=state.js.parameters if state.js else [],
                )
                phases.append(PhaseOutput("params", state.params.output, state.params.stats))
            except (JobCancelled, ScopeDenied):
                raise
            except Exception as exc:  # noqa: BLE001
                phases.append(_skipped("params", str(exc)))
        else:
            phases.append(_skipped("params", "no HTML page"))

        # 8. Security headers. Raw response dumps preserve the evidence; the
        # vuln phase turns missing headers into low/info candidates.
        ctx.check_cancel()
        if probes:
            raw = "\n".join(probe.raw_dump() for probe in probes)
            first = max(probes, key=lambda item: len(item.body))
            state.header_analysis = analyze_security_headers(
                {key: value for key, value in first.headers}, first.scheme
            )
            phases.append(
                PhaseOutput(
                    "headers",
                    raw,
                    {
                        "present": state.header_analysis["present_count"],
                        "missing": state.header_analysis["missing_count"],
                        "score": state.header_analysis["security_score"],
                    },
                )
            )
        else:
            phases.append(_skipped("headers", "no HTTP response"))

        # 9. API discovery. Fixed paths only; references are not contacted.
        ctx.check_cancel()
        if state.base_url:
            try:
                state.api = discover_api(
                    ctx,
                    base_url=state.base_url,
                    page_url=state.page_url,
                    html=state.html,
                    js_endpoints=state.js.endpoints if state.js else [],
                )
                phases.append(PhaseOutput("api", state.api.output, state.api.stats))
            except (JobCancelled, ScopeDenied):
                raise
            except Exception as exc:  # noqa: BLE001
                phases.append(_skipped("api", str(exc)))
        else:
            phases.append(_skipped("api", "no HTTP base URL"))

        # 10. Vulnerability candidates. Every record is manual-review-only.
        ctx.check_cancel()
        urls: list[str] = [state.page_url or ctx.target]
        urls.extend(probe.final_url for probe in probes if probe.final_url)
        if state.js:
            urls.extend(state.js.endpoints)
        if state.params:
            urls.extend(item["candidate_url"] for item in state.params.parameters)
        if state.api:
            urls.extend(state.api.endpoints)
            urls.extend(state.api.inferred)
        urls = list(dict.fromkeys(url for url in urls if url))
        try:
            state.vulns = vuln_result(
                target_url=state.page_url or ctx.target,
                urls=urls,
                parameters=state.params.parameters if state.params else [],
                api_endpoints=(state.api.endpoints + state.api.inferred) if state.api else [],
                header_analysis=state.header_analysis,
                high_risk_ports=state.port_result.high_risk if state.port_result else [],
            )
            phases.append(PhaseOutput("vulns", state.vulns.output, state.vulns.stats))
        except (JobCancelled,):
            raise
        except Exception as exc:  # noqa: BLE001
            phases.append(_skipped("vulns", str(exc)))

        # 11. CVE candidates: offline by default, never a finding without
        # local NVD/CPE verification (Phase 5).
        ctx.check_cancel()
        try:
            cve_content = state.html
            if state.js:
                cve_content += "\n" + " ".join(state.js.cves)
            state.cve = collect_cves(
                ctx,
                technologies=technologies,
                content=cve_content,
                target_url=state.page_url or ctx.target,
            )
            phases.append(PhaseOutput("cve", state.cve.output, state.cve.stats))
        except (JobCancelled,):
            raise
        except Exception as exc:  # noqa: BLE001
            phases.append(_skipped("cve", str(exc)))

        # 12. Graph observations. The earlier nmap/httpx phases already created
        # most edges; this phase seals a compact graph summary and reinforces
        # host/IP/port observations.
        ctx.check_cancel()
        try:
            state.graph = graph_observation(
                host=host,
                addresses=state.addresses,
                ports=state.port_result.open_ports if state.port_result else [],
                urls=_graph_urls(state),
            )
            phases.append(PhaseOutput("graph", state.graph.output, state.graph.stats))
        except (JobCancelled,):
            raise
        except Exception as exc:  # noqa: BLE001
            phases.append(_skipped("graph", str(exc)))

        stats = {
            "phases": len(phases),
            "open_ports": state.port_result.stats.get("open", 0) if state.port_result else 0,
            "endpoints": len(state.js.endpoints) if state.js else 0,
            "parameters": len(state.params.parameters) if state.params else 0,
            "api_observed": len(state.api.endpoints) if state.api else 0,
            "vuln_candidates": len(state.vulns.records) if state.vulns else 0,
            "cve_referenced": len(state.cve.cves) if state.cve else 0,
        }
        ctx.emit_event(
            "phase",
            f"recon complete: {stats['phases']} phases, {stats['open_ports']} open ports, "
            f"{stats['vuln_candidates']} candidates",
            **stats,
        )
        return CollectorResult(phases, stats)
