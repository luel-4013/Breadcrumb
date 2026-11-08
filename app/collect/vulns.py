"""Pattern-based vulnerability candidates.

Every record is a lead for manual review. Nothing here is labeled confirmed:
the nuclei-compatible records carry ``candidate`` tags and the output header
repeats that limitation. Matching is restricted to observed paths, parameters,
headers and open services -- never to arbitrary words in a page body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .base import (
    Collector,
    CollectorContext,
    CollectorResult,
    JobCancelled,
    PhaseOutput,
    register,
    require_no_proxy,
)
from .findings import nuclei_jsonl, nuclei_record
from .guard import ScopeDenied
from .http import _probe_targets
from .js import _origin
from .params import discover_params, is_suspicious
from .security import analyze_security_headers, header_finding_records

PATTERNS = {
    "debug_interface": {
        "patterns": (r"/debug(?:\b|/)", r"/trace(?:\b|/)", r"/console(?:\b|/)", r"/admin[^?]*debug"),
        "severity": "medium",
        "description": "Debug or administrative interface may be publicly accessible.",
    },
    "backup_file": {
        "patterns": (r"\.bak(?:$|\?)", r"\.old(?:$|\?)", r"\.backup(?:$|\?)", r"~$"),
        "severity": "low",
        "description": "Potential backup file exposed.",
    },
    "config_exposure": {
        "patterns": (r"/\.env(?:$|\?|/)", r"\.config(?:$|\?)", r"config\.json", r"settings\.json"),
        "severity": "high",
        "description": "Potential configuration file exposure.",
    },
    "version_control": {
        "patterns": (r"/\.git(?:$|/|\?)", r"/\.svn(?:$|/|\?)", r"/\.hg(?:$|/|\?)"),
        "severity": "high",
        "description": "Version-control metadata may be accessible.",
    },
    "test_environment": {
        "patterns": (r"/test(?:$|/|\?)", r"/staging(?:$|/|\?)", r"/dev(?:$|/|\?)", r"/beta(?:$|/|\?)"),
        "severity": "low",
        "description": "Test or development environment may be publicly accessible.",
    },
    "api_without_auth": {
        "patterns": (r"/api/internal", r"/api/admin", r"/api/debug"),
        "severity": "medium",
        "description": "API endpoint may lack authentication; verify authorization.",
    },
}


@dataclass
class VulnResult:
    output: str
    records: list[dict]
    stats: dict


def _norm_url(value: str) -> str:
    return (value or "").strip().rstrip(".,);]")


def build_vuln_records(
    *,
    target_url: str,
    urls: list[str] | None = None,
    parameters: list[dict] | None = None,
    api_endpoints: list[str] | None = None,
    header_analysis: dict | None = None,
    high_risk_ports: list | None = None,
) -> list[dict]:
    records: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(record: dict) -> None:
        key = (
            str(record.get("template-id")),
            str(record.get("matched-at")),
            str(record.get("matcher-name")),
        )
        if key not in seen:
            seen.add(key)
            records.append(record)

    candidates: list[tuple[str, str, str]] = []
    for url in urls or []:
        value = _norm_url(url)
        if not value:
            continue
        for vuln_type, info in PATTERNS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, value, re.IGNORECASE):
                    candidates.append((vuln_type, value, pattern))
                    break
    for endpoint in api_endpoints or []:
        candidates.append(("api_endpoint_observed", _norm_url(endpoint), "observed-api"))

    for vuln_type, location, pattern in candidates:
        info = PATTERNS.get(vuln_type, {
            "severity": "info",
            "description": "Observed API endpoint; verify authentication and exposure.",
        })
        add(
            nuclei_record(
                template_id=f"native-pattern-{vuln_type.replace('_', '-')}",
                name=f"Potential security issue: {vuln_type.replace('_', ' ').title()}",
                severity=info["severity"],
                matched_at=location,
                description=(
                    f"{info['description']} Pattern match only; manual verification "
                    "is required before reporting this as a vulnerability."
                ),
                tags=["native", "candidate", "pattern", vuln_type],
                matcher=f"pattern:{pattern}",
                extracted=[location],
                host=target_url,
            )
        )

    for item in parameters or []:
        name = str(item.get("name") or "")
        if not name or not is_suspicious(name):
            continue
        location = str(item.get("candidate_url") or item.get("location") or target_url)
        add(
            nuclei_record(
                template_id="native-param-idor-candidate",
                name=f"Suspicious parameter: {name}",
                severity="medium",
                matched_at=location,
                description=(
                    f"Parameter '{name}' may accept an object identifier or a "
                    "security-sensitive value. This is an IDOR/parameter-tampering "
                    "candidate requiring manual authorization testing."
                ),
                tags=["native", "candidate", "parameter", "idor"],
                matcher="suspicious-parameter",
                extracted=[name],
                host=target_url,
            )
        )

    for item in high_risk_ports or []:
        port = getattr(item, "port", None) or (item.get("port") if isinstance(item, dict) else None)
        service = getattr(item, "service", "") or (item.get("service", "") if isinstance(item, dict) else "")
        if not port:
            continue
        host = urlsplit(target_url).hostname if "://" in target_url else target_url
        host = (host or target_url).strip().rstrip(".")
        add(
            nuclei_record(
                template_id=f"native-open-{service or 'unknown'}-port",
                name=f"High-risk service exposed: {service or 'unknown'} on {port}/tcp",
                severity="medium",
                matched_at=f"{host}:{port}",
                description=(
                    "A commonly sensitive service is reachable. Exposure may be "
                    "intentional; verify authentication and network isolation."
                ),
                tags=["native", "candidate", "exposed-service"],
                matcher="open-port",
                extracted=[f"{port}/{service}"],
                host=target_url,
                port=int(port),
            )
        )

    if header_analysis:
        for record in header_finding_records(
            header_analysis,
            matched_at=target_url,
            host=target_url,
        ):
            add(record)

    return records


def vuln_result(
    *,
    target_url: str,
    urls: list[str] | None = None,
    parameters: list[dict] | None = None,
    api_endpoints: list[str] | None = None,
    header_analysis: dict | None = None,
    high_risk_ports: list | None = None,
) -> VulnResult:
    records = build_vuln_records(
        target_url=target_url,
        urls=urls,
        parameters=parameters,
        api_endpoints=api_endpoints,
        header_analysis=header_analysis,
        high_risk_ports=high_risk_ports,
    )
    stats = {
        "candidates": len(records),
        "high": sum(1 for r in records if r["info"]["severity"] == "high"),
        "medium": sum(1 for r in records if r["info"]["severity"] == "medium"),
        "low": sum(1 for r in records if r["info"]["severity"] == "low"),
        "info": sum(1 for r in records if r["info"]["severity"] == "info"),
    }
    output = nuclei_jsonl(
        records,
        header=(
            "Pattern-based candidates only. Manual verification is required; "
            "these are not confirmed vulnerabilities."
        ),
    )
    return VulnResult(output=output, records=records, stats=stats)


@register
class VulnCollector(Collector):
    id = "leadline-vulns"
    label = "Native vulnerability candidates"
    description = "Pattern candidates from observed paths, params and headers; never confirmed."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        try:
            require_no_proxy(ctx)
            probes, errors, _stats = _probe_targets(ctx)
            if not probes:
                raise RuntimeError("; ".join(errors) or "no HTTP response")
            probe = probes[0]
            page_url = probe.final_url or probe.url
            base_url = _origin(page_url)
            html = probe.body.decode("utf-8", errors="replace")
            parsed = discover_params(html, base_url, page_url=page_url)
            headers = {key: value for key, value in probe.headers}
            analysis = analyze_security_headers(headers, probe.scheme)
            result = vuln_result(
                target_url=page_url,
                urls=[item["candidate_url"] for item in parsed.parameters],
                parameters=parsed.parameters,
                header_analysis=analysis,
            )
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            return CollectorResult(
                [PhaseOutput("vulns", "", {"status": "failed"}, str(exc))]
            )
        return CollectorResult([PhaseOutput("vulns", result.output, result.stats)], result.stats)
