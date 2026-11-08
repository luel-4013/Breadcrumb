"""Offline-first CVE correlation.

The default path never calls the network. It records CVE identifiers that are
already referenced in observed content, then correlates versioned technologies
against a local NVD cache. A CVE becomes a finding **only** when a local
CPE/version-range check proves applicability; referenced IDs and optional NVD
keyword results stay informational and never affect risk.

The cache lives in ``breadcrumb.nvd.json`` by default (override with the
``nvd_cache`` collector option or ``BREADCRUMB_NVD_CACHE``). Import data with
``breadcrumb nvd import nvdcve-2.0.json.gz``.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

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
from .http import _probe_targets
from .nvd import (
    MAX_MATCHES,
    DEFAULT_TTL_DAYS,
    NvdCache,
    NvdCacheError,
    default_cache_path,
    load_cache,
    normalize_product,
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
VERSION_RE = re.compile(
    r"^(?P<product>[A-Za-z][A-Za-z0-9 ._+-]{1,60}?)[/ ](?P<version>\d[\w.\-]{0,30})"
)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_LOOKUPS = 5
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class CVEResult:
    output: str
    cves: list[str]
    stats: dict


def _technologies(values) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in values or []:
        if isinstance(item, dict):
            product = str(
                item.get("product") or item.get("technology") or item.get("name") or ""
            ).strip()
            version = str(item.get("version") or "").strip()
        else:
            product = str(item or "").strip()
            version = ""
        match = VERSION_RE.match(product)
        if match:
            product = match.group("product").strip()
            version = version or match.group("version")
        key = (product.lower(), version.lower())
        if product and key not in seen:
            seen.add(key)
            out.append({"product": product, "version": version})
    return out


def _nvd_keyword_lookup(query: str, api_key: str, timeout: float = 10.0) -> list[str]:
    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 20})
    request = urllib.request.Request(
        f"{NVD_URL}?{params}",
        headers={"User-Agent": "Breadcrumb/0.1 (local notebook)", "apiKey": api_key},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8", errors="replace"))
    out: list[str] = []
    for item in payload.get("vulnerabilities") or []:
        cve = (item.get("cve") or {}).get("id") if isinstance(item, dict) else None
        if cve and str(cve).upper().startswith("CVE-"):
            out.append(str(cve).upper())
    return out


def _nuclei_record(match: dict, target_url: str) -> dict:
    severity = str(match.get("cvss_severity") or "medium").lower()
    if severity not in VALID_SEVERITIES:
        severity = "medium"  # unscored CVE: do not silently downgrade to info
    cve_id = match["cve_id"]
    product = match.get("product") or ""
    version = match.get("version") or ""
    description = (
        f"Locally verified: {product} {version} falls within "
        f"{match.get('version_range') or 'all versions'} for the CPE "
        f"{match.get('matched_cpe')}.\n\n"
        f"{match.get('description') or 'No description available from NVD.'}"
    )
    return {
        "template-id": cve_id,
        "type": "cve-match",
        "host": target_url,
        "matched-at": target_url,
        "matcher-name": f"local-nvd:{normalize_product(product)}:{version}",
        "extracted-results": [
            f"{product} {version}",
            str(match.get("matched_cpe") or ""),
            str(match.get("version_range") or "all versions"),
        ],
        "info": {
            "name": f"CVE applies to observed version: {product} {version} -- {cve_id}",
            "severity": severity,
            "description": description,
            "tags": ["cve", "local-nvd", "applicability-verified"],
            "classification": {
                "cve-id": [cve_id],
                "cvss-score": match.get("cvss_score"),
            },
        },
    }


def collect_cves(
    ctx: CollectorContext,
    *,
    technologies=None,
    content: str = "",
    target_url: str = "",
) -> CVEResult:
    tech = _technologies(technologies)
    referenced: list[str] = []
    seen: set[str] = set()
    for match in CVE_RE.finditer(content or ""):
        value = match.group(0).upper()
        if value not in seen:
            seen.add(value)
            referenced.append(value)

    warnings: list[str] = []
    cache_path = Path(
        str(ctx.options.get("nvd_cache") or "").strip() or default_cache_path()
    ).expanduser()
    explicit_cache = bool(str(ctx.options.get("nvd_cache") or "").strip())
    cache: NvdCache | None = None
    if explicit_cache or cache_path.exists():
        try:
            cache = load_cache(cache_path)
        except NvdCacheError as exc:
            warnings.append(f"local NVD cache unavailable: {exc}")

    verified = cache.match_technologies(tech, max_matches=MAX_MATCHES) if cache else []

    nvd_ids: list[str] = []
    cached_keyword = 0
    api_key = str(ctx.options.get("nvd_api_key") or "").strip()
    opt_in = bool(ctx.options.get("nvd_lookup"))
    try:
        ttl_days = float(ctx.options.get("nvd_keyword_ttl_days") or DEFAULT_TTL_DAYS)
    except (TypeError, ValueError):
        ttl_days = DEFAULT_TTL_DAYS
    if opt_in and api_key:
        if cache is None:
            cache = NvdCache({}, path=cache_path)
        for item in tech[:MAX_LOOKUPS]:
            ctx.check_cancel()
            product = item["product"]
            version = item["version"]
            query = f"{product} {version}".strip()
            found = cache.keyword_get(query, ttl_days=ttl_days)
            if found is not None:
                cached_keyword += 1
            else:
                try:
                    found = _nvd_keyword_lookup(query, api_key)
                    cache.keyword_put(query, found)
                except Exception as exc:  # noqa: BLE001  (opt-in lookup is best effort)
                    warnings.append(f"{product}: {type(exc).__name__}")
                    continue
            for cve in found:
                if cve not in nvd_ids:
                    nvd_ids.append(cve)
        try:
            cache.save(cache_path)
        except OSError as exc:
            warnings.append(f"could not save NVD cache: {exc}")

    product_line = ", ".join(
        f"{item['product']} {item['version']}".strip() for item in tech
    ) or "none"
    lines = [
        f"# CVE correlation for {target_url or ctx.target}",
        "# Offline-first: findings exist only for locally proven CPE/version matches.",
        f"# Product/version candidates: {product_line}",
    ]
    if cache is not None:
        lines.append(
            f"# Local NVD cache: {cache.path or cache_path} ({cache.count} CVEs)"
        )
    if verified:
        lines.append(
            "# Locally verified CVE applicability (nuclei JSONL; only proven matches):"
        )
        for match in verified:
            lines.append(json.dumps(_nuclei_record(match, target_url or ctx.target), sort_keys=True))
    if opt_in and not api_key:
        lines.append("# NVD lookup requested but no nvd_api_key was supplied; staying offline.")
    if referenced:
        lines.append("# CVE identifiers referenced in observed content (not applicability-verified):")
        lines.extend(referenced)
    if nvd_ids:
        lines.append("# NVD keyword-search results (unverified; not CPE applicability):")
        lines.extend(nvd_ids)
    for warning in warnings:
        lines.append(f"# NVD warning: {warning}")

    all_ids = list(dict.fromkeys(
        [match["cve_id"] for match in verified] + referenced + nvd_ids
    ))
    if verified and nvd_ids:
        mode = "local-nvd+keyword"
    elif verified:
        mode = "local-nvd"
    elif nvd_ids:
        mode = "nvd-keyword"
    else:
        mode = "offline"
    stats = {
        "mode": mode,
        "technologies": len(tech),
        "local_nvd_cves": cache.count if cache is not None else 0,
        "applicability_verified": len(verified),
        "referenced": len(referenced),
        "nvd_unverified": len(nvd_ids),
        "cached_keyword": cached_keyword,
        "warnings": warnings,
    }
    ctx.emit_event(
        "phase",
        f"cve: {stats['applicability_verified']} verified locally, "
        f"{stats['referenced']} referenced, {stats['nvd_unverified']} keyword candidates",
        **{key: value for key, value in stats.items() if key != "warnings"},
    )
    return CVEResult(output="\n".join(lines) + "\n", cves=all_ids, stats=stats)


@register
class CVECollector(Collector):
    id = "leadline-cve"
    label = "Native CVE correlation"
    description = "Local NVD CPE/version verification; keyword results stay unverified."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        try:
            require_no_proxy(ctx)
            probes, errors, _stats = _probe_targets(ctx)
            if not probes:
                raise RuntimeError("; ".join(errors) or "no HTTP response")
            probe = probes[0]
            page_url = probe.final_url or probe.url
            html = probe.body.decode("utf-8", errors="replace")
            record = probe.as_httpx(page_url)
            tech = record.get("tech_versions") or [
                {"product": value, "version": ""}
                for value in (record.get("tech") or [])
            ]
            result = collect_cves(
                ctx,
                technologies=tech,
                content=html,
                target_url=page_url,
            )
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            return CollectorResult(
                [PhaseOutput("cve", "", {"status": "failed"}, str(exc))]
            )
        return CollectorResult([PhaseOutput("cve", result.output, result.stats)], result.stats)
