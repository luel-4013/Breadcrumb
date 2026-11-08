"""Native JavaScript analysis (never executes JavaScript).

Same-origin external scripts are fetched with the scope-pinned HTTP helper,
inline scripts are read from the page, and useful strings are extracted as
candidate endpoints and parameter names. Output is plain text containing URLs,
so Breadcrumb's URL parser creates ``url``/``path``/``param`` entities.

Inferred endpoints are observations, not proof that anything responds. The
collector never sends a request to an endpoint it extracted from JavaScript.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .base import (
    Collector,
    CollectorContext,
    CollectorError,
    CollectorResult,
    JobCancelled,
    PhaseOutput,
    register,
)
from .guard import ScopeDenied
from .http import _fetch, _probe_targets

SCRIPT_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*['\"](?P<src>[^'\"]+)['\"][^>]*>",
    re.IGNORECASE,
)
INLINE_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(?P<body>.*?)</script>", re.IGNORECASE | re.DOTALL)
ENDPOINT_RES = (
    re.compile(r"/api/[A-Za-z0-9/_\-.~%?=&]+"),
    re.compile(r"\bfetch\s*\(\s*[`'\"]([^`'\"]+)[`'\"]", re.IGNORECASE),
    re.compile(r"\baxios\.(?:get|post|put|patch|delete)\s*\(\s*[`'\"]([^`'\"]+)[`'\"]", re.IGNORECASE),
    re.compile(r"\$\.(?:get|post|ajax)\s*\(\s*[`'\"]([^`'\"]+)[`'\"]", re.IGNORECASE),
    re.compile(r"\b(?:path|route|endpoint|url)\s*[:=]\s*[`'\"](/[^`'\"]+)[`'\"]", re.IGNORECASE),
)
ABSOLUTE_RE = re.compile(r"https?://[^\s\"'<>)`\\]+", re.IGNORECASE)
PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,63})=")
ASSIGNED_PARAM_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]{0,63})\s*=",
)
INTERESTING_ASSIGNMENTS = {
    "id", "uid", "userid", "user_id", "orderid", "order_id", "fileid", "file_id",
    "query", "filter", "sort", "limit", "offset", "page", "redirect", "next",
    "url", "path", "file", "cmd", "command",
}
MAX_SCRIPTS = 25
MAX_EXTRACTED = 200


@dataclass
class JavaScriptResult:
    output: str
    scripts: list[str]
    endpoints: list[str]
    parameters: list[str]
    cves: list[str]
    stats: dict


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _same_origin(url: str, base: str) -> bool:
    return bool(_origin(url)) and _origin(url) == _origin(base)


def _clean(value: str) -> str:
    value = (value or "").strip().strip("`'\"")
    return value.rstrip(".,);]")


def _page_from_ctx(ctx: CollectorContext) -> tuple[str, str, str]:
    """Return (base_url, page_url, html) from a fresh, guarded HTTP probe."""
    probes, errors, _stats = _probe_targets(ctx)
    if not probes:
        raise RuntimeError("; ".join(errors) or "no HTTP response for JavaScript analysis")
    probe = max(probes, key=lambda item: len(item.body))
    body = probe.body.decode("utf-8", errors="replace")
    page_url = probe.final_url or probe.url
    return _origin(page_url) or page_url, page_url, body


def analyze_javascript(
    ctx: CollectorContext,
    *,
    base_url: str = "",
    page_url: str = "",
    html: str = "",
) -> JavaScriptResult:
    if not html:
        base_url, page_url, html = _page_from_ctx(ctx)
    base_url = base_url or _origin(page_url)
    if not base_url:
        raise RuntimeError("JavaScript analysis needs an http(s) base URL")

    ctx.check_cancel()
    scripts: list[str] = []
    seen_scripts: set[str] = set()
    for match in SCRIPT_RE.finditer(html):
        raw = _clean(match.group("src"))
        if not raw:
            continue
        try:
            url = urljoin(base_url + "/", raw)
        except ValueError:
            continue
        if not url.startswith(("http://", "https://")):
            continue
        if url not in seen_scripts:
            seen_scripts.add(url)
            scripts.append(url)

    inline = [match.group("body") or "" for match in INLINE_RE.finditer(html)]
    fetched: list[str] = []
    sources: list[tuple[str, str]] = [(page_url or base_url, html)]
    for chunk in inline:
        sources.append((page_url or base_url, chunk))

    for url in scripts[:MAX_SCRIPTS]:
        if not _same_origin(url, base_url):
            # Cross-origin script: record the reference, never fetch it.
            continue
        ctx.check_cancel()
        try:
            probe = _fetch(ctx, url, ctx.headers)
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001  (one broken script is not fatal)
            ctx.emit_event("warning", f"javascript fetch failed for {url}: {exc}")
            continue
        if probe.status >= 400:
            continue
        fetched.append(url)
        sources.append((url, probe.body.decode("utf-8", errors="replace")))
        if ctx.rate_limit:
            ctx.sleep(1.0 / ctx.rate_limit)

    endpoints: list[str] = []
    parameters: list[str] = []
    cves: list[str] = []
    seen_endpoints: set[str] = set()
    seen_params: set[str] = set()
    seen_cves: set[str] = set()

    def add_endpoint(value: str) -> None:
        value = _clean(value)
        if not value or len(value) > 2048:
            return
        if value.startswith("//"):
            value = f"{urlsplit(base_url).scheme}:{value}"
        if value.startswith("/"):
            try:
                value = urljoin(base_url + "/", value)
            except ValueError:
                return
        if not value.startswith(("http://", "https://")):
            return
        if value not in seen_endpoints and len(endpoints) < MAX_EXTRACTED:
            seen_endpoints.add(value)
            endpoints.append(value)

    def add_param(value: str) -> None:
        value = (value or "").strip()
        if value and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value):
            if value not in seen_params and len(parameters) < MAX_EXTRACTED:
                seen_params.add(value)
                parameters.append(value)

    for _source, content in sources:
        for pattern in ENDPOINT_RES:
            for match in pattern.finditer(content):
                value = match.group(1) if match.groups() else match.group(0)
                add_endpoint(value)
        for match in ABSOLUTE_RE.finditer(content):
            add_endpoint(match.group(0))
        for match in PARAM_RE.finditer(content):
            add_param(match.group(1))
        for match in ASSIGNED_PARAM_RE.finditer(content):
            name = match.group(1)
            if name.lower() in INTERESTING_ASSIGNMENTS:
                add_param(name)
        for match in re.finditer(r"\bCVE-\d{4}-\d{4,7}\b", content, re.IGNORECASE):
            value = match.group(0).upper()
            if value not in seen_cves:
                seen_cves.add(value)
                cves.append(value)

    lines = [
        f"# Native JavaScript analysis for {base_url}",
        f"# Scripts referenced: {len(scripts)}; fetched same-origin: {len(fetched)}; "
        f"inline analysed: {len(inline)}",
        "# Endpoints are inferred from source text and were not requested.",
    ]
    for url in scripts:
        lines.append(url)
    lines.extend(endpoints)
    if parameters:
        lines.append("# Candidate query parameters (inferred; empty values):")
        for name in parameters:
            lines.append(f"{base_url}/?{name}=")

    stats = {
        "scripts": len(scripts),
        "scripts_fetched": len(fetched),
        "inline_scripts": len(inline),
        "endpoints": len(endpoints),
        "parameters": len(parameters),
        "cves": len(cves),
    }
    ctx.emit_event(
        "phase",
        f"javascript: {stats['scripts_fetched']}/{stats['scripts']} scripts fetched, "
        f"{stats['endpoints']} endpoint(s), {stats['parameters']} parameter(s)",
        **stats,
    )
    return JavaScriptResult(
        output="\n".join(lines) + "\n",
        scripts=scripts,
        endpoints=endpoints,
        parameters=parameters,
        cves=cves,
        stats=stats,
    )


@register
class JavaScriptCollector(Collector):
    id = "leadline-js"
    label = "Native JavaScript analysis"
    description = "Same-origin script discovery, endpoint and parameter extraction; no execution."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        if ctx.proxy:
            raise CollectorError(
                "native collectors do not support a proxy; clear the header "
                "profile proxy or use an external runner"
            )
        try:
            result = analyze_javascript(ctx)
        except (CollectorError, JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            return CollectorResult(
                [PhaseOutput("js", "", {"status": "failed"}, str(exc))]
            )
        return CollectorResult([PhaseOutput("js", result.output, result.stats)], result.stats)
