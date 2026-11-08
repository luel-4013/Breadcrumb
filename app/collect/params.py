"""Native parameter discovery from HTML forms and URL query strings.

No active fuzzing: the collector only reports parameters that are already
present in the page or referenced by JavaScript. Suspicious names are leads
for manual review; the associated finding is emitted by the vuln phase.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlsplit

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
from .js import _origin, _page_from_ctx

HREF_RE = re.compile(r"\b(?:href|action)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b(?P<attrs>[^>]*)>", re.IGNORECASE)
ATTR_RE = re.compile(
    r"\b(?P<name>name|type|action)\s*=\s*['\"](?P<value>[^'\"]*)['\"]", re.IGNORECASE
)
SUSPICIOUS = (
    r"id$", r"uid$", r"user_?id$", r"file_?id$", r"order_?id$",
    r"file$", r"path$", r"dir$", r"url$", r"redirect$", r"next$",
    r"cmd$", r"exec$", r"command$", r"query$", r"sql$",
    r"page$", r"sort$", r"order$", r"filter$", r"search$", r"q$",
)
MAX_PARAMS = 500


@dataclass
class ParamResult:
    output: str
    parameters: list[dict]
    forms: list[dict]
    suspicious: list[dict]
    stats: dict


def _attrs(text: str) -> dict[str, str]:
    return {match.group("name").lower(): match.group("value") for match in ATTR_RE.finditer(text)}


def is_suspicious(name: str) -> bool:
    return any(re.search(pattern, name or "", re.IGNORECASE) for pattern in SUSPICIOUS)


def _candidate(name: str, path: str, base_url: str, source: str) -> dict:
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return {
        "name": name,
        "location": path,
        "source": source,
        "candidate_url": f"{base_url}{path}?{name}=",
    }


def discover_params(
    html: str,
    base_url: str,
    *,
    page_url: str = "",
    js_params: list[str] | None = None,
) -> ParamResult:
    base_url = base_url or _origin(page_url)
    if not base_url:
        raise RuntimeError("parameter discovery needs an http(s) base URL")
    parsed_page = urlsplit(page_url or base_url)
    current_path = parsed_page.path or "/"

    parameters: list[dict] = []
    forms: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, path: str, source: str) -> None:
        if not name or len(parameters) >= MAX_PARAMS:
            return
        key = (path or "/", name)
        if key in seen:
            return
        seen.add(key)
        parameters.append(_candidate(name, path, base_url, source))

    for match in HREF_RE.finditer(html or ""):
        raw = match.group(1).strip()
        if not raw or raw.startswith(("mailto:", "javascript:", "data:", "#")):
            continue
        try:
            absolute = urljoin(page_url or base_url + "/", raw)
            parsed = urlsplit(absolute)
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https") or _origin(absolute) != _origin(base_url):
            continue
        for name in parse_qs(parsed.query, keep_blank_values=True):
            add(name, parsed.path or "/", "html_link")

    for form_match in FORM_RE.finditer(html or ""):
        form_attrs = _attrs(form_match.group("attrs") or "")
        action = form_attrs.get("action", "")
        try:
            absolute_action = urljoin(page_url or base_url + "/", action or current_path)
            action_path = urlsplit(absolute_action).path or current_path
        except ValueError:
            action_path = current_path
        fields: list[dict] = []
        for input_match in INPUT_RE.finditer(form_match.group("body") or ""):
            attrs = _attrs(input_match.group("attrs") or "")
            name = attrs.get("name", "").strip()
            if not name:
                continue
            field_type = (attrs.get("type") or "text").strip().lower()
            fields.append({"name": name, "type": field_type, "action": action_path})
            add(name, action_path, "form_field")
        for name in parse_qs(urlsplit(urljoin(base_url + "/", action or "")).query,
                            keep_blank_values=True):
            add(name, action_path, "form_action")
        if fields:
            forms.append({"action": action_path, "fields": fields})

    for name in js_params or []:
        add(name, current_path, "javascript")

    suspicious = [dict(item, reason="potentially sensitive parameter name")
                  for item in parameters if is_suspicious(item["name"])]

    lines = [
        f"# Native parameter discovery for {page_url or base_url}",
        f"# Parameters: {len(parameters)}; forms: {len(forms)}; "
        f"suspicious names: {len(suspicious)}",
        "# Candidate URLs are inferred; no fuzzing or requests were performed.",
    ]
    lines.extend(item["candidate_url"] for item in parameters)
    if forms:
        lines.append("# Forms (name, type, action):")
        for form in forms:
            for field in form["fields"]:
                lines.append(f"# {field['name']}\t{field['type']}\t{form['action']}")
    if suspicious:
        lines.append("# Suspicious parameter names (manual review only):")
        for item in suspicious:
            lines.append(f"# {item['name']}\t{item['location']}\t{item['source']}")

    stats = {
        "parameters": len(parameters),
        "forms": len(forms),
        "suspicious": len(suspicious),
    }
    return ParamResult(
        output="\n".join(lines) + "\n",
        parameters=parameters,
        forms=forms,
        suspicious=suspicious,
        stats=stats,
    )


@register
class ParamCollector(Collector):
    id = "leadline-params"
    label = "Native parameter discovery"
    description = "URL query and form-field discovery from HTML; no fuzzing."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        try:
            require_no_proxy(ctx)
            base_url, page_url, html = _page_from_ctx(ctx)
            result = discover_params(html, base_url, page_url=page_url)
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            return CollectorResult(
                [PhaseOutput("params", "", {"status": "failed"}, str(exc))]
            )
        return CollectorResult([PhaseOutput("params", result.output, result.stats)], result.stats)
