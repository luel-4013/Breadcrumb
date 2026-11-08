"""Native REST/GraphQL/OpenAPI path discovery.

Only a small, fixed list of common paths is requested (GET), with manual
redirect and scope checks on every hop. Observed responses are emitted as
httpx JSONL, which Breadcrumb already parses into URL/host/port entities.

OpenAPI/Swagger documents are parsed locally into an operation inventory
(method + path). Every operation is labeled *inferred* and is never requested;
the evidence keeps the distinction between observed and documented endpoints.
References found in HTML or JavaScript are treated the same way.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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
from .http import _fetch
from .js import _origin, _page_from_ctx

try:  # PyYAML is an explicit runtime dependency, but stay import-safe.
    import yaml
except Exception:  # noqa: BLE001
    yaml = None

COMMON_API_PATHS = (
    "/api", "/api/v1", "/api/v2", "/api/graphql", "/graphql", "/graphiql",
    "/playground", "/swagger", "/swagger.json", "/swagger-ui", "/openapi.json",
    "/docs", "/redoc", "/api/docs", "/api/swagger",
)
API_LINK_RE = re.compile(r"\b(?:href|src)\s*=\s*['\"]([^'\"]*/api/[^'\"]*)['\"]", re.IGNORECASE)
INTERESTING_STATUS = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
MAX_PATHS = 50
MAX_INFERRED = 500
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_OPENAPI_PATHS = 300
MAX_OPENAPI_OPERATIONS = 500


@dataclass
class APIResult:
    output: str
    endpoints: list[str]
    inferred: list[str]
    stats: dict
    openapi_documents: list[dict] = field(default_factory=list)
    openapi_operations: list[dict] = field(default_factory=list)


def _option_paths(value) -> list[str]:
    if value in (None, "", []):
        return list(COMMON_API_PATHS)
    if isinstance(value, str):
        value = [chunk for chunk in re.split(r"[,\s]+", value) if chunk]
    out: list[str] = []
    for item in value:
        path = str(item).strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = "/" + path
        if path not in out:
            out.append(path)
    return out[:MAX_PATHS]


def _path_with_parameters(path: str) -> str:
    """Replace ``{id}`` with ``:id`` so URL parsing keeps the path intact."""
    return re.sub(r"\{([^}/]+)\}", r":\1", str(path or ""))


def _join_url_path(base_path: str, path: str) -> str:
    pieces = [str(part or "").strip("/") for part in (base_path, path)]
    joined = "/".join(piece for piece in pieces if piece)
    return "/" + joined if joined else "/"


def _server_base_path(document: dict) -> tuple[str, str]:
    """Return (path prefix, server URL/note) without trusting remote origins."""
    servers = document.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if not isinstance(server, dict):
                continue
            raw = str(server.get("url") or "").strip()
            if not raw:
                continue
            parsed = urlsplit(raw)
            return (parsed.path if parsed.path not in ("", "/") else ""), raw
    base_path = document.get("basePath")
    if isinstance(base_path, str) and base_path.strip("/"):
        return "/" + base_path.strip("/"), ""
    return "", ""


def _structured_document(probe) -> dict | None:
    body = getattr(probe, "body", b"") or b""
    if len(body) > MAX_DOCUMENT_BYTES:
        return None
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    if text[0] in "[{":
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except ValueError:
            pass
    if yaml is None:
        return None
    try:
        parsed = yaml.safe_load(text)
    except Exception:  # noqa: BLE001  (arbitrary HTML is not a document)
        return None
    return parsed if isinstance(parsed, dict) else None


def _openapi_summary(document: dict | None, base_url: str) -> dict | None:
    if not isinstance(document, dict):
        return None
    spec_version = ""
    if isinstance(document.get("openapi"), str):
        spec_version = f"OpenAPI {document['openapi']}"
    elif document.get("swagger") is not None:
        spec_version = f"Swagger {document['swagger']}"
    else:
        return None
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return None

    base_path, server_url = _server_base_path(document)
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    operations: list[dict] = []
    path_items = list(paths.items())[:MAX_OPENAPI_PATHS]
    truncated = len(paths) > MAX_OPENAPI_PATHS
    for raw_path, item in path_items:
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            if method not in item:
                continue
            if len(operations) >= MAX_OPENAPI_OPERATIONS:
                truncated = True
                break
            display_path = _join_url_path(
                base_path, _path_with_parameters(raw_path)
            )
            operation = item.get(method) if isinstance(item.get(method), dict) else {}
            operations.append(
                {
                    "method": method.upper(),
                    "path": display_path,
                    "spec_path": raw_path,
                    "url": urljoin(base_url + "/", display_path.lstrip("/")),
                    "operation_id": str(operation.get("operationId") or ""),
                }
            )
        if len(operations) >= MAX_OPENAPI_OPERATIONS:
            truncated = True
            break

    return {
        "spec_version": spec_version,
        "title": str(info.get("title") or ""),
        "api_version": str(info.get("version") or ""),
        "path_count": len(paths),
        "operation_count": len(operations),
        "base_path": base_path,
        "server_url": server_url,
        "operations": operations,
        "truncated": truncated,
    }


def discover_api(
    ctx: CollectorContext,
    *,
    base_url: str,
    page_url: str = "",
    html: str = "",
    js_endpoints: list[str] | None = None,
    paths=None,
) -> APIResult:
    base_url = base_url or _origin(page_url)
    if not base_url:
        raise RuntimeError("API discovery needs an http(s) base URL")
    host = urlsplit(base_url).hostname or ""
    selected = _option_paths(paths)
    records: list[dict] = []
    endpoints: list[str] = []
    seen: set[str] = set()
    inferred: list[str] = []
    seen_inferred: set[str] = set()
    openapi_documents: list[dict] = []
    openapi_operations: list[dict] = []

    def add_inferred(raw: str) -> None:
        raw = (raw or "").strip()
        if not raw or len(raw) > 2048:
            return
        if raw.startswith("/"):
            raw = urljoin(base_url + "/", raw)
        if not raw.startswith(("http://", "https://")):
            return
        lowered = raw.lower()
        if (
            "/api/" not in lowered
            and "graphql" not in lowered
            and not any(
                operation["url"] == raw for operation in openapi_operations
            )
        ):
            return
        if raw not in seen_inferred and len(inferred) < MAX_INFERRED:
            seen_inferred.add(raw)
            inferred.append(raw)

    for path in selected:
        ctx.check_cancel()
        url = urljoin(base_url + "/", path.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        try:
            probe = _fetch(ctx, url, ctx.headers)
        except (JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001  (one path is not fatal)
            ctx.emit_event("warning", f"api probe failed for {url}: {exc}")
            continue
        if probe.status not in INTERESTING_STATUS:
            continue
        record = probe.as_httpx(host)
        record["content_type"] = probe.header("content-type")
        record["api_type"] = (
            "graphql" if "graphql" in path.lower()
            else "openapi" if any(token in path.lower() for token in ("swagger", "openapi"))
            else "possible_api"
        )
        record["discovery_type"] = "observed"
        record["source"] = "path_probe"

        document = _structured_document(probe)
        summary = _openapi_summary(document, base_url)
        if summary is not None:
            record["api_type"] = "openapi"
            record["openapi"] = {
                key: value for key, value in summary.items() if key != "operations"
            }
            openapi_documents.append(
                {
                    **{key: value for key, value in summary.items() if key != "operations"},
                    "url": url,
                }
            )
            for operation in summary["operations"]:
                openapi_operations.append(operation)
                add_inferred(operation["url"])

        records.append(record)
        endpoints.append(url)
        if ctx.rate_limit:
            ctx.sleep(1.0 / ctx.rate_limit)

    for match in API_LINK_RE.finditer(html or ""):
        add_inferred(match.group(1))
    for endpoint in js_endpoints or []:
        add_inferred(endpoint)

    lines = [
        f"# Native API discovery for {base_url}",
        f"# Paths probed: {len(selected)}; observed: {len(records)}; "
        f"OpenAPI documents: {len(openapi_documents)}; "
        f"inferred (not requested): {len(inferred)}",
    ]
    for summary in openapi_documents:
        title = summary.get("title") or "untitled"
        lines.append(
            f"# {summary['spec_version']} document: {title!r} "
            f"({summary['path_count']} paths, {summary['operation_count']} operations) "
            f"at {summary['url']}"
            + (" [truncated]" if summary.get("truncated") else "")
        )
    for record in records:
        lines.append(json.dumps(record, sort_keys=True))
    if openapi_operations:
        lines.append("# OpenAPI operations (inferred from the document; never requested):")
        for operation in openapi_operations:
            lines.append(f"{operation['method']} {operation['url']}")
    if inferred:
        lines.append("# Inferred API references from HTML/JavaScript/OpenAPI:")
        lines.extend(inferred)

    stats = {
        "paths_probed": len(selected),
        "observed": len(records),
        "inferred": len(inferred),
        "endpoints": len(endpoints),
        "openapi_documents": len(openapi_documents),
        "openapi_operations": len(openapi_operations),
        "openapi_truncated": any(item.get("truncated") for item in openapi_documents),
    }
    ctx.emit_event(
        "phase",
        f"api discovery: {stats['observed']} observed, "
        f"{stats['openapi_operations']} OpenAPI operations, "
        f"{stats['inferred']} inferred",
        **stats,
    )
    return APIResult(
        output="\n".join(lines) + "\n",
        endpoints=endpoints,
        inferred=inferred,
        stats=stats,
        openapi_documents=openapi_documents,
        openapi_operations=openapi_operations,
    )


@register
class APICollector(Collector):
    id = "leadline-api"
    label = "Native API discovery"
    description = "Probe common REST/GraphQL/OpenAPI paths; GET only, scope-pinned."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        if ctx.proxy:
            raise CollectorError(
                "native collectors do not support a proxy; clear the header "
                "profile proxy or use an external runner"
            )
        try:
            base_url, page_url, html = _page_from_ctx(ctx)
            result = discover_api(ctx, base_url=base_url, page_url=page_url, html=html)
        except (CollectorError, JobCancelled, ScopeDenied):
            raise
        except Exception as exc:  # noqa: BLE001
            return CollectorResult(
                [PhaseOutput("api", "", {"status": "failed"}, str(exc))]
            )
        return CollectorResult([PhaseOutput("api", result.output, result.stats)], result.stats)
