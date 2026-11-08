"""Native HTTP probing collector.

Produces two kinds of output Breadcrumb already parses:

* ProjectDiscovery-style httpx JSONL (status, title, server, tech, CNAME,
  address) -> the ``httpx`` parser creates URL/host/tech/port entities;
* raw request/response dumps -> the ``http`` parser creates status, header and
  cookie entities.

Connections are pinned to the address the scope guard approved, and every
redirect hop is checked again. TLS SNI uses the original hostname, not the IP.
No third-party HTTP library is required.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urljoin, urlsplit

from .base import (
    Collector,
    CollectorContext,
    CollectorError,
    CollectorResult,
    PhaseOutput,
    register,
)
from .guard import ScopeDenied
from .tech import detect_technologies, tech_labels, tech_versions

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_BODY = 2 * 1024 * 1024
MAX_REDIRECTS = 5
DEFAULT_UA = "Breadcrumb/0.1 (+local recon notebook)"


@dataclass
class Probe:
    url: str
    final_url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    method: str
    address: str
    port: int
    port_default: bool
    scheme: str
    redirects: list[str] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False

    def header(self, name: str) -> str:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return ""

    def as_httpx(self, input_host: str) -> dict:
        body = self.body.decode("utf-8", errors="replace")
        match = TITLE_RE.search(body)
        title = unescape(match.group(1)).strip() if match else ""
        server = self.header("server")
        observations = detect_technologies(self.headers, body)
        tech = tech_labels(observations)
        versioned = tech_versions(observations)
        cnames: list[str] = []
        if ":" not in input_host:
            try:
                canonical, aliases, _ips = socket.gethostbyname_ex(input_host)
                candidates = [canonical] + list(aliases)
                for candidate in candidates:
                    candidate = candidate.strip().lower().rstrip(".")
                    if candidate and candidate != input_host and candidate not in cnames:
                        cnames.append(candidate)
            except (socket.gaierror, OSError):
                pass
        record = {
            "url": self.final_url,
            "input": input_host,
            "status_code": self.status,
            "title": title,
            "tech": tech,
            "cname": cnames,
            "webserver": server,
            "host": self.address,
            "port": str(self.port),
            "scheme": self.scheme,
            "content_length": len(self.body),
        }
        if versioned:
            record["tech_versions"] = versioned
        if self.error:
            record["error"] = self.error
        if self.truncated:
            record["truncated"] = True
        return record

    def raw_dump(self) -> str:
        # Reflect the request that was actually sent (hostname + Host header),
        # not the pinned address used for the socket. The connection address
        # stays in the httpx JSONL record as ``host``.
        host = (urlsplit(self.url).hostname or self.address).strip().lower().rstrip(".")
        host_header = f"[{host}]" if ":" in host else host
        if not self.port_default:
            host_header = f"{host_header}:{self.port}"
        lines = [
            f"{self.method} {urlsplit(self.final_url).path or '/'} HTTP/1.1",
            f"Host: {host_header}",
            "",
            f"HTTP/1.1 {self.status} {self.reason}".rstrip(),
        ]
        for name, value in self.headers:
            lines.append(f"{name}: {value}")
        return "\n".join(lines) + "\n"


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_address = address

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float,
                 context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _candidate_urls(target: str) -> list[str]:
    target = (target or "").strip()
    if not target:
        return []
    if "://" in target:
        return [target]
    return [f"https://{target}", f"http://{target}"]


def _request(ctx: CollectorContext, method: str, url: str, headers: dict) -> Probe:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {scheme!r}")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("URL has no host")
    port = parsed.port or (443 if scheme == "https" else 80)
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    decision = ctx.check_url(url)
    ctx.check_cancel()
    if not decision.addresses:
        raise RuntimeError("scope guard returned no pinned address")

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    request_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    request_headers.update(ctx.headers or {})
    host_for_header = f"[{host}]" if ":" in host else host
    request_headers["Host"] = host_for_header if default_port else f"{host_for_header}:{port}"

    last_error: Exception | None = None
    for address in decision.addresses:
        connection = None
        try:
            if scheme == "https":
                connection = _PinnedHTTPSConnection(
                    host, port, address, timeout=10.0,
                    context=ssl.create_default_context(),
                )
            else:
                connection = _PinnedHTTPConnection(host, port, address, timeout=10.0)
            connection.request(method, path, headers=request_headers)
            response = connection.getresponse()
            read_cap = 0 if method == "HEAD" else MAX_BODY
            body = response.read(read_cap + 1) if read_cap else b""
            truncated = len(body) > MAX_BODY
            if truncated:
                body = body[:MAX_BODY]
            return Probe(
                url=url,
                final_url=url,
                status=response.status,
                reason=response.reason or "",
                headers=list(response.getheaders()),
                body=body,
                method=method,
                address=address,
                port=port,
                port_default=default_port,
                scheme=scheme,
                truncated=truncated,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            last_error = exc
            continue
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # noqa: BLE001
                    pass
    raise RuntimeError(f"connection failed: {last_error}")


def _fetch(ctx: CollectorContext, url: str, headers: dict) -> Probe:
    current = url
    redirects: list[str] = []
    for _hop in range(MAX_REDIRECTS + 1):
        ctx.check_cancel()
        probe = _request(ctx, "GET", current, headers)
        if probe.status not in (301, 302, 303, 307, 308):
            probe.redirects = redirects
            return probe
        location = probe.header("location")
        if not location:
            probe.redirects = redirects
            return probe
        next_url = urljoin(current, location)
        # Manual redirects: the next hop gets its own scope + resolution check.
        ctx.check_url(next_url)
        redirects.append(next_url)
        current = next_url
    raise RuntimeError(f"redirect limit exceeded after {MAX_REDIRECTS} hops")


def _probe_targets(ctx: CollectorContext) -> tuple[list[Probe], list[str], dict]:
    probes: list[Probe] = []
    errors: list[str] = []
    stats = {"targets": 0, "requests": 0, "errors": 0, "redirects": 0}
    scheme_given = "://" in (ctx.target or "")
    for url in _candidate_urls(ctx.target):
        ctx.check_cancel()
        if len(url) > 2048:
            errors.append("target URL is too long")
            continue
        stats["targets"] += 1
        try:
            probe = _fetch(ctx, url, ctx.headers)
            probes.append(probe)
            stats["requests"] += 1
            stats["redirects"] += len(probe.redirects)
            ctx.emit_event(
                "phase",
                f"http {probe.final_url} -> {probe.status} {probe.reason}".strip(),
                url=probe.final_url,
                status=probe.status,
            )
            # For a bare host, https is the preferred scheme. Only fall back
            # to http when the first attempt fails entirely.
            if not scheme_given:
                break
        except ScopeDenied:
            # A redirect (or the initial target) left scope. Fail the whole
            # job closed instead of retrying a forbidden connection.
            raise
        except Exception as exc:  # noqa: BLE001  (collect the failure, keep other schemes)
            stats["errors"] += 1
            errors.append(f"{url}: {exc}")
            ctx.emit_event("warning", f"http probe failed for {url}: {exc}")
        if ctx.rate_limit:
            ctx.sleep(1.0 / ctx.rate_limit)
    return probes, errors, stats


class _HTTPCollector(Collector):
    mode = "all"
    description = "HTTP probing with scope-pinned connections and manual redirects."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        if ctx.proxy:
            raise CollectorError(
                "native collectors do not yet support a proxy; clear the "
                "header profile proxy or use an external runner"
            )
        probes, errors, stats = _probe_targets(ctx)
        phases: list[PhaseOutput] = []
        if probes:
            if self.mode in ("all", "http"):
                jsonl = "\n".join(
                    json.dumps(probe.as_httpx(urlsplit(probe.url).hostname or probe.url))
                    for probe in probes
                ) + "\n"
                phases.append(PhaseOutput("http", jsonl, dict(stats)))
            if self.mode in ("all", "headers"):
                raw = "\n".join(probe.raw_dump() for probe in probes)
                phases.append(PhaseOutput("headers", raw, dict(stats)))
        error = "; ".join(errors) if errors else None
        if not probes:
            phases.append(PhaseOutput(self.mode if self.mode != "all" else "http",
                                      "", dict(stats), error or "no HTTP response"))
        return CollectorResult(phases, stats)


@register
class HTTPCollector(_HTTPCollector):
    id = "leadline-http"
    label = "Native HTTP"
    description = "HTTP probe: status, title, server, tech, CNAME, headers."
    mode = "all"


@register
class TechCollector(_HTTPCollector):
    id = "leadline-tech"
    label = "Native tech detection"
    description = "HTTP probe emitted as httpx JSONL for tech fingerprints."
    mode = "http"


@register
class HeadersCollector(_HTTPCollector):
    id = "leadline-headers"
    label = "Native security headers"
    description = "HTTP probe emitted as raw response dumps for header analysis."
    mode = "headers"
