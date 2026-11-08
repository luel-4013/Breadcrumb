"""Phase 5: local NVD correlation, OpenAPI parsing, tech versions and depth.

These tests are deliberately local-only. They never contact NVD or any
external service; the CVE cache is a fixture written to a temporary file.
"""

import gzip
import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase5-")
os.environ.setdefault("BREADCRUMB_DB_PATH", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BREADCRUMB_SKIP_BACKUP", "1")

from app import cli  # noqa: E402
from app.collect.api import discover_api  # noqa: E402
from app.collect.base import CollectorContext  # noqa: E402
from app.collect.cve import collect_cves  # noqa: E402
from app.collect.guard import ScopeGuard  # noqa: E402
from app.collect.nvd import (  # noqa: E402
    NvdCache,
    cache_from_payload,
    compare_versions,
    import_nvd,
    load_cache,
)
from app.collect.tech import detect_technologies  # noqa: E402
from app.graph import path_tree  # noqa: E402
from app.parsers import extract_findings  # noqa: E402
from app.reporting import highlights, risk_explanation, severity_counts  # noqa: E402
from app.scope import Scope  # noqa: E402


def _cve(
    cve_id: str,
    vendor: str,
    product: str,
    *,
    version: str = "*",
    start: str = "",
    end_including: str = "",
    end_excluding: str = "",
    score: float = 9.8,
) -> dict:
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    match = {"vulnerable": True, "criteria": cpe}
    if start:
        match["versionStartIncluding"] = start
    if end_including:
        match["versionEndIncluding"] = end_including
    if end_excluding:
        match["versionEndExcluding"] = end_excluding
    return {
        "id": cve_id,
        "vulnStatus": "Analyzed",
        "published": "2024-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": f"Fixture description for {cve_id}."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {"baseScore": score, "baseSeverity": "critical"},
                    "baseSeverity": "critical",
                }
            ]
        },
        "configurations": [{"nodes": [{"cpeMatch": [match]}]}],
    }


def _cache_payload(*cves: dict) -> dict:
    return {"vulnerabilities": [{"cve": item} for item in cves]}


def _context(options: dict | None = None, target: str = "https://127.0.0.1/") -> CollectorContext:
    return CollectorContext(
        target=target,
        options=options or {},
        guard=ScopeGuard(Scope("127.0.0.1")),
        job_id=1,
        attempt_id=1,
        worker_id="phase5-test",
    )


def test_version_comparison_and_cpe_version_ranges():
    assert compare_versions("1.24", "1.24.0") == 0
    assert compare_versions("1.0rc1", "1.0") < 0
    assert compare_versions("2.4.58", "2.4.57") > 0

    cache = cache_from_payload(
        _cache_payload(
            _cve(
                "CVE-2024-0001",
                "nginx",
                "nginx",
                start="1.20.0",
                end_excluding="1.22.0",
            ),
            _cve(
                "CVE-2024-0002",
                "apache",
                "http_server",
                start="2.4.0",
                end_including="2.4.57",
                score=7.5,
            ),
            _cve("CVE-2024-0003", "nginx", "nginx", version="1.10.0"),
        )
    )
    matches = cache.match_technologies(
        [
            {"product": "nginx", "version": "1.21.6"},
            {"product": "Apache", "version": "2.4.57"},
        ]
    )
    by_id = {match["cve_id"]: match for match in matches}
    assert set(by_id) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert by_id["CVE-2024-0001"]["version_range"] == ">=1.20.0, <1.22.0"
    assert by_id["CVE-2024-0001"]["applicability_verified"] is True
    assert by_id["CVE-2024-0001"]["cvss_severity"] == "critical"

    # A different version of the same product must not match; an unknown
    # product must not fall back to a substring guess.
    assert cache.match_technologies([{"product": "nginx", "version": "1.24.0"}]) == []
    assert cache.match_technologies([{"product": "not-nginx", "version": "1.21.6"}]) == []


def test_nvd_import_merges_plain_and_gzip_payloads(tmp_path: Path, capsys):
    first = tmp_path / "nvd-page-1.json"
    first.write_text(
        json.dumps(_cache_payload(_cve("CVE-2024-1000", "nginx", "nginx"))),
        encoding="utf-8",
    )
    second = tmp_path / "nvd-page-2.json.gz"
    with gzip.open(second, "wt", encoding="utf-8") as handle:
        json.dump(
            _cache_payload(_cve("CVE-2024-2000", "openssl", "openssl")),
            handle,
        )
    cache_path = tmp_path / "breadcrumb.nvd.json"

    report = import_nvd(first, cache_path)
    assert report["imported"] == 1
    assert report["new"] == 1
    assert report["total"] == 1

    report = import_nvd(second, cache_path)
    assert report["imported"] == 1
    assert report["new"] == 1
    assert report["total"] == 2

    loaded = load_cache(cache_path)
    assert loaded.count == 2
    assert loaded.match_technologies([{"product": "openssl", "version": "3.0.0"}])

    assert cli.main(["nvd", "stats", "--cache", str(cache_path), "--json"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["cves"] == 2
    assert stats["indexed_products"] == 2


def test_nvd_keyword_cache_ttl_expires_to_offline_mode():
    cache = NvdCache({})
    cache.keyword_put("nginx 1.21.6", ["CVE-2024-1000", "not-a-cve"])
    assert cache.keyword_get("nginx 1.21.6") == ["CVE-2024-1000"]

    cache.keyword["nginx 1.21.6"]["fetched_at"] = (
        datetime.now(timezone.utc) - timedelta(days=30)
    ).isoformat()
    assert cache.keyword_get("nginx 1.21.6", ttl_days=7) is None
    assert cache.stats()["keyword_entries"] == 1


def test_cve_collector_emits_findings_only_for_locally_verified_matches(tmp_path: Path):
    cache_path = tmp_path / "breadcrumb.nvd.json"
    cache_from_payload(
        _cache_payload(
            _cve(
                "CVE-2024-0001",
                "nginx",
                "nginx",
                start="1.20.0",
                end_excluding="1.22.0",
            )
        )
    ).save(cache_path)

    result = collect_cves(
        _context({"nvd_cache": str(cache_path)}),
        technologies=[{"product": "nginx", "version": "1.21.6"}],
        content="See also CVE-2020-1111 in the page footer.",
        target_url="https://127.0.0.1/",
    )
    assert result.stats["applicability_verified"] == 1
    assert result.stats["mode"] == "local-nvd"
    assert "CVE-2024-0001" in result.cves
    assert "CVE-2020-1111" in result.cves
    findings = extract_findings(result.output)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["tags"] == ["cve", "local-nvd", "applicability-verified"]

    nonmatching = collect_cves(
        _context({"nvd_cache": str(cache_path)}),
        technologies=[{"product": "nginx", "version": "1.24.0"}],
        content="",
        target_url="https://127.0.0.1/",
    )
    assert nonmatching.stats["applicability_verified"] == 0
    assert extract_findings(nonmatching.output) == []
    assert "Locally verified CVE applicability" not in nonmatching.output


def test_tech_detection_captures_versions_and_cdn_headers():
    observations = detect_technologies(
        [
            ("Server", "nginx/1.21.6"),
            ("X-Powered-By", "PHP/8.1.2"),
            ("X-AspNet-Version", "4.0.30319"),
            ("CF-RAY", "abc123"),
        ],
        (
            '<meta name="generator" content="WordPress 6.4.2">'
            '<div ng-version="17.1.0"></div>'
            '<script src="/assets/jquery-3.6.0.min.js"></script>'
        ),
    )
    pairs = {(item.product, item.version) for item in observations}
    assert ("nginx", "1.21.6") in pairs
    assert ("PHP", "8.1.2") in pairs
    assert ("ASP.NET", "4.0.30319") in pairs
    assert ("Cloudflare", "") in pairs
    assert ("WordPress", "6.4.2") in pairs
    assert ("Angular", "17.1.0") in pairs
    assert ("jQuery", "3.6.0") in pairs


class _DocsHandler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, content_type: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/openapi.json":
            self._send(
                json.dumps(
                    {
                        "openapi": "3.0.3",
                        "info": {"title": "Fixture API", "version": "1.0.0"},
                        "servers": [{"url": "/v1"}],
                        "paths": {
                            "/users": {"get": {}, "post": {}},
                            "/users/{id}": {"get": {"operationId": "getUser"}},
                        },
                    }
                ).encode(),
                "application/json",
            )
            return
        if self.path == "/v3/api-docs.yaml":
            self._send(
                (
                    "openapi: 3.0.3\n"
                    "info:\n"
                    "  title: YAML API\n"
                    "  version: 1.0.0\n"
                    "servers:\n"
                    "  - url: /\n"
                    "paths:\n"
                    "  /health:\n"
                    "    get: {}\n"
                ).encode(),
                "application/yaml",
            )
            return
        self._send(b"not found", "text/plain", status=404)

    def log_message(self, *args):  # noqa: ARG002
        pass


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_openapi_json_and_yaml_documents_are_parsed_but_not_requested():
    server, port = _serve(_DocsHandler)
    try:
        result = discover_api(
            _context(target=f"http://127.0.0.1:{port}/"),
            base_url=f"http://127.0.0.1:{port}",
            paths=["/openapi.json", "/v3/api-docs.yaml"],
        )
        assert result.stats["observed"] == 2
        assert result.stats["openapi_documents"] == 2
        assert result.stats["openapi_operations"] == 4
        assert result.stats["openapi_truncated"] is False
        assert any(summary["title"] == "Fixture API" for summary in result.openapi_documents)
        assert any(summary["title"] == "YAML API" for summary in result.openapi_documents)
        assert any(url.endswith("/v1/users") for url in result.inferred)
        assert any(url.endswith("/v1/users/:id") for url in result.inferred)
        assert any(url.endswith("/health") for url in result.inferred)
        assert not any("{id}" in url for url in result.inferred)
        assert "OpenAPI 3.0.3 document" in result.output
        assert "never requested" in result.output
        json_records = [
            json.loads(line)
            for line in result.output.splitlines()
            if line.startswith("{")
        ]
        assert all(record["api_type"] == "openapi" for record in json_records)
    finally:
        server.shutdown()
        server.server_close()


def test_graph_path_tree_groups_hosts_and_paths():
    entities = [
        SimpleNamespace(type="url", value="https://a.test/api/v1/users", meta={"host": "a.test"}),
        SimpleNamespace(type="url", value="https://a.test/api/v1/items", meta={"host": "a.test"}),
        SimpleNamespace(type="path", value="/login", meta={"host": "a.test"}),
        SimpleNamespace(type="url", value="https://b.test/docs", meta={"host": "b.test"}),
        SimpleNamespace(type="tech", value="nginx", meta={}),
    ]
    tree = path_tree(entities)
    assert tree["paths"] == 4
    assert tree["hosts"] == 2
    assert tree["truncated"] is False
    roots = {root["host"]: root for root in tree["roots"]}
    assert roots["a.test"]["count"] == 3
    assert roots["b.test"]["count"] == 1
    api = next(child for child in roots["a.test"]["children"] if child["label"] == "api")
    v1 = next(child for child in api["children"] if child["label"] == "v1")
    assert {child["label"] for child in v1["children"]} == {"users", "items"}
    assert path_tree(entities, limit=1)["truncated"] is True


def test_report_highlights_explain_verified_and_candidate_findings():
    findings = [
        SimpleNamespace(
            title="CVE applies to observed version: nginx 1.21.6 -- CVE-2024-0001",
            severity="critical",
            cvss="9.8",
            status="open",
            tags=["cve", "applicability-verified"],
        ),
        SimpleNamespace(
            title="Potential security issue in /.env",
            severity="high",
            cvss=None,
            status="open",
            tags=["candidate"],
        ),
        SimpleNamespace(
            title="Missing security header",
            severity="low",
            cvss=None,
            status="open",
            tags=[],
        ),
    ]
    counts = severity_counts(findings)
    assert counts == {"critical": 1, "high": 1, "low": 1}
    top = highlights(findings)
    assert [item["title"] for item in top] == [
        findings[0].title,
        findings[1].title,
        findings[2].title,
    ]
    assert top[0]["verified"] is True
    assert "verified" in top[0]["explanation"].lower()
    assert "manual review" in top[1]["explanation"].lower()
    assert "cpe/version-range" in risk_explanation(findings[0]).lower()
