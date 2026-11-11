"""Docs-tested-by-CI: the README and UI must not rot.

Guards the "stale docs" complaint class: if a parser, runner, or export
route exists, it must be documented/linked, and documented examples must work.
"""

import os
import re
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-docs-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")

from app import runners  # noqa: E402
from app.parsers import REGISTRY, load_all  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _readme() -> str:
    with open(os.path.join(ROOT, "README.md")) as f:
        return f.read()


def test_every_parser_documented():
    load_all()
    readme = _readme().lower()
    names = sorted({p.name for p in REGISTRY})
    assert len(names) >= 10, f"parser registry looks gutted: {names}"
    missing = [n for n in names if n.replace("_", "-") not in readme and n not in readme]
    assert not missing, f"parsers missing from README: {missing}"


def test_runner_catalog_valid():
    seen = set()
    for runner in runners.list_runners():
        assert re.match(r"^[a-z0-9][a-z0-9-]{1,40}$", runner.id), runner.id
        assert runner.id not in seen, f"duplicate runner id: {runner.id}"
        seen.add(runner.id)
        assert runner.example.strip(), f"runner {runner.id} has no example command"
        binary = runners.runner_binary(runner)
        assert binary and " " not in binary and "/" not in binary, (
            f"runner {runner.id} has an unusable binary token: {binary!r}")
    assert len(seen) >= 20, "runner catalog shrank unexpectedly"


def test_export_routes_exist():
    from app.main import app

    paths = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        if path:
            paths.add(path)
    for expected in (
        "/reports/{program_id}/md",
        "/reports/{program_id}/json",
        "/reports/{program_id}/csv",
        "/reports/{program_id}/html",
        "/reports/{program_id}/h1",
        "/reports/{program_id}/sarif",
        "/reports/{program_id}/targets.txt",
        "/api/v1/pastes",
        "/api/v1/pastes/{paste_id}/report",
        "/api/v1/pastes/{paste_id}/manifest",
        "/api/v1/entities",
        "/api/v1/entities/bulk",
        "/api/v1/programs",
        "/api/v1/jobs",
        "/api/v1/findings",
        "/api/v1/gate",
        "/api/v1/backup",
        "/api/v1/verify",
        "/api/v1/doctor",
        "/api/v1/headers",
        "/pastes/{paste_id}/manifest.json",
        "/pastes/{paste_id}/manifest.md",
        "/demo",
        "/programs/{program_id}/changes",
        "/programs/{program_id}/scope",
        "/programs/{program_id}/graph",
        "/programs/{program_id}/reports",
        "/programs/{program_id}/reports/preview",
        "/reports/{program_id}/templates/{template_id}.{fmt}",
        "/reports/{program_id}/bundle",
        "/reports/{program_id}/defectdojo",
        "/reports/{program_id}/ghostwriter",
        "/reports/{program_id}/dradis.md",
        "/api/v1/report-templates",
        "/ledger",
        "/ledger/asset",
        "/ledger/export",
        "/api/v1/ledger",
        "/api/v1/ledger/asset",
        "/diff",
        "/api/v1/diff",
        "/runners",
        "/pipeline",
        "/headers",
        "/jobs/{job_id}",
        "/settings/notify",
    ):
        assert expected in paths, f"documented route missing: {expected}"


def test_readme_api_example_shape():
    """The exact JSON shape shown in README must be accepted."""
    from fastapi.testclient import TestClient

    from app.db import init_db
    from app.main import app as fastapi_app

    init_db()
    client = TestClient(fastapi_app)
    r = client.post("/api/v1/pastes", json={"text": "readme.example.com", "program_id": None})
    assert r.status_code == 201, r.text
    body = r.json()
    assert {"paste_id", "entities", "parsers", "errors", "warning"} <= set(body)
