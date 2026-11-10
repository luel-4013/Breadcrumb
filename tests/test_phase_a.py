"""Phase A: parser contract, import trust, manifest, doctor, demo, pagination."""

import json
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase-a-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import doctor  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.demo import run_demo  # noqa: E402
from app.ingest import IngestRequest, ingest  # noqa: E402
from app.main import app  # noqa: E402
from app.manifest import (  # noqa: E402
    build_manifest,
    manifest_json,
    verify_manifest_data,
    verify_paste_manifest,
)
from app.models import Entity, Paste, Program  # noqa: E402
from app.parsers import REGISTRY, analyze_detailed, load_all  # noqa: E402
from app.parsers.base import ParseResult  # noqa: E402

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

NMAP = """Starting Nmap 7.95
Nmap scan report for web.acme.test (10.0.0.5)
PORT    STATE SERVICE
443/tcp open  https
22/tcp  open  ssh
"""

BBOT = "\n".join(
    [
        '{"type":"DNS_NAME","data":"app.example.test","resolved_hosts":["192.0.2.9"]}',
        '{"type":"OPEN_TCP_PORT","data":"app.example.test:443"}',
        '{"type":"TECHNOLOGY","data":"nginx","host":"app.example.test"}',
        '{"type":"EMAIL_ADDRESS","data":"security@example.test"}',
        '{"type":"FINDING","data":"Exposed admin panel","severity":"high",'
        '"host":"app.example.test","url":"https://app.example.test/admin"}',
    ]
) + "\n"


def _program(name: str) -> int:
    r = client.post("/programs", data={"name": name}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rstrip("/").split("/")[-1])


def _ingest(pid: int, text: str = NMAP, **kwargs):
    with Session(engine) as session:
        return ingest(
            session,
            IngestRequest(text=text, program_id=pid, source="test", **kwargs),
        )


# --------------------------------------------------------------- contract ----
def test_every_parser_implements_the_contract():
    load_all()
    assert len(REGISTRY) >= 20
    for parser in REGISTRY:
        result = parser.parse_detailed("this is not any known tool output !!!")
        assert isinstance(result, ParseResult), parser.name
        assert result.parser_version, parser.name
        assert isinstance(result.entities, list), parser.name
        assert isinstance(result.issues, list), parser.name


def test_bbot_parser_and_findings():
    result = analyze_detailed(BBOT)
    assert "bbot" in result.parsers
    assert not result.errors
    types = {entity.type for entity in result.entities}
    assert {"subdomain", "ip", "port", "tech", "email"} <= types
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "high"
    assert result.completeness == 1.0


def test_jsonl_malformed_rows_are_reported_not_swallowed():
    result = analyze_detailed('{"url":"https://a.test","status_code":200,"host":"192.0.2.1"}\n{"broken"\n')
    assert "httpx" in result.parsers
    assert result.skipped_rows >= 1
    assert any(issue.code == "skipped_row" for issue in result.issues)
    assert result.completeness < 1.0


# ---------------------------------------------------------- import report ----
def test_import_report_explains_success_and_zero():
    pid = _program("Report")
    result = _ingest(pid)
    assert result.entities > 0
    assert result.completeness == 1.0
    report = result.report
    assert report["parsed_entities"] > 0
    assert report["parser_versions"]
    assert report["warning"] == ""

    empty = _ingest(pid, text="just some prose, nothing parseable !!!!")
    assert empty.entities == 0
    assert empty.warning == "no entities detected"
    assert empty.report["hint"]
    assert any(issue.get("code") == "no_parser" for issue in empty.report["issues"])


def test_reimport_consolidation_is_not_reported_as_empty():
    pid = _program("Consolidate")
    first = _ingest(pid)
    second = _ingest(pid, capture_key=f"consolidate-{first.paste.id}")
    assert second.report["parsed_entities"] > 0
    assert second.report["entities"] == 0
    assert second.report["consolidated"] is True
    assert second.report["warning"] == ""
    assert "merged" in second.report["hint"]


def test_api_report_and_manifest_routes():
    pid = _program("Routes")
    result = _ingest(pid)
    paste_id = result.paste.id
    report = client.get(f"/api/v1/pastes/{paste_id}/report")
    assert report.status_code == 200
    assert report.json()["paste_id"] == paste_id

    manifest = client.get(f"/api/v1/pastes/{paste_id}/manifest")
    assert manifest.status_code == 200
    body = manifest.json()
    assert body["manifest_version"] == 2
    assert body["capture"]["id"] == paste_id
    assert body["output"]["entities"] > 0

    md = client.get(f"/pastes/{paste_id}/manifest.md")
    assert md.status_code == 200
    assert "Breadcrumb evidence manifest" in md.text


def test_manifest_round_trip_and_redaction():
    pid = _program("Manifest")
    result = _ingest(
        pid,
        command="httpx --api-key=SECRET123 -json",
        source_meta={"filename": "scan.jsonl", "password": "hunter2"},
    )
    with Session(engine) as session:
        paste = session.get(Paste, result.paste.id)
        manifest = build_manifest(session, paste, redact=True)
        raw = paste.raw
        assert "SECRET123" not in manifest_json(manifest)
        assert "hunter2" not in manifest_json(manifest)
        assert "[redacted]" in manifest_json(manifest)
        assert manifest["chain"]["link_verifiable"] is True
        assert manifest["parser"]["completeness"] == 1.0

        offline = verify_manifest_data(manifest, raw=raw)
        assert offline["valid"], offline
        assert not verify_manifest_data(manifest, raw=raw + "\ntampered")["valid"]
        assert verify_paste_manifest(session, paste)["valid"]


def test_manifest_redacts_secret_entity_values():
    pid = _program("Secret manifest")
    result = _ingest(pid, text="api_key=AKIAABCDEFGHIJKLMNOP\n")
    with Session(engine) as session:
        paste = session.get(Paste, result.paste.id)
        manifest = build_manifest(session, paste, redact=True)
        assert "AKIAABCDEFGHIJKLMNOP" not in manifest_json(manifest)


# --------------------------------------------------------------- limits -----
def test_import_truncation_is_visible():
    pid = _program("Truncate")
    r = client.post(
        "/api/v1/pastes",
        json={"text": NMAP, "program_id": pid, "max_entities": 2},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["entities"] <= 2
    assert body["completeness"] < 1.0
    report = client.get(body["report_url"]).json()
    assert report["truncated_entities"] > 0
    assert any(issue.get("code") == "truncated" for issue in report["issues"])


def test_entity_api_pagination():
    pid = _program("Page")
    _ingest(pid)
    first = client.get("/api/v1/entities", params={"program_id": pid, "limit": 1}).json()
    assert first["count"] == 1
    assert first["total"] > 1
    assert first["next_offset"] == 1
    second = client.get(
        "/api/v1/entities", params={"program_id": pid, "limit": 1, "offset": 1}
    ).json()
    assert second["count"] == 1
    assert second["entities"][0]["id"] != first["entities"][0]["id"]


# ----------------------------------------------------------- doctor/demo -----
def test_doctor_reports_actionable_checks():
    from app.db import SCHEMA_VERSION

    report = doctor.run_checks()
    assert report["schema_version"] == SCHEMA_VERSION
    names = {check["name"] for check in report["checks"]}
    assert {"python", "sqlite", "database_integrity", "schema_version", "parsers"} <= names
    assert all(check["status"] in {"ok", "warn", "fail"} for check in report["checks"])
    assert "Breadcrumb doctor" in doctor.format_report(report)


def test_demo_is_idempotent_and_produces_a_report():
    with Session(engine) as session:
        first = run_demo(session)
    with Session(engine) as session:
        second = run_demo(session)
    assert first["program_id"] == second["program_id"]
    assert first["entities"] > 0
    assert first["findings"] > 0
    assert all(capture["duplicate"] for capture in second["captures"])
    assert client.get(first["report_url"]).status_code == 200
    with Session(engine) as session:
        program = session.get(Program, first["program_id"])
        assert program is not None
        assert len(session.exec(select(Entity).where(Entity.program_id == program.id)).all()) > 0
