"""Phase C: report templates, default-on redaction, review bundles, integrations."""

import io
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase-c-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"
os.environ.setdefault(
    "BREADCRUMB_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost"
)

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import cli, report_templates, reporting, review_bundle  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.ingest import IngestRequest, ingest  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, Finding, Program, Target  # noqa: E402

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

REPORT_DATE = "2026-11-10"
GENERATED_AT = "2026-11-10T12:00:00+00:00"
GOLDEN = Path(__file__).resolve().parent / "golden" / "phase_c"

NMAP_1 = """Starting Nmap 7.95
Nmap scan report for phase-c.test (192.0.2.10)
PORT     STATE SERVICE
443/tcp  open  https
"""

NMAP_2 = """Starting Nmap 7.95
Nmap scan report for phase-c.test (192.0.2.10)
PORT     STATE SERVICE
443/tcp  open  https
22/tcp   open  ssh
8080/tcp open  http-proxy
"""

SECRET = "AKIAIOSFODNN7EXAMPLE"
TEXT_SECRET = "supersecretvalue123"
URL_SECRET = "topsecret123"
BEARER = "abcdefghijklmnopqrstuvwxyz"
STRICT_HEX = "abcdef0123456789abcdef0123456789"

GOLDEN_VALUES = {
    "report_date": REPORT_DATE,
    "author": "Test Researcher",
    "client": "Acme",
    "engagement": "ENG-1",
    "executive_summary": "Executive summary body.",
    "business_context": "Business context body.",
    "recommendations": "Recommendations body.",
    "methodology": "Methodology body.",
    "include_inventory": True,
}


def _setup_program() -> int:
    """Create the Phase C fixture once, even when tests share a database."""
    with Session(engine) as session:
        existing = session.exec(
            select(Program).where(Program.name == "Phase C Reports")
        ).first()
        if existing is not None:
            return existing.id
        program = Program(
            name="Phase C Reports",
            platform="hackerone",
            scope_in="phase-c.test\n*.phase-c.test",
            scope_out="admin.phase-c.test",
            notes="Phase C fixture",
        )
        session.add(program)
        session.commit()
        session.refresh(program)
        target = Target(program_id=program.id, name="phase-c.test", kind="domain")
        session.add(target)
        session.commit()
        session.refresh(target)

        first = ingest(
            session,
            IngestRequest(
                text=NMAP_1,
                program_id=program.id,
                target_id=target.id,
                source="test",
                command="nmap -sV phase-c.test --token=supersecretvalue123",
            ),
        )
        second = ingest(
            session,
            IngestRequest(
                text=NMAP_2,
                program_id=program.id,
                target_id=target.id,
                source="test",
                command="nmap -sV phase-c.test",
            ),
        )
        paste_1, paste_2 = first.paste, second.paste
        paste_1.created_at = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)
        paste_2.created_at = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)
        session.add(paste_1)
        session.add(paste_2)

        session.add_all(
            [
                Entity(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    type="subdomain",
                    value="api.phase-c.test",
                    scope_status="in",
                    scope_reason="in_rule",
                    status_code=200,
                    tags=["prod"],
                ),
                Entity(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    type="endpoint",
                    value=f"https://api.phase-c.test/v1/users?token={URL_SECRET}",
                    scope_status="in",
                    scope_reason="in_rule",
                    status_code=200,
                ),
                Entity(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    type="tech",
                    value="nginx",
                    scope_status="in",
                    meta={"version": "1.25.0"},
                ),
                Entity(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    type="secret",
                    value=SECRET,
                    scope_status="in",
                    meta={"kind": "aws"},
                ),
            ]
        )
        session.add_all(
            [
                Finding(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    title="Exposed admin panel",
                    severity="high",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=(
                        "An unauthenticated admin panel exposes customer records.\n"
                        f"api_key={TEXT_SECRET}\n"
                        f"trace={STRICT_HEX}\n"
                        "<script>alert(1)</script>"
                    ),
                    steps=(
                        "1. Browse https://user:pass@phase-c.test/admin"
                        f"?token={URL_SECRET}\n"
                        "2. Observe the panel."
                    ),
                    impact="Full administrative access.",
                    evidence=(
                        "HTTP/1.1 200 OK\n"
                        f"Authorization: Bearer {BEARER}\n"
                        "Set-Cookie: sessionid=abcdef123456; HttpOnly\n"
                        "<script>alert(1)</script>"
                    ),
                    remediation="Require authentication and rotate credentials.",
                    tags=["verified", "cve", "CVE-2025-12345"],
                    rule_id="exposed-admin",
                    meta={
                        "url": "https://phase-c.test/admin",
                        "cwe": "CWE-306",
                        "references": "https://example.test/advisory",
                    },
                ),
                Finding(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    title="Project Falcon verbose error page acme-42",
                    severity="medium",
                    description="<img src=x onerror=alert(1)>",
                    steps="Request /error with an invalid parameter.",
                    impact="Internal paths and library versions are disclosed.",
                    evidence="Server: nginx/1.25.0\nX-Debug: true",
                    remediation="Disable debug output in production.",
                    tags=["verbose-errors"],
                ),
                Finding(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    title="Directory listing",
                    severity="low",
                    description="The /static/ directory lists its contents.",
                    steps="Browse /static/.",
                    impact="Files intended to be unlisted are discoverable.",
                    evidence="HTTP/1.1 200 OK\nIndex of /static/",
                    remediation="Disable autoindex.",
                    tags=["exposure"],
                ),
                Finding(
                    program_id=program.id,
                    target_id=target.id,
                    paste_id=paste_2.id,
                    title="False positive shell",
                    severity="critical",
                    status="wont-fix",
                    verdict="false-positive",
                    description="Analyst verified this is a test fixture.",
                    tags=["false-positive"],
                ),
            ]
        )
        session.commit()
        return program.id


PID = 0


def setup_module(module):  # noqa: ARG001
    """Create the fixture at test time, not during pytest collection.

    Pytest imports every test module before running the first test. Creating a
    program at import time would pollute the shared test database and break
    tests in earlier modules that expect an empty dashboard.
    """
    global PID
    PID = _setup_program()


def _session() -> Session:
    return Session(engine)


def _context(template: str = "hackerone", values=None):
    with _session() as session:
        return report_templates.build_context(
            session,
            PID,
            template,
            values if values is not None else dict(GOLDEN_VALUES),
            generated_at=GENERATED_AT,
        )


def _bundle(values=None, *, comments="", include_pdf=True):
    with _session() as session:
        return review_bundle.build_bundle(
            session,
            PID,
            "technical",
            values if values is not None else dict(GOLDEN_VALUES),
            comments=comments,
            include_pdf=include_pdf,
            generated_at=GENERATED_AT,
        )


# ------------------------------------------------------------- templates ----
def test_five_builtin_templates_and_typed_variables():
    templates = report_templates.list_templates()
    assert {template.id for template in templates} == {
        "hackerone",
        "executive",
        "technical",
        "recon",
        "change",
    }
    for template in templates:
        assert template.sections
        assert template.variables
        assert any(variable.kind == "choice" for variable in template.variables)
        assert all(variable.key for variable in template.variables)


def test_template_validation_errors():
    with pytest.raises(report_templates.TemplateError) as error:
        report_templates.get_template("does-not-exist")
    assert "template" in str(error.value).lower()

    with pytest.raises(report_templates.TemplateError) as error:
        report_templates.validate_variables("hackerone", {"max_findings": "0"})
    assert any("at least" in item for item in error.value.errors)

    with pytest.raises(report_templates.TemplateError):
        report_templates.validate_variables("hackerone", {"report_date": "11/10/2026"})

    with pytest.raises(report_templates.TemplateError):
        report_templates.validate_variables(
            "hackerone", {"confidentiality": "top-secret"}
        )

    with pytest.raises(report_templates.TemplateError) as error:
        report_templates.validate_variables(
            "hackerone", {"unknown": "x"}, strict_unknown=True
        )
    assert any("unknown" in item for item in error.value.errors)

    with pytest.raises(report_templates.TemplateError):
        _context("hackerone", {"redaction_rules": "regex:[invalid=value"})

    with pytest.raises(report_templates.TemplateError):
        _context("technical", {"finding_id": "99999999"})


def test_golden_reports_are_stable():
    for template_id in report_templates.TEMPLATE_IDS:
        text = report_templates.render_markdown(_context(template_id))
        path = GOLDEN / f"{template_id}.md"
        if os.environ.get("UPDATE_GOLDEN") == "1":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        assert path.exists(), f"missing golden file: {path}"
        assert text == path.read_text(encoding="utf-8"), template_id


def test_hostile_text_is_escaped_in_html_markdown_and_pdf():
    context = _context("technical")
    html = report_templates.render_html(context)
    markdown = report_templates.render_markdown(context)
    pdf = report_templates.render_pdf(context)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "<script>alert(1)</script>" not in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    assert pdf.startswith(b"%PDF")
    assert b"<script>" not in pdf


def test_default_redaction_masks_secrets_in_every_format():
    context = _context("technical")
    markdown = report_templates.render_markdown(context)
    html = report_templates.render_html(context)
    payload = json.loads(report_templates.render_json(context))

    for text in (markdown, html, json.dumps(payload)):
        assert TEXT_SECRET not in text
        assert URL_SECRET not in text
        assert BEARER not in text
        assert SECRET not in text
    assert "[redacted]" in markdown
    assert payload["redaction"]["enabled"] is True
    assert "redaction_rules" not in payload["variables"]
    assert payload["summary"]["total_findings"] == 3

    # Entity values live in the inventory template. Sensitive entities keep a
    # short prefix for operator recognition but are still masked by default.
    recon = _context("recon")
    recon_markdown = report_templates.render_markdown(recon)
    recon_html = report_templates.render_html(recon)
    recon_payload = json.loads(report_templates.render_json(recon))
    for text in (recon_markdown, recon_html, json.dumps(recon_payload)):
        assert SECRET not in text
        assert URL_SECRET not in text
    assert "[masked]" in recon_markdown


def test_reveal_is_explicit_and_disables_masking():
    context = _context("technical", {**GOLDEN_VALUES, "reveal": True})
    markdown = report_templates.render_markdown(context)
    assert TEXT_SECRET in markdown
    assert URL_SECRET in markdown
    assert BEARER in markdown

    recon = _context("recon", {**GOLDEN_VALUES, "reveal": True})
    recon_markdown = report_templates.render_markdown(recon)
    assert SECRET in recon_markdown
    assert URL_SECRET in recon_markdown


def test_custom_redaction_rules_are_additive_and_not_echoed():
    context = _context(
        "technical",
        {
            **GOLDEN_VALUES,
            "redaction_rules": "literal:Project Falcon=Project X\n"
            "regex:acme-[0-9]+=acme-REDACTED",
        },
    )
    markdown = report_templates.render_markdown(context)
    payload = json.loads(report_templates.render_json(context))
    serialized = json.dumps(payload)

    assert "Project Falcon" not in markdown
    assert "Project X" in markdown
    assert "acme-42" not in markdown
    assert "acme-REDACTED" in markdown
    assert "Project Falcon" not in serialized
    assert "literal:Project Falcon" not in serialized
    assert payload["redaction"]["custom_rules"] == 2
    assert TEXT_SECRET not in serialized


def test_strict_profile_masks_long_opaque_values():
    default = report_templates.render_markdown(_context("technical"))
    strict = report_templates.render_markdown(
        _context("technical", {**GOLDEN_VALUES, "redaction_profile": "strict"})
    )
    assert STRICT_HEX in default
    assert STRICT_HEX not in strict
    assert "[redacted-hex]" in strict


def test_default_reporting_exports_redact_findings():
    with _session() as session:
        masked = json.dumps(reporting.to_dict(session, PID))
        revealed = json.dumps(reporting.to_dict(session, PID, mask=False))
    assert TEXT_SECRET not in masked
    assert SECRET not in masked
    assert TEXT_SECRET in revealed
    assert SECRET in revealed


# ---------------------------------------------------------------- bundle ----
def test_review_bundle_build_verify_and_contents():
    data, manifest = _bundle(
        comments=f"Please check api_key={TEXT_SECRET} before sending.",
        include_pdf=True,
    )
    assert manifest["captures_included"] == 2
    assert manifest["comments"]["included"] is True
    assert manifest["file_count"] >= 9

    result = review_bundle.verify_bundle(data)
    assert result["valid"], [c for c in result["checks"] if not c["ok"]]
    assert result["warnings"] == []
    assert result["summary"]["template"] == "technical"

    archive = zipfile.ZipFile(io.BytesIO(data))
    names = set(archive.namelist())
    assert {
        "report.html",
        "report.md",
        "report.json",
        "report.pdf",
        "manifest.json",
        "manifest.sha256",
        "SHA256SUMS",
        "README.txt",
        "comments.md",
    } <= names
    evidence = sorted(name for name in names if name.startswith("evidence/"))
    assert len(evidence) == 2
    assert "verify-bundle" in archive.read("README.txt").decode()
    comments = archive.read("comments.md").decode()
    assert TEXT_SECRET not in comments
    assert "[redacted]" in comments
    assert TEXT_SECRET.encode() not in archive.read("report.md")
    for name in evidence:
        nested = json.loads(archive.read(name))
        assert nested["manifest_version"] >= 2
        assert nested["input"]["raw_included"] is False
        assert b"Starting Nmap" not in archive.read(name)
        assert review_bundle.verify_manifest_data(nested)["valid"]


def test_tampered_bundle_fails_verification():
    data, _ = _bundle(include_pdf=False)
    source = zipfile.ZipFile(io.BytesIO(data))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            content = source.read(info.filename)
            if info.filename == "report.md":
                content = content + b"\nTAMPERED\n"
            target.writestr(info, content)
    result = review_bundle.verify_bundle(output.getvalue())
    assert result["valid"] is False
    assert any(
        check["name"] == "file_hash:report.md" and not check["ok"]
        for check in result["checks"]
    )


def test_bundle_verifier_rejects_path_traversal():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../escape.txt", "nope")
        archive.writestr("manifest.json", "{}")
        archive.writestr("manifest.sha256", "0  manifest.json\n")
    result = review_bundle.verify_bundle(output.getvalue())
    assert result["valid"] is False
    assert any(
        check["name"] == "path_safety" and not check["ok"]
        for check in result["checks"]
    )


def test_reveal_bundle_verifies_with_a_warning():
    data, manifest = _bundle(
        {**GOLDEN_VALUES, "reveal": True}, include_pdf=False
    )
    assert manifest["report"]["reveal"] is True
    result = review_bundle.verify_bundle(data)
    assert result["valid"] is True
    assert result["warnings"]


# ------------------------------------------------------------ integrations ----
DD_ALLOWED = {
    "title",
    "severity",
    "description",
    "date",
    "cwe",
    "cve",
    "cvssv3",
    "cvssv3_score",
    "mitigation",
    "impact",
    "steps_to_reproduce",
    "severity_justification",
    "references",
    "active",
    "verified",
    "false_p",
    "duplicate",
    "out_of_scope",
    "risk_accepted",
    "under_review",
    "numerical_severity",
    "line",
    "file_path",
    "component_name",
    "component_version",
    "static_finding",
    "dynamic_finding",
    "unique_id_from_tool",
    "vuln_id_from_tool",
    "tags",
    "endpoints",
    "service",
}


def test_defectdojo_export_shape_and_redaction():
    with _session() as session:
        data = reporting.to_defectdojo(session, PID)
        internal = reporting.to_defectdojo(session, PID, include_triaged=True)
    assert data["type"] == "Generic Findings Import"
    assert len(data["findings"]) == 3
    assert len(internal["findings"]) == 4
    serialized = json.dumps(data)
    assert TEXT_SECRET not in serialized
    assert URL_SECRET not in serialized
    assert BEARER not in serialized
    assert SECRET not in serialized
    for item in data["findings"]:
        assert {"title", "severity", "description"} <= set(item)
        assert set(item) <= DD_ALLOWED
        assert item["description"].strip()
        assert item["severity"] in {"Critical", "High", "Medium", "Low", "Info"}
        assert item["numerical_severity"] in {"S0", "S1", "S2", "S3", "S4"}
        assert item["unique_id_from_tool"].startswith("breadcrumb-")
        assert isinstance(item.get("endpoints", []), list)
        assert all(isinstance(endpoint, str) for endpoint in item.get("endpoints", []))
    high = next(item for item in data["findings"] if item["severity"] == "High")
    assert high["numerical_severity"] == "S1"
    assert high["verified"] is True
    assert high["cve"] == "CVE-2025-12345"
    false_positive = next(
        item for item in internal["findings"] if item["false_p"] is True
    )
    assert false_positive["title"] == "False positive shell"


def test_ghostwriter_and_dradis_exports():
    with _session() as session:
        ghost = reporting.to_ghostwriter(session, PID)
        dradis = reporting.to_dradis_markdown(session, PID)
        dradis_internal = reporting.to_dradis_markdown(
            session, PID, include_triaged=True
        )
    assert ghost["format"] == "breadcrumb.ghostwriter"
    assert len(ghost["findings"]) == 3
    assert {item["severity"] for item in ghost["findings"]} <= {
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    }
    assert "[redacted]" not in json.dumps(ghost) or TEXT_SECRET not in json.dumps(ghost)
    assert TEXT_SECRET not in json.dumps(ghost)
    assert TEXT_SECRET not in dradis
    assert dradis.count("#[Title]#") >= 4
    assert "#[Severity]#" in dradis
    assert "False positive shell" not in dradis
    assert "False positive shell" in dradis_internal


# ----------------------------------------------------------------- routes ----
def test_report_studio_page_and_preview():
    page = client.get(f"/programs/{PID}/reports")
    assert page.status_code == 200
    assert "Report studio" in page.text
    assert "HackerOne submission" in page.text
    assert "Pentest executive summary" in page.text
    assert "Review workflow" in page.text

    page = client.get(
        f"/programs/{PID}/reports",
        params={"template": "executive", "submitted": "1", "report_date": REPORT_DATE},
    )
    assert page.status_code == 200
    assert "Pentest executive summary" in page.text

    preview = client.get(
        f"/programs/{PID}/reports/preview",
        params={"template": "recon", "report_date": REPORT_DATE, "include_inventory": "1"},
    )
    assert preview.status_code == 200
    assert "Attack-surface inventory" in preview.text
    assert "<script>alert(1)</script>" not in preview.text

    bad = client.get(
        f"/programs/{PID}/reports/preview",
        params={"template": "hackerone", "max_findings": "0", "submitted": "1"},
    )
    assert bad.status_code == 400
    assert "Report could not be rendered" in bad.text


def test_template_downloads_and_errors():
    for fmt, content_type in (
        ("md", "text/markdown"),
        ("html", "text/html"),
        ("json", "application/json"),
        ("pdf", "application/pdf"),
    ):
        response = client.get(
            f"/reports/{PID}/templates/hackerone.{fmt}",
            params={"report_date": REPORT_DATE},
        )
        assert response.status_code == 200, fmt
        assert response.headers["content-type"].startswith(content_type)
        assert "attachment" in response.headers["content-disposition"]
        assert response.content
    assert client.get(
        f"/reports/{PID}/templates/hackerone.pdf",
        params={"report_date": REPORT_DATE},
    ).content.startswith(b"%PDF")

    assert client.get(f"/reports/{PID}/templates/nope.md").status_code == 400
    assert (
        client.get(
            f"/reports/{PID}/templates/hackerone.md",
            params={"max_findings": "0", "submitted": "1"},
        ).status_code
        == 400
    )


def test_bundle_route_and_integration_routes():
    response = client.post(
        f"/reports/{PID}/bundle",
        data={
            "csrf_token": client.cookies["bc_csrf"],
            "template": "technical",
            "report_date": REPORT_DATE,
            "submitted": "1",
            "include_scope": "1",
            "include_targets": "1",
            "include_findings": "1",
            "include_evidence": "1",
            "comments": f"Review api_key={TEXT_SECRET}",
        },
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["x-breadcrumb-bundle-captures"] == "2"
    result = review_bundle.verify_bundle(response.content)
    assert result["valid"], [c for c in result["checks"] if not c["ok"]]

    for route in ("defectdojo", "ghostwriter"):
        response = client.get(f"/reports/{PID}/{route}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert TEXT_SECRET not in response.text
        assert SECRET not in response.text
    dradis = client.get(f"/reports/{PID}/dradis.md")
    assert dradis.status_code == 200
    assert dradis.headers["content-type"].startswith("text/plain")
    assert "#[Title]#" in dradis.text
    assert TEXT_SECRET not in dradis.text


def test_report_templates_api():
    response = client.get("/api/v1/report-templates")
    assert response.status_code == 200
    data = response.json()
    assert data["version"]
    assert {item["id"] for item in data["templates"]} == {
        "hackerone",
        "executive",
        "technical",
        "recon",
        "change",
    }
    hackerone = next(item for item in data["templates"] if item["id"] == "hackerone")
    assert any(variable["key"] == "redaction_rules" for variable in hackerone["variables"])


# -------------------------------------------------------------------- CLI ----
def test_cli_render_bundle_and_verify(tmp_path):
    markdown = tmp_path / "recon.md"
    assert (
        cli.main(
            [
                "render",
                str(PID),
                "--template",
                "recon",
                "--format",
                "md",
                "-o",
                str(markdown),
                "--var",
                f"report_date={REPORT_DATE}",
                "--var",
                "include_inventory=1",
            ]
        )
        == 0
    )
    assert "Attack-surface inventory" in markdown.read_text()

    pdf = tmp_path / "report.pdf"
    assert (
        cli.main(
            [
                "render",
                str(PID),
                "--template",
                "hackerone",
                "--format",
                "pdf",
                "-o",
                str(pdf),
                "--var",
                f"report_date={REPORT_DATE}",
            ]
        )
        == 0
    )
    assert pdf.read_bytes().startswith(b"%PDF")

    comments = tmp_path / "comments.md"
    comments.write_text(f"Check api_key={TEXT_SECRET}", encoding="utf-8")
    bundle = tmp_path / "review.zip"
    assert (
        cli.main(
            [
                "bundle",
                str(PID),
                "--template",
                "technical",
                "-o",
                str(bundle),
                "--comments",
                str(comments),
                "--var",
                f"report_date={REPORT_DATE}",
            ]
        )
        == 0
    )
    assert review_bundle.verify_bundle_file(bundle)["valid"] is True
    assert cli.main(["verify-bundle", str(bundle)]) == 0
    assert cli.main(["verify-bundle", str(bundle), "--json"]) == 0


def test_cli_exports_and_template_listing(capsys):
    assert cli.main(["export", str(PID), "--format", "defectdojo"]) == 0
    output = capsys.readouterr().out
    assert "Generic Findings Import" in output
    assert TEXT_SECRET not in output
    assert cli.main(["export", str(PID), "--format", "ghostwriter"]) == 0
    assert "breadcrumb.ghostwriter" in capsys.readouterr().out
    assert cli.main(["export", str(PID), "--format", "dradis"]) == 0
    assert "#[Title]#" in capsys.readouterr().out
    assert cli.main(["report-templates"]) == 0
    listing = capsys.readouterr().out
    for template_id in report_templates.TEMPLATE_IDS:
        assert template_id in listing
