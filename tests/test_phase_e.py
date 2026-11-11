"""Phase E: screenshot evidence, manifest import, reports, bundles, adapters."""

import base64
import hashlib
import io
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase-e-")
os.environ.setdefault("BREADCRUMB_DB_PATH", os.path.join(_tmp, "test.db"))
os.environ["BREADCRUMB_ARTIFACT_DIR"] = os.path.join(_tmp, "artifacts")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"
os.environ.setdefault(
    "BREADCRUMB_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost"
)

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import artifacts, cli, report_templates, review_bundle  # noqa: E402
from app.db import SCHEMA_VERSION, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, EvidenceArtifact, Finding, Program, Target  # noqa: E402

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

REPORT_DATE = "2026-11-11"
URL_SECRET = "supersecretvalue123"

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAQAAAADCAIAAAA7ljmRAAAAFElEQVR4nGOUqzjBAANMDE"
    "gAhQMAMogBZGgQu3YAAAAASUVORK5CYII="
)
JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHR"
    "ofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgy"
    "IRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj"
    "L/wAARCAADAAQDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL"
    "/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0f"
    "AkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1"
    "dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1N"
    "XW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQF"
    "BgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRob"
    "HBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVm"
    "Z2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExc"
    "bHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDFooor7E+R"
    "P//Z"
)
GIF = base64.b64decode(
    "R0lGODdhBAADAIEAAB54yAAAAAAAAAAAACwAAAAABAADAAAICAABCBxIUGBAADs="
)
WEBP = base64.b64decode(
    "UklGRjoAAABXRUJQVlA4IC4AAAAQAgCdASoEAAMAAUAmJaACdLoB+AH4AAPIAP7tTd/9QW"
    "Csy/ew/+jBcBwPeEAA"
)

_counter = 0


def _program(name: str | None = None) -> int:
    global _counter
    _counter += 1
    unique = name or f"phase-e-{_counter}-{os.getpid()}"
    with Session(engine) as session:
        existing = session.exec(select(Program).where(Program.name == unique)).first()
        if existing is not None:
            return existing.id
        program = Program(name=unique)
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def _target(pid: int, name: str = "app.phase-e.test") -> int:
    with Session(engine) as session:
        existing = session.exec(
            select(Target).where(Target.program_id == pid).where(Target.name == name)
        ).first()
        if existing is not None:
            return existing.id
        target = Target(program_id=pid, name=name, kind="domain")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _finding(pid: int, target_id: int | None = None, title: str = "Phase E finding") -> int:
    with Session(engine) as session:
        finding = Finding(program_id=pid, target_id=target_id, title=title, severity="high")
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _import(pid: int, data: bytes = PNG, **kwargs):
    with Session(engine) as session:
        return artifacts.import_image(session, data, program_id=pid, **kwargs)


# ------------------------------------------------------------------ schema ---
def test_schema_8_has_content_addressed_artifacts():
    assert SCHEMA_VERSION == 8
    with Session(engine) as session:
        assert session.exec(select(EvidenceArtifact)).all() is not None


def test_all_supported_raster_formats_report_dimensions():
    for data, kind, media_type in (
        (PNG, "png", "image/png"),
        (JPEG, "jpeg", "image/jpeg"),
        (GIF, "gif", "image/gif"),
        (WEBP, "webp", "image/webp"),
    ):
        info = artifacts.inspect_image(data)
        assert info.kind == kind
        assert info.media_type == media_type
        assert (info.width, info.height) == (4, 3)


def test_non_raster_and_corrupt_images_are_rejected():
    for data in (
        b"",
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        b"%PDF-1.7\nnot an image",
        b"plain text screenshot",
        PNG[:20],
    ):
        with pytest.raises(artifacts.ArtifactError):
            artifacts.inspect_image(data)

    oversized = b"x" * (artifacts.MAX_IMAGE_BYTES + 1)
    with pytest.raises(artifacts.ArtifactError) as error:
        artifacts.inspect_image(oversized)
    assert "too large" in str(error.value)

    huge = bytearray(PNG)
    huge[16:20] = (50_000).to_bytes(4, "big")
    with pytest.raises(artifacts.ArtifactError) as error:
        artifacts.inspect_image(bytes(huge))
    assert "dimensions" in str(error.value)


# ---------------------------------------------------------- import + links ---
def test_import_preserves_hash_links_target_entity_and_deduplicates():
    pid = _program()
    target_id = _target(pid)
    with Session(engine) as session:
        entity = Entity(
            program_id=pid,
            target_id=target_id,
            type="domain",
            value="app.phase-e.test",
            normalized="app.phase-e.test",
        )
        session.add(entity)
        session.commit()
        session.refresh(entity)

    with Session(engine) as session:
        artifact, duplicate = artifacts.import_image(
            session,
            PNG,
            program_id=pid,
            filename="<evil>.png",
            source="manual",
            source_url="https://app.phase-e.test/login",
            captured_at="2026-11-11T10:00:00Z",
            meta={"title": "Login page"},
        )
        assert duplicate is False
        assert artifact.program_id == pid
        assert artifact.target_id == target_id
        assert artifact.entity_id == entity.id
        assert artifact.filename == "<evil>.png"
        assert artifact.sha256 == hashlib.sha256(PNG).hexdigest()
        assert artifact.bytes == len(PNG)
        assert (artifact.width, artifact.height) == (4, 3)
        assert artifact.captured_at is not None
        assert artifact.captured_at.tzinfo is not None
        assert artifact.meta["title"] == "Login page"

        verification = artifacts.verify_artifact(artifact)
        assert verification["exists"] is True
        assert verification["hash_ok"] is True
        assert verification["size_ok"] is True
        assert artifacts.artifact_bytes(artifact) == PNG

        same, duplicate = artifacts.import_image(
            session,
            PNG,
            program_id=pid,
            filename="another.png",
            source="manual",
            source_url="https://app.phase-e.test/login",
        )
        assert duplicate is True
        assert same.id == artifact.id

        finding_id = _finding(pid, target_id)
        linked, duplicate = artifacts.import_image(
            session,
            PNG,
            program_id=pid,
            finding_id=finding_id,
            source_url="https://app.phase-e.test/login",
        )
        assert duplicate is False
        assert linked.id != artifact.id
        assert linked.storage_path == artifact.storage_path
        assert linked.sha256 == artifact.sha256

        listed = artifacts.list_artifacts(session, program_id=pid)
        assert listed["total"] == 2
        assert listed["count"] == 2

        first_delete = artifacts.delete_artifact(session, artifact)
        assert first_delete["bytes_removed"] is False
        assert first_delete["remaining_rows"] == 1
        assert artifacts.artifact_path(linked).is_file()

        second_delete = artifacts.delete_artifact(session, linked)
        assert second_delete["bytes_removed"] is True
        assert second_delete["remaining_rows"] == 0
        assert not artifacts.artifact_path(linked).exists()
        assert artifacts.list_artifacts(session, program_id=pid)["total"] == 0


def test_import_never_creates_targets_and_checks_program_links():
    pid = _program()
    with Session(engine) as session:
        assert session.exec(select(Target).where(Target.program_id == pid)).all() == []
        artifact, _ = artifacts.import_image(
            session,
            GIF,
            program_id=pid,
            source_url="https://not-a-target.phase-e.test/",
        )
        assert artifact.target_id is None
        assert session.exec(select(Target).where(Target.program_id == pid)).all() == []

    other = _program()
    other_target = _target(other, "other.phase-e.test")
    with Session(engine) as session:
        with pytest.raises(artifacts.ArtifactError):
            artifacts.import_image(
                session,
                PNG,
                program_id=pid,
                target_id=other_target,
            )
        with pytest.raises(artifacts.ArtifactError):
            artifacts.import_image(session, PNG, program_id=999_999_999)


def test_artifact_paths_reject_traversal_and_hash_mismatch():
    bad = EvidenceArtifact(program_id=1, sha256="a" * 64, storage_path="../escape.png")
    with pytest.raises(artifacts.ArtifactError):
        artifacts.artifact_path(bad)

    pid = _program()
    artifact, _ = _import(pid, PNG)
    with Session(engine) as session:
        row = session.get(EvidenceArtifact, artifact.id)
        path = artifacts.artifact_path(row)
        original = path.read_bytes()
        try:
            changed = bytearray(original)
            changed[-1] ^= 0xFF
            path.write_bytes(bytes(changed))
            verification = artifacts.verify_artifact(row)
            assert verification["exists"] is True
            assert verification["hash_ok"] is False
            with pytest.raises(artifacts.ArtifactError):
                artifacts.artifact_bytes(row)
        finally:
            path.write_bytes(original)

        path.unlink()
        missing = artifacts.verify_artifact(row)
        assert missing["exists"] is False
        assert missing["error"]
        assert artifacts.delete_artifact(session, row)["remaining_rows"] == 0


# --------------------------------------------------------------- manifests ---
def test_manifest_imports_all_formats_and_reports_bad_rows(tmp_path):
    pid = _program()
    target_id = _target(pid, "manifest.phase-e.test")
    (tmp_path / "shot.png").write_bytes(PNG)
    (tmp_path / "shot.gif").write_bytes(GIF)

    json_manifest = tmp_path / "eyewitness.json"
    json_manifest.write_text(
        json.dumps(
            [
                {
                    "url": "https://manifest.phase-e.test/login",
                    "screenshot": "shot.png",
                    "status": "200 OK",
                    "title": "Login",
                    "captured_at": "2026-11-11T10:00:00Z",
                },
                {
                    "url": "https://manifest.phase-e.test/missing",
                    "screenshot": "missing.png",
                },
            ]
        ),
        encoding="utf-8",
    )
    with Session(engine) as session:
        result = artifacts.import_manifest(
            session, json_manifest, program_id=pid, target_id=target_id
        )
    assert result["format"] == "json"
    assert result["imported"] == 1
    assert result["skipped"] == 1
    assert any("image not found" in item["error"] for item in result["errors"])
    imported = result["artifacts"][0]
    assert imported["target_id"] == target_id
    assert imported["meta"]["status_code"] == 200
    assert imported["captured_at"].startswith("2026-11-11T10:00:00")

    jsonl_manifest = tmp_path / "gowitness.jsonl"
    jsonl_manifest.write_text(
        json.dumps(
            {
                "final_url": "https://manifest.phase-e.test/admin",
                "filename": "shot.gif",
                "perception_hash": "abc123",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with Session(engine) as session:
        result = artifacts.import_manifest(session, jsonl_manifest, program_id=pid)
        assert result["format"] == "jsonl"
        assert result["source"] == "gowitness"
        assert result["imported"] == 1
        assert result["artifacts"][0]["meta"]["perception_hash"] == "abc123"

    csv_manifest = tmp_path / "eyewitness.csv"
    csv_manifest.write_text(
        "URL,Screenshot,Title\n"
        "https://manifest.phase-e.test/csv,shot.png,CSV page\n",
        encoding="utf-8",
    )
    with Session(engine) as session:
        result = artifacts.import_manifest(session, csv_manifest, program_id=pid)
        assert result["format"] == "csv"
        assert result["source"] == "eyewitness"
        assert result["imported"] == 1
        assert result["artifacts"][0]["meta"]["title"] == "CSV page"

    # The JSON catch-all ("results" list) is also supported.
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "url": "https://manifest.phase-e.test/wrapped",
                        "filename": "shot.gif",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with Session(engine) as session:
        result = artifacts.import_manifest(session, wrapped, program_id=pid)
        assert result["imported"] == 1

    # Re-importing the same manifest is idempotent per source URL.
    with Session(engine) as session:
        result = artifacts.import_manifest(session, json_manifest, program_id=pid)
        assert result["imported"] == 0
        assert result["duplicates"] == 1


def test_manifest_import_never_creates_targets(tmp_path):
    pid = _program()
    (tmp_path / "shot.png").write_bytes(PNG)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [{"url": "https://unknown.phase-e.test/", "screenshot": "shot.png"}]
        ),
        encoding="utf-8",
    )
    with Session(engine) as session:
        result = artifacts.import_manifest(session, manifest, program_id=pid)
        assert result["imported"] == 1
        assert result["artifacts"][0]["target_id"] is None
        assert session.exec(select(Target).where(Target.program_id == pid)).all() == []


def test_artifact_manifest_lists_metadata_without_inline_bytes():
    pid = _program()
    artifact, _ = _import(pid, PNG, source_url="https://manifest-only.phase-e.test/")
    with Session(engine) as session:
        payload = artifacts.artifact_manifest(session, program_id=pid)
    assert payload["artifact_manifest_version"] == 1
    assert payload["generator"]["schema_version"] == SCHEMA_VERSION
    assert payload["count"] == 1
    item = payload["artifacts"][0]
    assert item["id"] == artifact.id
    assert item["sha256"] == artifact.sha256
    assert item["storage_path"] == artifact.storage_path
    assert "content_url" not in item
    assert "data_uri" not in json.dumps(payload)


# ----------------------------------------------------------------- reports ---
def _report_program() -> tuple[int, int, int]:
    pid = _program()
    target_id = _target(pid, "report.phase-e.test")
    finding_id = _finding(pid, target_id, "Report screenshot finding")
    with Session(engine) as session:
        artifact, _ = artifacts.import_image(
            session,
            PNG,
            program_id=pid,
            source_url=(
                "https://report.phase-e.test/login?"
                f"token={URL_SECRET}&next=<script>alert(1)</script>"
            ),
            finding_id=finding_id,
        )
        assert artifact.finding_id == finding_id
    return pid, target_id, finding_id


def test_report_screenshots_escape_html_and_never_inline_json_bytes():
    pid, _, _ = _report_program()
    with Session(engine) as session:
        context = report_templates.build_context(
            session,
            pid,
            "technical",
            {"report_date": REPORT_DATE, "include_screenshots": True},
        )
        html = report_templates.render_html(context)
        markdown = report_templates.render_markdown(context)
        payload = json.loads(report_templates.render_json(context))
        pdf = report_templates.render_pdf(context)

    assert "data:image/png;base64," in html
    assert "Screenshots are included as captured" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert URL_SECRET not in html
    assert URL_SECRET not in markdown
    assert "Screenshots" in markdown
    assert "pixels" in markdown
    assert payload["screenshots"]["total"] == 1
    screenshot = payload["screenshots"]["items"][0]
    assert "data_uri" not in screenshot
    assert screenshot["sha256"] == hashlib.sha256(PNG).hexdigest()
    assert pdf.startswith(b"%PDF")

    with Session(engine) as session:
        default_context = report_templates.build_context(
            session, pid, "technical", {"report_date": REPORT_DATE}
        )
        default_html = report_templates.render_html(default_context)
    assert "data:image/png;base64," not in default_html
    screenshot_variable = next(
        variable
        for variable in report_templates.get_template("hackerone").variables
        if variable.key == "include_screenshots"
    )
    assert screenshot_variable.default is False


# ----------------------------------------------------------------- bundles ---
def test_review_bundle_includes_and_verifies_screenshots():
    pid, _, _ = _report_program()
    with Session(engine) as session:
        data, manifest = review_bundle.build_bundle(
            session,
            pid,
            "technical",
            {"report_date": REPORT_DATE},
            include_screenshots=True,
        )
    result = review_bundle.verify_bundle(data)
    assert result["valid"], [check for check in result["checks"] if not check["ok"]]
    assert manifest["screenshots"]["included"] is True
    assert manifest["screenshots"]["count"] == 1
    assert manifest["screenshots"]["pixels_are_not_redacted"] is True
    assert any("pixels" in warning for warning in result["warnings"])
    entry = manifest["screenshots"]["items"][0]
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.read(entry["path"]) == PNG
        assert b"data:image/png;base64," in archive.read("report.html")

    with Session(engine) as session:
        plain, plain_manifest = review_bundle.build_bundle(
            session, pid, "technical", {"report_date": REPORT_DATE}
        )
    assert plain_manifest["screenshots"]["included"] is False
    assert plain_manifest["screenshots"]["count"] == 0
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        assert not [
            name for name in archive.namelist() if name.startswith("screenshots/")
        ]
    assert review_bundle.verify_bundle(plain)["valid"] is True


def test_bundle_verifier_rejects_tampered_screenshot_bytes():
    pid, _, _ = _report_program()
    with Session(engine) as session:
        data, manifest = review_bundle.build_bundle(
            session,
            pid,
            "technical",
            {"report_date": REPORT_DATE},
            include_screenshots=True,
        )
    entry = manifest["screenshots"]["items"][0]
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target:
            for info in source.infolist():
                payload = source.read(info.filename)
                if info.filename == entry["path"]:
                    payload = b"tampered screenshot bytes"
                target.writestr(info, payload)
    result = review_bundle.verify_bundle(buffer.getvalue())
    assert result["valid"] is False
    assert any(
        not check["ok"] and check["name"].startswith("screenshot_hash")
        for check in result["checks"]
    )


# -------------------------------------------------------------- web routes ---
def test_artifact_routes_upload_content_filter_and_delete():
    pid = _program()
    target_id = _target(pid, "routes.phase-e.test")
    finding_id = _finding(pid, target_id, "Route screenshot")

    response = client.post(
        "/api/v1/artifacts",
        files={"upload": ("shot.png", PNG, "image/png")},
        data={
            "program_id": str(pid),
            "target_id": str(target_id),
            "finding_id": str(finding_id),
            "source_url": "https://routes.phase-e.test/login",
            "source": "test",
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["duplicate"] is False
    artifact_id = payload["artifact"]["id"]
    assert payload["artifact"]["sha256"] == hashlib.sha256(PNG).hexdigest()

    duplicate = client.post(
        "/api/v1/artifacts",
        files={"upload": ("shot.png", PNG, "image/png")},
        data={
            "program_id": str(pid),
            "target_id": str(target_id),
            "finding_id": str(finding_id),
            "source_url": "https://routes.phase-e.test/login",
            "source": "test",
        },
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["artifact"]["id"] == artifact_id

    listed = client.get("/api/v1/artifacts", params={"program_id": pid})
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["artifacts"][0]["id"] == artifact_id

    detail = client.get(f"/api/v1/artifacts/{artifact_id}")
    assert detail.status_code == 200
    assert detail.json()["verification"]["hash_ok"] is True

    content = client.get(f"/api/v1/artifacts/{artifact_id}/content")
    assert content.status_code == 200
    assert content.content == PNG
    assert content.headers["content-type"].startswith("image/png")
    assert content.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in content.headers["content-security-policy"]

    manifest = client.get("/api/v1/artifacts/manifest", params={"program_id": pid})
    assert manifest.status_code == 200
    assert manifest.json()["count"] == 1

    invalid = client.post(
        "/api/v1/artifacts",
        files={"upload": ("evil.svg", b"<svg onload=alert(1)>", "image/svg+xml")},
        data={"program_id": str(pid)},
    )
    assert invalid.status_code == 400
    assert "unsupported image format" in invalid.text

    page = client.get("/artifacts", params={"program_id": pid})
    assert page.status_code == 200
    assert "Screenshot gallery" in page.text
    assert "Screenshots" in page.text

    detail_page = client.get(f"/artifacts/{artifact_id}")
    assert detail_page.status_code == 200
    assert payload["artifact"]["sha256"] in detail_page.text
    assert "Hash verified" in detail_page.text

    program_page = client.get(f"/programs/{pid}")
    assert program_page.status_code == 200
    assert "Screenshots" in program_page.text

    deleted = client.delete(f"/api/v1/artifacts/{artifact_id}")
    assert deleted.status_code == 200
    assert deleted.json()["id"] == artifact_id
    assert client.get(f"/api/v1/artifacts/{artifact_id}").status_code == 404


def test_manifest_api_and_upload_ui():
    pid = _program()
    target_id = _target(pid, "manifestapi.phase-e.test")
    tmp = Path(tempfile.mkdtemp(prefix="breadcrumb-phase-e-manifest-"))
    (tmp / "shot.png").write_bytes(PNG)
    manifest = tmp / "manifest.json"
    manifest.write_text(
        json.dumps(
            [{"url": "https://manifestapi.phase-e.test/", "screenshot": "shot.png"}]
        ),
        encoding="utf-8",
    )
    response = client.post(
        "/api/v1/artifacts/import",
        json={
            "manifest_path": str(manifest),
            "program_id": pid,
            "target_id": target_id,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["imported"] == 1
    assert response.json()["artifacts"][0]["target_id"] == target_id

    upload = client.post(
        "/artifacts/upload",
        files={"upload": ("ui.png", JPEG, "image/png")},
        data={
            "csrf_token": client.cookies["bc_csrf"],
            "program_id": str(pid),
            "source_url": "https://manifestapi.phase-e.test/ui",
            "source": "upload",
        },
        follow_redirects=False,
    )
    assert upload.status_code == 303
    assert "/artifacts/" in upload.headers["location"]


def test_tool_adapter_diagnostics(monkeypatch):
    from app.collect import tools as tools_mod

    monkeypatch.setattr(tools_mod, "probe_version", lambda *args, **kwargs: "test 1.0")
    response = client.get("/api/v1/tools")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 10
    assert data["version"]
    assert all("scope_mode" in item for item in data["tools"])
    assert all("strict_policy" in item for item in data["tools"])


# -------------------------------------------------------------------- CLI ---
def test_cli_artifacts_and_screenshot_bundle(tmp_path):
    pid = _program()
    target_id = _target(pid, "cli.phase-e.test")
    finding_id = _finding(pid, target_id, "CLI screenshot")
    with Session(engine) as session:
        artifact, _ = artifacts.import_image(
            session,
            PNG,
            program_id=pid,
            target_id=target_id,
            finding_id=finding_id,
            source_url="https://cli.phase-e.test/login",
        )
        artifact_id = artifact.id

    assert cli.main(["artifacts", "list", "--program", str(pid), "--json"]) == 0
    assert cli.main(["artifacts", "show", str(artifact_id), "--json"]) == 0
    exported = tmp_path / "exported.png"
    assert (
        cli.main(
            ["artifacts", "export", str(artifact_id), "-o", str(exported)]
        )
        == 0
    )
    assert exported.read_bytes() == PNG

    manifest_path = tmp_path / "manifest.json"
    assert (
        cli.main(
            [
                "artifacts",
                "manifest",
                "--program",
                str(pid),
                "-o",
                str(manifest_path),
            ]
        )
        == 0
    )
    payload = json.loads(manifest_path.read_text())
    assert payload["count"] == 1

    bundle_path = tmp_path / "review.zip"
    assert (
        cli.main(
            [
                "bundle",
                str(pid),
                "--template",
                "technical",
                "--var",
                f"report_date={REPORT_DATE}",
                "--include-screenshots",
                "-o",
                str(bundle_path),
            ]
        )
        == 0
    )
    result = review_bundle.verify_bundle_file(bundle_path)
    assert result["valid"], [check for check in result["checks"] if not check["ok"]]
    assert result["summary"]["screenshots"] == 1

    image_dir = tmp_path / "images"
    image_dir.mkdir()
    (image_dir / "cli.png").write_bytes(PNG)
    image_manifest = image_dir / "manifest.json"
    image_manifest.write_text(
        json.dumps(
            [{"url": "https://cli-import.phase-e.test/", "screenshot": "cli.png"}]
        ),
        encoding="utf-8",
    )
    assert (
        cli.main(
            [
                "artifacts",
                "import",
                str(image_manifest),
                "--program",
                str(pid),
                "--json",
            ]
        )
        == 0
    )
    assert cli.main(["artifacts", "delete", str(artifact_id), "--yes"]) == 0
