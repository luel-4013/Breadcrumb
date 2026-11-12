"""Breadcrumb test suite: `pytest` (needs requirements-dev.txt).

Uses an isolated temp SQLite database so the real breadcrumb.db is untouched.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-test-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

NMAP = """Starting Nmap 7.94
Nmap scan report for web.acme.test (10.0.0.5)
PORT    STATE SERVICE
443/tcp open  https
22/tcp  open  ssh
"""


def _program(name="Acme"):
    r = client.post("/programs", data={"name": name}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r.headers["location"].rstrip("/").split("/")[-1]


def test_dashboard_empty():
    r = client.get("/")
    assert r.status_code == 200
    assert "No programs yet" in r.text


def test_ingest_and_filters():
    pid = _program()
    r = client.post(
        "/paste",
        data={"text": NMAP, "program_id": pid},
        follow_redirects=False,
    )
    assert r.status_code == 303

    r = client.get("/entities")
    assert r.status_code == 200
    assert "results" in r.text

    r = client.get("/entities", params={"q": "type:port"})
    assert r.status_code == 200
    assert "2 results" in r.text

    r = client.get("/entities", params={"q": "scope:in"})
    assert r.status_code == 200

    r = client.get("/entities", params={"q": "program:acme"})
    assert r.status_code == 200
    assert "0 results" not in r.text


def test_file_upload_and_api_ingest():
    pid = _program("Upload")
    r = client.post(
        "/paste",
        data={"text": "", "program_id": pid},
        files={"upload": ("scan.txt", NMAP.encode())},
    )
    assert r.status_code == 200
    assert "web.acme.test" in r.text

    r = client.post(
        "/api/v1/pastes",
        json={"text": "api-host.example.com", "program_id": int(pid)},
    )
    assert r.status_code == 201
    assert r.json()["entities"] >= 1

    r = client.get("/api/v1/entities", params={"program_id": pid})
    assert r.status_code == 200
    assert r.json()["count"] >= 1

    r = client.get("/api/v1/programs")
    assert any(p["name"] == "Upload" for p in r.json()["programs"])


def test_ignore_and_changes():
    pid = _program("Changes")
    client.post("/paste", data={"text": "one.example.com", "program_id": pid})
    client.post("/paste", data={"text": "one.example.com\ntwo.example.com", "program_id": pid})

    r = client.get(f"/programs/{pid}/changes")
    assert r.status_code == 200
    assert "two.example.com" in r.text

    rows = client.get("/api/v1/entities", params={"program_id": int(pid)}).json()["entities"]
    eid = rows[0]["id"]
    r = client.post(f"/entities/{eid}/ignore", follow_redirects=False)
    assert r.status_code == 303
    after = client.get("/api/v1/entities", params={"program_id": int(pid)}).json()["entities"]
    assert {e["id"] for e in after} == {e["id"] for e in rows} - {eid}


def test_exports_and_masking():
    pid = _program("Exports")
    client.post(
        "/paste",
        data={"text": "AKIAIOSFODNN7EXAMPLE secret leak", "program_id": pid},
    )
    for route in ("csv", "targets.txt", "h1", "json", "md", "html"):
        r = client.get(f"/reports/{pid}/{route}")
        assert r.status_code == 200, route
    masked = client.get(f"/reports/{pid}/json").json()
    assert any("masked" in e["value"] for e in masked["entities"] if e["type"] == "secret")
    revealed = client.get(f"/reports/{pid}/json", params={"reveal": "1"}).json()
    assert any(e["value"] == "AKIAIOSFODNN7EXAMPLE" for e in revealed["entities"])


def test_findings_workflow():
    pid = _program("Findings")
    client.post(
        f"/programs/{pid}/findings",
        data={"title": "Weak TLS", "severity": "high"},
        follow_redirects=False,
    )
    from sqlmodel import Session, select

    from app.db import engine
    from app.models import Finding

    with Session(engine) as s:
        fid = s.exec(select(Finding.id).where(Finding.program_id == int(pid))).first()
    r = client.post(f"/findings/{fid}/status", data={"status": "resolved"},
                    follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as s:
        assert s.get(Finding, fid).status == "resolved"


def test_runners_and_jobs():
    r = client.get("/runners")
    assert r.status_code == 200
    assert "nuclei" in r.text.lower()

    r = client.post(
        "/api/v1/jobs",
        json={"runner": "nmap", "target": "10.0.0.0/24"},
    )
    assert r.status_code == 202
    jid = r.json()["job_id"]

    r = client.post(f"/api/v1/jobs/{jid}/status", json={"status": "running"})
    assert r.json()["status"] == "running"

    r = client.post("/api/v1/jobs", json={"runner": "nope"})
    assert r.status_code == 400


def test_backup_download():
    r = client.get("/api/v1/backup")
    assert r.status_code == 200
    assert len(r.content) > 1024


def test_faulty_parser_is_reported_not_fatal():
    from app.parsers import REGISTRY, analyze
    from app.parsers.base import Parser

    class Boom(Parser):
        name = "boom-test"
        description = "always explodes"

        def detect(self, text):
            return 5.0

        def parse(self, text):
            raise RuntimeError("synthetic failure")

    REGISTRY.append(Boom())
    try:
        entities, rels, parsers, errors = analyze("hello.example.com\n")
        assert any(e["parser"] == "boom-test" for e in errors), errors
        assert "boom-test" in parsers  # matched, even though it failed
        assert any(e.type in ("domain", "subdomain") for e in entities), (
            "healthy parsers must still produce entities")
    finally:
        REGISTRY[:] = [p for p in REGISTRY if p.name != "boom-test"]


def test_ingest_truncation_and_summary():
    import app.main as main_mod

    old_cap = main_mod.MAX_ENTITIES_PER_PASTE
    main_mod.MAX_ENTITIES_PER_PASTE = 5
    try:
        pid = _program("Truncate")
        body = "\n".join(f"host-{i}.example.com" for i in range(30))
        r = client.post("/paste", data={"text": body, "program_id": pid},
                        follow_redirects=False)
        assert r.status_code == 303
        location = r.headers["location"]
        assert "msg=" in location  # ingest summary toast, never silent
        paste_id = location.split("/pastes/")[1].split("?")[0]
        page = client.get(f"/pastes/{paste_id}").text
        assert "parser issue" in page  # truncation notice is visible
    finally:
        main_mod.MAX_ENTITIES_PER_PASTE = old_cap


def test_zero_entity_paste_warns():
    pid = _program("Empty")
    r = client.post("/paste", data={"text": "just some prose, nothing parseable !!!!",
                                    "program_id": pid}, follow_redirects=False)
    assert r.status_code == 303
    assert "no+entities" in r.headers["location"] or "no%20entities" in r.headers["location"]
    paste_id = r.headers["location"].split("/pastes/")[1].split("?")[0]
    assert "No entities detected" in client.get(f"/pastes/{paste_id}").text
    api = client.post("/api/v1/pastes", json={"text": "just some prose !!!"})
    assert api.json()["warning"] == "no entities detected"


def test_header_generator():
    from app import headers_gen

    for family in headers_gen.FAMILY_IDS:
        used, headers = headers_gen.build_headers(family)
        assert used == family
        ua = headers_gen.user_agent_of(headers)
        assert ua, family
    _, headers = headers_gen.build_headers("random")
    assert headers_gen.user_agent_of(headers)

    try:
        headers_gen.build_headers("nope")
        raise AssertionError("should have raised")
    except ValueError:
        pass

    custom = headers_gen.parse_custom_headers("X-Api: 1\n# comment\nCookie: a=b\n")
    assert custom == {"X-Api": "1", "Cookie": "a=b"}
    for bad in ("no-colon", "Bad Name!: x", "X-Empty:"):
        try:
            headers_gen.parse_custom_headers(bad)
            raise AssertionError(f"should have raised for {bad!r}")
        except ValueError:
            pass

    merged = headers_gen.merge_headers({"User-Agent": "a", "Accept": "*/*"},
                                        {"user-agent": "b", "X-New": "1"})
    assert merged["user-agent"] == "b" and "User-Agent" not in merged
    assert "-H 'X-New: 1'" in headers_gen.to_curl_args(merged)


def test_header_profiles():
    r = client.post(
        "/headers",
        data={"name": "chrome-win", "family": "chrome-windows",
              "custom": "X-Test: yes"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    profiles = client.get("/api/v1/headers").json()["profiles"]
    prof = next(p for p in profiles if p["name"] == "chrome-win")
    assert "Chrome" in prof["user_agent"]
    assert prof["headers"]["X-Test"] == "yes"
    assert "-H" in prof["curl"]

    old_ua = prof["user_agent"]
    client.post(f"/headers/{prof['id']}/randomize", follow_redirects=False)
    again = client.get(f"/api/v1/headers/{prof['id']}").json()
    assert again["headers"]["X-Test"] == "yes"  # custom override survives
    assert again["user_agent"]  # (may rarely equal old_ua by chance)

    r = client.post("/headers", data={"name": "bad", "custom": "no-colon"})
    assert r.status_code == 400

    client.post(f"/headers/{prof['id']}/delete", follow_redirects=False)
    assert all(p["name"] != "chrome-win"
               for p in client.get("/api/v1/headers").json()["profiles"])

    r = client.post("/api/v1/headers", json={"name": "api-prof", "family": "curl-minimal"})
    assert r.status_code == 201
    assert r.json()["user_agent"].startswith("curl/")


def test_custom_runners():
    r = client.post(
        "/runners/custom",
        data={"runner_id": "myfuzzer", "label": "MyFuzzer",
              "example": "myfuzzer -u https://t/FUZZ"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert "myfuzzer" in client.get("/runners").text

    r = client.post("/api/v1/jobs", json={"runner": "myfuzzer", "target": "https://t/"})
    assert r.status_code == 202

    r = client.post("/runners/custom", data={"runner_id": "Bad ID!"})
    assert r.status_code == 400
    r = client.post("/runners/custom", data={"runner_id": "nmap"})
    assert r.status_code == 400  # collides with built-in

    r = client.get("/runners/custom/999999/verify", follow_redirects=False)
    assert r.status_code == 404

    from sqlmodel import Session, select

    from app.db import engine
    from app.models import CustomRunner

    with Session(engine) as s:
        cid = s.exec(select(CustomRunner.id).where(CustomRunner.runner_id == "myfuzzer")).first()
    r = client.get(f"/runners/custom/{cid}/verify", follow_redirects=False)
    assert r.status_code == 303
    assert "msg=" in r.headers["location"]

    client.post(f"/runners/custom/{cid}/delete", follow_redirects=False)
    r = client.post("/api/v1/jobs", json={"runner": "myfuzzer", "target": "x"})
    assert r.status_code == 400  # no longer a known runner


def test_runner_catalog_toggle_and_validate():
    from app import runners

    assert len(runners.list_runners()) >= 20
    assert runners.runner_binary(runners.get_runner("hakrawler")) == "hakrawler"

    # deactivate nuclei -> jobs must refuse it
    r = client.post("/runners/toggle", data={"runner_id": "nuclei"},
                    follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/api/v1/jobs", json={"runner": "nuclei", "target": "x"})
    assert r.status_code == 400
    assert "nuclei" not in client.get("/api/v1/jobs").json().get("known", "")
    # reactivate
    client.post("/runners/toggle", data={"runner_id": "nuclei", "enabled": "on"},
                follow_redirects=False)
    r = client.post("/api/v1/jobs", json={"runner": "nuclei", "target": "x"})
    assert r.status_code == 202

    r = client.post("/runners/toggle", data={"runner_id": "nope", "enabled": "on"})
    assert r.status_code == 400

    from sqlmodel import Session

    from app.db import engine

    with Session(engine) as s:
        report = runners.validate_custom("bad id!", "", s)
        assert any(lvl == "err" for lvl, _ in report)
        report = runners.validate_custom("fine-tool", "fine-tool -u x", s)
        assert any(lvl == "ok" for lvl, _ in report)


def test_job_with_header_profile():
    pid = _program("JobHeaders")
    prof = client.post("/api/v1/headers", json={"name": "job-ua"}).json()
    r = client.post(
        "/api/v1/jobs",
        json={"runner": "httpx", "target": "t", "program_id": int(pid),
              "header_profile_id": prof["id"]},
    )
    assert r.status_code == 202
    jobs = client.get("/api/v1/jobs").json()["jobs"]
    match = next(j for j in jobs if j["header_profile_id"] == prof["id"])
    assert match["header_profile_name"] == "job-ua"

    # usage is visible on the headers page and profile name on the jobs table
    page = client.get("/headers").text
    assert "In use by" in page
    assert f"job #{match['id']}" in page
    runners_page = client.get("/runners").text
    assert "job-ua" in runners_page

    r = client.post("/api/v1/jobs",
                    json={"runner": "httpx", "header_profile_id": 999999})
    assert r.status_code == 400


# ---------------- Phase 0: local boundaries, chain, backup ----------------


def test_host_header_allowlist():
    assert client.get("/health").status_code == 200
    assert client.get("/health", headers={"host": "localhost:8787"}).status_code == 200
    assert client.get("/health", headers={"host": "evil.example"}).status_code == 400
    assert client.get("/health", headers={"host": "127.0.0.1:8787"}).status_code == 200


def test_csrf_blocks_cross_site_form_posts():
    fresh = TestClient(app)
    r = fresh.post("/programs", data={"name": "csrf-no-cookie"}, follow_redirects=False)
    assert r.status_code == 403
    fresh.get("/health")
    token = fresh.cookies["bc_csrf"]

    r = fresh.post("/programs", data={"name": "csrf-no-token"}, follow_redirects=False)
    assert r.status_code == 403

    # A token minted for another browser session is not accepted.
    r = fresh.post(
        "/programs",
        data={"name": "csrf-other-client", "csrf_token": client.cookies["bc_csrf"]},
        follow_redirects=False,
    )
    assert r.status_code == 403

    r = fresh.post(
        "/programs",
        data={"name": "csrf-ok", "csrf_token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303

    r = fresh.post(
        "/programs",
        data={"name": "csrf-origin", "csrf_token": token},
        headers={"origin": "http://evil.example"},
        follow_redirects=False,
    )
    assert r.status_code == 403

    r = fresh.post(
        "/programs",
        data={"name": "csrf-header"},
        headers={"x-csrf-token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_backup_snapshot_is_consistent():
    import sqlite3

    from sqlmodel import Session, func, select

    from app.db import backup_database, engine
    from app.models import Paste

    dest = os.path.join(_tmp, "backup-consistency.db")
    backup_database(dest)
    conn = sqlite3.connect(dest)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"program", "entity", "paste"} <= tables
        backed_up = conn.execute("SELECT COUNT(*) FROM paste").fetchone()[0]
    finally:
        conn.close()
    with Session(engine) as session:
        live = session.exec(select(func.count()).select_from(Paste)).one()
    assert backed_up == live


def test_restore_rejects_non_breadcrumb_database():
    import sqlite3

    bad = os.path.join(_tmp, "not-breadcrumb.db")
    conn = sqlite3.connect(bad)
    conn.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    with open(bad, "rb") as fh:
        raw = fh.read()
    r = client.post(
        "/backup/restore",
        files={"upload": ("not-breadcrumb.db", raw, "application/x-sqlite3")},
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "Breadcrumb" in r.text


def test_backup_restore_roundtrip():
    from sqlmodel import Session, func, select

    from app.db import backup_database, engine, restore_database
    from app.models import Paste

    with Session(engine) as session:
        before = session.exec(select(func.count()).select_from(Paste)).one()
    src = os.path.join(_tmp, "roundtrip.db")
    backup_database(src)
    restore_database(src)
    with Session(engine) as session:
        after = session.exec(select(func.count()).select_from(Paste)).one()
    assert after == before
    assert client.get("/api/v1/verify").json()["valid"] is True


def test_llm_model_roles_and_fit_estimates():
    from app import llm

    info = llm.model_roles("qwen3-4b-instruct-2507")
    assert "reports" in info["roles"]
    assert "Report compilation" in info["role_labels"]
    gemma = llm.model_roles("google/gemma-4-12b-qat")
    assert "writing" in gemma["roles"]
    assert "12B" in gemma["note"]

    gpu = {"name": "GTX 1650", "total_mb": 4096, "free_mb": 3719,
           "total_gb": 4.0, "free_gb": 3.63}
    assert llm.estimate_fit(2_899_221_600, gpu)["level"] == "fits"
    assert llm.estimate_fit(3_300_000_000, gpu)["level"] == "tight"
    assert llm.estimate_fit(6_980_000_000, gpu)["level"] == "too-large"


def test_llm_detailed_listing_merges_metadata(monkeypatch):
    from app import llm

    provider = {
        "id": "lmstudio",
        "label": "LM Studio (local)",
        "base_url": "http://127.0.0.1:1234/v1",
    }
    monkeypatch.setattr(
        llm, "_request", lambda *args, **kwargs: {"data": [{"id": "qwen3-4b-instruct-2507"}]}
    )
    monkeypatch.setattr(llm, "gpu_info", lambda: {
        "name": "GTX 1650", "total_mb": 4096, "free_mb": 3719,
        "total_gb": 4.0, "free_gb": 3.63,
    })
    monkeypatch.setattr(llm, "_lmstudio_native_metadata", lambda provider, timeout=5.0: {
        "qwen3-4b-instruct-2507": {
            "id": "qwen3-4b-instruct-2507",
            "state": "not-loaded",
            "max_context_length": 262144,
            "capabilities": ["tool_use"],
        }
    })
    monkeypatch.setattr(llm, "_lmstudio_cli_metadata", lambda: {
        "qwen3-4b-instruct-2507": {
            "modelKey": "qwen3-4b-instruct-2507",
            "displayName": "Qwen3 4B Instruct 2507 UD",
            "publisher": "unsloth",
            "paramsString": "4B",
            "sizeBytes": 2_899_221_600,
            "quantization": {"name": "Q5_K_XL"},
        }
    })
    monkeypatch.setattr(llm, "_loaded_lmstudio_models", lambda: {})
    monkeypatch.setattr(llm, "_lms_path", lambda: "/usr/bin/lms")

    result = llm.list_models_detailed(provider, timeout=1)
    assert result["ok"] is True
    assert result["count"] == 1
    model = result["models"][0]
    assert model["fit"]["level"] == "fits"
    assert model["size_label"] == "2.90 GB"
    assert "reports" in model["roles"]
    assert result["suggestions"]


def test_llm_detailed_listing_offline(monkeypatch):
    import urllib.error

    from app import llm

    def refuse(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(llm, "_request", refuse)
    monkeypatch.setattr(llm, "gpu_info", lambda: {})
    result = llm.list_models_detailed(
        {"id": "lmstudio", "base_url": "http://127.0.0.1:1234/v1"}, timeout=1
    )
    assert result["ok"] is False
    assert result["reachable"] is False
    assert "cannot reach" in result["error"]


def test_llm_chat_detailed_flags_reasoning_only(monkeypatch):
    from app import llm

    def fake_request(method, url, provider, payload=None, timeout=30.0):
        return {
            "choices": [{
                "message": {"content": "", "reasoning_content": "thinking..."},
                "finish_reason": "length",
            }],
            "usage": {"completion_tokens": 12, "prompt_tokens": 3},
        }

    monkeypatch.setattr(llm, "_request", fake_request)
    detail = llm.chat_detailed(
        {"base_url": "http://127.0.0.1:1234/v1"},
        "model",
        [{"role": "user", "content": "hi"}],
        timeout=1,
    )
    assert detail["reasoning_only"] is True
    assert detail["empty_content"] is True
    assert detail["content"] == ""
    assert detail["completion_tokens"] == 12


def test_llm_test_model_reports_reasoning_only(monkeypatch):
    from app import llm

    monkeypatch.setattr(llm, "chat_detailed", lambda *args, **kwargs: {
        "content": "",
        "reasoning": "thinking...",
        "finish_reason": "length",
        "completion_tokens": 12,
        "prompt_tokens": 3,
        "elapsed_s": 1.5,
        "tok_per_s": 8.0,
        "empty_content": True,
        "reasoning_only": True,
    })
    monkeypatch.setattr(llm, "_loaded_lmstudio_models", lambda: {})
    result = llm.test_model(
        {"id": "lmstudio", "base_url": "http://127.0.0.1:1234/v1"},
        "model",
        timeout=1,
    )
    assert result["ok"] is True
    assert result["usable"] is False
    assert result["verdict"] == "reasoning-only"
    assert "reasoning" in result["error"]


def test_settings_has_model_picker():
    r = client.get("/settings")
    assert r.status_code == 200
    assert 'id="modelPicker"' in r.text
    assert 'id="modelRefresh"' in r.text
    assert 'id="route_fast"' in r.text
    assert 'name="csrf-token"' in r.text
    assert 'id="modelNotes"' in r.text
    assert "Qwen3-4B-Instruct-2507" in r.text
    assert "Which model for which task" in r.text
    assert "Future PC guide" in r.text


def test_local_model_notes_have_actionable_fields():
    from app import llm

    notes = llm.LOCAL_MODEL_NOTES
    assert notes["reviewed"] and notes["hardware"]
    ids = {model["id"] for model in notes["models"]}
    assert "qwen3-4b-instruct-2507" in ids
    assert "qwen3-coder-30b-a3b-instruct" in ids
    for model in notes["models"]:
        assert model["name"] and model["size"] and model["best_for"]
        assert model["fit"] in {"fits", "tight", "too-large", "unknown"}
    assert {task["task"] for task in notes["tasks"]}
    assert notes["future_tiers"] and notes["buying_note"]


def test_api_llm_models_detailed(monkeypatch):
    from app import llm

    config = {
        "active_provider": "lmstudio",
        "providers": [
            {"id": "lmstudio", "label": "LM Studio", "base_url": "http://127.0.0.1:1234/v1"}
        ],
    }
    monkeypatch.setattr(llm, "load_config", lambda: config)
    monkeypatch.setattr(llm, "list_models_detailed", lambda provider: {
        "ok": True,
        "provider": provider["id"],
        "count": 0,
        "models": [],
        "suggestions": [],
    })
    r = client.get("/api/llm/models", params={"provider_id": "lmstudio", "detailed": 1})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["provider"] == "lmstudio"


def test_api_llm_routes_updates_config(monkeypatch, tmp_path):
    import json

    from app import llm

    path = tmp_path / "breadcrumb.llm.json"
    path.write_text(json.dumps({
        "active_provider": "lmstudio",
        "providers": [
            {"id": "lmstudio", "label": "LM Studio", "base_url": "http://127.0.0.1:1234/v1"}
        ],
        "routing": {task: "old-model" for task in llm.TASK_CLASSES},
    }))
    monkeypatch.setattr(llm, "CONFIG_PATH", path)

    r = client.post("/api/llm/routes", json={
        "task": "prose",
        "model": "qwen3-4b-instruct-2507",
    })
    assert r.status_code == 200, r.text
    assert r.json()["routing"]["prose"] == "qwen3-4b-instruct-2507"
    saved = json.loads(path.read_text())
    assert saved["routing"]["prose"] == "qwen3-4b-instruct-2507"
    assert saved["routing"]["fast"] == "old-model"


def test_api_llm_routes_requires_csrf():
    r = client.post(
        "/api/llm/routes",
        json={"task": "prose", "model": "qwen3-4b-instruct-2507"},
        headers={"X-CSRF-Token": ""},
    )
    assert r.status_code == 403
