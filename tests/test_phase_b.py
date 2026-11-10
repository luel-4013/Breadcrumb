"""Phase B: Ledger v2, Diff v2, Scope v2, Graph v2, and Ledger round-trip."""

import json
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase-b-")
os.environ["BREADCRUMB_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["BREADCRUMB_SKIP_BACKUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import diff as diff_mod  # noqa: E402
from app import ledger as ledger_mod  # noqa: E402
from app.attribution import rebuild_program  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.ingest import IngestRequest, ingest, reapply_severity_overrides  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Entity, Finding, Program, ScanJob, Target  # noqa: E402
from app.parsers import analyze_detailed  # noqa: E402
from app.scope import (  # noqa: E402
    Scope,
    format_severity_overrides,
    parse_severity_overrides,
)

init_db()
client = TestClient(app)
client.get("/health")
client.headers["X-CSRF-Token"] = client.cookies["bc_csrf"]

_counter = 0


def _program(name: str | None = None, scope_in: str | None = None) -> int:
    global _counter
    _counter += 1
    unique = name or f"pb-{_counter}"
    with Session(engine) as session:
        existing = session.exec(select(Program).where(Program.name == unique)).first()
        if existing is not None:
            return existing.id
        program = Program(name=unique, scope_in=scope_in)
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def _ingest(pid: int, text: str, **kwargs):
    with Session(engine) as session:
        return ingest(
            session,
            IngestRequest(text=text, program_id=pid, source="test", **kwargs),
        )


def _entities(pid: int, etype: str | None = None):
    with Session(engine) as session:
        stmt = select(Entity).where(Entity.program_id == pid)
        if etype:
            stmt = stmt.where(Entity.type == etype)
        return session.exec(stmt).all()


# --------------------------------------------------------------- scope v2 ---
def test_status_path_and_negation_rules_are_explainable():
    scope = Scope("example.com status:200,204\n!example.com/private", "")
    decision = scope.explain("https://example.com/", "url", status_code=200)
    assert decision.status == "in"
    assert decision.reason == "in_rule"
    assert "status:200,204" in decision.rule

    hidden = scope.explain("https://example.com/private/x", "url", status_code=200)
    assert hidden.status == "out"
    assert hidden.reason == "in_negated"

    wrong_code = scope.explain("https://example.com/", "url", status_code=404)
    assert wrong_code.status == "out"
    assert wrong_code.reason == "status_filter"
    assert wrong_code.detail == {"allowed": [200, 204]}

    no_status = scope.explain("https://example.com/", "url")
    assert no_status.status == "unknown"
    assert no_status.reason == "status_unknown"

    empty = Scope("", "")
    assert empty.explain("example.com", "domain").reason == "no_scope"


def test_path_rules_do_not_scope_the_whole_host():
    scope = Scope("example.com/admin/*", "")
    inside = scope.explain("https://example.com/admin/users", "url", status_code=200)
    outside = scope.explain("https://example.com/blog", "url", status_code=200)
    subdomain = scope.explain("admin.example.com", "subdomain", status_code=200)
    assert inside.status == "in"
    assert outside.status == "unknown"
    assert subdomain.status == "unknown"


def test_severity_override_parsing_rejects_junk():
    parsed = parse_severity_overrides("template-a=HIGH\nnot-a-line\ntemplate-b=urgent\nx=low")
    assert parsed == {"template-a": "high", "x": "low"}
    assert format_severity_overrides({"b": "low", "a": "high"}) == "a=high\nb=low"


def test_ingest_persists_status_code_and_scope_reason():
    pid = _program(scope_in="status.test status:200")
    httpx = "\n".join(
        [
            json.dumps(
                {"url": "https://status.test/ok", "status_code": 200, "tech": ["nginx"]}
            ),
            json.dumps(
                {"url": "https://status.test/gone", "status_code": 404, "tech": ["nginx"]}
            ),
        ]
    )
    result = _ingest(pid, httpx)
    assert result.entities > 0

    urls = {entity.value: entity for entity in _entities(pid, "url")}
    assert urls["https://status.test/ok"].scope_status == "in"
    assert urls["https://status.test/ok"].status_code == 200
    assert urls["https://status.test/ok"].scope_reason == "in_rule"
    assert urls["https://status.test/gone"].scope_status == "out"
    assert urls["https://status.test/gone"].scope_reason == "status_filter"
    assert urls["https://status.test/gone"].status_code == 404

    with Session(engine) as session:
        summary = rebuild_program(session, pid)
    assert summary["scope_reasons"]["status_filter"] >= 1
    assert summary["scope_reasons"]["in_rule"] >= 1


def test_per_rule_severity_override_applies_and_reverts():
    pid = _program()
    nuclei = json.dumps(
        {
            "template-id": "tech-detect",
            "matched-at": "https://override.test/",
            "host": "override.test",
            "info": {"name": "Technology detection", "severity": "info"},
        }
    )
    _ingest(pid, nuclei)
    with Session(engine) as session:
        finding = session.exec(select(Finding).where(Finding.program_id == pid)).first()
        assert finding is not None
        assert finding.rule_id == "tech-detect"
        assert finding.severity == "info"
        assert finding.meta["parser_severity"] == "info"

        program = session.get(Program, pid)
        program.rule_severities = {"tech-detect": "high"}
        session.add(program)
        session.commit()
        changed = reapply_severity_overrides(session, pid)
        assert changed["changed"] == 1
        session.refresh(finding)
        assert finding.severity == "high"
        assert finding.meta["severity_override"] == {
            "rule_id": "tech-detect",
            "from": "info",
            "to": "high",
        }

        program.rule_severities = {}
        session.add(program)
        session.commit()
        reapply_severity_overrides(session, pid)
        session.refresh(finding)
        assert finding.severity == "info"
        assert "severity_override" not in finding.meta


def test_program_update_route_saves_overrides():
    pid = _program()
    r = client.post(
        f"/programs/{pid}/update",
        data={
            "name": f"pb-{_counter}",
            "scope_in": "",
            "scope_out": "",
            "rule_severities": "tech-detect=critical\nbogus=nope",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(engine) as session:
        program = session.get(Program, pid)
        assert program.rule_severities == {"tech-detect": "critical"}


# -------------------------------------------------------------- ledger v2 ---
def test_ledger_aggregates_across_programs_and_links_timeline():
    shared = "shared.ledger.test"
    first = _program()
    second = _program()
    _ingest(first, f"{shared}\n")
    _ingest(second, f"{shared}\n")

    with Session(engine) as session:
        filters = ledger_mod.parse_query(f"type:subdomain program:pb- seen:other-program")
        page = ledger_mod.ledger_assets(session, filters, limit=500)
        asset = next(a for a in page["assets"] if a["value"] == shared)
        assert asset["program_count"] == 2
        assert {p["id"] for p in asset["programs"]} == {first, second}
        assert asset["seen_before"] is True
        assert len(asset["captures"]) == 2

        timeline = ledger_mod.asset_timeline(session, "subdomain", shared)
        assert timeline is not None
        assert timeline["program_count"] == 2
        assert len(timeline["sightings"]) == 2

        scoped = ledger_mod.parse_query(f"type:subdomain program:{first}")
        only_first = ledger_mod.ledger_assets(session, scoped, limit=500)
        assert all(
            first in {p["id"] for p in a["programs"]} for a in only_first["assets"]
        )


def test_ledger_filters_tags_and_status_codes():
    pid = _program(scope_in="filters.ledger.test status:200")
    _ingest(
        pid,
        json.dumps({"url": "https://filters.ledger.test/admin", "status_code": 200}),
    )
    with Session(engine) as session:
        entity = session.exec(
            select(Entity).where(
                Entity.program_id == pid, Entity.type == "url"
            )
        ).first()
        entity.tags = ["needs-auth"]
        entity.verdict = "confirmed"
        session.add(entity)
        session.commit()

        tagged = ledger_mod.ledger_assets(
            session, ledger_mod.parse_query("tag:needs-auth verdict:confirmed"), limit=100
        )
        assert any(a["value"] == "https://filters.ledger.test/admin" for a in tagged["assets"])

        coded = ledger_mod.ledger_assets(
            session,
            ledger_mod.parse_query(f"program:{pid} status:200 type:url"),
            limit=100,
        )
        assert coded["total"] >= 1

        missing = ledger_mod.ledger_assets(
            session, ledger_mod.parse_query(f"program:{pid} status:500"), limit=100
        )
        assert missing["total"] == 0


def test_ledger_saved_views_crud():
    with Session(engine) as session:
        view = ledger_mod.save_view(
            session, "Phase B port view", kind="ledger", query="type:port scope:in"
        )
        assert view.id is not None
        listed = ledger_mod.list_views(session, "ledger")
        assert any(v.name == "Phase B port view" for v in listed)
        # Same name updates instead of duplicating.
        again = ledger_mod.save_view(
            session, "Phase B port view", kind="ledger", query="type:port"
        )
        assert again.id == view.id
        assert again.query == "type:port"
        assert ledger_mod.delete_view(session, view.id) is True
        assert ledger_mod.get_view(session, view.id) is None


def test_ledger_export_round_trips_into_a_clean_program():
    pid = _program(scope_in="roundtrip.ledger.test")
    _ingest(pid, "roundtrip.ledger.test\n")
    with Session(engine) as session:
        page = ledger_mod.ledger_assets(
            session, ledger_mod.parse_query(f"program:{pid}"), limit=100
        )
        exported = ledger_mod.assets_to_jsonl(page["assets"])
    assert exported.strip()
    row = json.loads(exported.splitlines()[0])
    assert row["ledger_version"] == 1

    analysis = analyze_detailed(exported)
    assert "ledger_jsonl" in analysis.parsers

    clean = _program()
    _ingest(clean, exported)
    with Session(engine) as session:
        copied = session.exec(
            select(Entity).where(
                Entity.program_id == clean,
                Entity.type == row["type"],
                Entity.normalized == row["normalized"],
            )
        ).first()
        assert copied is not None
        assert copied.value == row["value"]

    csv_body = ledger_mod.assets_to_csv(page["assets"])
    assert "type,value" in csv_body.splitlines()[0]


def test_ledger_pages_and_api_render():
    for url in ("/ledger", "/api/v1/ledger", "/ledger/export?format=jsonl"):
        r = client.get(url)
        assert r.status_code == 200, (url, r.text[:300])
    r = client.get("/api/v1/ledger/asset", params={"type": "subdomain", "value": "nope.test"})
    assert r.status_code == 404

    r = client.post(
        "/ledger/views",
        data={"name": "API view", "query": "type:subdomain", "kind": "ledger"},
        follow_redirects=False,
    )
    assert r.status_code == 303


# ---------------------------------------------------------------- diff v2 ---
def test_diff_captures_and_categories_real():
    pid = _program(scope_in="diff2.ledger.test")
    first = _ingest(
        pid,
        "\n".join(
            [
                "Nmap scan report for diff2.ledger.test (192.0.2.9)",
                "PORT    STATE SERVICE",
                "443/tcp open  https",
                json.dumps(
                    {
                        "template-id": "exposed-panel",
                        "matched-at": "https://diff2.ledger.test/admin",
                        "host": "diff2.ledger.test",
                        "info": {"name": "Exposed panel", "severity": "high"},
                    }
                ),
            ]
        ),
    )
    second = _ingest(
        pid,
        "\n".join(
            [
                "Nmap scan report for diff2.ledger.test (192.0.2.9)",
                "PORT    STATE SERVICE",
                "80/tcp  open  http",
            ]
        ),
    )
    with Session(engine) as session:
        result = diff_mod.diff_selectors(
            session, f"paste:{first.paste.id}", f"paste:{second.paste.id}"
        )
    assert result["summary"]["new_findings"] == 0
    assert result["summary"]["removed_findings"] == 1
    assert any(item["port"] == "443/tcp" for item in result["ports"]["closed"])
    assert any(item["port"] == "80/tcp" for item in result["ports"]["opened"])
    assert result["entities"]["available"] is True
    assert result["risk"]["direction"] == "decreased"
    markdown = diff_mod.diff_to_markdown(result)
    assert "## New findings" in markdown
    assert "Ports opened" in markdown


def test_diff_programs_and_invalid_selector():
    first = _program()
    second = _program()
    _ingest(first, "diff3.ledger.test\n")
    _ingest(second, "diff3.ledger.test\nother.diff3.ledger.test\n")
    with Session(engine) as session:
        result = diff_mod.diff_selectors(
            session, f"program:{first}", f"program:{second}"
        )
    assert result["entities"]["available"] is True
    assert any(
        item["value"] == "other.diff3.ledger.test"
        for item in result["entities"]["added"]
    )
    with Session(engine) as session:
        try:
            diff_mod.diff_selectors(session, "program:999999", f"program:{second}")
        except ValueError as exc:
            assert "not found" in str(exc)
        else:
            raise AssertionError("missing selector should raise")


def test_diff_job_snapshot_selector():
    pid = _program()
    _ingest(pid, "jobdiff.ledger.test\n443/tcp open https\n")
    with Session(engine) as session:
        job = ScanJob(program_id=pid, runner="test", target="jobdiff.ledger.test", status="done")
        session.add(job)
        session.commit()
        session.refresh(job)
    _ingest(pid, "jobdiff.ledger.test\n", job_id=job.id)
    with Session(engine) as session:
        from app import history

        history.generate_snapshot(session, job)
        result = diff_mod.diff_selectors(session, f"job:{job.id}", f"program:{pid}")
    assert result["entities"]["available"] is False
    assert result["findings"]["new"] == []  # program includes the job findings
    assert result["risk"]["before"] >= 0


def test_diff_api_and_page():
    first = _program()
    second = _program()
    _ingest(first, "diffpage.ledger.test\n")
    _ingest(second, "diffpage.ledger.test\n")
    r = client.get(
        "/api/v1/diff",
        params={"left": f"paste:{_latest_paste(first)}", "right": f"paste:{_latest_paste(second)}"},
    )
    assert r.status_code == 200, r.text
    assert "summary" in r.json()
    r = client.get(
        "/diff",
        params={"left": f"program:{first}", "right": f"program:{second}"},
    )
    assert r.status_code == 200
    assert "Compare anything" in r.text
    assert client.get("/api/v1/diff", params={"left": "bogus", "right": "paste:1"}).status_code == 400


def _latest_paste(pid: int) -> int:
    from app.models import Paste

    with Session(engine) as session:
        row = session.exec(
            select(Paste).where(Paste.program_id == pid).order_by(Paste.id.desc())
        ).first()
        return row.id


# --------------------------------------------------------------- scope UI ---
def test_scope_page_and_bulk_rescope():
    pid = _program()
    _ingest(pid, "bulk.scope.test\n")
    r = client.get(f"/programs/{pid}/scope")
    assert r.status_code == 200
    assert "scope decisions" in r.text

    with Session(engine) as session:
        entity = session.exec(
            select(Entity).where(
                Entity.program_id == pid,
                Entity.type == "subdomain",
                Entity.value == "bulk.scope.test",
            )
        ).first()
        assert entity is not None
        assert entity.scope_status == "unknown"

    r = client.post(
        f"/programs/{pid}/scope/bulk",
        data={"action": "in", "values": ["subdomain|bulk.scope.test"]},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(engine) as session:
        program = session.get(Program, pid)
        assert "bulk.scope.test" in (program.scope_in or "")
        entity = session.exec(
            select(Entity).where(
                Entity.program_id == pid,
                Entity.type == "subdomain",
                Entity.value == "bulk.scope.test",
            )
        ).first()
        assert entity.scope_status == "in"
        assert entity.scope_reason in {"in_rule", "no_scope"}

    # Re-running is idempotent: no duplicate scope line.
    client.post(
        f"/programs/{pid}/scope/bulk",
        data={"action": "in", "values": ["subdomain|bulk.scope.test"]},
        follow_redirects=False,
    )
    with Session(engine) as session:
        program = session.get(Program, pid)
        lines = [line for line in (program.scope_in or "").splitlines() if line.strip()]
        assert lines.count("bulk.scope.test") == 1


def test_scope_why_link_returns_decision():
    pid = _program(scope_in="status2.scope.test status:200")
    _ingest(
        pid,
        json.dumps({"url": "https://status2.scope.test/gone", "status_code": 404}),
    )
    r = client.get(
        f"/programs/{pid}/scope",
        params={"type": "url", "value": "https://status2.scope.test/gone"},
    )
    assert r.status_code == 200
    assert "status_filter" in r.text
    assert "Why is" in r.text


# --------------------------------------------------------------- graph v2 ---
def test_graph_shared_assets_and_saved_views():
    first = _program()
    second = _program()
    _ingest(first, "graph.shared.test\n")
    _ingest(second, "graph.shared.test\n")
    r = client.get(f"/programs/{first}/graph")
    assert r.status_code == 200
    assert "Seen in other programs" in r.text
    assert "graph.shared.test" in r.text

    r = client.post(
        f"/programs/{first}/graph/views",
        data={"name": "shared hosts", "q": "graph", "node_type": "subdomain"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(engine) as session:
        views = ledger_mod.list_views(session, "graph")
        assert any(v.name == "shared hosts" for v in views)
        view = next(v for v in views if v.name == "shared hosts")
        assert ledger_mod.delete_view(session, view.id)
