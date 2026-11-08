"""Phase 7: external tool adapters, scope preflight and parser fixtures.

These tests never require nmap/httpx/nuclei to be installed. Every adapter is
exercised against a small fake binary placed on a temporary ``PATH`` so the
spawn/no-spawn assertions are real process assertions, not mocks.

Local-only: the scope guard resolves names through the system resolver, so the
tests use IP literals (and direct ``build_argv`` calls) whenever a target would
otherwise need DNS.
"""

import io
import json
import os
import sys
import tempfile
import textwrap
import threading
import time
import uuid
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="breadcrumb-phase7-")
os.environ.setdefault("BREADCRUMB_DB_PATH", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BREADCRUMB_SKIP_BACKUP", "1")

import pytest  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app import runners  # noqa: E402
from app.collect import (  # noqa: E402
    adapter_ids,
    adapters_enabled,
    claimable_collector_ids,
    collector_ids,
    get_collector,
)
from app.collect.base import CollectorContext, CollectorError  # noqa: E402
from app.collect.guard import (  # noqa: E402
    PRIVATE_TARGET_WARNING,
    ScopeDecision,
    ScopeDenied,
    ScopeGuard,
)
from app.collect.tools import (  # noqa: E402
    AdapterContext,
    AdapterSpec,
    HttpxAdapter,
    ToolAdapter,
    _annotate,
    _option_text,
    _ports_option,
    _severity_option,
    _strict_ok,
    _tool_env,
    adapter_specs,
    parse_target,
    probe_version,
    run_tool,
    strict_mode,
)
from app.db import engine, init_db  # noqa: E402
from app.jobs import worker  # noqa: E402
from app.models import Program, ScanJob, ScanPhase  # noqa: E402
from app.parsers import analyze, extract_findings  # noqa: E402
from app.scope import Scope  # noqa: E402

TAG = uuid.uuid4().hex[:8]


# ----------------------------------------------------------------- helpers ----


def guard(scope_in: str = "", scope_out: str = "", allow_private: bool = True) -> ScopeGuard:
    return ScopeGuard(
        Scope(scope_in, scope_out), allow_private=allow_private
    )


def make_ctx(
    target: str,
    guard_obj: ScopeGuard,
    *,
    options: dict | None = None,
    headers: dict | None = None,
    proxy: str = "",
    cancel_event: threading.Event | None = None,
) -> CollectorContext:
    events: list[tuple[str, str, dict]] = []
    ctx = CollectorContext(
        target=target,
        options=dict(options or {}),
        guard=guard_obj,
        job_id=1,
        attempt_id=1,
        worker_id="phase7-test",
        cancel_event=cancel_event or threading.Event(),
        headers=dict(headers or {}),
        proxy=proxy,
        emit=lambda kind, message, data: events.append((kind, message, data)),
    )
    ctx.events = events  # type: ignore[attr-defined]
    return ctx


def write_tool(bindir: Path, name: str, body: str = "") -> Path:
    """Create an executable fake tool that answers version probes first."""
    path = bindir / name
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys, time\n"
        "args = sys.argv[1:]\n"
        "if args and args[0] in {'--version', '-version', '-V', 'version'}:\n"
        f"    print({f'{name} 1.0.0'!r})\n"
        "    sys.exit(0)\n"
        + textwrap.dedent(body),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.fixture()
def bindir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "bin"
    directory.mkdir()
    monkeypatch.setenv(
        "PATH", str(directory) + os.pathsep + os.environ.get("PATH", "")
    )
    return directory


def _program(scope_in: str = "127.0.0.1") -> int:
    with Session(engine) as session:
        program = Program(
            name=f"phase7-{TAG}-{uuid.uuid4().hex[:6]}", scope_in=scope_in
        )
        session.add(program)
        session.commit()
        session.refresh(program)
        return program.id


def _job(program_id: int, runner: str, target: str) -> int:
    with Session(engine) as session:
        job = ScanJob(program_id=program_id, runner=runner, target=target)
        session.add(job)
        session.commit()
        session.refresh(job)
        return job.id


def _get_job(job_id: int) -> ScanJob:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert job is not None
        return job


def _process_alive(pid: int) -> bool:
    """Linux: a zombie has already exited for our purposes."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return False
    fields = stat.split(") ", 1)
    return len(fields) == 2 and fields[1].split()[0] != "Z"


# ------------------------------------------------------- target/argv safety --


def test_parse_target_shapes():
    url = parse_target("https://example.test:8443/login")
    assert url.url == "https://example.test:8443/login"
    assert url.host == "example.test"
    assert url.port == 8443
    assert not url.is_ip

    bare = parse_target("example.test:8080")
    assert (bare.host, bare.port, bare.is_ip) == ("example.test", 8080, False)

    network = parse_target("10.0.0.0/24")
    assert network.is_cidr
    assert network.host == "10.0.0.0"

    ipv6 = parse_target("[::1]:8080")
    assert ipv6.is_ip and ipv6.host == "::1" and ipv6.port == 8080

    plain_v6 = parse_target("::1")
    assert plain_v6.is_ip and plain_v6.host == "::1"

    assert parse_target("127.0.0.1").default_url() == "https://127.0.0.1/"
    assert parse_target("example.test:80").default_url() == "http://example.test:80/"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-oX",
        "ftp://example.test/",
        "http://example.test/\nsecond",
        "http://example.test/\x00",
        "https:///nohost",
    ],
)
def test_parse_target_rejects_unsafe_values(value):
    with pytest.raises(CollectorError):
        parse_target(value)


def test_option_validation_rejects_injection():
    assert _ports_option({"ports": "80,443,8000-8100"}) == "80,443,8000-8100"
    for bad in ("0", "65536", "80-", "80,", "80;rm -rf /", "1-2-3"):
        with pytest.raises(CollectorError):
            _ports_option({"ports": bad})
    assert _severity_option({"severity": "high,critical"}) == "high,critical"
    with pytest.raises(CollectorError):
        _severity_option({"severity": "urgent"})
    with pytest.raises(CollectorError):
        _option_text({"depth": "3\n--script"}, "depth")


def test_runner_catalog_marks_adapters():
    nmap = runners.get_runner("nmap")
    assert nmap is not None and nmap.adapter and not nmap.native
    assert nmap.scope_mode == "ip_literal"
    assert nmap.strict_policy == "ip_only"

    for adapter_id in ("whatweb", "wafw00f", "ffuf", "dalfox", "amass"):
        runner = runners.get_runner(adapter_id)
        assert runner is not None and runner.adapter, adapter_id

    assert runners.get_runner("leadline-recon").native is True


def test_adapter_specs_are_complete_and_unique():
    specs = adapter_specs()
    assert len(specs) == 12
    assert {spec.id for spec in specs} == set(adapter_ids())
    for spec in specs:
        assert spec.scope_mode in {
            "ip_literal", "resolve_override", "preflight_only", "passive"
        }
        assert spec.strict_policy in {"always", "ip_only", "never"}
        assert spec.version_args


def test_strict_mode_policies():
    by_id = {spec.id: spec for spec in adapter_specs()}
    ip = parse_target("127.0.0.1")
    domain = parse_target("example.test")

    assert _strict_ok(by_id["nmap"], ip)
    assert not _strict_ok(by_id["nmap"], domain)
    assert _strict_ok(by_id["httpx"], domain)
    assert not _strict_ok(by_id["nuclei"], ip)


# --------------------------------------------------------- scope/guard ------


def test_check_network_containment_and_hard_blocks():
    g = guard("10.0.0.0/8", scope_out="10.2.0.0/16")
    allowed = g.check_network("10.1.0.0/24")
    assert allowed.allowed
    assert PRIVATE_TARGET_WARNING in allowed.warnings

    excluded = g.check_network("10.2.0.0/24")
    assert not excluded.allowed and excluded.status == "out"

    metadata = g.check_network("169.254.169.254/32")
    assert not metadata.allowed and metadata.status == "out"
    assert metadata.blocked_addresses

    outside = g.check_network("192.168.1.0/24")
    assert not outside.allowed and outside.status == "unknown"

    empty = guard("").check_network("10.0.0.0/24")
    assert not empty.allowed


def test_check_network_private_switch():
    g = guard("10.0.0.0/8", allow_private=False)
    decision = g.check_network("10.1.0.0/24")
    assert not decision.allowed
    assert "private targets are disabled" in decision.reason


def test_private_target_warning_is_emitted(bindir):
    write_tool(bindir, "nmap", "print('<nmaprun></nmaprun>')\n")
    ctx = make_ctx("127.0.0.1", guard("127.0.0.1"))
    get_collector("nmap").run(ctx)
    warnings = [message for kind, message, _ in ctx.events if kind == "warning"]
    assert any(PRIVATE_TARGET_WARNING in message for message in warnings)


# ------------------------------------------------------- adapter execution ---


def test_denied_target_never_spawns(bindir):
    marker = bindir / "spawned"
    write_tool(
        bindir,
        "nmap",
        f"open({str(marker)!r}, 'w').write('x')\nprint('<nmaprun/>')\n",
    )
    ctx = make_ctx("example.test", guard("other.test"))
    with pytest.raises(ScopeDenied):
        get_collector("nmap").run(ctx)
    assert not marker.exists()


def test_metadata_target_never_spawns(bindir):
    marker = bindir / "spawned"
    write_tool(
        bindir,
        "nmap",
        f"open({str(marker)!r}, 'w').write('x')\nprint('<nmaprun/>')\n",
    )
    ctx = make_ctx("169.254.169.254", guard("169.254.169.254/32"))
    with pytest.raises(ScopeDenied):
        get_collector("nmap").run(ctx)
    assert not marker.exists()


def test_proxy_is_refused_before_spawn(bindir):
    marker = bindir / "spawned"
    write_tool(
        bindir,
        "httpx",
        f"open({str(marker)!r}, 'w').write('x')\nprint('{{}}')\n",
    )
    ctx = make_ctx(
        "127.0.0.1", guard("127.0.0.1"), proxy="http://127.0.0.1:8080"
    )
    with pytest.raises(CollectorError, match="proxy"):
        get_collector("httpx").run(ctx)
    assert not marker.exists()


def test_missing_binary_is_explicitly_not_installed(bindir):
    class MissingAdapter(ToolAdapter):
        spec = AdapterSpec(
            id="missing-tool",
            binary="breadcrumb-definitely-missing-xyz",
            label="missing",
            description="test",
            phase="missing",
            kinds=("ip",),
        )

    ctx = make_ctx("127.0.0.1", guard("127.0.0.1"))
    with pytest.raises(CollectorError, match="is not installed"):
        MissingAdapter().run(ctx)


def test_strict_mode_blocks_unpinnable_adapter(bindir, monkeypatch):
    marker = bindir / "spawned"
    write_tool(
        bindir,
        "nuclei",
        f"open({str(marker)!r}, 'w').write('x')\nprint('{{}}')\n",
    )
    monkeypatch.setenv("BREADCRUMB_STRICT_MODE", "1")
    assert strict_mode()
    ctx = make_ctx("127.0.0.1", guard("127.0.0.1"))
    with pytest.raises(CollectorError, match="strict mode"):
        get_collector("nuclei").run(ctx)
    assert not marker.exists()


def test_strict_mode_allows_pinnable_httpx(bindir, monkeypatch):
    write_tool(
        bindir,
        "httpx",
        "print(json.dumps({'url': 'https://127.0.0.1/', 'status_code': 200}))\n",
    )
    monkeypatch.setenv("BREADCRUMB_STRICT_MODE", "1")
    ctx = make_ctx("127.0.0.1", guard("127.0.0.1"))
    result = get_collector("httpx").run(ctx)
    assert result.stats["strict"] is True
    assert result.stats["scope_mode"] == "ip_literal"
    assert result.phases[0].error is None


def test_invalid_ports_are_rejected_before_spawn(bindir):
    marker = bindir / "spawned"
    write_tool(
        bindir,
        "nmap",
        f"open({str(marker)!r}, 'w').write('x')\nprint('<nmaprun/>')\n",
    )
    ctx = make_ctx(
        "127.0.0.1", guard("127.0.0.1"), options={"ports": "0"}
    )
    with pytest.raises(CollectorError, match="between 1 and 65535"):
        get_collector("nmap").run(ctx)
    assert not marker.exists()

    ctx = make_ctx(
        "127.0.0.1", guard("127.0.0.1"), options={"ports": "80;touch /tmp/pwned"}
    )
    with pytest.raises(CollectorError):
        get_collector("nmap").run(ctx)
    assert not marker.exists()


def test_nmap_xml_fixture_runs_through_adapter(bindir):
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX -">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="Fake" version="1.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    write_tool(bindir, "nmap", "sys.stdout.write(" + repr(xml) + ")\n")
    ctx = make_ctx("127.0.0.1", guard("127.0.0.1"))
    result = get_collector("nmap").run(ctx)

    phase = result.phases[0]
    assert phase.error is None
    assert phase.output.startswith("<?xml")
    assert "# breadcrumb adapter" not in phase.output
    assert result.stats["scope_mode"] == "ip_literal"
    assert result.stats["pinned"] is True
    assert result.stats["returncode"] == 0

    entities, _rels, parsers, errors = analyze(phase.output)
    assert "nmap" in parsers and not errors
    ports = [entity for entity in entities if entity.type == "port"]
    assert ports and ports[0].meta["port"] == 8080


def test_httpx_resolve_override_argv():
    adapter = HttpxAdapter()
    target = parse_target("https://example.test/login")
    actx = AdapterContext(
        target=target,
        options={},
        decision=ScopeDecision(True, "in", "example.test", "in scope"),
        workdir=Path("/tmp"),
        addresses=["203.0.113.9"],
    )
    argv = adapter.build_argv(actx)
    assert argv[:2] == ["httpx", "-silent"]
    assert argv[argv.index("-resolve") + 1] == "example.test:443:203.0.113.9"

    ip_target = parse_target("127.0.0.1")
    ip_actx = AdapterContext(
        target=ip_target,
        options={},
        decision=ScopeDecision(True, "in", "127.0.0.1", "in scope"),
        workdir=Path("/tmp"),
        addresses=["127.0.0.1"],
    )
    assert "-resolve" not in adapter.build_argv(ip_actx)


def test_ffuf_reads_json_output_file(bindir, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nlogin\n", encoding="utf-8")
    body = """
    out = args[args.index("-o") + 1]
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"results": [{
            "input": {"FUZZ": "admin"},
            "status": 200,
            "length": 12,
            "url": "https://127.0.0.1/admin",
        }]}, fh)
    """
    write_tool(bindir, "ffuf", body)
    ctx = make_ctx(
        "127.0.0.1", guard("127.0.0.1"), options={"wordlist": str(wordlist)}
    )
    result = get_collector("ffuf").run(ctx)
    phase = result.phases[0]
    assert phase.error is None
    assert '"admin"' in phase.output
    assert result.stats["returncode"] == 0

    entities, _rels, parsers, errors = analyze(phase.output)
    assert "ffuf" in parsers and not errors
    assert any(entity.type == "url" and "admin" in entity.value for entity in entities)


def test_adapter_does_not_receive_header_profiles(bindir):
    write_tool(
        bindir,
        "httpx",
        "print(json.dumps({'url': 'https://127.0.0.1/', 'status_code': 200}))\n",
    )
    ctx = make_ctx(
        "127.0.0.1",
        guard("127.0.0.1"),
        headers={"Authorization": "Bearer super-secret"},
    )
    result = get_collector("httpx").run(ctx)
    messages = [message for _kind, message, _data in ctx.events]
    assert any("header profiles" in message for message in messages)
    assert "Authorization" not in " ".join(result.stats["argv"])
    assert "super-secret" not in phase_text(result)


def phase_text(result) -> str:
    return "\n".join(phase.output for phase in result.phases)


def test_annotate_preserves_xml_and_marks_text():
    spec = AdapterSpec(
        id="demo", binary="demo", label="demo", description="", phase="demo"
    )
    stats = {
        "scope_mode": "ip_literal",
        "pinned": True,
        "scope": {"status": "in"},
        "version": "1.0",
    }
    xml = '<?xml version="1.0"?>\n<nmaprun/>'
    assert _annotate(spec, xml, stats) == xml
    text = _annotate(spec, "hello\n", stats)
    assert text.startswith("# breadcrumb adapter: demo")
    assert "# pinned: true" in text
    assert text.endswith("hello\n")


# ------------------------------------------------------------- run_tool ------


def test_run_tool_uses_argv_and_no_shell(monkeypatch, tmp_path):
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(b"")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr("app.collect.tools.subprocess.Popen", fake_popen)
    run = run_tool(
        ["tool", "a;b", "$(id)"], workdir=tmp_path, timeout=5, max_output=100
    )
    assert run.returncode == 0
    assert captured["argv"] == ["tool", "a;b", "$(id)"]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["kwargs"]["stdin"] is not None


def test_tool_env_excludes_secrets_and_proxies(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("BREADCRUMB_SECRET_KEY", "do-not-leak")
    env = _tool_env(tmp_path)
    assert "HTTPS_PROXY" not in env
    assert "HTTP_PROXY" not in env
    assert "BREADCRUMB_SECRET_KEY" not in env
    assert env["HOME"] == str(tmp_path)
    assert env["TMPDIR"] == str(tmp_path)


def test_run_tool_timeout_kills_the_process(tmp_path):
    started = time.monotonic()
    run = run_tool(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        workdir=tmp_path,
        timeout=1,
        max_output=1024,
    )
    elapsed = time.monotonic() - started
    assert run.timed_out and not run.cancelled
    assert elapsed < 10


def test_run_tool_caps_output(tmp_path):
    run = run_tool(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"],
        workdir=tmp_path,
        timeout=10,
        max_output=1000,
    )
    assert run.truncated
    assert len(run.stdout) == 1000


def test_run_tool_cancels_the_whole_process_group(tmp_path):
    pidfile = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(60)'])\n"
        "open(sys.argv[1], 'w').write(str(child.pid))\n"
        "time.sleep(60)\n"
    )
    cancel = threading.Event()
    outcome = {}

    def target():
        outcome["run"] = run_tool(
            [sys.executable, "-c", code, str(pidfile)],
            workdir=tmp_path,
            timeout=30,
            max_output=1024,
            cancel_event=cancel,
        )

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not pidfile.exists():
        time.sleep(0.05)
    assert pidfile.exists(), "fake tool did not start"
    child_pid = int(pidfile.read_text(encoding="utf-8"))

    cancel.set()
    thread.join(timeout=10)
    assert not thread.is_alive(), "run_tool did not return after cancellation"
    assert outcome["run"].cancelled

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _process_alive(child_pid):
        time.sleep(0.05)
    assert not _process_alive(child_pid), "child survived process-group cancellation"


def test_probe_version_reads_and_caches(bindir):
    write_tool(bindir, "fake-tool")
    first = probe_version("fake-tool")
    assert first == "fake-tool 1.0.0"
    assert probe_version("fake-tool") == first


# ---------------------------------------------------- parser fixtures --------


FFUF_JSON = """# breadcrumb adapter: ffuf
# scope_mode: preflight_only
{"results": [{"input": {"FUZZ": "admin"}, "status": 200, "length": 123,
  "words": 10, "lines": 5, "content-type": "text/html",
  "redirectlocation": "", "url": "https://example.test/admin"}],
 "config": {"url": "https://example.test/FUZZ"}}
"""

DALFOX_JSONL = """# breadcrumb adapter: dalfox
{"type": "V", "inject_type": "inHTML", "method": "GET",
 "data": "https://example.test/?q=1", "payload": "<script>alert(1)</script>",
 "evidence": "reflected", "severity": "High", "message": "XSS candidate",
 "url": "https://example.test/?q=1", "param": "q"}
"""

AMASS_JSONL = """# breadcrumb adapter: amass
{"name": "api.example.test", "domain": "example.test",
 "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 64500}],
 "tag": "cert", "sources": ["crtsh"]}
"""

WHATWEB_JSON = """# breadcrumb adapter: whatweb
[{"target": "https://example.test/", "http_status": 200,
  "plugins": {"Apache": {"version": ["2.4.58"], "string": ["Apache"]},
              "PHP": {"version": ["8.2"]}}}]
"""

WAFW00F_JSON = """# breadcrumb adapter: wafw00f
[{"url": "https://example.test/", "detected": true,
  "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]
"""


def test_ffuf_parser_fixture():
    entities, _rels, parsers, errors = analyze(FFUF_JSON)
    assert "ffuf" in parsers and not errors
    assert "dalfox" not in parsers, "ffuf output must not be read as XSS"
    types = {entity.type for entity in entities}
    assert {"url", "path", "domain"} <= types
    assert any(entity.type == "url" and entity.value.endswith("/admin") for entity in entities)


def test_dalfox_parser_fixture_marks_candidates():
    entities, _rels, parsers, errors = analyze(DALFOX_JSONL)
    assert "dalfox" in parsers and not errors
    assert any(entity.type == "param" and entity.value == "q" for entity in entities)
    findings = extract_findings(DALFOX_JSONL)
    assert len(findings) == 1
    assert "candidate" in findings[0]["tags"]
    assert findings[0]["severity"] == "high"
    assert findings[0]["parser"] == "dalfox"


def test_amass_parser_fixture():
    entities, rels, parsers, errors = analyze(AMASS_JSONL)
    assert "amass" in parsers and not errors
    types = {entity.type for entity in entities}
    assert {"subdomain", "ip", "cidr"} <= types
    assert any(rel.rel_type == "resolves_to" for rel in rels)


def test_whatweb_parser_fixture():
    entities, _rels, parsers, errors = analyze(WHATWEB_JSON)
    assert "whatweb" in parsers and not errors
    tech = {entity.value: entity for entity in entities if entity.type == "tech"}
    assert set(tech) == {"Apache", "PHP"}
    assert tech["Apache"].meta["version"] == "2.4.58"


def test_wafw00f_parser_fixture():
    entities, _rels, parsers, errors = analyze(WAFW00F_JSON)
    assert "wafw00f" in parsers and not errors
    tech = [entity for entity in entities if entity.type == "tech"]
    assert tech and tech[0].value == "Cloudflare"
    assert tech[0].meta["manufacturer"] == "Cloudflare Inc."


# ------------------------------------------------- registry/worker gating ---


def test_adapter_registry_and_claim_gating(monkeypatch):
    assert len(collector_ids()) == 17
    assert len(adapter_ids()) == 12
    assert "nmap" not in collector_ids()
    assert get_collector("nmap") is not None
    assert get_collector("leadline-recon") is not None

    monkeypatch.delenv("BREADCRUMB_EXTERNAL_TOOLS", raising=False)
    assert not adapters_enabled()
    assert "nmap" not in claimable_collector_ids()

    monkeypatch.setenv("BREADCRUMB_EXTERNAL_TOOLS", "1")
    assert adapters_enabled()
    assert "nmap" in claimable_collector_ids()


def test_worker_does_not_claim_adapter_jobs_by_default(bindir, monkeypatch):
    init_db()
    monkeypatch.delenv("BREADCRUMB_EXTERNAL_TOOLS", raising=False)
    write_tool(bindir, "nmap", "print('<nmaprun/>')\n")
    program_id = _program()
    job_id = _job(program_id, "nmap", "127.0.0.1")

    assert worker.run_once(job_id=job_id) is False
    assert _get_job(job_id).status == "queued"

    # Leave no queued adapter job behind for later tests that drain the queue.
    with Session(engine) as session:
        session.delete(session.get(ScanJob, job_id))
        session.commit()


def test_worker_runs_adapter_job_when_opt_in(bindir, monkeypatch):
    init_db()
    monkeypatch.setenv("BREADCRUMB_EXTERNAL_TOOLS", "1")
    xml = (
        '<?xml version="1.0"?>'
        '<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>'
        '<hostnames><hostname name="localhost"/></hostnames>'
        '<ports><port protocol="tcp" portid="8080"><state state="open"/>'
        '<service name="http"/></port></ports></host></nmaprun>'
    )
    write_tool(bindir, "nmap", "sys.stdout.write(" + repr(xml) + ")\n")
    program_id = _program()
    job_id = _job(program_id, "nmap", "127.0.0.1")

    assert worker.run_once(job_id=job_id) is True
    job = _get_job(job_id)
    assert job.status == "done"
    assert job.output_paste_id is not None

    with Session(engine) as session:
        phase = session.exec(
            select(ScanPhase).where(ScanPhase.job_id == job_id)
        ).first()
        assert phase is not None
        assert phase.name == "nmap"
        assert phase.stats["adapter"] == "nmap"
        assert phase.stats["pinned"] is True
