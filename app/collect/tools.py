"""Opt-in external tool adapters (Phase 7).

External tools resolve names themselves, so Breadcrumb cannot pin every
connection they make. Each adapter therefore declares a scope mode and a
strict-mode policy, preflights the target through the same guard the native
collectors use, and refuses to spawn for a denied target.

Safety rules implemented here:

* argv lists only, ``shell=False``; target/options are never interpolated into
  a shell string and only a fixed set of option keys is understood;
* a fresh process group per run, killed as a group on cancel/timeout/overflow;
* per-run timeout, output cap, temporary ``cwd``/``HOME`` and an environment
  allowlist that excludes proxies and application secrets;
* binary presence and version are reported separately from job success: a
  missing binary fails the job with an explicit "not installed" error rather
  than looking like an empty successful scan;
* ``BREADCRUMB_STRICT_MODE=1`` disables adapters that cannot be pinned.

Adapters are not claimed by the durable worker unless
``BREADCRUMB_EXTERNAL_TOOLS=1``. A job page's Run now action (or the CLI's
``--run-now``) can still execute one adapter job explicitly.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ..scope import host_of
from .base import (
    Collector,
    CollectorContext,
    CollectorError,
    CollectorResult,
    JobCancelled,
    PhaseOutput,
    register_adapter,
    require_no_proxy,
)
from .guard import ScopeDecision

DEFAULT_TIMEOUT = 600
DEFAULT_MAX_OUTPUT = 10 * 1024 * 1024
VERSION_TIMEOUT = 5
VERSION_MAX_OUTPUT = 4096
KILL_GRACE_SECONDS = 2.0
READ_CHUNK = 65536
MAX_TARGET_LENGTH = 2048
MAX_OPTION_LENGTH = 512

_PORT_TOKEN_RE = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?$")
_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_VERSION_CACHE: dict[tuple[str, int, tuple[str, ...]], str] = {}
_VERSION_LOCK = threading.Lock()


def strict_mode() -> bool:
    return os.environ.get("BREADCRUMB_STRICT_MODE", "").strip().lower() in (
        "1", "true", "yes", "on"
    )


@dataclass(frozen=True)
class AdapterTarget:
    raw: str
    host: str
    url: str
    scheme: str
    port: int | None
    is_ip: bool
    is_cidr: bool
    network: object | None = None

    @property
    def is_network(self) -> bool:
        return self.is_cidr

    def default_url(self, scheme: str = "https") -> str:
        if self.url:
            return self.url
        if self.is_cidr:
            return ""
        chosen = scheme
        if self.port == 80:
            chosen = "http"
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = f":{self.port}" if self.port else ""
        return f"{chosen}://{host}{port}/"


def _safe_target_text(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise CollectorError("adapter target is empty")
    if len(value) > MAX_TARGET_LENGTH:
        raise CollectorError(f"adapter target is longer than {MAX_TARGET_LENGTH} characters")
    if value.startswith("-"):
        raise CollectorError("adapter target must not start with '-'")
    if any(ch in value for ch in ("\x00", "\n", "\r")):
        raise CollectorError("adapter target contains a control character")
    return value


def parse_target(raw: str) -> AdapterTarget:
    value = _safe_target_text(raw)
    if "://" in value:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise CollectorError(f"invalid target URL: {exc}") from exc
        if parsed.scheme.lower() not in ("http", "https"):
            raise CollectorError("adapter target URL must use http or https")
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            raise CollectorError("adapter target URL has no host")
        try:
            port = parsed.port
        except ValueError as exc:
            raise CollectorError(f"invalid target port: {exc}") from exc
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass
        return AdapterTarget(
            raw=value, host=host, url=value, scheme=parsed.scheme.lower(),
            port=port, is_ip=is_ip, is_cidr=False,
        )

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        network = None
    if network is not None and "/" in value:
        return AdapterTarget(
            raw=value, host=str(network.network_address), url="",
            scheme="", port=None, is_ip=False, is_cidr=True, network=network,
        )
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise CollectorError("adapter target has an unterminated IPv6 literal")
        literal = value[1:end]
        rest = value[end + 1:]
        port = None
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise CollectorError("adapter target has an invalid IPv6 port")
            port = int(rest[1:])
        try:
            address = ipaddress.ip_address(literal)
        except ValueError as exc:
            raise CollectorError(f"invalid IPv6 target: {literal}") from exc
        return AdapterTarget(
            raw=value, host=str(address), url="", scheme="", port=port,
            is_ip=True, is_cidr=False,
        )
    bare_host = value
    bare_port = None
    if value.count(":") == 1:
        candidate, _, port_text = value.partition(":")
        if port_text.isdigit():
            bare_host = candidate
            bare_port = int(port_text)
    try:
        address = ipaddress.ip_address(bare_host)
        host = str(address)
        is_ip = True
    except ValueError:
        host = host_of(bare_host, "url" if "/" in bare_host else "domain").strip().lower().rstrip(".")
        is_ip = False
    if not host:
        raise CollectorError("adapter target has no host")
    return AdapterTarget(
        raw=value, host=host, url="", scheme="", port=bare_port,
        is_ip=is_ip, is_cidr=False,
    )


def _option_text(options: dict, key: str, default: str = "") -> str:
    raw = options.get(key)
    if raw is None:
        return default
    if isinstance(raw, (list, tuple)):
        raw = ",".join(str(item) for item in raw)
    value = str(raw).strip()
    if not value:
        return default
    if len(value) > MAX_OPTION_LENGTH or any(
        ch in value for ch in ("\x00", "\n", "\r")
    ):
        raise CollectorError(f"adapter option {key!r} is invalid")
    return value


def _ports_option(options: dict, default: str = "") -> str:
    value = _option_text(options, "ports", default)
    if not value:
        return ""
    tokens = value.split(",")
    for token in tokens:
        if not _PORT_TOKEN_RE.fullmatch(token):
            raise CollectorError("ports must be a comma list of ports or ranges (1-65535)")
        for part in token.split("-"):
            port = int(part)
            if port < 1 or port > 65535:
                raise CollectorError("ports must be between 1 and 65535")
    return ",".join(tokens)


def _severity_option(options: dict) -> str:
    value = _option_text(options, "severity")
    if not value:
        return ""
    names = [item.strip().lower() for item in value.split(",") if item.strip()]
    bad = [name for name in names if name not in _SEVERITIES]
    if bad or not names:
        raise CollectorError(
            "severity must be a comma list of " + ", ".join(_SEVERITIES)
        )
    return ",".join(names)


def _int_option(options: dict, key: str, default: int, low: int, high: int) -> int:
    raw = options.get(key, default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise CollectorError(f"adapter option {key!r} must be an integer") from exc
    if value < low or value > high:
        raise CollectorError(f"adapter option {key!r} must be between {low} and {high}")
    return value


def _wordlist_option(options: dict) -> str:
    raw = _option_text(options, "wordlist")
    if not raw:
        raise CollectorError(
            "ffuf requires a 'wordlist' option pointing at a local wordlist file"
        )
    path = Path(raw).expanduser()
    if not path.is_file():
        raise CollectorError(f"ffuf wordlist does not exist: {raw}")
    if path.stat().st_size > 10 * 1024 * 1024:
        raise CollectorError("ffuf wordlist is larger than 10 MB")
    return str(path.resolve())


@dataclass(frozen=True)
class AdapterSpec:
    id: str
    binary: str
    label: str
    description: str
    phase: str
    version_args: tuple[str, ...] = ("--version",)
    scope_mode: str = "preflight_only"
    strict_policy: str = "never"  # always | ip_only | never
    timeout: int = DEFAULT_TIMEOUT
    max_output: int = DEFAULT_MAX_OUTPUT
    output_file: str = ""
    kinds: tuple[str, ...] = ("domain", "ip", "url")


@dataclass
class AdapterContext:
    target: AdapterTarget
    options: dict
    decision: ScopeDecision
    workdir: Path
    addresses: list[str] = field(default_factory=list)
    version: str = ""
    scope_mode: str = ""
    pinned: bool = False


@dataclass
class ToolRun:
    stdout: str
    stderr: str
    returncode: int | None
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False
    duration: float = 0.0


def _tool_env(workdir: Path) -> dict:
    """Environment allowlist for a tool run.

    Deliberately excludes proxy variables, BREADCRUMB_SECRET_KEY, notification
    tokens and every other application secret.
    """
    env = {}
    for key in ("PATH", "LANG", "LC_ALL", "TZ", "TERM"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    env["HOME"] = str(workdir)
    env["TMPDIR"] = str(workdir)
    env["NO_COLOR"] = "1"
    env["CI"] = "1"
    return env


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.terminate()
            except OSError:
                pass
    else:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=KILL_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass
    else:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass


def _read_capped(path: Path, cap: int) -> tuple[str, bool]:
    try:
        if not path.is_file():
            return "", False
        data = path.read_bytes()
    except OSError:
        return "", False
    truncated = len(data) > cap
    return data[:cap].decode("utf-8", errors="replace"), truncated


def run_tool(
    argv: list[str],
    *,
    workdir: Path,
    timeout: float,
    max_output: int,
    cancel_event: threading.Event | None = None,
) -> ToolRun:
    """Run one argv list with process-group cancellation and output caps."""
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise CollectorError("adapter argv must be a non-empty list of strings")
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=str(workdir),
            env=_tool_env(workdir),
            start_new_session=(os.name == "posix"),
            close_fds=True,
        )
    except FileNotFoundError as exc:
        raise CollectorError(f"tool binary not found: {argv[0]}") from exc
    except OSError as exc:
        raise CollectorError(f"could not start {argv[0]}: {exc}") from exc

    stdout = bytearray()
    stderr = bytearray()
    state = {"truncated": False, "overflow": threading.Event()}
    lock = threading.Lock()

    def reader(pipe, sink: bytearray) -> None:
        try:
            while True:
                chunk = pipe.read(READ_CHUNK)
                if not chunk:
                    break
                with lock:
                    remaining = max_output - len(sink)
                    if remaining > 0:
                        sink.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        state["truncated"] = True
                        state["overflow"].set()
        except (OSError, ValueError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    out_thread = threading.Thread(target=reader, args=(proc.stdout, stdout), daemon=True)
    err_thread = threading.Thread(target=reader, args=(proc.stderr, stderr), daemon=True)
    out_thread.start()
    err_thread.start()

    cancelled = False
    timed_out = False
    deadline = started + max(1.0, float(timeout))
    try:
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            if state["overflow"].is_set():
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.05)
        if cancelled or timed_out or state["overflow"].is_set():
            _terminate(proc)
        try:
            proc.wait(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            _terminate(proc)
    finally:
        out_thread.join(timeout=KILL_GRACE_SECONDS)
        err_thread.join(timeout=KILL_GRACE_SECONDS)
        if out_thread.is_alive() or err_thread.is_alive():
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass
    duration = time.monotonic() - started
    return ToolRun(
        stdout=bytes(stdout).decode("utf-8", errors="replace"),
        stderr=bytes(stderr).decode("utf-8", errors="replace"),
        returncode=proc.returncode,
        timed_out=timed_out,
        cancelled=cancelled,
        truncated=bool(state["truncated"]),
        duration=duration,
    )


def probe_version(binary: str, version_args: tuple[str, ...] = ("--version",)) -> str:
    """Return a short version string, cached by binary path and mtime."""
    path = shutil.which(binary) if not os.path.isabs(binary) else binary
    if not path or not os.path.isfile(path):
        return ""
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        mtime = 0
    key = (path, mtime, tuple(version_args))
    with _VERSION_LOCK:
        if key in _VERSION_CACHE:
            return _VERSION_CACHE[key]
    workdir = Path(tempfile.mkdtemp(prefix="breadcrumb-version-"))
    try:
        run = run_tool(
            [path, *version_args],
            workdir=workdir,
            timeout=VERSION_TIMEOUT,
            max_output=VERSION_MAX_OUTPUT,
        )
        text = (run.stdout or run.stderr or "").strip()
        first = next((line.strip() for line in text.splitlines() if line.strip()), "")
        value = first[:160]
    except Exception:  # noqa: BLE001  (version is metadata, never fatal)
        value = ""
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    with _VERSION_LOCK:
        _VERSION_CACHE[key] = value
    return value


def _scope_mode_for(spec: AdapterSpec, target: AdapterTarget) -> str:
    if spec.scope_mode == "passive":
        return "passive"
    if spec.scope_mode == "resolve_override":
        return "ip_literal" if target.is_ip else "resolve_override"
    if spec.scope_mode == "ip_literal":
        return "ip_literal" if (target.is_ip or target.is_cidr) else "preflight_only"
    return "preflight_only"


def _pinned_for(spec: AdapterSpec, target: AdapterTarget) -> bool:
    return _scope_mode_for(spec, target) in (
        "ip_literal", "resolve_override", "passive"
    )


def _strict_ok(spec: AdapterSpec, target: AdapterTarget) -> bool:
    if spec.strict_policy == "always":
        return True
    if spec.strict_policy == "ip_only":
        return target.is_ip or target.is_cidr
    return False


def _annotate(spec: AdapterSpec, output: str, stats: dict) -> str:
    """Prefix text artifacts with the scope decision.

    XML is left byte-for-byte intact because a leading comment before the XML
    declaration would break strict parsers. The scope decision still exists in
    the phase stats and job event for XML tools.
    """
    if not output.strip() or output.lstrip().startswith("<"):
        return output
    lines = [
        f"# breadcrumb adapter: {spec.id}",
        f"# scope_mode: {stats.get('scope_mode', '')}",
        f"# pinned: {str(bool(stats.get('pinned'))).lower()}",
        f"# scope: {stats.get('scope', {}).get('status', '')}",
        f"# tool_version: {stats.get('version', '') or 'unknown'}",
    ]
    return "\n".join(lines) + "\n" + output


class ToolAdapter(Collector):
    """Base class for external-tool adapters."""

    spec: AdapterSpec
    category = "external"

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def label(self) -> str:
        return self.spec.label

    @property
    def description(self) -> str:
        return self.spec.description

    def preflight(self, ctx: CollectorContext, target: AdapterTarget) -> ScopeDecision:
        if target.is_cidr:
            return ctx.check_network(target.raw)
        if target.url:
            return ctx.check_url(target.url)
        return ctx.check_host(target.host, port=target.port)

    def build_argv(self, actx: AdapterContext) -> list[str]:
        raise NotImplementedError

    def run(self, ctx: CollectorContext) -> CollectorResult:
        require_no_proxy(ctx)
        target = parse_target(ctx.target)
        decision = self.preflight(ctx, target)
        for warning in decision.warnings:
            ctx.emit_event("warning", warning, **decision.as_dict())

        scope_mode = _scope_mode_for(self.spec, target)
        pinned = _pinned_for(self.spec, target)
        if strict_mode() and not _strict_ok(self.spec, target):
            raise CollectorError(
                f"strict mode: {self.spec.id} cannot be pinned for "
                f"{target.host}; use a native collector or disable strict mode"
            )

        binary_path = shutil.which(self.spec.binary)
        if not binary_path:
            raise CollectorError(
                f"{self.spec.binary} is not installed on the executor PATH; "
                "install it or run the tool externally and post its output"
            )
        ctx.check_cancel()
        version = probe_version(binary_path, self.spec.version_args)
        ctx.check_cancel()

        if ctx.headers:
            ctx.emit_event(
                "warning",
                "external adapters do not receive header profiles; "
                "run the tool externally if authenticated requests are required",
            )

        workdir = Path(tempfile.mkdtemp(prefix=f"breadcrumb-{self.spec.id}-"))
        try:
            actx = AdapterContext(
                target=target,
                options=dict(ctx.options or {}),
                decision=decision,
                workdir=workdir,
                addresses=list(decision.addresses),
                version=version,
                scope_mode=scope_mode,
                pinned=pinned,
            )
            argv = self.build_argv(actx)
            if not argv or not all(isinstance(item, str) and item for item in argv):
                raise CollectorError(f"{self.spec.id} produced an invalid argv list")
            argv = [binary_path, *argv[1:]]
            ctx.emit_event(
                "phase",
                f"running {self.spec.id} ({scope_mode}"
                f"{', pinned' if pinned else ', preflight only'})",
                adapter=self.spec.id,
                argv=argv,
                scope_mode=scope_mode,
                pinned=pinned,
                version=version,
                scope=decision.as_dict(),
            )
            run = run_tool(
                argv,
                workdir=workdir,
                timeout=self.spec.timeout,
                max_output=self.spec.max_output,
                cancel_event=ctx.cancel_event,
            )
            if run.cancelled:
                raise JobCancelled("job cancellation requested")

            output = run.stdout
            file_truncated = False
            if self.spec.output_file:
                file_output, file_truncated = _read_capped(
                    workdir / self.spec.output_file, self.spec.max_output
                )
                if file_output.strip():
                    output = file_output
            truncated = run.truncated or file_truncated
            stats = {
                "adapter": self.spec.id,
                "binary": self.spec.binary,
                "version": version,
                "scope_mode": scope_mode,
                "pinned": pinned,
                "strict": strict_mode(),
                "scope": decision.as_dict(),
                "argv": argv,
                "returncode": run.returncode,
                "duration_ms": round(run.duration * 1000),
                "truncated": truncated,
                "warnings": list(decision.warnings),
            }
            if truncated:
                stats["warning"] = (
                    f"output capped at {self.spec.max_output} bytes; "
                    "the evidence artifact is truncated"
                )
                ctx.emit_event("warning", stats["warning"], **stats)

            error = None
            if run.timed_out:
                error = f"{self.spec.id} timed out after {self.spec.timeout}s"
            elif run.returncode not in (0, None) and not truncated:
                detail = (run.stderr or run.stdout or "").strip().splitlines()
                tail = detail[-1][:300] if detail else ""
                error = (
                    f"{self.spec.id} exited with status {run.returncode}"
                    + (f": {tail}" if tail else "")
                )
            if not error and not output.strip():
                error = f"{self.spec.id} produced no output"

            output = _annotate(self.spec, output, stats)
            if error:
                ctx.emit_event("error", error, **stats)
            return CollectorResult(
                [PhaseOutput(self.spec.phase, output, stats, error)], stats
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------- adapters ----


@register_adapter
class NmapAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="nmap",
        binary="nmap",
        label="Nmap adapter",
        description="Port/service discovery emitted as nmap XML for the existing parser.",
        phase="nmap",
        version_args=("--version",),
        scope_mode="ip_literal",
        strict_policy="ip_only",
        timeout=900,
        max_output=20 * 1024 * 1024,
        kinds=("domain", "ip", "cidr"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        argv = [
            "nmap", "-Pn", "-sT", "-sV", "--version-light", "-T4",
            "--max-retries", "2", "--host-timeout", "600s", "-oX", "-",
        ]
        ports = _ports_option(actx.options)
        if ports:
            argv.extend(["-p", ports])
        else:
            argv.extend(["--top-ports", "1000"])
        argv.append(actx.target.raw if actx.target.is_cidr else actx.target.host)
        return argv


@register_adapter
class HttpxAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="httpx",
        binary="httpx",
        label="httpx adapter",
        description="Live-host probing emitted as httpx JSONL for the existing parser.",
        phase="httpx",
        version_args=("-version",),
        scope_mode="resolve_override",
        strict_policy="always",
        timeout=300,
        max_output=10 * 1024 * 1024,
        kinds=("domain", "ip", "url"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        target = actx.target
        url = target.default_url()
        if not url:
            raise CollectorError("httpx requires a domain, IP or URL target")
        argv = [
            "httpx", "-silent", "-json", "-no-color", "-disable-update-check",
            "-timeout", "10", "-retries", "1", "-u", url,
        ]
        if not target.is_ip:
            address = actx.addresses[0] if actx.addresses else ""
            if not address:
                raise CollectorError("httpx resolve override needs a pinned address")
            port = target.port or (80 if url.startswith("http://") else 443)
            host = target.host
            argv.extend(["-resolve", f"{host}:{port}:{address}"])
        return argv


@register_adapter
class NucleiAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="nuclei",
        binary="nuclei",
        label="Nuclei adapter",
        description="Template scanning emitted as nuclei JSONL for the existing parser.",
        phase="nuclei",
        version_args=("-version",),
        scope_mode="preflight_only",
        strict_policy="never",
        timeout=900,
        max_output=20 * 1024 * 1024,
        kinds=("domain", "ip", "url"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        url = actx.target.default_url()
        if not url:
            raise CollectorError("nuclei requires a domain, IP or URL target")
        argv = [
            "nuclei", "-silent", "-jsonl", "-no-color", "-disable-update-check",
            "-timeout", "10", "-retries", "1", "-u", url,
        ]
        severity = _severity_option(actx.options)
        if severity:
            argv.extend(["-severity", severity])
        return argv


@register_adapter
class SubfinderAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="subfinder",
        binary="subfinder",
        label="Subfinder adapter",
        description="Passive subdomain enumeration emitted as a host list.",
        phase="subfinder",
        version_args=("-version",),
        scope_mode="passive",
        strict_policy="always",
        timeout=300,
        max_output=5 * 1024 * 1024,
        kinds=("domain",),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        target = actx.target
        if target.is_ip or target.is_cidr:
            raise CollectorError("subfinder requires a domain target")
        return [
            "subfinder", "-d", target.host, "-silent", "-no-color",
            "-disable-update-check",
        ]


@register_adapter
class NaabuAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="naabu",
        binary="naabu",
        label="Naabu adapter",
        description="Fast port scanning emitted as naabu JSONL.",
        phase="naabu",
        version_args=("-version",),
        scope_mode="ip_literal",
        strict_policy="ip_only",
        timeout=600,
        max_output=10 * 1024 * 1024,
        kinds=("domain", "ip"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        target = actx.target
        if target.is_cidr:
            raise CollectorError("naabu requires a domain or single IP target")
        argv = [
            "naabu", "-host", target.host, "-silent", "-json", "-no-color",
            "-disable-update-check", "-timeout", "5000",
        ]
        ports = _ports_option(actx.options)
        if ports:
            argv.extend(["-p", ports])
        else:
            argv.extend(["-top-ports", "1000"])
        return argv


@register_adapter
class MasscanAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="masscan",
        binary="masscan",
        label="Masscan adapter",
        description="Async port scanning emitted as masscan text.",
        phase="masscan",
        version_args=("--version",),
        scope_mode="ip_literal",
        strict_policy="always",
        timeout=600,
        max_output=5 * 1024 * 1024,
        kinds=("ip", "cidr"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        target = actx.target
        if not (target.is_ip or target.is_cidr):
            raise CollectorError(
                "masscan requires an IP or CIDR target; a hostname is refused "
                "so a shared address is never scanned by accident"
            )
        ports = _ports_option(actx.options, "1-1000")
        rate = _int_option(actx.options, "rate", 1000, 1, 100000)
        return [
            "masscan", target.raw, "-p", ports, "--rate", str(rate), "--wait", "3",
        ]


@register_adapter
class KatanaAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="katana",
        binary="katana",
        label="Katana adapter",
        description="Crawling emitted as a URL list for the existing URL parser.",
        phase="katana",
        version_args=("-version",),
        scope_mode="preflight_only",
        strict_policy="never",
        timeout=600,
        max_output=10 * 1024 * 1024,
        kinds=("url", "domain"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        url = actx.target.default_url()
        if not url:
            raise CollectorError("katana requires a domain, IP or URL target")
        depth = _int_option(actx.options, "depth", 3, 1, 5)
        rate = _int_option(actx.options, "rate", 150, 1, 100000)
        return [
            "katana", "-u", url, "-silent", "-no-color", "-d", str(depth),
            "-rl", str(rate), "-timeout", "10",
        ]


@register_adapter
class FfufAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="ffuf",
        binary="ffuf",
        label="ffuf adapter",
        description="Content discovery emitted as ffuf JSON.",
        phase="ffuf",
        version_args=("-V",),
        scope_mode="preflight_only",
        strict_policy="never",
        timeout=600,
        max_output=20 * 1024 * 1024,
        output_file="ffuf.json",
        kinds=("url", "domain"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        url = actx.target.default_url()
        if not url:
            raise CollectorError("ffuf requires a domain, IP or URL target")
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        wordlist = _wordlist_option(actx.options)
        return [
            "ffuf", "-u", url, "-w", wordlist, "-of", "json",
            "-o", str(actx.workdir / self.spec.output_file),
            "-s", "-noninteractive", "-t", "20", "-timeout", "10",
        ]


@register_adapter
class DalfoxAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="dalfox",
        binary="dalfox",
        label="Dalfox adapter",
        description="Parameter/XSS analysis emitted as Dalfox JSON candidates.",
        phase="dalfox",
        version_args=("version",),
        scope_mode="preflight_only",
        strict_policy="never",
        timeout=600,
        max_output=20 * 1024 * 1024,
        output_file="dalfox.json",
        kinds=("url",),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        url = actx.target.default_url()
        if not url:
            raise CollectorError("dalfox requires a URL target")
        return [
            "dalfox", "url", url, "--silence", "--no-spinner",
            "--format", "json", "-o", str(actx.workdir / self.spec.output_file),
        ]


@register_adapter
class AmassAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="amass",
        binary="amass",
        label="Amass adapter",
        description="Attack-surface enumeration emitted as Amass JSON.",
        phase="amass",
        version_args=("-version",),
        scope_mode="passive",
        strict_policy="always",
        timeout=900,
        max_output=20 * 1024 * 1024,
        output_file="amass.json",
        kinds=("domain",),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        target = actx.target
        if target.is_ip or target.is_cidr:
            raise CollectorError("amass requires a domain target")
        return [
            "amass", "enum", "-d", target.host, "-silent",
            "-json", str(actx.workdir / self.spec.output_file),
        ]


@register_adapter
class WhatWebAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="whatweb",
        binary="whatweb",
        label="WhatWeb adapter",
        description="Technology fingerprinting emitted as WhatWeb JSON.",
        phase="whatweb",
        version_args=("--version",),
        scope_mode="preflight_only",
        strict_policy="never",
        timeout=300,
        max_output=10 * 1024 * 1024,
        output_file="whatweb.json",
        kinds=("url", "domain"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        url = actx.target.default_url()
        if not url:
            raise CollectorError("whatweb requires a domain, IP or URL target")
        return [
            "whatweb", f"--log-json={actx.workdir / self.spec.output_file}",
            "--no-errors", url,
        ]


@register_adapter
class Wafw00fAdapter(ToolAdapter):
    spec = AdapterSpec(
        id="wafw00f",
        binary="wafw00f",
        label="wafw00f adapter",
        description="WAF fingerprinting emitted as wafw00f JSON.",
        phase="wafw00f",
        version_args=("--version",),
        scope_mode="preflight_only",
        strict_policy="never",
        timeout=300,
        max_output=5 * 1024 * 1024,
        output_file="wafw00f.json",
        kinds=("url", "domain"),
    )

    def build_argv(self, actx: AdapterContext) -> list[str]:
        url = actx.target.default_url()
        if not url:
            raise CollectorError("wafw00f requires a domain, IP or URL target")
        return [
            "wafw00f", url, "-o", str(actx.workdir / self.spec.output_file),
            "-f", "json", "-a",
        ]


def adapter_specs() -> list[AdapterSpec]:
    from .base import ADAPTER_REGISTRY

    return [ADAPTER_REGISTRY[key].spec for key in sorted(ADAPTER_REGISTRY)]
