"""`breadcrumb doctor`: diagnose the first-run and first-mile failures.

The check is read-only by default. It never creates a database, key, or
directory; it reports what is missing and gives the exact command to fix it.
This is the antidote to "install succeeded, nothing works" support threads.
"""

from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .db import DB_PATH, SCHEMA_VERSION

OPTIONAL_TOOLS = (
    "nmap",
    "httpx",
    "nuclei",
    "subfinder",
    "amass",
    "bbot",
    "ffuf",
    "dalfox",
    "naabu",
    "whatweb",
    "wafw00f",
)


def _check(name: str, status: str, detail: str, fix: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def _db_path() -> Path:
    return Path(DB_PATH)


def _port_available(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _check_python() -> dict:
    version = sys.version_info
    if version < (3, 10):
        return _check(
            "python",
            "fail",
            f"Python {version.major}.{version.minor}.{version.micro}; Breadcrumb needs 3.10+",
            "Install Python 3.12 and recreate the virtualenv.",
        )
    status = "ok" if version >= (3, 12) else "warn"
    return _check(
        "python",
        status,
        f"Python {version.major}.{version.minor}.{version.micro}",
        "" if status == "ok" else "Python 3.12 is the tested runtime.",
    )


def _check_sqlite() -> dict:
    version = sqlite3.sqlite_version_info
    if version < (3, 35):
        return _check(
            "sqlite",
            "fail",
            f"SQLite {sqlite3.sqlite_version}; needs 3.35+ for reliable upserts",
            "Use a newer Python/SQLite build.",
        )
    return _check("sqlite", "ok", f"SQLite {sqlite3.sqlite_version}")


def _check_paths() -> list[dict]:
    path = _db_path()
    parent = path.parent
    checks: list[dict] = []
    if parent.exists() and parent.is_dir():
        writable = os.access(parent, os.W_OK)
        checks.append(
            _check(
                "database_directory",
                "ok" if writable else "fail",
                f"{parent} ({'writable' if writable else 'not writable'})",
                "" if writable else f"chmod u+w {parent}",
            )
        )
        try:
            free = shutil.disk_usage(parent).free
            status = "ok" if free >= 100 * 1024 * 1024 else "warn"
            checks.append(
                _check(
                    "disk_space",
                    status,
                    f"{free / (1024 * 1024):.1f} MiB free in {parent}",
                    "" if status == "ok" else "Free at least 100 MiB before importing.",
                )
            )
        except OSError as exc:  # noqa: BLE001
            checks.append(_check("disk_space", "warn", f"could not measure: {exc}"))
    else:
        checks.append(
            _check(
                "database_directory",
                "fail",
                f"{parent} does not exist",
                f"mkdir -p {parent}",
            )
        )
    if path.exists():
        readable = os.access(path, os.R_OK)
        checks.append(
            _check(
                "database_file",
                "ok" if readable else "fail",
                f"{path} ({path.stat().st_size} bytes)",
                "" if readable else f"chmod u+r {path}",
            )
        )
    else:
        checks.append(
            _check(
                "database_file",
                "warn",
                f"{path} does not exist yet (created on first run)",
                "Run `python -m app.cli serve` or `python -m app.cli demo`.",
            )
        )
    return checks


def _check_database() -> list[dict]:
    path = _db_path()
    if not path.exists() or path.stat().st_size == 0:
        return [
            _check(
                "database_integrity",
                "warn",
                "database not created yet",
                "Run `python -m app.cli demo` to create and seed it.",
            )
        ]
    checks: list[dict] = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        try:
            row = conn.execute("PRAGMA quick_check").fetchone()
            ok = bool(row and row[0] == "ok")
            checks.append(
                _check(
                    "database_integrity",
                    "ok" if ok else "fail",
                    str(row[0] if row else "no result"),
                    "" if ok else "Restore from a backup; do not edit the file by hand.",
                )
            )
            try:
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            except sqlite3.DatabaseError:
                mode = "unknown"
            checks.append(
                _check(
                    "wal_mode",
                    "ok" if str(mode).lower() == "wal" else "warn",
                    f"journal_mode={mode}",
                    "" if str(mode).lower() == "wal" else "Open the database once with the app to enable WAL.",
                )
            )
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "appstate" in tables:
                state = conn.execute(
                    "SELECT schema_version FROM appstate WHERE id=1"
                ).fetchone()
                found = int(state[0]) if state else 0
                status = "ok" if found == SCHEMA_VERSION else "warn"
                checks.append(
                    _check(
                        "schema_version",
                        status,
                        f"found {found}, expected {SCHEMA_VERSION}",
                        "" if status == "ok" else "Start the app once to run the additive migration.",
                    )
                )
            else:
                checks.append(
                    _check(
                        "schema_version",
                        "warn",
                        "appstate table missing (pre-0.4 file?)",
                        "Back up the file, then start the app to migrate it.",
                    )
                )
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        checks.append(
            _check(
                "database_integrity",
                "fail",
                f"could not open database: {exc}",
                "Check permissions and restore a known-good backup.",
            )
        )
    return checks


def _check_key() -> dict:
    from .secrets_store import _env_key_values, _key_file_path

    env_keys = _env_key_values()
    if env_keys:
        return _check(
            "secret_key",
            "ok",
            "BREADCRUMB_SECRET_KEY(S) is set (environment keys take precedence)",
        )
    path = _key_file_path()
    if path.exists():
        mode = oct(path.stat().st_mode & 0o777)
        status = "ok" if os.access(path, os.R_OK) else "fail"
        return _check(
            "secret_key",
            status,
            f"{path} (mode {mode})",
            "" if status == "ok" else f"chmod u+r {path}",
        )
    old = Path(str(path) + ".old")
    if old.exists():
        return _check(
            "secret_key",
            "warn",
            f"only the rotation backup exists: {old}",
            "Restore it to the key-file path or set BREADCRUMB_SECRET_KEY.",
        )
    return _check(
        "secret_key",
        "warn",
        f"{path} does not exist yet (created on first encrypted header profile)",
        "Back it up separately from the database once it exists.",
    )


def _check_port() -> dict:
    host = os.environ.get("BREADCRUMB_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("BREADCRUMB_PORT", "8787"))
    except ValueError:
        return _check("port", "fail", "BREADCRUMB_PORT is not an integer", "Set BREADCRUMB_PORT=8787.")
    if _port_available(host, port):
        return _check("port", "ok", f"{host}:{port} is available")
    return _check(
        "port",
        "warn",
        f"{host}:{port} is already in use (Breadcrumb may already be running)",
        f"Use --port {port + 1} or stop the other process.",
    )


def _check_parsers() -> dict:
    from .parsers import REGISTRY, load_all, parser_catalog

    try:
        load_all()
    except Exception as exc:  # noqa: BLE001
        return _check("parsers", "fail", f"parser registry failed: {exc}", "Reinstall requirements.")
    names = sorted(item["name"] for item in parser_catalog())
    return _check(
        "parsers",
        "ok" if len(REGISTRY) >= 20 else "warn",
        f"{len(REGISTRY)} parser(s): {', '.join(names)}",
        "" if len(REGISTRY) >= 20 else "The parser registry is smaller than expected.",
    )


def _check_tools() -> dict:
    found = []
    missing = []
    for binary in OPTIONAL_TOOLS:
        path = shutil.which(binary)
        if path:
            found.append(f"{binary}={path}")
        else:
            missing.append(binary)
    return _check(
        "optional_tools",
        "ok" if found else "warn",
        f"found {len(found)}/{len(OPTIONAL_TOOLS)}"
        + (f": {', '.join(found)}" if found else ""),
        ""
        if not missing
        else f"Optional, not required: {', '.join(missing)}. Import their output instead.",
    )


def run_checks() -> dict:
    checks = [_check_python(), _check_sqlite()]
    checks.extend(_check_paths())
    checks.extend(_check_database())
    checks.append(_check_key())
    checks.append(_check_port())
    checks.append(_check_parsers())
    checks.append(_check_tools())
    counts = {"ok": 0, "warn": 0, "fail": 0}
    for item in checks:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "ok": counts["fail"] == 0,
        "version": __version__,
        "database": str(_db_path()),
        "schema_version": SCHEMA_VERSION,
        "checks": checks,
        "summary": counts,
    }


def format_report(report: dict) -> str:
    lines = [
        f"Breadcrumb doctor {report.get('version')}",
        f"database: {report.get('database')} (schema {report.get('schema_version')})",
        "",
    ]
    for item in report.get("checks", []):
        mark = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}.get(item["status"], "?   ")
        lines.append(f"[{mark}] {item['name']}: {item['detail']}")
        if item.get("fix"):
            lines.append(f"       fix: {item['fix']}")
    summary = report.get("summary", {})
    lines += [
        "",
        f"{summary.get('ok', 0)} ok, {summary.get('warn', 0)} warning(s), "
        f"{summary.get('fail', 0)} failure(s).",
    ]
    return "\n".join(lines)
