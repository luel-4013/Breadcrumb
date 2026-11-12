"""Local release-gate checks for Breadcrumb.

Everything here runs offline against the checkout. It is deliberately boring:
parse requirements pins, walk tracked source for a few dangerous constructs,
look for obvious credential shapes, and verify that relative documentation
links and reference pages still point at real files.

The checker is not a substitute for a security review. It exists so the
repeatable parts of that review run on every release instead of being retyped
from memory.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    "htmlcov",
}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".html",
    ".css",
    ".js",
    ".json",
    ".sh",
}

DANGEROUS_PATTERNS = (
    ("shell_true", re.compile(r"shell\s*=\s*True")),
    ("os.system", re.compile(r"\bos\.system\s*\(")),
    ("eval", re.compile(r"(?<![.\w])eval\s*\(")),
    ("exec", re.compile(r"(?<![.\w])exec\s*\(")),
)

SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)

# Test fixtures deliberately contain fake credentials so the secret scanner
# and redaction paths have something to find. They are not live credentials.
ALLOWED_FAKE_SECRETS = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAABCDEFGHIJKLMNOP",
}

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
CLI_REFERENCE = "docs/CLI_REFERENCE.md"
API_REFERENCE = "docs/API_REFERENCE.md"


def _tracked_files(root: Path) -> list[Path]:
    """Return tracked text files, or a filesystem walk outside a git checkout."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=True,
            capture_output=True,
        )
        names = [name for name in result.stdout.decode("utf-8").split("\0") if name]
        return [root / name for name in names]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            files.append(path)
        return files


def _is_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def scan_dangerous_patterns(root: Path = ROOT) -> list[dict]:
    """Find shell execution and dynamic-eval constructs in shipped code."""
    findings: list[dict] = []
    for path in _tracked_files(root):
        relative = _relative(path, root)
        if not relative.startswith(("app/", "scripts/")) and relative != "run.py":
            continue
        if not _is_text(path):
            continue
        for number, line in enumerate(_read(path).splitlines(), 1):
            for name, pattern in DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "file": relative,
                            "line": number,
                            "pattern": name,
                            "text": line.strip()[:160],
                        }
                    )
    return findings


def scan_secrets(root: Path = ROOT) -> list[dict]:
    """Find credential-shaped strings in tracked text files.

    Matches are masked in the result. Known fake fixtures are ignored; any
    other match is treated as a release blocker until a human confirms it.
    """
    findings: list[dict] = []
    for path in _tracked_files(root):
        if any(part in SKIP_DIRS for part in path.parts) or not _is_text(path):
            continue
        relative = _relative(path, root)
        for number, line in enumerate(_read(path).splitlines(), 1):
            for name, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    value = match.group(0)
                    if value in ALLOWED_FAKE_SECRETS:
                        continue
                    findings.append(
                        {
                            "file": relative,
                            "line": number,
                            "pattern": name,
                            "preview": value[:4] + "…",
                        }
                    )
    return findings


def _link_target(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    target = target.split()[0]
    return target.split("#", 1)[0]


def check_docs_links(root: Path = ROOT) -> list[dict]:
    """Return relative Markdown links that do not resolve to a real file."""
    broken: list[dict] = []
    candidates = [root / "README.md", root / "CONTRIBUTING.md", root / "CHANGELOG.md"]
    candidates.extend(sorted((root / "docs").glob("*.md")))
    for path in candidates:
        if not path.is_file():
            continue
        for number, line in enumerate(_read(path).splitlines(), 1):
            for match in LINK_RE.finditer(line):
                target = _link_target(match.group(1))
                if not target or target.startswith(
                    ("http://", "https://", "mailto:", "tel:", "#", "/")
                ):
                    continue
                resolved = (path.parent / target).resolve()
                try:
                    resolved.relative_to(root.resolve())
                except ValueError:
                    broken.append(
                        {
                            "file": _relative(path, root),
                            "line": number,
                            "target": target,
                            "reason": "outside repository",
                        }
                    )
                    continue
                if not resolved.exists():
                    broken.append(
                        {
                            "file": _relative(path, root),
                            "line": number,
                            "target": target,
                            "reason": "missing",
                        }
                    )
    return broken


def _requirement_pins(path: Path) -> list[tuple[str, str]]:
    pins: list[tuple[str, str]] = []
    for line in _read(path).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        if "==" not in line:
            pins.append((line, ""))
            continue
        name, version = line.split("==", 1)
        name = name.split("[", 1)[0].strip()
        pins.append((name, version.split(";", 1)[0].strip()))
    return pins


def check_dependencies(root: Path = ROOT) -> dict:
    """Verify direct runtime pins are installed at the pinned versions."""
    runtime = _requirement_pins(root / "requirements.txt")
    development = _requirement_pins(root / "requirements-dev.txt")
    missing: list[dict] = []
    unpinned: list[str] = []
    for name, version in runtime:
        if not version:
            unpinned.append(name)
            continue
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            missing.append({"package": name, "expected": version, "installed": ""})
            continue
        if installed != version:
            missing.append(
                {"package": name, "expected": version, "installed": installed}
            )
    return {
        "runtime_pins": len(runtime),
        "development_pins": len(development),
        "unpinned_runtime": unpinned,
        "mismatches": missing,
        "ok": not unpinned and not missing,
    }


def _cli_commands(root: Path) -> set[str]:
    """Read the command names without importing the whole web application."""
    text = _read(root / "app" / "cli.py")
    return set(
        re.findall(r"(?<![A-Za-z_])sub\.add_parser\(\s*[\"']([a-z0-9-]+)[\"']", text)
    )


def check_cli_reference(root: Path = ROOT) -> list[str]:
    """Return CLI commands missing from docs/CLI_REFERENCE.md."""
    reference = _read(root / CLI_REFERENCE)
    return sorted(
        command
        for command in _cli_commands(root)
        if f"`{command}" not in reference and f"breadcrumb {command}" not in reference
    )


def _api_routes(root: Path) -> set[tuple[str, str]]:
    text = _read(root / "app" / "main.py")
    routes = set()
    for method, path in re.findall(
        r"@app\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']", text
    ):
        if path.startswith("/api/v1") or path in {"/health", "/backup/restore"}:
            routes.add((method.upper(), path))
    return routes


def check_api_reference(root: Path = ROOT) -> list[str]:
    """Return documented API routes that are missing from API_REFERENCE.md."""
    reference = _read(root / API_REFERENCE)
    missing = []
    for method, path in sorted(_api_routes(root)):
        if path not in reference:
            missing.append(f"{method} {path}")
    return missing


def release_report(root: Path = ROOT) -> dict:
    """Run every local release gate and return a JSON-serializable report."""
    from . import __version__
    from .db import SCHEMA_VERSION

    dangerous = scan_dangerous_patterns(root)
    secrets = scan_secrets(root)
    links = check_docs_links(root)
    dependencies = check_dependencies(root)
    cli_missing = check_cli_reference(root)
    api_missing = check_api_reference(root)
    files = _tracked_files(root)
    checks = {
        "dangerous_code": {
            "ok": not dangerous,
            "count": len(dangerous),
            "findings": dangerous,
        },
        "secrets": {"ok": not secrets, "count": len(secrets), "findings": secrets},
        "docs_links": {"ok": not links, "count": len(links), "findings": links},
        "dependencies": dependencies,
        "cli_reference": {"ok": not cli_missing, "missing": cli_missing},
        "api_reference": {"ok": not api_missing, "missing": api_missing},
    }
    return {
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "tracked_files": len(files),
        "checks": checks,
        "ok": all(check.get("ok") for check in checks.values()),
    }


def write_checksums(paths: list[Path], output: Path) -> Path:
    """Write a ``sha256sum -c`` compatible file for release artifacts."""
    lines = []
    for path in sorted(paths):
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        lines.append(f"{digest}  {Path(path).name}")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def report_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
