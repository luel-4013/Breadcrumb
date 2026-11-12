#!/usr/bin/env python3
"""Dependency audit for Breadcrumb release candidates.

Offline by default: verifies that every direct runtime pin is installed at the
pinned version and prints the inventory. With ``--online``, sends only package
names and versions to the OSV batch API and reports known vulnerabilities. No
database, target, capture or user data is sent.

This is a release-time script, not a startup check. The application itself
never calls OSV or any other network service.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def pins(path: Path) -> list[tuple[str, str]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "==" not in line:
            continue
        name, version = line.split("==", 1)
        rows.append((name.split("[", 1)[0].strip(), version.strip()))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true", help="query OSV for known CVEs")
    parser.add_argument("-o", "--output", default="")
    args = parser.parse_args(argv)

    runtime = pins(ROOT / "requirements.txt")
    inventory = []
    failures = []
    for name, expected in runtime:
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = ""
        inventory.append(
            {"package": name, "expected": expected, "installed": installed}
        )
        if installed != expected:
            failures.append(
                f"{name}: expected {expected}, installed {installed or 'missing'}"
            )

    result: dict = {
        "runtime": inventory,
        "failures": failures,
        "online": bool(args.online),
        "vulnerabilities": [],
    }
    if args.online:
        body = json.dumps(
            {
                "queries": [
                    {
                        "package": {"name": name, "ecosystem": "PyPI"},
                        "version": expected,
                    }
                    for name, expected in runtime
                ]
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            OSV_BATCH,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"OSV query failed: {type(exc).__name__}: {exc}")
            payload = {"results": []}
        for (name, version), item in zip(runtime, payload.get("results", [])):
            for vuln in item.get("vulns", []):
                result["vulnerabilities"].append(
                    {
                        "package": name,
                        "version": version,
                        "id": vuln.get("id"),
                        "summary": vuln.get("summary", ""),
                    }
                )
        if result["vulnerabilities"]:
            failures.append(
                f"{len(result['vulnerabilities'])} known vulnerability record(s)"
            )

    result["ok"] = not failures
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {output}")
    print(text)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
