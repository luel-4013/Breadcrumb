"""Offline review bundle for a report.

A bundle is a single zip a researcher can email or hand to a reviewer. It is
read-only, needs no server and no login, and contains:

* ``report.html`` — the printable, self-contained report
* ``report.md`` / ``report.json`` — machine-readable copies of the same context
* ``report.pdf`` — optional, when requested
* ``manifest.json`` — file hashes, report metadata, capture list
* ``manifest.sha256`` — hash of the manifest itself
* ``SHA256SUMS`` — ``sha256sum -c`` compatible checksums for the payload
* ``README.txt`` — what is inside and how to verify it offline
* ``comments.md`` — optional reviewer comments
* ``evidence/capture-*.json`` — redacted evidence manifests per capture

The zip never includes raw capture bodies. Evidence manifests are redacted by
default; an explicit ``reveal`` report disables masking in both report and
manifest, and the verifier reports that as a warning.

Verification is in-memory: no extraction, so a hostile zip cannot write outside
the working directory. Path traversal, duplicate names, symlinks, oversized
archives, missing files, wrong hashes and broken capture-manifest chains all
fail the check.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import Path

from sqlmodel import Session, func, select

from . import __version__, report_templates
from .db import SCHEMA_VERSION
from .manifest import build_manifest, verify_manifest_data
from .models import Paste, Program
from .redaction import RedactionPolicy, policy_from

BUNDLE_VERSION = 1
MAX_ENTRIES = 256
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_CAPTURES = 100

_HASH_KEYS = {
    "sha256",
    "redacted_sha256",
    "chain_hash",
    "prev_chain_hash",
    "in_sha256",
    "out_sha256",
    "content_sha256",
    "manifest_sha256",
}
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def _json_bytes(value) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        + "\n"
    ).encode("utf-8")


def _redact_json(value, policy: RedactionPolicy):
    """Apply per-report rules to free text without touching integrity hashes."""
    if isinstance(value, dict):
        return {
            key: (
                item
                if str(key) in _HASH_KEYS
                else _redact_json(item, policy)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item, policy) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_json(item, policy) for item in value)
    if isinstance(value, str):
        return policy.text(value)
    return value


def _record(path: str, data: bytes) -> dict:
    return {"path": path, "bytes": len(data), "sha256": sha256_bytes(data)}


def _safe_path(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    if _WINDOWS_DRIVE.match(name):
        return False
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    return True


def _capture_files(
    session: Session, program_id: int, policy: RedactionPolicy
) -> tuple[dict[str, bytes], list[dict], int]:
    total = int(
        session.exec(
            select(func.count()).select_from(Paste).where(Paste.program_id == program_id)
        ).one()
        or 0
    )
    pastes = session.exec(
        select(Paste)
        .where(Paste.program_id == program_id)
        .order_by(Paste.id.desc())
        .limit(MAX_CAPTURES)
    ).all()
    pastes.reverse()
    files: dict[str, bytes] = {}
    records: list[dict] = []
    for paste in pastes:
        manifest = build_manifest(session, paste, redact=policy.enabled)
        manifest = _redact_json(manifest, policy)
        data = _json_bytes(manifest)
        path = f"evidence/capture-{paste.id:04d}.json"
        files[path] = data
        records.append(
            {
                "id": paste.id,
                "path": path,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "created_at": manifest.get("capture", {}).get("created_at"),
                "redacted_output_sha256": manifest.get("output", {}).get(
                    "redacted_sha256"
                ),
                "chain_hash": manifest.get("chain", {}).get("chain_hash"),
            }
        )
    return files, records, total


def _readme(manifest: dict) -> bytes:
    report = manifest.get("report") or {}
    lines = [
        "BREADCRUMB REVIEW BUNDLE",
        "=" * 24,
        "",
        f"Report:       {report.get('title') or 'Breadcrumb report'}",
        f"Program:      {(report.get('program') or {}).get('name') or 'unknown'}",
        f"Template:     {report.get('template_name') or report.get('template') or 'report'}",
        f"Reference:    {report.get('reference') or '-'}",
        f"Generated:    {report.get('generated_at') or '-'}",
        f"Classification: {report.get('confidentiality_label') or 'CONFIDENTIAL'}",
        "",
        "What is inside",
        "--------------",
        "- report.html: printable report (open it in any browser)",
        "- report.md: Markdown copy for HackerOne, Git, or a ticket",
        "- report.json: the same redacted context for automation",
        "- manifest.json: report metadata and SHA-256 for every file",
        "- manifest.sha256: SHA-256 of manifest.json",
        "- SHA256SUMS: sha256sum-compatible checksums for the payload",
        "- evidence/capture-*.json: redacted evidence manifest per capture",
        "- comments.md: reviewer comments (when supplied)",
        "",
        "What is NOT inside",
        "------------------",
        "Raw capture bodies, authentication cookies, tokens and secret values are",
        "not included. Evidence manifests contain hashes and redacted metadata.",
        "The raw evidence stays in the researcher's local Breadcrumb database.",
        "",
        "Verify offline",
        "--------------",
        "  python -m app.cli verify-bundle <this-file>.zip",
        "",
        "Or, after extracting the zip:",
        "",
        "  sha256sum -c SHA256SUMS",
        "  sha256sum -c manifest.sha256",
        "",
        "No account, server, network call or Breadcrumb installation is required to",
        "read the report. The verifier only needs the zip file.",
        "",
    ]
    if not (report.get("redaction") or {}).get("enabled", True):
        lines.insert(
            8,
            "WARNING: masking was explicitly disabled for this bundle (reveal).\n"
            "Do not share it outside the authorized assessment team.\n",
        )
    return "\n".join(lines).encode("utf-8")


def build_bundle(
    session: Session,
    program_id: int,
    template_id: str = "hackerone",
    values: dict | None = None,
    *,
    comments: str = "",
    include_pdf: bool = False,
    generated_at=None,
) -> tuple[bytes, dict]:
    """Render one report context into a deterministic, verifiable zip."""
    context = report_templates.build_context(
        session,
        program_id,
        template_id,
        values,
        generated_at=generated_at,
    )
    validated = report_templates.validate_variables(template_id, values)
    policy = policy_from(
        reveal=validated["reveal"],
        profile=validated["redaction_profile"],
        rules_text=validated["redaction_rules"],
    )
    program = session.get(Program, program_id)
    if program is None:
        raise report_templates.TemplateError(
            "program not found", ["program not found"]
        )

    files: dict[str, bytes] = {
        "report.md": str(report_templates.render(context, "md")).encode("utf-8"),
        "report.html": str(report_templates.render(context, "html")).encode("utf-8"),
        "report.json": str(report_templates.render(context, "json")).encode("utf-8"),
    }
    if include_pdf:
        files["report.pdf"] = bytes(report_templates.render(context, "pdf"))

    evidence_files, capture_records, captures_total = _capture_files(
        session, program_id, policy
    )
    files.update(evidence_files)

    safe_comments = policy.text(comments or "").strip()
    if safe_comments:
        files["comments.md"] = (
            "# Reviewer comments\n\n"
            "These comments are local notes exported with the report. They are\n"
            "read-only for the reviewer.\n\n"
            f"{safe_comments}\n"
        ).encode("utf-8")

    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "generator": {
            "name": "breadcrumb",
            "version": __version__,
            "schema_version": SCHEMA_VERSION,
        },
        "created_at": context["generated_at"],
        "report": {
            "title": context["title"],
            "reference": context["report_reference"],
            "template": context["template"]["id"],
            "template_name": context["template"]["name"],
            "program": {
                "id": context["program"]["id"],
                "name": context["program"]["name"],
            },
            "report_date": context["report_date"],
            "generated_at": context["generated_at"],
            "confidentiality": context["confidentiality"],
            "confidentiality_label": context["confidentiality_label"],
            "redaction": context["redaction"],
            "reveal": bool(validated["reveal"]),
        },
        "captures": capture_records,
        "captures_total": captures_total,
        "captures_included": len(capture_records),
        "comments": {
            "included": bool(safe_comments),
            "path": "comments.md" if safe_comments else None,
        },
        "limits": {
            "max_entries": MAX_ENTRIES,
            "max_uncompressed_bytes": MAX_UNCOMPRESSED_BYTES,
            "max_captures": MAX_CAPTURES,
        },
        "verify": {
            "command": "python -m app.cli verify-bundle <this-file>.zip",
            "network_required": False,
            "extraction_required": False,
        },
    }
    files["README.txt"] = _readme(manifest)

    payload_records = [_record(path, data) for path, data in sorted(files.items())]
    sums = "".join(f"{item['sha256']}  {item['path']}\n" for item in payload_records)
    files["SHA256SUMS"] = sums.encode("utf-8")
    payload_records.append(_record("SHA256SUMS", files["SHA256SUMS"]))
    manifest["files"] = sorted(payload_records, key=lambda item: item["path"])
    manifest["file_count"] = len(manifest["files"])
    manifest_bytes = _json_bytes(manifest)
    manifest_sha = sha256_bytes(manifest_bytes)
    files["manifest.json"] = manifest_bytes
    files["manifest.sha256"] = f"{manifest_sha}  manifest.json\n".encode("utf-8")

    ordered = sorted(files)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ordered:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, files[name])
    manifest["bundle_sha256"] = sha256_bytes(buffer.getvalue())
    return buffer.getvalue(), manifest


def bundle_filename(manifest_or_context: dict) -> str:
    data = manifest_or_context or {}
    report = data.get("report") if "report" in data else data
    reference = (report or {}).get("reference") or (report or {}).get(
        "report_reference"
    )
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", str(reference or "breadcrumb-review")).strip(
        "-"
    )
    return f"{base or 'breadcrumb-review'}-review.zip"


def verify_bundle(data: bytes) -> dict:
    """Verify a bundle without extracting it or touching the network."""
    checks: list[dict] = []
    warnings: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    try:
        archive = zipfile.ZipFile(io.BytesIO(data or b""))
    except Exception as exc:  # noqa: BLE001 - hostile input must not raise
        return {
            "valid": False,
            "checks": [
                {
                    "name": "zip_readable",
                    "ok": False,
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            ],
            "warnings": [],
            "manifest": {},
            "summary": {},
        }

    try:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        check("non_empty", bool(infos))
        check(
            "entry_limit",
            len(infos) <= MAX_ENTRIES,
            f"{len(infos)} entries, limit {MAX_ENTRIES}",
        )
        check(
            "no_duplicate_entries",
            len(names) == len(set(names)),
            "duplicate zip entries",
        )
        bad_paths = [name for name in names if not _safe_path(name)]
        check("path_safety", not bad_paths, ", ".join(bad_paths[:5]))
        check(
            "no_encrypted_entries",
            all(not (info.flag_bits & 0x1) for info in infos),
            "encrypted entries cannot be reviewed offline",
        )
        symlinks = [
            info.filename
            for info in infos
            if stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF)
        ]
        check("no_symlinks", not symlinks, ", ".join(symlinks[:5]))
        total_bytes = sum(info.file_size for info in infos)
        check(
            "uncompressed_size_limit",
            total_bytes <= MAX_UNCOMPRESSED_BYTES,
            f"{total_bytes} bytes, limit {MAX_UNCOMPRESSED_BYTES}",
        )
        required = {"manifest.json", "manifest.sha256", "report.html", "report.md", "report.json"}
        check("required_files", required <= set(names), ", ".join(sorted(required - set(names))))
        if "manifest.json" not in names:
            return {
                "valid": False,
                "checks": checks,
                "warnings": warnings,
                "manifest": {},
                "summary": {},
            }
        raw_manifest = archive.read("manifest.json")
        manifest = json.loads(raw_manifest.decode("utf-8"))
        check(
            "manifest_version",
            int(manifest.get("bundle_version") or 0) == BUNDLE_VERSION,
            f"expected {BUNDLE_VERSION}",
        )
        if "manifest.sha256" in names:
            expected = (
                archive.read("manifest.sha256").decode("utf-8", errors="replace").split()
                or [""]
            )[0]
            check(
                "manifest_sha256",
                expected == sha256_bytes(raw_manifest),
                f"expected {expected}",
            )
        else:
            check("manifest_sha256", False, "manifest.sha256 missing")

        listed = {
            item.get("path"): item
            for item in (manifest.get("files") or [])
            if item.get("path")
        }
        extra = set(names) - set(listed) - {"manifest.json", "manifest.sha256"}
        check("no_unlisted_files", not extra, ", ".join(sorted(extra)[:5]))
        missing = sorted(set(listed) - set(names))
        check("all_listed_files_present", not missing, ", ".join(missing[:5]))
        file_ok = True
        for path, item in listed.items():
            if path not in names:
                continue
            content = archive.read(path)
            if len(content) != item.get("bytes") or sha256_bytes(content) != item.get(
                "sha256"
            ):
                file_ok = False
                check(f"file_hash:{path}", False, "size or sha256 mismatch")
        check("payload_hashes", file_ok)

        if "SHA256SUMS" in names:
            sums_ok = True
            for line in archive.read("SHA256SUMS").decode(
                "utf-8", errors="replace"
            ).splitlines():
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                digest, path = parts
                if path not in names:
                    sums_ok = False
                    check(f"checksum_file:{path}", False, "listed file is missing")
                    continue
                if sha256_bytes(archive.read(path)) != digest:
                    sums_ok = False
                    check(f"checksum_hash:{path}", False, "sha256 mismatch")
            check("sha256sums", sums_ok)
        else:
            check("sha256sums", False, "SHA256SUMS missing")

        captures = manifest.get("captures") or []
        check(
            "capture_limit",
            len(captures) <= MAX_CAPTURES,
            f"{len(captures)} captures, limit {MAX_CAPTURES}",
        )
        captures_ok = True
        for capture in captures:
            path = capture.get("path")
            if not path or path not in names:
                captures_ok = False
                check(f"capture_present:{path}", False, "capture manifest missing")
                continue
            try:
                nested = json.loads(archive.read(path).decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                captures_ok = False
                check(f"capture_json:{path}", False, str(exc))
                continue
            nested_ok = int(nested.get("manifest_version") or 0) >= 2
            check(f"capture_version:{path}", nested_ok)
            check(
                f"capture_id:{path}",
                (nested.get("capture") or {}).get("id") == capture.get("id"),
            )
            chain = verify_manifest_data(nested)
            check(f"capture_chain:{path}", chain.get("valid", False))
            check(
                f"capture_redacted_hash:{path}",
                bool((nested.get("output") or {}).get("redacted_sha256")),
            )
            if not (nested_ok and chain.get("valid")):
                captures_ok = False
        check("capture_manifests", captures_ok)

        report_info = manifest.get("report") or {}
        redaction = report_info.get("redaction") or {}
        if redaction.get("enabled") is False or report_info.get("reveal"):
            warnings.append(
                "redaction is disabled in this bundle (reveal); treat it as "
                "internal-only and do not share it externally"
            )
        check("redaction_metadata", bool(report_info.get("redaction")))
        return {
            "valid": all(item["ok"] for item in checks),
            "checks": checks,
            "warnings": warnings,
            "manifest": manifest,
            "summary": {
                "title": report_info.get("title"),
                "reference": report_info.get("reference"),
                "template": report_info.get("template"),
                "files": manifest.get("file_count"),
                "captures": manifest.get("captures_included"),
                "captures_total": manifest.get("captures_total"),
                "redaction": redaction.get("profile"),
                "comments": bool((manifest.get("comments") or {}).get("included")),
            },
        }
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to a reviewer
        check("bundle_readable", False, f"{type(exc).__name__}: {exc}")
        return {
            "valid": False,
            "checks": checks,
            "warnings": warnings,
            "manifest": {},
            "summary": {},
        }
    finally:
        archive.close()


def verify_bundle_file(path: str | Path) -> dict:
    return verify_bundle(Path(path).expanduser().read_bytes())
