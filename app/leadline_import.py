"""One-way, read-only importer for a Leadline SQLite database (Phase 8).

Design rules (from ``docs/LEADLINE_MERGE_PLAN.md`` section 18):

* the source database is opened with ``mode=ro`` and is never modified;
* ``--dry-run`` reads and reports only; it writes no destination rows;
* a real import backs up the destination, runs under maintenance mode, and
  commits the mapped rows in one transaction;
* a JSON manifest records the source-ID -> destination-ID map so an
  interrupted import can resume without duplicating rows;
* imported scans are historical ``ScanJob`` rows (``runner=leadline.imported``)
  that the durable worker can never claim, retry, or re-run;
* custom headers are stored only through the encrypted ``HeaderProfile``
  columns. If encryption is unavailable the whole import aborts rather than
  leaving plaintext credentials in the destination database;
* malformed or duplicate source rows are reported and skipped; they do not
  abort the rest of the import;
* the evidence-chain formula is not involved because the importer does not
  fabricate captures. Imported findings and graph observations are marked with
  their Leadline source IDs and scan IDs in ``meta``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlmodel import Session, select

from . import history, triage
from .db import (
    DB_PATH,
    backup_database,
    engine,
    get_app_state,
    init_db,
    set_maintenance,
)
from .models import (
    Entity,
    Finding,
    HeaderProfile,
    JobAttempt,
    JobEvent,
    Program,
    Relationship,
    ScanJob,
    ScanPhase,
    Target,
)

IMPORT_RUNNER = "leadline.imported"
IMPORT_SOURCE = "leadline-import"
DEFAULT_PROGRAM = "Leadline import"
MANIFEST_VERSION = 1
MAX_JSON_BYTES = 200_000
SAMPLE_LIMIT = 10

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ALIASES = {
    "moderate": "medium",
    "informational": "info",
    "warning": "medium",
    "none": "info",
}

SCAN_STATUS = {
    "completed": "done",
    "complete": "done",
    "done": "done",
    "failed": "failed",
    "error": "failed",
    "stopped": "cancelled",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "running": "cancelled",
    "pending": "cancelled",
    "queued": "cancelled",
}

PHASE_STATUS = {
    "completed": "done",
    "complete": "done",
    "done": "done",
    "failed": "failed",
    "error": "failed",
    "stopped": "cancelled",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "running": "cancelled",
    "pending": "cancelled",
    "queued": "cancelled",
}

NODE_TYPE_MAP = {
    "root": "target",
    "endpoint": "endpoint",
    "api": "endpoint",
    "admin": "endpoint",
    "debug": "endpoint",
    "javascript": "path",
    "static": "path",
    "parameter": "param",
    "param": "param",
    "domain": "domain",
    "subdomain": "subdomain",
    "ip": "ip",
    "cidr": "cidr",
    "port": "port",
    "service": "service",
    "tech": "tech",
    "url": "url",
    "path": "path",
    "cve": "cve",
    "header": "header",
    "cookie": "cookie",
    "finding": "finding",
    "evidence": "evidence",
    "note": "note",
}


class LeadlineImportError(RuntimeError):
    """A source or destination problem that should abort the import."""


class SourceChangedError(LeadlineImportError):
    """The source database changed while it was being read."""


@dataclass
class SourceDB:
    path: Path
    sha256: str
    size: int
    tables: dict[str, list[dict[str, Any]]]
    columns: dict[str, set[str]]
    warnings: list[str] = field(default_factory=list)

    def rows(self, table: str) -> list[dict[str, Any]]:
        return self.tables.get(table, [])

    def count(self, table: str) -> int:
        return len(self.rows(table))


# ---------------------------------------------------------------------------
# source reading / fingerprints
# ---------------------------------------------------------------------------


def source_fingerprint(path: str | Path) -> tuple[str, int]:
    """Hash the main SQLite file and its WAL, if present.

    The source is opened read-only, but another process could still be writing
    to it. Hashing both files before and after the read makes a concurrent
    change visible instead of silently importing a torn snapshot.
    """
    path = Path(path)
    digest = hashlib.sha256()
    total = 0
    for candidate in (path, Path(str(path) + "-wal")):
        if not candidate.exists():
            continue
        digest.update(candidate.name.encode("utf-8"))
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                total += len(chunk)
    return digest.hexdigest(), total


def read_source(path: str | Path) -> SourceDB:
    """Read every Leadline table through a read-only SQLite connection."""
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise LeadlineImportError(f"source database does not exist: {path}")
    if not path.is_file():
        raise LeadlineImportError(f"source is not a file: {path}")

    before_hash, before_size = source_fingerprint(path)
    uri = f"{path.as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=30.0)
    except sqlite3.Error as exc:
        raise LeadlineImportError(f"could not open {path} read-only: {exc}") from exc
    connection.row_factory = sqlite3.Row
    tables: dict[str, list[dict[str, Any]]] = {}
    columns: dict[str, set[str]] = {}
    warnings: list[str] = []
    try:
        connection.execute("PRAGMA query_only=ON")
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "targets" not in names:
            raise LeadlineImportError(
                f"{path} is not a Leadline database: missing targets table"
            )
        for table in ("targets", "scans", "scan_events", "findings", "graph_nodes"):
            if table not in names:
                tables[table] = []
                columns[table] = set()
                warnings.append(f"source has no {table} table; treated as empty")
                continue
            columns[table] = {
                str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
            }
            tables[table] = [
                dict(row) for row in connection.execute(f"SELECT * FROM {table}")
            ]
    except sqlite3.Error as exc:
        raise LeadlineImportError(f"could not read {path}: {exc}") from exc
    finally:
        connection.close()

    after_hash, after_size = source_fingerprint(path)
    if after_hash != before_hash or after_size != before_size:
        raise SourceChangedError(
            "source database changed while it was being read; stop any Leadline "
            "process and run the import again"
        )
    return SourceDB(
        path=path,
        sha256=before_hash,
        size=before_size,
        tables=tables,
        columns=columns,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# value helpers
# ---------------------------------------------------------------------------


def _int_id(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _parse_dt(value: Any) -> datetime | None:
    """Parse Leadline/SQLite timestamps into timezone-aware UTC datetimes."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%f",
            ):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _json_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _cap_json(value: Any, limit: int = MAX_JSON_BYTES) -> Any:
    """Keep structured data when it fits; otherwise return a labeled preview."""
    if value is None:
        return None
    text = _json_text(value)
    size = len(text.encode("utf-8"))
    if size <= limit:
        return value
    return {
        "truncated": True,
        "original_bytes": size,
        "preview": text[:limit],
    }


def _decode_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def _effective_triage(row: dict[str, Any]) -> tuple[str, str]:
    status = str(row.get("triage_status") or "open").strip().lower()
    if bool(row.get("is_false_positive")):
        status = "false_positive"
    if status not in triage.TRIAGE_STATUSES:
        return "open", (
            f"finding {row.get('id')}: unknown triage_status {status!r}; "
            "imported as open"
        )
    return status, ""


def _normalize_severity(value: Any) -> tuple[str, str]:
    severity = str(value or "info").strip().lower()
    severity = SEVERITY_ALIASES.get(severity, severity)
    if severity not in SEVERITIES:
        return "info", f"unknown severity {value!r}; imported as info"
    return severity, ""


def _headers_hash(headers: dict[str, str]) -> str:
    payload = json.dumps(headers, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_headers(row: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Return a safe header dict and warnings; never store control characters."""
    raw = row.get("custom_headers")
    warnings: list[str] = []
    if raw is None or raw == "":
        return {}, warnings
    value = _decode_json(raw)
    if not isinstance(value, dict):
        warnings.append(
            f"target {row.get('id')}: custom_headers is not a JSON object; ignored"
        )
        return {}, warnings
    headers: dict[str, str] = {}
    for key, item in value.items():
        name = str(key).strip()
        if not name or any(char in name for char in "\x00\r\n"):
            warnings.append(
                f"target {row.get('id')}: ignored a header with an invalid name"
            )
            continue
        if isinstance(item, (dict, list)):
            text = json.dumps(item, ensure_ascii=False)
        else:
            text = str(item)
        if any(char in text for char in "\x00\r\n"):
            warnings.append(
                f"target {row.get('id')}: ignored header {name!r} with control characters"
            )
            continue
        headers[name] = text
    return headers, warnings


def _target_identity(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return ``(display_name, kind, raw_url, host)`` for a Leadline target.

    Leadline stores a mix of bare hosts, host:port values, URLs and CIDRs.
    Breadcrumb's ``Target.kind`` drives attribution, so the importer maps the
    shape rather than forcing every value into a URL.
    """
    raw_url = str(row.get("url") or "").strip()
    name = str(row.get("name") or "").strip()
    if not raw_url:
        raise ValueError("missing url")
    if not name:
        name = raw_url
    if any(char in raw_url for char in "\x00\r\n"):
        raise ValueError("url contains control characters")

    if "://" in raw_url:
        parsed = urlsplit(raw_url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported URL scheme {scheme!r}")
        if not parsed.hostname:
            raise ValueError("url has no host")
        return raw_url, "url", raw_url, parsed.hostname.lower().rstrip(".")

    # A bare CIDR is not a URL path.
    if "/" in raw_url:
        try:
            network = ipaddress.ip_network(raw_url, strict=False)
            return raw_url, "cidr", raw_url, str(network.network_address)
        except ValueError:
            pass

    try:
        address = ipaddress.ip_address(raw_url)
        return raw_url, "ip", raw_url, str(address)
    except ValueError:
        pass

    try:
        parsed = urlsplit("//" + raw_url)
    except ValueError as exc:
        raise ValueError(f"malformed url: {exc}") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("url has no host")
    if parsed.port is not None or (parsed.path and parsed.path != "/"):
        return raw_url, "url", raw_url, host
    try:
        ipaddress.ip_address(host)
        kind = "ip"
    except ValueError:
        kind = "domain"
    return raw_url, kind, raw_url, host


def _target_notes(row: dict[str, Any]) -> str | None:
    notes = str(row.get("notes") or "").strip()
    if not bool(row.get("is_active", True)):
        marker = "[Leadline: target was inactive at import]"
        notes = (notes + "\n\n" if notes else "") + marker
    return notes or None


def _finding_fingerprint(target_url: str, scan_id: int, finding_id: int) -> str:
    payload = f"{target_url}|{scan_id}|{finding_id}".encode("utf-8")
    return "leadline:" + hashlib.sha256(payload).hexdigest()[:32]


def _node_entity_type(node_type: Any) -> tuple[str, str]:
    key = str(node_type or "").strip().lower()
    return NODE_TYPE_MAP.get(key, "endpoint"), key


def _scan_error(status: str, source_error: Any) -> str | None:
    error = str(source_error or "").strip()
    if error:
        return error
    if status in ("failed",):
        return "Leadline scan failed"
    if status in ("stopped", "cancelled", "canceled"):
        return "Leadline scan was stopped"
    if status in ("pending", "queued", "running"):
        return (
            f"Imported from Leadline while the source scan was still {status}; "
            "it was not resumed"
        )
    return None


# ---------------------------------------------------------------------------
# dry-run / source report
# ---------------------------------------------------------------------------


def _source_report(source: SourceDB) -> dict[str, Any]:
    warnings = list(source.warnings)
    errors: list[dict[str, Any]] = []
    targets = source.rows("targets")
    scans = source.rows("scans")
    events = source.rows("scan_events")
    findings = source.rows("findings")
    nodes = source.rows("graph_nodes")

    valid_targets: dict[int, dict[str, Any]] = {}
    target_headers: dict[int, dict[str, str]] = {}
    header_sets: set[str] = set()
    for row in targets:
        source_id = _int_id(row.get("id"))
        if source_id is None:
            errors.append({"table": "targets", "id": None, "reason": "missing id"})
            continue
        try:
            _target_identity(row)
        except ValueError as exc:
            errors.append({"table": "targets", "id": source_id, "reason": str(exc)})
            continue
        headers, header_warnings = _parse_headers(row)
        warnings.extend(header_warnings)
        valid_targets[source_id] = row
        target_headers[source_id] = headers
        if headers:
            header_sets.add(_headers_hash(headers))

    valid_scans: dict[int, dict[str, Any]] = {}
    for row in scans:
        scan_id = _int_id(row.get("id"))
        if scan_id is None:
            errors.append({"table": "scans", "id": None, "reason": "missing id"})
            continue
        target_id = _int_id(row.get("target_id"))
        if target_id not in valid_targets:
            errors.append(
                {
                    "table": "scans",
                    "id": scan_id,
                    "reason": f"target {target_id!r} is missing or malformed",
                }
            )
            continue
        valid_scans[scan_id] = row

    valid_events = [
        row for row in events if _int_id(row.get("scan_id")) in valid_scans
    ]
    valid_findings: list[dict[str, Any]] = []
    for row in findings:
        if _int_id(row.get("scan_id")) not in valid_scans:
            continue
        if _int_id(row.get("id")) is None:
            errors.append(
                {"table": "findings", "id": None, "reason": "missing id"}
            )
            continue
        valid_findings.append(row)
    valid_nodes: list[dict[str, Any]] = []
    for row in nodes:
        if _int_id(row.get("scan_id")) not in valid_scans:
            continue
        node_id = str(row.get("node_id") or "").strip()
        label = str(row.get("label") or node_id).strip()
        if not node_id or not label:
            errors.append(
                {
                    "table": "graph_nodes",
                    "id": _int_id(row.get("id")),
                    "reason": "missing node_id or label",
                }
            )
            continue
        valid_nodes.append(row)

    triage_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    for row in valid_findings:
        status, warning = _effective_triage(row)
        if warning:
            warnings.append(warning)
        triage_counts[status] += 1
        severity, warning = _normalize_severity(row.get("severity"))
        if warning:
            warnings.append(warning)
        severity_counts[severity] += 1

    scan_status: Counter[str] = Counter(
        str(row.get("status") or "unknown").strip().lower() for row in scans
    )
    phase_status: Counter[str] = Counter(
        str(row.get("status") or "unknown").strip().lower() for row in events
    )

    def sample_target(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": _int_id(row.get("id")),
            "name": str(row.get("name") or ""),
            "url": str(row.get("url") or ""),
            "is_active": bool(row.get("is_active", True)),
            "has_custom_headers": bool(target_headers.get(_int_id(row.get("id")) or -1)),
            "notes": (str(row.get("notes") or "")[:160] or None),
        }

    def sample_finding(row: dict[str, Any]) -> dict[str, Any]:
        status, _ = _effective_triage(row)
        severity, _ = _normalize_severity(row.get("severity"))
        return {
            "id": _int_id(row.get("id")),
            "scan_id": _int_id(row.get("scan_id")),
            "type": str(row.get("finding_type") or ""),
            "severity": severity,
            "title": str(row.get("title") or "")[:160],
            "triage_status": status,
            "has_extra_data": bool(row.get("extra_data")),
        }

    counts = {
        "targets": len(targets),
        "scans": len(scans),
        "events": len(events),
        "findings": len(findings),
        "graph_nodes": len(nodes),
    }
    would_import = {
        "targets": len(valid_targets),
        "scans": len(valid_scans),
        "events": len(valid_events),
        "findings": len(valid_findings),
        "graph_nodes": len(valid_nodes),
        "header_profiles": len(header_sets),
    }
    return {
        "source": {
            "path": str(source.path),
            "sha256": source.sha256,
            "size": source.size,
            "tables": {key: len(value) for key, value in source.tables.items()},
        },
        "counts": counts,
        "would_import": would_import,
        "distinct_header_sets": len(header_sets),
        "triage": dict(sorted(triage_counts.items())),
        "severity": dict(sorted(severity_counts.items())),
        "scan_status": dict(sorted(scan_status.items())),
        "phase_status": dict(sorted(phase_status.items())),
        "malformed_targets": [
            item for item in errors if item["table"] == "targets"
        ],
        "malformed_scans": [item for item in errors if item["table"] == "scans"],
        "errors": errors,
        "warnings": warnings,
        "sample": {
            "targets": [sample_target(row) for row in targets[:5]],
            "scans": [
                {
                    "id": _int_id(row.get("id")),
                    "target_id": _int_id(row.get("target_id")),
                    "status": str(row.get("status") or ""),
                    "progress": row.get("progress"),
                    "current_phase": row.get("current_phase"),
                }
                for row in scans[:5]
            ],
            "findings": [sample_finding(row) for row in findings[:5]],
            "graph_nodes": [
                {
                    "id": _int_id(row.get("id")),
                    "scan_id": _int_id(row.get("scan_id")),
                    "node_id": str(row.get("node_id") or ""),
                    "node_type": str(row.get("node_type") or ""),
                    "label": str(row.get("label") or ""),
                    "depth": _int_id(row.get("depth")),
                }
                for row in nodes[:5]
            ],
        },
    }


def _destination_summary(
    *, program_id: int | None = None, program_name: str = DEFAULT_PROGRAM
) -> dict[str, Any]:
    """Read-only summary of the destination for dry-run output."""
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return {"exists": False, "program": None, "counts": {}}
    try:
        connection = sqlite3.connect(
            f"{DB_PATH.resolve().as_uri()}?mode=ro", uri=True, timeout=10.0
        )
    except sqlite3.Error as exc:
        return {"exists": True, "error": str(exc), "program": None, "counts": {}}
    connection.row_factory = sqlite3.Row
    try:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        program = None
        if "program" in names:
            if program_id is not None:
                row = connection.execute(
                    "SELECT id, name FROM program WHERE id = ?", (program_id,)
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT id, name FROM program WHERE name = ?", (program_name,)
                ).fetchone()
            if row is not None:
                program = {"id": int(row["id"]), "name": row["name"]}
        counts: dict[str, int] = {}
        if program is not None:
            pid = program["id"]
            if "target" in names:
                counts["targets"] = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM target WHERE program_id = ? "
                        "AND meta LIKE '%leadline_source_id%'",
                        (pid,),
                    ).fetchone()[0]
                )
            if "scanjob" in names:
                counts["scans"] = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM scanjob WHERE program_id = ? "
                        "AND runner = ?",
                        (pid, IMPORT_RUNNER),
                    ).fetchone()[0]
                )
            if "finding" in names:
                counts["findings"] = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM finding WHERE program_id = ? "
                        "AND source_tool = 'leadline'",
                        (pid,),
                    ).fetchone()[0]
                )
            if "entity" in names:
                counts["graph_entities"] = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM entity WHERE program_id = ? "
                        "AND parser = ?",
                        (pid, IMPORT_SOURCE),
                    ).fetchone()[0]
                )
        return {"exists": True, "program": program, "counts": counts}
    except sqlite3.Error as exc:
        return {"exists": True, "error": str(exc), "program": None, "counts": {}}
    finally:
        connection.close()


def dry_run(
    source_path: str | Path,
    *,
    program_id: int | None = None,
    program_name: str = DEFAULT_PROGRAM,
) -> dict[str, Any]:
    """Inspect a source database and report what a real import would do."""
    source = read_source(source_path)
    report = _source_report(source)
    report["destination"] = _destination_summary(
        program_id=program_id, program_name=program_name
    )
    report["program"] = {
        "id": program_id,
        "name": program_name,
        "would_create": (
            program_id is None
            and (report["destination"].get("program") is None)
        ),
    }
    report["dry_run"] = True
    return report


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def default_manifest_path() -> Path:
    return Path(str(DB_PATH) + ".leadline-import.json")


def _empty_manifest(source_path: Path | None = None) -> dict[str, Any]:
    return {
        "version": MANIFEST_VERSION,
        "source": {
            "path": str(source_path) if source_path else "",
            "sha256": "",
            "size": 0,
        },
        "program_id": None,
        "program_name": "",
        "imported_at": None,
        "targets": {},
        "scans": {},
        "findings": {},
        "graph_nodes": {},
        "header_profiles": {},
        "counts": {},
    }


def _load_manifest(
    path: Path | None, source_path: Path
) -> tuple[dict[str, Any], list[str]]:
    manifest = _empty_manifest(source_path)
    warnings: list[str] = []
    if path is None or not path.exists():
        return manifest, warnings
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warnings.append(f"manifest {path} could not be read: {exc}; starting fresh")
        return manifest, warnings
    if not isinstance(loaded, dict):
        warnings.append(f"manifest {path} is not a JSON object; starting fresh")
        return manifest, warnings
    previous = (loaded.get("source") or {}).get("path")
    if previous and Path(previous).expanduser().resolve() != source_path.resolve():
        warnings.append(
            f"manifest belongs to {previous}, not {source_path}; its ID map is ignored"
        )
        return manifest, warnings
    for key in ("targets", "scans", "findings", "graph_nodes", "header_profiles"):
        if isinstance(loaded.get(key), dict):
            manifest[key] = loaded[key]
    manifest["program_id"] = loaded.get("program_id")
    manifest["program_name"] = loaded.get("program_name") or ""
    manifest["source"] = loaded.get("source") or manifest["source"]
    manifest["counts"] = loaded.get("counts") or {}
    return manifest, warnings


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _manifest_id(manifest: dict[str, Any], table: str, source_id: Any) -> int | None:
    try:
        return int(manifest.get(table, {}).get(str(source_id)))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# destination writes
# ---------------------------------------------------------------------------


def _resolve_program(
    session: Session,
    program_id: int | None,
    program_name: str,
    source_path: Path,
) -> tuple[Program, bool]:
    if program_id is not None:
        program = session.get(Program, program_id)
        if program is None:
            raise LeadlineImportError(f"destination program #{program_id} does not exist")
        return program, False
    program = session.exec(select(Program).where(Program.name == program_name)).first()
    if program is not None:
        return program, False
    program = Program(
        name=program_name,
        platform="leadline",
        scope_in="",
        scope_out="",
        notes=f"Leadline import source: {source_path}",
    )
    session.add(program)
    session.flush()
    return program, True


def _ensure_header_profile(
    session: Session,
    headers: dict[str, str],
    manifest: dict[str, Any],
    cache: dict[str, int],
) -> tuple[int | None, bool]:
    if not headers:
        return None, False
    key = _headers_hash(headers)
    if key in cache:
        return cache[key], False
    mapped = manifest.get("header_profiles", {}).get(key)
    if mapped is not None:
        try:
            profile = session.get(HeaderProfile, int(mapped))
        except (TypeError, ValueError):
            profile = None
        if profile is not None:
            cache[key] = profile.id
            return profile.id, False
    name = f"Leadline import {key[:12]}"
    profile = session.exec(select(HeaderProfile).where(HeaderProfile.name == name)).first()
    created = profile is None
    if profile is None:
        # EncryptedJSON performs the encryption on flush. If the key is
        # missing/unavailable this raises and the caller rolls back the whole
        # import instead of writing plaintext.
        profile = HeaderProfile(name=name, family="leadline", headers=dict(headers))
        session.add(profile)
        session.flush()
    cache[key] = profile.id
    return profile.id, created


def _import_targets(
    session: Session,
    source: SourceDB,
    program: Program,
    manifest: dict[str, Any],
    counts: dict[str, Any],
    warnings: list[str],
    errors: list[dict[str, Any]],
) -> tuple[dict[int, int], dict[int, dict[str, Any]]]:
    target_map: dict[int, int] = {}
    target_meta: dict[int, dict[str, Any]] = {}
    header_cache: dict[str, int] = {}
    now = datetime.now(timezone.utc)

    existing_by_source: dict[int, Target] = {}
    for target in session.exec(select(Target).where(Target.program_id == program.id)).all():
        source_id = (target.meta or {}).get("leadline_source_id")
        if source_id is not None:
            existing_by_source[int(source_id)] = target

    for row in source.rows("targets"):
        source_id = _int_id(row.get("id"))
        if source_id is None:
            errors.append({"table": "targets", "id": None, "reason": "missing id"})
            continue
        try:
            display, kind, raw_url, _host = _target_identity(row)
        except ValueError as exc:
            errors.append({"table": "targets", "id": source_id, "reason": str(exc)})
            continue
        headers, header_warnings = _parse_headers(row)
        warnings.extend(header_warnings)

        target = existing_by_source.get(source_id)
        if target is None:
            mapped = _manifest_id(manifest, "targets", source_id)
            if mapped is not None:
                candidate = session.get(Target, mapped)
                if candidate is not None and candidate.program_id == program.id:
                    target = candidate
        if target is not None:
            target_map[source_id] = target.id
            profile_id = (target.meta or {}).get("leadline_header_profile_id")
            if headers and profile_id is None:
                profile_id, created = _ensure_header_profile(
                    session, headers, manifest, header_cache
                )
                if profile_id is not None:
                    target.meta = {
                        **(target.meta or {}),
                        "leadline_header_profile_id": profile_id,
                    }
                    session.add(target)
                    manifest["header_profiles"][_headers_hash(headers)] = profile_id
                    if created:
                        counts["imported"]["header_profiles"] += 1
            target_meta[source_id] = {
                "row": row,
                "headers": headers,
                "profile_id": profile_id,
                "target": target,
            }
            counts["skipped"]["targets"] += 1
            manifest["targets"][str(source_id)] = target.id
            continue

        meta = {
            "leadline_source_id": source_id,
            "leadline_name": str(row.get("name") or ""),
            "leadline_url": raw_url,
            "leadline_is_active": bool(row.get("is_active", True)),
            "leadline_created_at": _iso(_parse_dt(row.get("created_at"))),
            "leadline_updated_at": _iso(_parse_dt(row.get("updated_at"))),
            "leadline_headers_hash": _headers_hash(headers) if headers else "",
            "import_source": str(source.path),
            "imported_at": now.isoformat(),
        }
        target = Target(
            program_id=program.id,
            name=display,
            kind=kind,
            notes=_target_notes(row),
            meta=meta,
            created_at=_parse_dt(row.get("created_at")) or now,
        )
        session.add(target)
        session.flush()

        profile_id, profile_created = _ensure_header_profile(
            session, headers, manifest, header_cache
        )
        if profile_id is not None:
            target.meta = {
                **target.meta,
                "leadline_header_profile_id": profile_id,
            }
            session.add(target)
            manifest["header_profiles"][_headers_hash(headers)] = profile_id
            if profile_created:
                counts["imported"]["header_profiles"] += 1

        target_map[source_id] = target.id
        target_meta[source_id] = {
            "row": row,
            "headers": headers,
            "profile_id": profile_id,
            "target": target,
        }
        counts["imported"]["targets"] += 1
        manifest["targets"][str(source_id)] = target.id

    return target_map, target_meta


def _build_finding(
    row: dict[str, Any],
    *,
    program_id: int,
    target_id: int,
    target_url: str,
    source_path: Path,
    now: datetime,
    warnings: list[str],
) -> tuple[Finding | None, str | None]:
    finding_id = _int_id(row.get("id"))
    scan_id = _int_id(row.get("scan_id"))
    if finding_id is None:
        return None, "missing id"
    if scan_id is None:
        return None, "missing scan_id"
    title = str(row.get("title") or "").strip() or f"Imported finding #{finding_id}"
    severity, severity_warning = _normalize_severity(row.get("severity"))
    if severity_warning:
        warnings.append(f"finding {finding_id}: {severity_warning}")
    triage_status, triage_warning = _effective_triage(row)
    if triage_warning:
        warnings.append(triage_warning)

    extra = _decode_json(row.get("extra_data"))
    if isinstance(extra, str):
        extra = {"raw": extra}
    if not isinstance(extra, dict):
        extra = {"value": extra} if extra is not None else {}
    location = str(row.get("location") or "").strip()
    evidence = str(row.get("evidence") or "").strip()
    if location and evidence and location not in evidence:
        combined = f"{location}  -> {evidence}"
    else:
        combined = location or evidence or None

    finding_type = str(row.get("finding_type") or "").strip()
    tags = ["leadline-imported"]
    if finding_type:
        tags.append(finding_type)
    extra_tags = extra.get("tags") if isinstance(extra, dict) else None
    if isinstance(extra_tags, list):
        tags.extend(str(tag).strip() for tag in extra_tags if str(tag).strip())
    if isinstance(extra, dict):
        for key in ("cve", "cve_id"):
            cve = extra.get(key)
            if cve:
                tags.append(str(cve).upper())
                tags.append("cve")
                break
    tags = list(dict.fromkeys(tags))

    cvss = None
    if isinstance(extra, dict):
        value = extra.get("cvss") or extra.get("cvss_score")
        if value not in (None, ""):
            cvss = str(value)

    meta = {
        "leadline_finding_id": finding_id,
        "leadline_scan_id": scan_id,
        "leadline_finding_type": finding_type or None,
        "leadline_location": location or None,
        "leadline_extra_data": _cap_json(extra),
        "leadline_is_false_positive": bool(row.get("is_false_positive")),
        "leadline_triage_status": str(row.get("triage_status") or "open"),
        "leadline_triage_note": str(row.get("triage_note") or "").strip() or None,
        "leadline_triaged_at": _iso(_parse_dt(row.get("triaged_at"))),
        "leadline_created_at": _iso(_parse_dt(row.get("created_at"))),
        "import_source": str(source_path),
        "imported_at": now.isoformat(),
    }
    created_at = _parse_dt(row.get("created_at")) or now
    updated_at = _parse_dt(row.get("triaged_at")) or created_at
    finding = Finding(
        program_id=program_id,
        target_id=target_id,
        paste_id=None,
        title=title,
        severity=severity,
        cvss=cvss,
        description=str(row.get("description") or "").strip() or None,
        evidence=combined,
        remediation=str(row.get("remediation") or "").strip() or None,
        tags=tags,
        fingerprint=_finding_fingerprint(target_url, scan_id, finding_id),
        source_tool="leadline",
        meta=meta,
        created_at=created_at,
        updated_at=updated_at,
    )
    triage.apply_triage(
        finding,
        triage_status,
        str(row.get("triage_note") or "").strip() or None,
    )
    # apply_triage stamps "now"; keep the source timestamps on a historical row.
    finding.created_at = created_at
    finding.updated_at = updated_at
    return finding, None


def _import_scans(
    session: Session,
    source: SourceDB,
    program: Program,
    target_map: dict[int, int],
    target_meta: dict[int, dict[str, Any]],
    manifest: dict[str, Any],
    counts: dict[str, Any],
    warnings: list[str],
    errors: list[dict[str, Any]],
) -> list[int]:
    imported_job_ids: list[int] = []
    now = datetime.now(timezone.utc)

    def group(rows: Iterable[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
        grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            scan_id = _int_id(row.get("scan_id"))
            if scan_id is not None:
                grouped[scan_id].append(row)
        return grouped

    events_by_scan = group(source.rows("scan_events"))
    findings_by_scan = group(source.rows("findings"))
    nodes_by_scan = group(source.rows("graph_nodes"))

    existing_by_source: dict[int, ScanJob] = {}
    for job in session.exec(
        select(ScanJob).where(
            ScanJob.program_id == program.id, ScanJob.runner == IMPORT_RUNNER
        )
    ).all():
        source_id = (job.params or {}).get("leadline_source_id")
        if source_id is not None:
            existing_by_source[int(source_id)] = job

    existing_finding_ids: dict[str, int] = {}
    for fingerprint, finding_id in session.exec(
        select(Finding.fingerprint, Finding.id).where(
            Finding.program_id == program.id,
            Finding.source_tool == "leadline",
        )
    ).all():
        if fingerprint and finding_id is not None:
            existing_finding_ids[fingerprint] = int(finding_id)
    existing_fingerprints = set(existing_finding_ids)
    existing_entity_norms = {
        normalized
        for normalized in session.exec(
            select(Entity.normalized).where(
                Entity.program_id == program.id, Entity.parser == IMPORT_SOURCE
            )
        ).all()
        if normalized
    }
    existing_relationships = {
        (rel.src_value, rel.dst_value, rel.rel_type)
        for rel in session.exec(
            select(Relationship).where(
                Relationship.program_id == program.id,
                Relationship.source == IMPORT_SOURCE,
            )
        ).all()
    }

    for row in source.rows("scans"):
        scan_id = _int_id(row.get("id"))
        if scan_id is None:
            errors.append({"table": "scans", "id": None, "reason": "missing id"})
            continue
        target_source_id = _int_id(row.get("target_id"))
        if target_source_id not in target_map:
            errors.append(
                {
                    "table": "scans",
                    "id": scan_id,
                    "reason": f"target {target_source_id!r} is missing or malformed",
                }
            )
            continue

        job = existing_by_source.get(scan_id)
        if job is None:
            mapped = _manifest_id(manifest, "scans", scan_id)
            if mapped is not None:
                candidate = session.get(ScanJob, mapped)
                if (
                    candidate is not None
                    and candidate.program_id == program.id
                    and candidate.runner == IMPORT_RUNNER
                ):
                    job = candidate
        if job is not None:
            counts["skipped"]["scans"] += 1
            manifest["scans"][str(scan_id)] = job.id
            continue

        leadline_status = str(row.get("status") or "pending").strip().lower()
        job_status = SCAN_STATUS.get(leadline_status, "cancelled")
        if leadline_status not in SCAN_STATUS:
            warnings.append(
                f"scan {scan_id}: unknown status {leadline_status!r}; imported as cancelled"
            )
        target_id = target_map[target_source_id]
        target_row = target_meta[target_source_id]["row"]
        target_url = str(target_row.get("url") or target_row.get("name") or "")
        created_at = _parse_dt(row.get("created_at")) or now
        started_at = _parse_dt(row.get("started_at"))
        finished_at = _parse_dt(row.get("completed_at"))
        if job_status in ("done", "failed", "cancelled"):
            started_at = started_at or created_at
            finished_at = finished_at or started_at
        error = _scan_error(leadline_status, row.get("error_message"))
        events = sorted(
            events_by_scan.get(scan_id, []),
            key=lambda item: (
                _int_id(item.get("phase_order")) or 0,
                _int_id(item.get("id")) or 0,
            ),
        )
        findings = findings_by_scan.get(scan_id, [])
        nodes = nodes_by_scan.get(scan_id, [])
        profile_id = target_meta[target_source_id].get("profile_id")

        params = {
            "imported": True,
            "leadline_source_id": scan_id,
            "leadline_target_id": target_source_id,
            "leadline_status": leadline_status,
            "leadline_progress": row.get("progress"),
            "leadline_current_phase": row.get("current_phase"),
            "evasion_enabled": bool(row.get("evasion_enabled", True)),
            "request_delay": row.get("request_delay"),
            "enable_external_lookups": bool(row.get("enable_external_lookups", True)),
            "leadline_created_at": _iso(created_at),
            "leadline_error": error,
            "leadline_event_count": len(events),
            "leadline_finding_count": len(findings),
            "leadline_graph_node_count": len(nodes),
            "import_source": str(source.path),
            "imported_at": now.isoformat(),
        }
        job = ScanJob(
            program_id=program.id,
            target_id=target_id,
            runner=IMPORT_RUNNER,
            target=target_url,
            status=job_status,
            header_profile_id=profile_id,
            params=params,
            priority=0,
            attempts=1,
            max_attempts=1,
            created_at=created_at,
            started_at=started_at,
            finished_at=finished_at,
            error=error,
            log=f"Imported from Leadline scan #{scan_id} (status {leadline_status})",
        )
        session.add(job)
        session.flush()

        attempt = JobAttempt(
            job_id=job.id,
            attempt_no=1,
            worker_id="leadline-import",
            status=job_status,
            started_at=started_at or created_at,
            finished_at=finished_at or created_at,
            error=error,
            stats={
                "leadline_scan_id": scan_id,
                "leadline_status": leadline_status,
                "progress": row.get("progress"),
                "current_phase": row.get("current_phase"),
                "event_count": len(events),
                "finding_count": len(findings),
                "graph_node_count": len(nodes),
            },
        )
        session.add(attempt)
        session.flush()
        session.add(
            JobEvent(
                job_id=job.id,
                attempt_id=attempt.id,
                kind="imported",
                message=f"Imported from Leadline scan #{scan_id}",
                data={
                    "source": str(source.path),
                    "leadline_scan_id": scan_id,
                    "leadline_status": leadline_status,
                },
                created_at=created_at,
            )
        )

        graph_count = len(nodes)
        phases: list[ScanPhase] = []
        for event in events:
            event_id = _int_id(event.get("id"))
            phase_order = _int_id(event.get("phase_order")) or 0
            phase_name = str(event.get("phase_name") or "phase").strip() or "phase"
            event_status = str(event.get("status") or "pending").strip().lower()
            phase_status = PHASE_STATUS.get(event_status, "cancelled")
            if event_status not in PHASE_STATUS:
                warnings.append(
                    f"scan {scan_id} event {event_id}: unknown status "
                    f"{event_status!r}; imported as cancelled"
                )
            result_data = _decode_json(event.get("result_data"))
            result_text = _json_text(result_data) if result_data is not None else ""
            stats = {
                "findings": _int_id(event.get("findings_count")) or 0,
                "leadline_event_id": event_id,
                "leadline_status": event_status,
                "leadline_phase_order": phase_order,
                "result_data": _cap_json(result_data),
                "result_data_bytes": len(result_text.encode("utf-8")),
                "result_data_truncated": len(result_text.encode("utf-8"))
                > MAX_JSON_BYTES,
            }
            phase = ScanPhase(
                job_id=job.id,
                attempt_id=attempt.id,
                seq=phase_order,
                name=phase_name,
                status=phase_status,
                started_at=_parse_dt(event.get("started_at"))
                or started_at
                or created_at,
                finished_at=_parse_dt(event.get("completed_at")),
                stats=stats,
                error=str(event.get("error_message") or "").strip() or None,
            )
            phases.append(phase)
            session.add(phase)
        for phase in phases:
            if "graph" in phase.name.lower():
                phase.stats = {**(phase.stats or {}), "entities": graph_count}
                session.add(phase)

        for finding_row in findings:
            finding, reason = _build_finding(
                finding_row,
                program_id=program.id,
                target_id=target_id,
                target_url=target_url,
                source_path=source.path,
                now=now,
                warnings=warnings,
            )
            if finding is None:
                errors.append(
                    {
                        "table": "findings",
                        "id": _int_id(finding_row.get("id")),
                        "reason": reason or "malformed finding",
                    }
                )
                continue
            if finding.fingerprint in existing_fingerprints:
                counts["skipped"]["findings"] += 1
                manifest["findings"][str(finding.meta["leadline_finding_id"])] = (
                    existing_finding_ids.get(finding.fingerprint)
                )
                continue
            session.add(finding)
            session.flush()
            existing_fingerprints.add(finding.fingerprint)
            existing_finding_ids[finding.fingerprint] = finding.id
            manifest["findings"][str(finding.meta["leadline_finding_id"])] = finding.id
            counts["imported"]["findings"] += 1

        entity_by_node: dict[str, Entity] = {}
        rel_keys: set[tuple[str, str, str]] = set(existing_relationships)
        new_entities: list[Entity] = []
        for node_row in nodes:
            node_id = str(node_row.get("node_id") or "").strip()
            label = str(node_row.get("label") or node_id).strip()
            if not node_id or not label:
                errors.append(
                    {
                        "table": "graph_nodes",
                        "id": _int_id(node_row.get("id")),
                        "reason": "missing node_id or label",
                    }
                )
                continue
            normalized = f"leadline:{scan_id}:{node_id}"
            if normalized in existing_entity_norms:
                counts["skipped"]["entities"] += 1
                continue
            entity_type, original_type = _node_entity_type(node_row.get("node_type"))
            parent_id = str(node_row.get("parent_id") or "").strip() or None
            depth = _int_id(node_row.get("depth")) or 0
            extra = _decode_json(node_row.get("extra_data"))
            entity = Entity(
                paste_id=None,
                program_id=program.id,
                target_id=target_id,
                type=entity_type,
                value=label,
                normalized=normalized,
                confidence=0.9,
                parser=IMPORT_SOURCE,
                status="new",
                scope_status="unknown",
                ignored=False,
                verdict="none",
                tags=["leadline-imported", original_type],
                notes=None,
                occurrences=1,
                meta={
                    "leadline_scan_id": scan_id,
                    "leadline_node_id": node_id,
                    "leadline_node_type": original_type,
                    "leadline_parent_id": parent_id,
                    "depth": depth,
                    "leadline_extra_data": _cap_json(extra),
                    "import_source": str(source.path),
                    "imported_at": now.isoformat(),
                },
                provenance=[normalized],
                cross_programs=[],
                created_at=_parse_dt(node_row.get("created_at")) or now,
            )
            new_entities.append(entity)
            entity_by_node[node_id] = entity
            existing_entity_norms.add(normalized)
        if new_entities:
            session.add_all(new_entities)
            session.flush()
            counts["imported"]["entities"] += len(new_entities)

        for node_row in nodes:
            node_id = str(node_row.get("node_id") or "").strip()
            parent_id = str(node_row.get("parent_id") or "").strip() or None
            if not node_id or not parent_id:
                continue
            child = entity_by_node.get(node_id)
            parent = entity_by_node.get(parent_id)
            if child is None or parent is None:
                if child is not None:
                    warnings.append(
                        f"scan {scan_id} node {node_id}: parent {parent_id!r} not found"
                    )
                continue
            key = (child.value, parent.value, "part_of")
            if key in rel_keys:
                continue
            rel_keys.add(key)
            session.add(
                Relationship(
                    paste_id=None,
                    program_id=program.id,
                    target_id=target_id,
                    src_value=child.value,
                    src_type=child.type,
                    dst_value=parent.value,
                    dst_type=parent.type,
                    rel_type="part_of",
                    src_entity_id=child.id,
                    dst_entity_id=parent.id,
                    confidence=0.9,
                    source=IMPORT_SOURCE,
                    meta={
                        "leadline_scan_id": scan_id,
                        "leadline_node_id": node_id,
                        "leadline_parent_id": parent_id,
                        "depth": (child.meta or {}).get("depth", 0),
                        "leadline_relationship": "contains",
                    },
                )
            )
            counts["imported"]["relationships"] += 1

        # Explicit edges from the graph phase's result_data. Parent edges
        # above are enough for the stored tree, but Leadline also records
        # named edges that are not implied by parent_id.
        for event in events:
            if "graph" not in str(event.get("phase_name") or "").lower():
                continue
            data = _decode_json(event.get("result_data"))
            if not isinstance(data, dict):
                continue
            for edge in data.get("edges") or []:
                if not isinstance(edge, dict):
                    continue
                source_node = str(edge.get("source") or "").strip()
                target_node = str(edge.get("target") or "").strip()
                if not source_node or not target_node:
                    continue
                source_entity = entity_by_node.get(source_node)
                target_entity = entity_by_node.get(target_node)
                if source_entity is None or target_entity is None:
                    continue
                relationship = str(edge.get("relationship") or "contains").strip().lower()
                if relationship in ("contains", "part_of", "parent"):
                    child, parent = target_entity, source_entity
                    rel_type = "part_of"
                else:
                    child, parent = source_entity, target_entity
                    rel_type = "references"
                key = (child.value, parent.value, rel_type)
                if key in rel_keys:
                    continue
                rel_keys.add(key)
                session.add(
                    Relationship(
                        paste_id=None,
                        program_id=program.id,
                        target_id=target_id,
                        src_value=child.value,
                        src_type=child.type,
                        dst_value=parent.value,
                        dst_type=parent.type,
                        rel_type=rel_type,
                        src_entity_id=child.id,
                        dst_entity_id=parent.id,
                        confidence=0.85,
                        source=IMPORT_SOURCE,
                        meta={
                            "leadline_scan_id": scan_id,
                            "leadline_relationship": relationship,
                        },
                    )
                )
                counts["imported"]["relationships"] += 1

        counts["imported"]["scans"] += 1
        counts["imported"]["attempts"] += 1
        counts["imported"]["events"] += len(events)
        counts["imported"]["phases"] += len(events)
        counts["imported"]["graph_nodes"] += len(new_entities)
        manifest["scans"][str(scan_id)] = job.id
        for entity in new_entities:
            manifest["graph_nodes"][
                f"{scan_id}:{entity.meta.get('leadline_node_id')}"
            ] = entity.id
        imported_job_ids.append(job.id)

    return imported_job_ids


def _backup_destination() -> Path | None:
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    destination = DB_PATH.with_suffix(DB_PATH.suffix + f".pre-import-{stamp}.bak")
    return backup_database(destination)


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------


def import_leadline(
    source_path: str | Path,
    *,
    program_id: int | None = None,
    program_name: str = DEFAULT_PROGRAM,
    manifest_path: str | Path | None = None,
    backup: bool = True,
    generate_snapshots: bool = True,
    verify: bool = True,
) -> dict[str, Any]:
    """Import a Leadline database into Breadcrumb.

    The main destination rows are committed in one transaction. Snapshots and
    the manifest are written after that commit; a snapshot failure is recorded
    but never invalidates the imported evidence.
    """
    init_db()
    source = read_source(source_path)
    report = _source_report(source)
    manifest_file = (
        Path(manifest_path).expanduser()
        if manifest_path
        else default_manifest_path()
    )
    manifest, manifest_warnings = _load_manifest(manifest_file, source.path)
    warnings = list(report["warnings"]) + manifest_warnings
    errors = list(report["errors"])
    counts: dict[str, Any] = {
        "source": report["counts"],
        "would_import": report["would_import"],
        "imported": {
            "programs": 0,
            "targets": 0,
            "header_profiles": 0,
            "scans": 0,
            "attempts": 0,
            "events": 0,
            "phases": 0,
            "findings": 0,
            "entities": 0,
            "graph_nodes": 0,
            "relationships": 0,
            "snapshots": 0,
        },
        "skipped": {
            "targets": 0,
            "scans": 0,
            "findings": 0,
            "entities": 0,
        },
    }

    backup_path = _backup_destination() if backup else None
    state = get_app_state()
    previous_maintenance = (bool(state.maintenance), state.maintenance_reason or "")
    set_maintenance(True, "Leadline import in progress")
    session = Session(engine)
    program: Program | None = None
    resolved_program_id: int | None = None
    resolved_program_name = ""
    imported_job_ids: list[int] = []
    try:
        program, created = _resolve_program(
            session, program_id, program_name, source.path
        )
        counts["imported"]["programs"] = 1 if created else 0
        target_map, target_meta = _import_targets(
            session, source, program, manifest, counts, warnings, errors
        )
        imported_job_ids = _import_scans(
            session,
            source,
            program,
            target_map,
            target_meta,
            manifest,
            counts,
            warnings,
            errors,
        )
        session.commit()
        # Read the identity before closing: a committed Program is expired and
        # cannot be refreshed from a detached instance.
        resolved_program_id = program.id
        resolved_program_name = program.name
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        set_maintenance(previous_maintenance[0], previous_maintenance[1])

    assert resolved_program_id is not None
    snapshot_counts = {"built": 0, "failed": 0, "skipped": 0}
    if generate_snapshots and imported_job_ids:
        with Session(engine) as snapshot_session:
            for job_id in imported_job_ids:
                job = snapshot_session.get(ScanJob, job_id)
                if job is None or job.status not in ("done", "failed", "cancelled"):
                    snapshot_counts["skipped"] += 1
                    continue
                try:
                    history.generate_snapshot(snapshot_session, job)
                    snapshot_counts["built"] += 1
                except Exception as exc:  # noqa: BLE001  (snapshots are rebuildable)
                    history.upsert_snapshot(
                        snapshot_session, job, status="failed", error=str(exc)
                    )
                    snapshot_counts["failed"] += 1
                    warnings.append(
                        f"snapshot for imported job #{job.id} failed: {exc}"
                    )
    counts["imported"]["snapshots"] = snapshot_counts["built"]

    verification = None
    if verify:
        verification = verify_import(
            source.path,
            program_id=resolved_program_id,
            program_name=resolved_program_name,
            manifest_path=manifest_file,
            _manifest=manifest,
        )
        if not verification.get("ok"):
            warnings.append(
                "post-import verification reported differences; "
                "see verification.checks"
            )

    manifest["version"] = MANIFEST_VERSION
    manifest["source"] = {
        "path": str(source.path),
        "sha256": source.sha256,
        "size": source.size,
    }
    manifest["program_id"] = resolved_program_id
    manifest["program_name"] = resolved_program_name
    manifest["imported_at"] = datetime.now(timezone.utc).isoformat()
    manifest["counts"] = counts
    _write_manifest(manifest_file, manifest)

    return {
        "ok": bool(verification.get("ok")) if verification else True,
        "dry_run": False,
        "source": {
            "path": str(source.path),
            "sha256": source.sha256,
            "size": source.size,
        },
        "program": {
            "id": resolved_program_id,
            "name": resolved_program_name,
            "created": bool(counts["imported"]["programs"]),
        },
        "counts": counts,
        "snapshots": snapshot_counts,
        "warnings": list(dict.fromkeys(warnings)),
        "errors": errors,
        "backup": str(backup_path) if backup_path else None,
        "manifest": str(manifest_file),
        "verification": verification,
    }


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------


def _check(name: str, ok: bool, detail: Any) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def verify_import(
    source_path: str | Path,
    *,
    program_id: int | None = None,
    program_name: str = DEFAULT_PROGRAM,
    manifest_path: str | Path | None = None,
    _manifest: dict[str, Any] | None = None,
    sample_limit: int = SAMPLE_LIMIT,
) -> dict[str, Any]:
    """Compare a destination import against its source database."""
    source = read_source(source_path)
    report = _source_report(source)
    manifest_file = (
        Path(manifest_path).expanduser()
        if manifest_path
        else default_manifest_path()
    )
    if _manifest is not None:
        manifest = _manifest
    else:
        manifest, _warnings = _load_manifest(manifest_file, source.path)

    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return {
            "ok": False,
            "checks": [
                _check("destination", False, "destination database does not exist")
            ],
            "source": {"path": str(source.path), "sha256": source.sha256},
            "manifest": str(manifest_file),
        }

    init_db()
    with Session(engine) as session:
        program = None
        if program_id is not None:
            program = session.get(Program, program_id)
        elif manifest.get("program_id") is not None:
            try:
                program = session.get(Program, int(manifest["program_id"]))
            except (TypeError, ValueError):
                program = None
        if program is None:
            program = session.exec(
                select(Program).where(Program.name == program_name)
            ).first()
        if program is None:
            return {
                "ok": False,
                "checks": [
                    _check(
                        "program",
                        False,
                        f"destination program {program_name!r} was not found",
                    )
                ],
                "source": {"path": str(source.path), "sha256": source.sha256},
                "manifest": str(manifest_file),
            }

        targets = session.exec(
            select(Target).where(Target.program_id == program.id)
        ).all()
        imported_targets = [
            target
            for target in targets
            if (target.meta or {}).get("leadline_source_id") is not None
        ]
        jobs = session.exec(
            select(ScanJob).where(
                ScanJob.program_id == program.id,
                ScanJob.runner == IMPORT_RUNNER,
            )
        ).all()
        imported_jobs = [
            job
            for job in jobs
            if (job.params or {}).get("leadline_source_id") is not None
        ]
        findings = session.exec(
            select(Finding).where(
                Finding.program_id == program.id,
                Finding.source_tool == "leadline",
            )
        ).all()
        entities = session.exec(
            select(Entity).where(
                Entity.program_id == program.id,
                Entity.parser == IMPORT_SOURCE,
            )
        ).all()
        phases = session.exec(
            select(ScanPhase).where(
                ScanPhase.job_id.in_([job.id for job in imported_jobs])
            )
        ).all() if imported_jobs else []

        expected = report["would_import"]
        actual = {
            "targets": len(imported_targets),
            "scans": len(imported_jobs),
            "events": len(phases),
            "findings": len(findings),
            "graph_nodes": len(entities),
        }
        counts_ok = all(actual[key] == expected[key] for key in actual)
        checks = [
            _check(
                "counts",
                counts_ok,
                {
                    "expected": expected,
                    "actual": actual,
                    "source": report["counts"],
                },
            )
        ]

        source_triage = Counter(report["triage"])
        dest_triage: Counter[str] = Counter()
        for finding in findings:
            dest_triage[triage.triage_status(finding)] += 1
        triage_ok = dict(source_triage) == dict(dest_triage)
        checks.append(
            _check(
                "triage",
                triage_ok,
                {
                    "source": dict(sorted(source_triage.items())),
                    "destination": dict(sorted(dest_triage.items())),
                },
            )
        )

        source_severity = Counter(report["severity"])
        dest_severity: Counter[str] = Counter(
            str(finding.severity or "info").lower() for finding in findings
        )
        severity_ok = dict(source_severity) == dict(dest_severity)
        checks.append(
            _check(
                "severity",
                severity_ok,
                {
                    "source": dict(sorted(source_severity.items())),
                    "destination": dict(sorted(dest_severity.items())),
                },
            )
        )

        # Sample field equality. Never include full evidence or header values.
        valid_target_ids = set()
        for target_row in source.rows("targets"):
            try:
                _target_identity(target_row)
            except ValueError:
                continue
            source_target_id = _int_id(target_row.get("id"))
            if source_target_id is not None:
                valid_target_ids.add(source_target_id)
        scan_target_url: dict[int, str] = {}
        valid_scan_ids: set[int] = set()
        for scan_row in source.rows("scans"):
            source_scan_id = _int_id(scan_row.get("id"))
            source_target_id = _int_id(scan_row.get("target_id"))
            if source_scan_id is None or source_target_id not in valid_target_ids:
                continue
            valid_scan_ids.add(source_scan_id)
            for target_row in source.rows("targets"):
                if _int_id(target_row.get("id")) == source_target_id:
                    scan_target_url[source_scan_id] = str(
                        target_row.get("url") or ""
                    )
                    break
        source_findings = {
            int(row["id"]): row
            for row in source.rows("findings")
            if _int_id(row.get("id")) is not None
            and _int_id(row.get("scan_id")) in valid_scan_ids
        }
        destination_by_id = {finding.id: finding for finding in findings}
        manifest_findings = manifest.get("findings", {})
        samples: list[dict[str, Any]] = []
        sample_ok = True
        for source_id in sorted(source_findings)[: max(1, int(sample_limit))]:
            row = source_findings[source_id]
            destination = None
            mapped = manifest_findings.get(str(source_id))
            if mapped is not None:
                try:
                    destination = destination_by_id.get(int(mapped))
                except (TypeError, ValueError):
                    destination = None
            if destination is None:
                source_scan_id = _int_id(row.get("scan_id")) or 0
                fingerprint = _finding_fingerprint(
                    scan_target_url.get(source_scan_id, ""),
                    source_scan_id,
                    source_id,
                )
                destination = next(
                    (
                        finding
                        for finding in findings
                        if finding.fingerprint == fingerprint
                    ),
                    None,
                )
            source_status, _ = _effective_triage(row)
            source_severity_value, _ = _normalize_severity(row.get("severity"))
            source_location = str(row.get("location") or "").strip()
            source_note = str(row.get("triage_note") or "").strip() or None
            differences: list[str] = []
            if destination is None:
                differences.append("missing destination finding")
            else:
                if destination.title != (
                    str(row.get("title") or "").strip()
                    or f"Imported finding #{source_id}"
                ):
                    differences.append("title")
                if destination.severity != source_severity_value:
                    differences.append("severity")
                if triage.triage_status(destination) != source_status:
                    differences.append("triage_status")
                if (destination.notes or None) != source_note:
                    differences.append("triage_note")
                if source_location and (destination.meta or {}).get(
                    "leadline_location"
                ) != source_location:
                    differences.append("location")
                source_evidence = str(row.get("evidence") or "").strip()
                if source_evidence and source_evidence not in (
                    destination.evidence or ""
                ):
                    differences.append("evidence")
            if differences:
                sample_ok = False
            samples.append(
                {
                    "source_id": source_id,
                    "destination_id": destination.id if destination else None,
                    "differences": differences,
                }
            )
        checks.append(_check("samples", sample_ok, samples))

        # Header round-trip: compare decrypted profile values to the source.
        header_checks: list[dict[str, Any]] = []
        headers_ok = True
        for target_row in source.rows("targets"):
            headers, _warnings = _parse_headers(target_row)
            if not headers:
                continue
            source_id = _int_id(target_row.get("id"))
            destination_target = next(
                (
                    target
                    for target in imported_targets
                    if (target.meta or {}).get("leadline_source_id") == source_id
                ),
                None,
            )
            profile = None
            if destination_target is not None:
                profile_id = (destination_target.meta or {}).get(
                    "leadline_header_profile_id"
                )
                if profile_id:
                    profile = session.get(HeaderProfile, int(profile_id))
                if profile is None:
                    job = next(
                        (
                            item
                            for item in imported_jobs
                            if item.target_id == destination_target.id
                        ),
                        None,
                    )
                    if job is not None and job.header_profile_id:
                        profile = session.get(HeaderProfile, job.header_profile_id)
            match = bool(profile is not None and (profile.headers or {}) == headers)
            headers_ok = headers_ok and match
            header_checks.append(
                {
                    "target_id": source_id,
                    "destination_target_id": destination_target.id
                    if destination_target
                    else None,
                    "profile_id": profile.id if profile else None,
                    "headers_match": match,
                    "header_count": len(headers),
                }
            )
        checks.append(_check("header_profiles", headers_ok, header_checks))

        # The read_source() helper already checked the hash before/after the
        # read. Record it explicitly so the verification report is self-contained.
        checks.append(
            _check(
                "source_read_only",
                True,
                {"path": str(source.path), "sha256": source.sha256},
            )
        )

        ok = all(check["ok"] for check in checks)
        return {
            "ok": ok,
            "checks": checks,
            "source": {
                "path": str(source.path),
                "sha256": source.sha256,
                "size": source.size,
            },
            "program": {"id": program.id, "name": program.name},
            "counts": {"expected": expected, "actual": actual, "source": report["counts"]},
            "triage": {
                "source": dict(sorted(source_triage.items())),
                "destination": dict(sorted(dest_triage.items())),
            },
            "severity": {
                "source": dict(sorted(source_severity.items())),
                "destination": dict(sorted(dest_severity.items())),
            },
            "samples": samples,
            "manifest": str(manifest_file),
        }
