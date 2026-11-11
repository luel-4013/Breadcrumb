"""Evidence artifacts: content-addressed screenshots (Phase E).

Breadcrumb does not drive a browser. It imports screenshots produced by tools
the researcher already runs (EyeWitness, Gowitness, a manual upload) and stores
the bytes outside SQLite in a content-addressed directory. The database keeps
metadata, the SHA-256 of the bytes, dimensions, provenance and optional links
to a program, target, capture, entity or finding.

Design choices that matter:

* **Content addressed.** Two imports of identical bytes share one file on disk
  but can still have separate rows when they belong to different programs or
  findings.
* **Magic-byte validation.** The extension and manifest field are not trusted.
  PNG, JPEG, GIF and WebP are decoded just enough to read dimensions. SVG and
  PDF are rejected because an evidence image is rendered in a browser context.
* **Bounded.** One image is capped at 12 MiB, one manifest at 5 MiB / 2,000
  rows, and one import at 1,000 images. There is no browser, network fetch or
  automatic target creation.
* **Idempotent.** Re-importing the same manifest does not create a second row
  for the same program, content hash, source URL and finding link.
* **Never inlined in SQLite.** Backups stay small; the artifact root can be
  placed on a different local disk with ``BREADCRUMB_ARTIFACT_DIR``.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

from sqlmodel import Session, func, select

from . import __version__
from .attribution import attribute_target
from .db import DB_PATH, SCHEMA_VERSION
from .models import Entity, EvidenceArtifact, Finding, Paste, Program, Target

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids a runtime cycle
    from .redaction import RedactionPolicy

MAX_IMAGE_BYTES = 12 * 1024 * 1024
MAX_IMAGE_DIMENSION = 12_000
MAX_MANIFEST_BYTES = 5 * 1024 * 1024
MAX_MANIFEST_ROWS = 2_000
MAX_ARTIFACTS_PER_IMPORT = 1_000
MAX_LIST_LIMIT = 200
MAX_REPORT_SCREENSHOTS = 6
MAX_META_BYTES = 8_000
ARTIFACT_MANIFEST_VERSION = 1

IMAGE_TYPES = {
    "png": ("image/png", ".png"),
    "jpeg": ("image/jpeg", ".jpg"),
    "gif": ("image/gif", ".gif"),
    "webp": ("image/webp", ".webp"),
}
_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

# Manifest field normalization. Keys are lower-cased with separators removed.
_URL_KEYS = (
    "url",
    "finalurl",
    "target",
    "host",
    "pageurl",
    "address",
    "matchedat",
    "uri",
    "input",
)
_FILE_KEYS = (
    "screenshot",
    "screenshotpath",
    "filename",
    "file",
    "image",
    "imagepath",
    "path",
    "screenshotfile",
    "screenshotname",
    "img",
)
_STATUS_KEYS = ("status", "statuscode", "responsecode", "httpstatus", "code")
_TITLE_KEYS = ("title", "pagetitle", "heading")
_CAPTURED_KEYS = ("capturedat", "createdat", "timestamp", "time", "date")
_PERCEPTION_KEYS = ("perceptionhash", "perceptualhash")
_CONTENT_HASH_KEYS = ("contenthash", "sha256", "hash")
_SOURCE_KEYS = ("source", "tool", "scanner")


class ArtifactError(ValueError):
    """A user-facing artifact validation or storage failure."""


@dataclass(frozen=True)
class ImageInfo:
    kind: str
    media_type: str
    extension: str
    width: int
    height: int


def default_artifact_root() -> Path:
    """The directory that holds image bytes.

    ``BREADCRUMB_ARTIFACT_DIR`` wins; otherwise the root sits next to the
    SQLite file as ``<database-name>.artifacts``. Keeping it beside the database
    makes a copy of both obvious while preserving the one-file database.
    """
    configured = os.environ.get("BREADCRUMB_ARTIFACT_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return DB_PATH.parent / f"{DB_PATH.stem}.artifacts"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def _parse_dimensions(data: bytes, info: ImageInfo) -> tuple[int, int]:
    kind = info.kind
    if kind == "png":
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        return width, height
    if kind == "gif":
        width = int.from_bytes(data[6:8], "little")
        height = int.from_bytes(data[8:10], "little")
        return width, height
    if kind == "jpeg":
        index = 2
        sof_markers = {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }
        while index + 4 <= len(data):
            if data[index] != 0xFF:
                index += 1
                continue
            marker = data[index + 1]
            if marker in (0xD8, 0xD9):
                index += 2
                continue
            if marker == 0xDA:  # start of scan; dimensions must have appeared
                break
            length = int.from_bytes(data[index + 2 : index + 4], "big")
            if length < 2:
                break
            if marker in sof_markers and index + 9 <= len(data):
                height = int.from_bytes(data[index + 5 : index + 7], "big")
                width = int.from_bytes(data[index + 7 : index + 9], "big")
                return width, height
            index += 2 + length
        return 0, 0
    if kind == "webp":
        chunk = data[12:16]
        if chunk == b"VP8X" and len(data) >= 30:
            width = 1 + int.from_bytes(data[24:27], "little")
            height = 1 + int.from_bytes(data[27:30], "little")
            return width, height
        if chunk == b"VP8L" and len(data) >= 25:
            bits = int.from_bytes(data[21:25], "little")
            width = 1 + (bits & 0x3FFF)
            height = 1 + ((bits >> 14) & 0x3FFF)
            return width, height
        if chunk == b"VP8 " and len(data) >= 30:
            marker = data.find(b"\x9d\x01\x2a", 20, 30)
            if marker != -1 and marker + 7 <= len(data):
                width = int.from_bytes(data[marker + 3 : marker + 5], "little")
                width &= 0x3FFF
                height = int.from_bytes(data[marker + 5 : marker + 7], "little")
                height &= 0x3FFF
                return width, height
        return 0, 0
    return 0, 0


def inspect_image(data: bytes) -> ImageInfo:
    """Validate image bytes and return their kind, MIME type and dimensions.

    SVG and every non-raster format are rejected: the UI serves artifacts to a
    browser, and an uploaded SVG can contain script. A screenshot is a raster
    image; there is no product reason to accept anything else.
    """
    if not data:
        raise ArtifactError("image is empty")
    if len(data) > MAX_IMAGE_BYTES:
        raise ArtifactError(
            f"image is too large ({len(data)} bytes; limit {MAX_IMAGE_BYTES})"
        )
    kind = ""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 33 or data[12:16] != b"IHDR":
            raise ArtifactError("PNG is truncated or missing its IHDR header")
        kind = "png"
    elif data.startswith(b"\xff\xd8\xff"):
        kind = "jpeg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        kind = "gif"
    elif len(data) >= 16 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind = "webp"
    if not kind:
        raise ArtifactError(
            "unsupported image format (PNG, JPEG, GIF and WebP are accepted)"
        )
    media_type, extension = IMAGE_TYPES[kind]
    info = ImageInfo(
        kind=kind,
        media_type=media_type,
        extension=extension,
        width=0,
        height=0,
    )
    width, height = _parse_dimensions(data, info)
    if width <= 0 or height <= 0:
        raise ArtifactError("could not read image dimensions; the file is corrupt")
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise ArtifactError(
            f"image dimensions {width}x{height} exceed the "
            f"{MAX_IMAGE_DIMENSION}px limit"
        )
    return ImageInfo(
        kind=kind,
        media_type=media_type,
        extension=extension,
        width=width,
        height=height,
    )


def _relative_storage_path(sha256: str, extension: str) -> Path:
    return Path("sha256") / sha256[:2] / sha256[2:4] / f"{sha256}{extension}"


def _store_bytes(data: bytes, info: ImageInfo) -> tuple[str, str]:
    """Write content-addressed bytes once; return (sha256, relative path)."""
    sha256 = _sha256(data)
    relative = _relative_storage_path(sha256, info.extension)
    root = default_artifact_root()
    path = root / relative
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise ArtifactError(f"could not read existing artifact: {exc}") from exc
        if _sha256(existing) != sha256:
            raise ArtifactError(
                "the content-addressed artifact file is corrupt; "
                "remove it and re-import the screenshot"
            )
        return sha256, relative.as_posix()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(data)
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ArtifactError(f"could not write artifact: {exc}") from exc
    return sha256, relative.as_posix()


def _safe_filename(value: object, fallback: str = "screenshot") -> str:
    text = str(value or "").replace("\\", "/").split("/")[-1]
    text = re.sub(r"[\x00-\x1f\x7f]+", "", text).strip()
    text = text[:180]
    return text or fallback


def _safe_source(value: object) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-")
    return text[:40] or "manual"


def _safe_meta(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    try:
        encoded = json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return {}
    if len(encoded.encode("utf-8")) > MAX_META_BYTES:
        return {"truncated": True}
    return json.loads(encoded)


def _parse_datetime(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, pattern)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _url_host(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlparse(text if "://" in text else f"//{text}")
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _validate_program(session: Session, program_id: int) -> Program:
    try:
        pid = int(program_id)
    except (TypeError, ValueError) as exc:
        raise ArtifactError("a valid program is required") from exc
    program = session.get(Program, pid)
    if program is None:
        raise ArtifactError(f"program #{pid} not found")
    return program


def _validate_link(
    session: Session,
    model,
    value: int | None,
    program_id: int,
    label: str,
):
    if value in (None, ""):
        return None
    try:
        row_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ArtifactError(f"{label} id must be an integer") from exc
    row = session.get(model, row_id)
    if row is None:
        raise ArtifactError(f"{label} #{row_id} not found")
    linked_program = getattr(row, "program_id", None)
    if linked_program is not None and int(linked_program) != int(program_id):
        raise ArtifactError(f"{label} #{row_id} belongs to another program")
    return row


def _infer_target(session: Session, program_id: int, source_url: str):
    host = _url_host(source_url)
    if not host:
        return None
    targets = session.exec(select(Target).where(Target.program_id == program_id)).all()
    return attribute_target(host, targets)


def _infer_entity(session: Session, program_id: int, source_url: str):
    if not source_url.strip():
        return None
    exact = session.exec(
        select(Entity)
        .where(Entity.program_id == program_id)
        .where(func.lower(Entity.value) == source_url.strip().lower())
        .order_by(Entity.id)
    ).first()
    if exact is not None:
        return exact
    host = _url_host(source_url)
    if not host:
        return None
    return session.exec(
        select(Entity)
        .where(Entity.program_id == program_id)
        .where(func.lower(Entity.normalized) == host.lower())
        .where(Entity.type.in_(("domain", "subdomain", "url", "ip")))
        .order_by(Entity.id)
    ).first()


def _find_duplicate(
    session: Session,
    *,
    program_id: int,
    sha256: str,
    source_url: str,
    finding_id: int | None,
) -> EvidenceArtifact | None:
    statement = (
        select(EvidenceArtifact)
        .where(EvidenceArtifact.program_id == program_id)
        .where(EvidenceArtifact.sha256 == sha256)
        .where(EvidenceArtifact.source_url == source_url)
    )
    if finding_id is None:
        statement = statement.where(EvidenceArtifact.finding_id == None)  # noqa: E711
    else:
        statement = statement.where(EvidenceArtifact.finding_id == finding_id)
    return session.exec(statement.order_by(EvidenceArtifact.id)).first()


def import_image(
    session: Session,
    data: bytes,
    *,
    program_id: int,
    filename: str = "",
    source: str = "manual",
    source_url: str = "",
    target_id: int | None = None,
    finding_id: int | None = None,
    entity_id: int | None = None,
    paste_id: int | None = None,
    captured_at=None,
    meta: dict | None = None,
    kind: str = "screenshot",
    commit: bool = True,
) -> tuple[EvidenceArtifact, bool]:
    """Validate, store and link one image.

    Returns ``(artifact, duplicate)``. The bytes are only written the first
    time; a duplicate row is detected by program, SHA-256, source URL and
    finding link. Missing target/entity links are filled from the URL when
    possible, but the importer never creates targets.
    """
    info = inspect_image(data)
    program = _validate_program(session, program_id)
    target = _validate_link(session, Target, target_id, program.id, "target")
    finding = _validate_link(session, Finding, finding_id, program.id, "finding")
    entity = _validate_link(session, Entity, entity_id, program.id, "entity")
    paste = _validate_link(session, Paste, paste_id, program.id, "capture")

    safe_url = (str(source_url or "").strip())[:2048]
    if finding is not None and target is None and finding.target_id:
        target = session.get(Target, finding.target_id)
    if target is None and safe_url:
        target = _infer_target(session, program.id, safe_url)
    if entity is None and safe_url:
        entity = _infer_entity(session, program.id, safe_url)
    if paste is not None and target is None and paste.target_id:
        target = session.get(Target, paste.target_id)

    sha256, storage_path = _store_bytes(data, info)
    duplicate = _find_duplicate(
        session,
        program_id=program.id,
        sha256=sha256,
        source_url=safe_url,
        finding_id=finding.id if finding else None,
    )
    if duplicate is not None:
        changed = False
        if duplicate.target_id is None and target is not None:
            duplicate.target_id = target.id
            changed = True
        if duplicate.entity_id is None and entity is not None:
            duplicate.entity_id = entity.id
            changed = True
        if duplicate.paste_id is None and paste is not None:
            duplicate.paste_id = paste.id
            changed = True
        if changed:
            session.add(duplicate)
            if commit:
                session.commit()
        return duplicate, True

    artifact = EvidenceArtifact(
        program_id=program.id,
        target_id=target.id if target else None,
        paste_id=paste.id if paste else None,
        entity_id=entity.id if entity else None,
        finding_id=finding.id if finding else None,
        kind=kind or "screenshot",
        source=_safe_source(source),
        source_url=safe_url,
        filename=_safe_filename(filename),
        media_type=info.media_type,
        sha256=sha256,
        bytes=len(data),
        width=info.width,
        height=info.height,
        storage_path=storage_path,
        captured_at=_parse_datetime(captured_at),
        meta=_safe_meta(meta),
    )
    session.add(artifact)
    if commit:
        session.commit()
        session.refresh(artifact)
    else:
        session.flush()
    return artifact, False


def import_image_file(
    session: Session,
    path: str | Path,
    *,
    program_id: int,
    filename: str = "",
    source: str = "manual",
    source_url: str = "",
    target_id: int | None = None,
    finding_id: int | None = None,
    entity_id: int | None = None,
    paste_id: int | None = None,
    captured_at=None,
    meta: dict | None = None,
) -> tuple[EvidenceArtifact, bool]:
    file_path = Path(path).expanduser()
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise ArtifactError(f"could not read image: {exc}") from exc
    if size > MAX_IMAGE_BYTES:
        raise ArtifactError(
            f"image is too large ({size} bytes; limit {MAX_IMAGE_BYTES})"
        )
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise ArtifactError(f"could not read image: {exc}") from exc
    return import_image(
        session,
        data,
        program_id=program_id,
        filename=filename or file_path.name,
        source=source,
        source_url=source_url,
        target_id=target_id,
        finding_id=finding_id,
        entity_id=entity_id,
        paste_id=paste_id,
        captured_at=captured_at,
        meta=meta,
    )


# --------------------------------------------------------------- manifests ---
def _normalized_row(row: dict) -> dict:
    normalized = {}
    for key, value in (row or {}).items():
        if key is None:
            continue
        name = re.sub(r"[^a-z0-9]+", "", str(key).lower())
        if name:
            normalized[name] = value
    return normalized


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("path", "file", "filename", "url", "value", "name"):
            if value.get(key):
                return str(value[key]).strip()
        return ""
    if isinstance(value, (list, tuple)):
        return ""
    return str(value).strip()


def _pick(row: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _as_text(row.get(key))
        if value:
            return value
    return ""


def _first_number(value: object) -> int | None:
    match = re.search(r"\b(\d{3})\b", str(value or ""))
    return int(match.group(1)) if match else None


def _manifest_records(path: Path) -> tuple[list[dict], list[dict], str]:
    """Read a JSON, JSONL or CSV manifest; return (records, errors, format)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ArtifactError(f"could not read manifest: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ArtifactError(
            f"manifest is too large ({len(raw)} bytes; limit {MAX_MANIFEST_BYTES})"
        )
    suffix = path.suffix.lower()
    errors: list[dict] = []
    records: list[dict] = []

    def parse_json_text(text: str, file_format: str) -> None:
        try:
            payload = json.loads(text)
        except ValueError as exc:
            if file_format in ("json", "jsonl"):
                for number, line in enumerate(text.splitlines(), start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError as line_error:
                        if len(errors) < 50:
                            errors.append(
                                {"line": number, "error": f"invalid JSON: {line_error}"}
                            )
                        continue
                    _append_json_item(item, number)
                return
            errors.append({"line": None, "error": f"invalid JSON: {exc}"})
            return
        if isinstance(payload, list):
            for index, item in enumerate(payload, start=1):
                _append_json_item(item, index)
        elif isinstance(payload, dict):
            for key in ("results", "items", "screenshots", "data", "records", "pages"):
                value = payload.get(key)
                if isinstance(value, list):
                    for index, item in enumerate(value, start=1):
                        _append_json_item(item, index)
                    return
            if all(isinstance(value, dict) for value in payload.values()):
                for index, (name, item) in enumerate(payload.items(), start=1):
                    merged = dict(item)
                    merged.setdefault("filename", name)
                    _append_json_item(merged, index)
                return
            _append_json_item(payload, 1)
        else:
            errors.append({"line": None, "error": "manifest must be a JSON object or array"})

    def _append_json_item(item, line: int) -> None:
        if not isinstance(item, dict):
            if len(errors) < 50:
                errors.append({"line": line, "error": "record is not an object"})
            return
        records.append(item)

    if suffix == ".csv":
        text = raw.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(text.splitlines())
        for index, row in enumerate(reader, start=2):
            records.append(dict(row))
        return records, errors, "csv"

    text = raw.decode("utf-8-sig", errors="replace")
    file_format = "jsonl" if suffix in (".jsonl", ".ndjson") else "json"
    if file_format == "jsonl":
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                _append_json_item(json.loads(line), number)
            except ValueError as exc:
                if len(errors) < 50:
                    errors.append({"line": number, "error": f"invalid JSON: {exc}"})
    else:
        parse_json_text(text, file_format)
    return records, errors, file_format


def _resolve_image_path(
    raw: str, manifest_path: Path, base_dir: Path
) -> Path | None:
    text = (raw or "").strip().strip("'\"")
    if not text:
        return None
    if text.startswith("file://"):
        text = text[7:]
    text = unquote(text).replace("\\", "/")
    candidate = Path(text).expanduser()
    candidates: list[Path] = []
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        candidates.extend(
            [
                base_dir / candidate,
                manifest_path.parent / candidate,
                base_dir / "screenshots" / candidate.name,
                manifest_path.parent / "screenshots" / candidate.name,
                base_dir / candidate.name,
                manifest_path.parent / candidate.name,
            ]
        )
    for item in candidates:
        try:
            if item.is_file():
                return item
        except OSError:
            continue
    return None


def _infer_manifest_source(
    records: list[dict], file_format: str, keys: set[str], explicit: str
) -> str:
    if explicit:
        return _safe_source(explicit)
    if "perceptionhash" in keys or "finalurl" in keys:
        return "gowitness"
    if "screenshot" in keys and ("url" in keys or "screenshotpath" in keys):
        return "eyewitness" if file_format == "csv" else "manifest"
    return "manifest"


def import_manifest(
    session: Session,
    manifest_path: str | Path,
    *,
    program_id: int,
    base_dir: str | Path | None = None,
    target_id: int | None = None,
    finding_id: int | None = None,
    entity_id: int | None = None,
    source: str = "",
    max_images: int = MAX_ARTIFACTS_PER_IMPORT,
) -> dict:
    """Import an EyeWitness/Gowitness-style manifest and its images.

    Relative paths are resolved against ``base_dir`` (default: the manifest's
    directory), then a handful of conventional ``screenshots/`` locations.
    Rows with a missing/unreadable image are reported, not fatal. Duplicate
    bytes in the same program/finding/source-URL context are skipped.
    """
    program = _validate_program(session, program_id)
    manifest = Path(manifest_path).expanduser()
    if not manifest.is_file():
        raise ArtifactError(f"manifest not found: {manifest}")
    base = Path(base_dir).expanduser() if base_dir else manifest.parent
    if not base.is_dir():
        raise ArtifactError(f"image folder not found: {base}")
    records, parse_errors, file_format = _manifest_records(manifest)

    all_keys: set[str] = set()
    for row in records:
        all_keys.update(_normalized_row(row).keys())
    manifest_source = _infer_manifest_source(records, file_format, all_keys, source)

    limit = max(1, min(int(max_images or MAX_ARTIFACTS_PER_IMPORT), MAX_ARTIFACTS_PER_IMPORT))
    result = {
        "manifest": str(manifest),
        "base_dir": str(base),
        "format": file_format,
        "source": manifest_source,
        "rows": len(records),
        "imported": 0,
        "duplicates": 0,
        "skipped": 0,
        "errors": list(parse_errors),
        "artifacts": [],
        "truncated": False,
    }
    for number, row in enumerate(records, start=1):
        if result["imported"] + result["duplicates"] >= limit:
            result["truncated"] = True
            result["skipped"] += len(records) - number + 1
            break
        normalized = _normalized_row(row)
        raw_file = _pick(normalized, _FILE_KEYS)
        source_url = _pick(normalized, _URL_KEYS)
        if not raw_file:
            result["skipped"] += 1
            result["errors"].append(
                {"line": number, "error": "missing screenshot/file field"}
            )
            continue
        image_path = _resolve_image_path(raw_file, manifest, base)
        if image_path is None:
            result["skipped"] += 1
            result["errors"].append(
                {"line": number, "error": f"image not found: {_safe_filename(raw_file)}"}
            )
            continue
        captured_at = _parse_datetime(_pick(normalized, _CAPTURED_KEYS))
        metadata = {
            "manifest": str(manifest.name),
            "manifest_line": number,
            "title": _pick(normalized, _TITLE_KEYS)[:300],
            "status_code": _first_number(_pick(normalized, _STATUS_KEYS)),
            "perception_hash": _pick(normalized, _PERCEPTION_KEYS)[:160],
            "content_hash": _pick(normalized, _CONTENT_HASH_KEYS)[:160],
            "tool_source": _pick(normalized, _SOURCE_KEYS)[:80],
        }
        try:
            artifact, duplicate = import_image_file(
                session,
                image_path,
                program_id=program.id,
                filename=_safe_filename(raw_file),
                source=manifest_source,
                source_url=source_url,
                target_id=target_id,
                finding_id=finding_id,
                entity_id=entity_id,
                captured_at=captured_at,
                meta=metadata,
            )
        except ArtifactError as exc:
            result["skipped"] += 1
            result["errors"].append(
                {"line": number, "error": f"{_safe_filename(raw_file)}: {exc}"}
            )
            continue
        if duplicate:
            result["duplicates"] += 1
        else:
            result["imported"] += 1
        if len(result["artifacts"]) < 100:
            result["artifacts"].append(artifact_dict(artifact))
    return result


# ------------------------------------------------------------------ queries ---
def _artifact_query(
    *,
    program_id: int | None = None,
    target_id: int | None = None,
    finding_id: int | None = None,
    entity_id: int | None = None,
    source: str = "",
    q: str = "",
):
    statement = select(EvidenceArtifact)
    if program_id is not None:
        statement = statement.where(EvidenceArtifact.program_id == int(program_id))
    if target_id is not None:
        statement = statement.where(EvidenceArtifact.target_id == int(target_id))
    if finding_id is not None:
        statement = statement.where(EvidenceArtifact.finding_id == int(finding_id))
    if entity_id is not None:
        statement = statement.where(EvidenceArtifact.entity_id == int(entity_id))
    if source:
        statement = statement.where(EvidenceArtifact.source == _safe_source(source))
    if q:
        like = f"%{q.strip()}%"
        statement = statement.where(
            (EvidenceArtifact.filename.ilike(like))
            | (EvidenceArtifact.source_url.ilike(like))
            | (EvidenceArtifact.sha256.ilike(like))
        )
    return statement


def list_artifacts(
    session: Session,
    *,
    program_id: int | None = None,
    target_id: int | None = None,
    finding_id: int | None = None,
    entity_id: int | None = None,
    source: str = "",
    q: str = "",
    limit: int = 60,
    offset: int = 0,
) -> dict:
    limit = max(1, min(int(limit or 60), MAX_LIST_LIMIT))
    offset = max(0, int(offset or 0))
    query = _artifact_query(
        program_id=program_id,
        target_id=target_id,
        finding_id=finding_id,
        entity_id=entity_id,
        source=source,
        q=q,
    )
    total = int(
        session.exec(
            select(func.count()).select_from(query.subquery())
        ).one()
        or 0
    )
    rows = session.exec(
        query.order_by(EvidenceArtifact.id.desc()).offset(offset).limit(limit)
    ).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "next_offset": offset + limit if offset + limit < total else None,
        "artifacts": rows,
    }


def artifact_dict(artifact: EvidenceArtifact, *, policy=None) -> dict:
    def safe(value):
        return policy.text(value) if policy is not None else value

    return {
        "id": artifact.id,
        "program_id": artifact.program_id,
        "target_id": artifact.target_id,
        "paste_id": artifact.paste_id,
        "entity_id": artifact.entity_id,
        "finding_id": artifact.finding_id,
        "kind": artifact.kind,
        "source": artifact.source,
        "source_url": safe(artifact.source_url or ""),
        "filename": safe(artifact.filename or ""),
        "media_type": artifact.media_type,
        "sha256": artifact.sha256,
        "bytes": artifact.bytes,
        "width": artifact.width,
        "height": artifact.height,
        "captured_at": artifact.captured_at.isoformat() if artifact.captured_at else None,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
        "meta": artifact.meta or {},
        "content_url": f"/api/v1/artifacts/{artifact.id}/content",
        "detail_url": f"/artifacts/{artifact.id}",
    }


def artifact_path(artifact: EvidenceArtifact) -> Path:
    root = default_artifact_root().resolve()
    relative = Path(artifact.storage_path or "")
    if not artifact.storage_path or relative.is_absolute():
        raise ArtifactError("artifact storage path is missing or invalid")
    path = (root / relative).resolve()
    if root != path and root not in path.parents:
        raise ArtifactError("artifact storage path escapes the artifact directory")
    return path


def verify_artifact(artifact: EvidenceArtifact) -> dict:
    result = {
        "id": artifact.id,
        "exists": False,
        "hash_ok": False,
        "size_ok": False,
        "expected_sha256": artifact.sha256,
        "actual_sha256": "",
        "expected_bytes": artifact.bytes,
        "actual_bytes": 0,
        "error": "",
    }
    try:
        path = artifact_path(artifact)
        result["exists"] = path.is_file()
        if not result["exists"]:
            result["error"] = "file is missing"
            return result
        data = path.read_bytes()
        result["actual_bytes"] = len(data)
        result["actual_sha256"] = _sha256(data)
        result["size_ok"] = result["actual_bytes"] == int(artifact.bytes or 0)
        result["hash_ok"] = result["actual_sha256"] == artifact.sha256
    except (OSError, ArtifactError) as exc:
        result["error"] = str(exc)
    return result


def artifact_bytes(artifact: EvidenceArtifact, *, verify: bool = True) -> bytes:
    try:
        data = artifact_path(artifact).read_bytes()
    except OSError as exc:
        raise ArtifactError(f"artifact file is unavailable: {exc}") from exc
    if verify and _sha256(data) != artifact.sha256:
        raise ArtifactError(
            "artifact hash mismatch; the stored file was modified or corrupted"
        )
    return data


def delete_artifact(session: Session, artifact: EvidenceArtifact) -> dict:
    """Delete the row; remove bytes only when no row references them."""
    artifact_id = artifact.id
    storage_path = artifact.storage_path
    path = None
    try:
        path = artifact_path(artifact)
    except ArtifactError:
        path = None
    session.delete(artifact)
    session.commit()
    remaining = int(
        session.exec(
            select(func.count())
            .select_from(EvidenceArtifact)
            .where(EvidenceArtifact.storage_path == storage_path)
        ).one()
        or 0
    )
    removed = False
    if remaining == 0 and path is not None:
        try:
            path.unlink(missing_ok=True)
            removed = True
        except OSError:
            removed = False
    return {"id": artifact_id, "bytes_removed": removed, "remaining_rows": remaining}


def export_artifact(artifact: EvidenceArtifact, destination: str | Path) -> Path:
    data = artifact_bytes(artifact)
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_dir():
        suffix = Path(artifact.filename or "").suffix or {
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }.get(artifact.media_type, ".bin")
        path = path / f"artifact-{artifact.id}{suffix}"
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def artifact_manifest(
    session: Session,
    *,
    program_id: int | None = None,
    include_meta: bool = True,
    limit: int = 10_000,
) -> dict:
    rows = session.exec(
        _artifact_query(program_id=program_id)
        .order_by(EvidenceArtifact.id)
        .limit(max(1, min(int(limit or 10_000), 100_000)))
    ).all()
    artifacts = []
    for row in rows:
        item = artifact_dict(row)
        item.pop("content_url", None)
        item.pop("detail_url", None)
        if not include_meta:
            item.pop("meta", None)
        item["storage_path"] = row.storage_path
        artifacts.append(item)
    return {
        "artifact_manifest_version": ARTIFACT_MANIFEST_VERSION,
        "generator": {
            "name": "breadcrumb",
            "version": __version__,
            "schema_version": SCHEMA_VERSION,
        },
        "generated_at": _utcnow().isoformat(),
        "program_id": program_id,
        "count": len(artifacts),
        "artifacts": artifacts,
    }


def report_artifacts(
    session: Session,
    program_id: int,
    *,
    policy: "RedactionPolicy | None" = None,
    limit: int = MAX_REPORT_SCREENSHOTS,
    include_data: bool = False,
    finding_ids: list[int] | None = None,
) -> dict:
    """Redacted screenshot metadata for a report context.

    ``include_data`` adds a base64 data URI for HTML/PDF rendering. JSON
    exports strip that key; image bytes are never written to SQLite. Images are
    included as-is when requested: redaction cannot mask pixels, so the report
    UI and docs say so explicitly.
    """
    limit = max(0, min(int(limit or 0), MAX_REPORT_SCREENSHOTS))
    query = _artifact_query(program_id=program_id)
    if finding_ids is not None:
        ids = [int(value) for value in finding_ids if str(value).isdigit()]
        if not ids:
            return {"total": 0, "shown": 0, "items": [], "included": False}
        query = query.where(EvidenceArtifact.finding_id.in_(ids))
    total = int(
        session.exec(select(func.count()).select_from(query.subquery())).one() or 0
    )
    rows = session.exec(
        query.order_by(EvidenceArtifact.id.desc()).limit(limit)
    ).all() if limit else []
    items = []
    for row in rows:
        target = session.get(Target, row.target_id) if row.target_id else None
        data_uri = ""
        error = ""
        if include_data:
            try:
                encoded = base64.b64encode(artifact_bytes(row)).decode("ascii")
                data_uri = f"data:{row.media_type};base64,{encoded}"
            except ArtifactError as exc:
                error = str(exc)
        items.append(
            {
                "id": row.id,
                "source_url": policy.text(row.source_url or "") if policy else row.source_url,
                "filename": policy.text(row.filename or "") if policy else row.filename,
                "source": row.source,
                "media_type": row.media_type,
                "sha256": row.sha256,
                "bytes": row.bytes,
                "width": row.width,
                "height": row.height,
                "captured_at": row.captured_at.isoformat() if row.captured_at else "",
                "target": (policy.text(target.name) if policy else target.name)
                if target
                else "",
                "target_id": row.target_id,
                "finding_id": row.finding_id,
                "data_uri": data_uri,
                "error": error,
            }
        )
    return {
        "total": total,
        "shown": len(items),
        "items": items,
        "included": bool(include_data),
        "max": MAX_REPORT_SCREENSHOTS,
    }
