"""Local parser SDK (Phase D).

Third-party parsers are ordinary Python modules in a local directory. There is
no remote marketplace, no package index and no auto-update: the operator points
Breadcrumb at a folder they already trust, exactly like a shell ``PATH``.

Resolution order:

1. ``$BREADCRUMB_PARSER_DIR`` when set;
2. ``~/.breadcrumb/parsers`` otherwise.

A module exposes either a module-level ``PARSER`` (instance or class) or a
``get_parser()`` callable returning one. The parser must subclass
:class:`app.parsers.base.Parser` and have a non-empty, unique ``name``.

The loader validates the contract, never lets a broken plugin abort startup,
and records failures for ``breadcrumb doctor``/the Parsers page. Because a
plugin is imported Python, installing one grants it the same trust as any code
you run locally. Breadcrumb does not sandbox it and says so in the docs.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import REGISTRY
from .base import Parser

MAX_PLUGIN_BYTES = 2 * 1024 * 1024
MAX_PLUGIN_ERRORS = 100
_META_KEYS = ("author", "homepage", "license", "description", "version")


@dataclass
class PluginRecord:
    name: str
    path: str
    module: str
    version: str = "1"
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "module": self.module,
            "version": self.version,
            "source": "local",
            "meta": dict(self.meta),
        }


_LOADED_PATHS: dict[str, str] = {}
PLUGIN_ERRORS: list[dict] = []
PLUGINS: list[PluginRecord] = []


def default_parser_dir() -> Path:
    configured = os.environ.get("BREADCRUMB_PARSER_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".breadcrumb" / "parsers"


def plugin_errors() -> list[dict]:
    return [dict(item) for item in PLUGIN_ERRORS]


def plugin_catalog() -> list[dict]:
    return [record.as_dict() for record in sorted(PLUGINS, key=lambda item: item.name)]


def _record_error(path: Path, error: str) -> None:
    entry = {"path": str(path), "error": " ".join(str(error).split())[:500]}
    for existing in PLUGIN_ERRORS:
        if existing["path"] == entry["path"] and existing["error"] == entry["error"]:
            return
    PLUGIN_ERRORS.append(entry)
    del PLUGIN_ERRORS[:-MAX_PLUGIN_ERRORS]


def _meta_from_module(module) -> dict:
    raw = getattr(module, "PARSER_META", None)
    if not isinstance(raw, dict):
        return {}
    meta = {}
    for key in _META_KEYS:
        value = raw.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            meta[key] = str(value).strip()[:200]
    return meta


def _coerce_parser(module):
    candidate = getattr(module, "PARSER", None)
    if candidate is None:
        factory = getattr(module, "get_parser", None)
        if callable(factory):
            candidate = factory()
    if isinstance(candidate, type) and issubclass(candidate, Parser):
        candidate = candidate()
    if not isinstance(candidate, Parser):
        raise TypeError(
            "module must define PARSER as a Parser instance/class or get_parser()"
        )
    return candidate


def _validate_parser(parser: Parser, path: Path) -> None:
    name = str(getattr(parser, "name", "") or "").strip()
    if not name:
        raise ValueError("parser.name must be a non-empty string")
    if name in {"base"}:
        raise ValueError("parser.name 'base' is reserved")
    for existing in REGISTRY:
        if existing is parser:
            continue
        if existing.name == name:
            raise ValueError(f"parser name {name!r} is already registered")
    for method in ("detect", "parse", "parse_detailed"):
        if not callable(getattr(parser, method, None)):
            raise TypeError(f"parser {name!r} does not implement {method}()")
    version = getattr(parser, "parser_version", "1")
    if not isinstance(version, (str, int, float)) or not str(version).strip():
        raise ValueError(f"parser {name!r} has an invalid parser_version")
    parser.parser_version = str(version)
    if not getattr(parser, "description", ""):
        parser.description = f"Local parser from {path.name}"


def load_local_parsers(
    directory: str | Path | None = None, *, reload: bool = False
) -> list[dict]:
    """Import valid local parsers and return metadata for the loaded set.

    Missing directories are not an error; the SDK is optional. A broken plugin
    is skipped and recorded in :data:`PLUGIN_ERRORS`.
    """
    root = Path(directory).expanduser() if directory is not None else default_parser_dir()
    root = root.resolve()
    if not root.is_dir():
        return []
    loaded: list[dict] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if path.suffix != ".py" or path.name.startswith("_") or path.name.startswith("."):
            continue
        if not path.is_file():
            continue
        key = str(path.resolve())
        if key in _LOADED_PATHS and not reload:
            for record in PLUGINS:
                if record.path == key:
                    loaded.append(record.as_dict())
            continue
        try:
            size = path.stat().st_size
            if size > MAX_PLUGIN_BYTES:
                raise ValueError(
                    f"plugin is larger than {MAX_PLUGIN_BYTES // 1024} KB"
                )
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
            module_name = f"breadcrumb_local_parser_{path.stem}_{digest}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise ImportError("could not create an import spec")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            parser = _coerce_parser(module)
            _validate_parser(parser, path)
            parser.plugin_path = str(path)
            parser.plugin_meta = _meta_from_module(module)
            REGISTRY.append(parser)
            record = PluginRecord(
                name=parser.name,
                path=key,
                module=module_name,
                version=str(getattr(parser, "parser_version", "1")),
                meta=dict(getattr(parser, "plugin_meta", {})),
            )
            PLUGINS.append(record)
            _LOADED_PATHS[key] = parser.name
            loaded.append(record.as_dict())
        except Exception as exc:  # noqa: BLE001  (broken plugin must not kill startup)
            _record_error(path, f"{type(exc).__name__}: {exc}")
            continue
    return loaded
