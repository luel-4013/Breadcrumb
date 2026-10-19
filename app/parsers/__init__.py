"""Parser registry and analysis pipeline.

Every module in this package that defines a ``Parser`` subclass decorated with
``@register`` is auto-discovered. Adding support for a new kind of data is a
matter of dropping a new file here -- no core changes required.
"""

import importlib
import pkgutil
from pathlib import Path

from .base import Entity, Parser, Relationship

REGISTRY: list[Parser] = []
_LOADED = False


def register(cls):
    """Class decorator that instantiates and registers a Parser."""
    REGISTRY.append(cls())
    return cls


def load_all() -> None:
    global _LOADED
    if _LOADED:
        return
    pkgdir = Path(__file__).resolve().parent
    for mod in pkgutil.iter_modules([str(pkgdir)]):
        if mod.name in {"__init__", "base"}:
            continue
        importlib.import_module(f"{__name__}.{mod.name}")
    _LOADED = True


def analyze(text: str):
    """Run every parser over ``text``.

    Returns (entities, relationships, parsers, errors). A parser only runs
    when its ``detect`` score is > 0. Entities of the same (type, normalized
    value) are de-duplicated, keeping the highest-confidence match.
    Every parser is sandboxed so one bad regex can never take down the
    pipeline — but failures are REPORTED in ``errors`` instead of swallowed,
    so a zero-entity result is always explainable.
    """
    load_all()
    if not text or not text.strip():
        return [], [], [], [{"parser": "*", "error": "empty input"}]

    matched: list[tuple[str, float]] = []
    collected: list[tuple[str, float, list[Entity], list[Relationship]]] = []
    errors: list[dict] = []

    for parser in REGISTRY:
        try:
            score = float(parser.detect(text))
        except Exception as exc:  # noqa: BLE001
            errors.append({"parser": parser.name, "error": f"detect failed: {exc}"})
            continue
        if score <= 0:
            continue
        matched.append((parser.name, round(score, 3)))
        try:
            ents, rels = parser.parse(text)
        except Exception as exc:  # noqa: BLE001
            errors.append({"parser": parser.name, "error": f"parse failed: {exc}"})
            continue
        for ent in ents:
            if not ent.parser:
                ent.parser = parser.name
        collected.append((parser.name, score, ents, rels))

    best: dict[tuple[str, str], Entity] = {}
    for _name, _score, ents, _rels in collected:
        for ent in ents:
            key = (ent.type, ent.normalized.lower())
            current = best.get(key)
            if current is None or ent.confidence > current.confidence:
                best[key] = ent
    entities = list(best.values())

    seen: set[tuple[str, str, str]] = set()
    relationships: list[Relationship] = []
    for _name, _score, _ents, rels in collected:
        for rel in rels:
            key = (rel.src_value.lower(), rel.dst_value.lower(), rel.rel_type)
            if key in seen:
                continue
            seen.add(key)
            relationships.append(rel)

    matched.sort(key=lambda item: -item[1])
    return entities, relationships, [name for name, _ in matched], errors


def extract_findings(text: str) -> list[dict]:
    """Collect structured findings (vulnerabilities) from capable parsers.

    Mirrors ``analyze`` isolation: a broken parser is skipped, never fatal.
    Results are de-duplicated on (dedup_key) so re-importing the same tool
    output does not spray duplicate findings.
    """
    load_all()
    if not text or not text.strip():
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for parser in REGISTRY:
        finder = getattr(parser, "findings", None)
        if finder is None:
            continue
        try:
            if float(parser.detect(text)) <= 0:
                continue
            found = finder(text) or []
        except Exception:  # noqa: BLE001
            continue
        for item in found:
            key = str(item.get("dedup_key") or f"{item.get('title')}|{item.get('target')}")
            if key in seen:
                continue
            seen.add(key)
            item.setdefault("parser", parser.name)
            out.append(item)
    return out
