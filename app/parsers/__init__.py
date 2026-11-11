"""Parser registry and analysis pipeline.

Every module in this package that defines a ``Parser`` subclass decorated with
``@register`` is auto-discovered. Adding support for a new kind of data is a
matter of dropping a new file here -- no core changes required.

Phase A adds ``analyze_detailed``: the same pipeline, but it returns the full
contract (warnings, skipped rows, parser versions, detected confidence) so an
import can explain itself. ``analyze`` remains the four-tuple compatibility
wrapper used by older callers.
"""

import importlib
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path

from .base import Entity, Parser, ParserIssue, ParseResult, Relationship

REGISTRY: list[Parser] = []
_LOADED = False


@dataclass
class AnalysisResult:
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    parsers: list[str] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    issues: list[ParserIssue] = field(default_factory=list)
    skipped_rows: int = 0
    detected: list[dict] = field(default_factory=list)
    parser_versions: dict[str, str] = field(default_factory=dict)

    @property
    def warnings(self) -> list[str]:
        return [issue.message for issue in self.issues]

    @property
    def completeness(self) -> float:
        """Fraction of rows the parsers accounted for.

        A capture with no matched parser is 0.0, not a silent success. A
        parser that reports no skipped rows is 1.0. Findings count as
        accounted-for output because some parsers only emit findings.
        """
        if not self.parsers:
            return 0.0
        accounted = len(self.entities) + len(self.findings)
        skipped = max(0, int(self.skipped_rows or 0))
        if accounted + skipped == 0:
            return 1.0
        return round(accounted / (accounted + skipped), 4)


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
        if mod.name in {"__init__", "base", "sdk"}:
            continue
        importlib.import_module(f"{__name__}.{mod.name}")
    # Optional local parser SDK: explicit directory, never a remote index.
    try:
        from .sdk import load_local_parsers

        load_local_parsers()
    except Exception:  # noqa: BLE001  (a broken local plugin must not kill startup)
        pass
    _LOADED = True


def _dedupe_entities(collected: list[tuple[str, float, list[Entity], list[Relationship]]]):
    best: dict[tuple[str, str], Entity] = {}
    for _name, _score, ents, _rels in collected:
        for ent in ents:
            key = (ent.type, ent.normalized.lower())
            current = best.get(key)
            if current is None or ent.confidence > current.confidence:
                best[key] = ent
    return list(best.values())


def _dedupe_relationships(collected: list[tuple[str, float, list[Entity], list[Relationship]]]):
    seen: set[tuple[str, str, str]] = set()
    relationships: list[Relationship] = []
    for _name, _score, _ents, rels in collected:
        for rel in rels:
            key = (rel.src_value.lower(), rel.dst_value.lower(), rel.rel_type)
            if key in seen:
                continue
            seen.add(key)
            relationships.append(rel)
    return relationships


def _dedupe_findings(items: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for item in items:
        key = str(item.get("dedup_key") or f"{item.get('title')}|{item.get('target')}")
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def analyze_detailed(text: str) -> AnalysisResult:
    """Run every parser and return the full, explainable contract."""
    load_all()
    result = AnalysisResult()
    if not text or not text.strip():
        issue = ParserIssue("*", "empty", "empty input")
        result.issues.append(issue)
        result.errors.append(issue.as_dict())
        return result

    collected: list[tuple[str, float, list[Entity], list[Relationship]]] = []
    for parser in REGISTRY:
        try:
            score = float(parser.detect(text))
        except Exception as exc:  # noqa: BLE001
            issue = ParserIssue(parser.name, "exception", f"detect failed: {exc}")
            result.issues.append(issue)
            result.errors.append(issue.as_dict())
            continue
        if score <= 0:
            continue
        result.parsers.append(parser.name)
        result.detected.append(
            {
                "name": parser.name,
                "score": round(score, 3),
                "version": getattr(parser, "parser_version", "1"),
            }
        )
        result.parser_versions[parser.name] = getattr(parser, "parser_version", "1")
        try:
            parsed = parser.parse_detailed(text)
        except Exception as exc:  # noqa: BLE001
            issue = ParserIssue(parser.name, "exception", f"parse failed: {exc}")
            result.issues.append(issue)
            result.errors.append(issue.as_dict())
            continue
        if not isinstance(parsed, ParseResult):
            issue = ParserIssue(
                parser.name,
                "unsupported",
                "parse_detailed must return a ParseResult",
            )
            result.issues.append(issue)
            result.errors.append(issue.as_dict())
            continue
        for ent in parsed.entities:
            if not ent.parser:
                ent.parser = parser.name
        for issue in parsed.issues:
            if not issue.parser:
                issue.parser = parser.name
            result.issues.append(issue)
            result.errors.append(issue.as_dict())
        result.skipped_rows += max(0, int(parsed.skipped_rows or 0))
        for finding in parsed.findings:
            finding.setdefault("parser", parser.name)
        result.findings.extend(parsed.findings)
        collected.append((parser.name, score, parsed.entities, parsed.relationships))

    result.entities = _dedupe_entities(collected)
    result.relationships = _dedupe_relationships(collected)
    result.findings = _dedupe_findings(result.findings)
    result.parsers.sort(key=lambda name: -dict(
        (item["name"], item["score"]) for item in result.detected
    ).get(name, 0))
    if not result.parsers:
        issue = ParserIssue("*", "no_parser", "no parser matched this input")
        result.issues.append(issue)
        result.errors.append(issue.as_dict())
    return result


def analyze(text: str):
    """Compatibility wrapper returning (entities, relationships, parsers, errors)."""
    result = analyze_detailed(text)
    return result.entities, result.relationships, result.parsers, result.errors


def extract_findings(text: str) -> list[dict]:
    """Collect structured findings from capable parsers.

    Kept for compatibility. New code should use ``analyze_detailed().findings``
    so entities and findings share one parse.
    """
    return analyze_detailed(text).findings


def parser_catalog() -> list[dict]:
    """Metadata for docs, doctor and the parser SDK UI.

    ``source`` is ``builtin`` or ``local``. Local parser metadata is additive;
    the analysis pipeline and the parser contract are unchanged.
    """
    load_all()
    return [
        {
            "name": parser.name,
            "description": parser.description,
            "version": getattr(parser, "parser_version", "1"),
            "source": "local" if getattr(parser, "plugin_path", None) else "builtin",
            "path": str(getattr(parser, "plugin_path", "") or ""),
            "meta": dict(getattr(parser, "plugin_meta", {}) or {}),
        }
        for parser in sorted(REGISTRY, key=lambda item: item.name)
    ]
