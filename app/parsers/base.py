from dataclasses import dataclass, field


@dataclass
class Entity:
    type: str
    value: str
    normalized: str = ""
    confidence: float = 1.0
    meta: dict = field(default_factory=dict)
    parser: str = ""

    def __post_init__(self) -> None:
        if not self.normalized:
            self.normalized = self.value.strip()
        else:
            self.normalized = self.normalized.strip()


@dataclass
class Relationship:
    src_value: str
    src_type: str
    dst_value: str
    dst_type: str
    rel_type: str


@dataclass
class ParserIssue:
    """A non-fatal parser problem, kept visible instead of swallowed.

    ``code`` is stable for automation: ``exception``, ``skipped_row``,
    ``truncated``, ``unsupported``, ``warning``.
    """

    parser: str
    code: str
    message: str
    line: int | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        # ``error`` is kept for compatibility with the pre-contract API shape;
        # new code should read ``message``/``code``.
        return {
            "parser": self.parser,
            "code": self.code,
            "message": self.message,
            "error": self.message,
            "line": self.line,
            "detail": self.detail,
        }


@dataclass
class ParseResult:
    """The parser contract: everything an import needs to be explainable.

    Legacy parsers only implement ``parse``/``findings``; ``parse_detailed``
    wraps them. New parsers should override ``parse_detailed`` to report
    skipped rows and warnings.
    """

    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    issues: list[ParserIssue] = field(default_factory=list)
    skipped_rows: int = 0
    parser_version: str = "1"
    stats: dict = field(default_factory=dict)


class Parser:
    """Base class for all parsers.

    A parser advertises how confidently it recognizes a blob via ``detect``
    and, when picked, produces structured entities/relationships via ``parse``.
    Parsers that recognize *vulnerabilities* (nuclei, httpx takeover signals)
    may also implement ``findings`` to emit Finding records during ingest.

    Phase A adds the ``parse_detailed`` contract so an import can report
    warnings, skipped rows and a parser version. The old methods remain the
    compatibility surface for existing parsers and third-party code.
    """

    name = "base"
    description = ""
    parser_version = "1"

    def detect(self, text: str) -> float:
        return 0.0

    def parse(self, text: str) -> tuple[list[Entity], list[Relationship]]:
        return [], []

    def findings(self, text: str) -> list[dict]:
        """Optional: return finding dicts {title, severity, ...}.

        Keys understood by the ingest layer: ``title`` (required), ``severity``,
        ``cvss``, ``description``, ``evidence``, ``tags`` (list), ``dedup_key``
        (stable identity for re-import de-duplication), ``target`` (host to
        attribute the finding to).
        """
        return []

    def parse_detailed(self, text: str) -> ParseResult:
        """Run this parser and return the full contract.

        The default is deliberately boring: existing parsers keep working.
        New parsers override this to add skipped-row accounting and warnings.
        """
        entities, relationships = self.parse(text)
        return ParseResult(
            entities=entities,
            relationships=relationships,
            findings=self.findings(text),
            parser_version=self.parser_version,
        )
