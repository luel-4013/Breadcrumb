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


class Parser:
    """Base class for all parsers.

    A parser advertises how confidently it recognizes a blob via ``detect``
    and, when picked, produces structured entities/relationships via ``parse``.
    Parsers that recognize *vulnerabilities* (nuclei, httpx takeover signals)
    may also implement ``findings`` to emit Finding records during ingest.
    """

    name = "base"
    description = ""

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
