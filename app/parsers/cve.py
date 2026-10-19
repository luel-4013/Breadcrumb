import re

from . import register
from .base import Entity, Parser

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@register
class CVEParser(Parser):
    name = "cve"
    description = "CVE identifiers"

    def detect(self, text):
        return min(len(CVE_RE.findall(text)), 5.0)

    def parse(self, text):
        entities = []
        seen = set()
        for value in CVE_RE.findall(text):
            value = value.upper()
            if value in seen:
                continue
            seen.add(value)
            entities.append(Entity(type="cve", value=value, normalized=value, confidence=0.95))
        return entities, []
