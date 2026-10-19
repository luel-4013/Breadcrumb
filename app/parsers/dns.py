import re

from . import register
from .base import Entity, Parser

SECTION_RE = re.compile(r";;\s*(?:ANSWER|AUTHORITY|ADDITIONAL|QUESTION)\s+SECTION", re.IGNORECASE)
RECORD_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.*\-]+?)\.?\s+(?:\d+\s+)?(?:IN\s+)?"
    r"(?P<rtype>A|AAAA|CNAME|MX|NS|TXT|SOA|PTR|SRV)\s+(?P<value>.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)


@register
class DNSParser(Parser):
    name = "dns"
    description = "DNS records (dig / host / nslookup)"

    def detect(self, text):
        if SECTION_RE.search(text):
            return 3.0
        return min(len(RECORD_RE.findall(text)), 4.0)

    def parse(self, text):
        entities = []
        for match in RECORD_RE.finditer(text):
            name = match.group("name").rstrip(".")
            rtype = match.group("rtype").upper()
            value = match.group("value").strip()
            entities.append(
                Entity(
                    type="dns_record",
                    value=f"{name} {rtype} {value}",
                    normalized=f"{name.lower()}|{rtype}|{value.lower()}",
                    meta={"name": name, "rtype": rtype, "value": value},
                    confidence=0.8,
                )
            )
        return entities, []
