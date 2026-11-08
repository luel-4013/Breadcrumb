"""OWASP Amass JSON/JSONL enumeration results.

Amass records a discovered name plus every address, CIDR, ASN and source it
saw. The parser turns those into normal host/IP entities and ``resolves_to``
relationships; no discovered host is scanned automatically.
"""

from . import register
from .base import Entity, Parser, Relationship
from .tool_json import add_unique, iter_json_values


def _records(text):
    for obj in iter_json_values(text):
        if isinstance(obj.get("name"), str) and any(
            key in obj for key in ("addresses", "domain", "tag", "sources")
        ):
            yield obj


@register
class AmassParser(Parser):
    name = "amass"
    description = "OWASP Amass JSON/JSONL enumeration results"

    def detect(self, text):
        score = 0.0
        for _item in _records(text):
            score += 3.0
            if score >= 6.0:
                break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen = set()
        for item in _records(text):
            name = str(item.get("name") or "").strip().lower().rstrip(".")
            if not name:
                continue
            add_unique(
                entities,
                seen,
                Entity(
                    type="subdomain" if name.count(".") > 1 else "domain",
                    value=name,
                    normalized=name,
                    meta={"from": "amass", "tag": item.get("tag") or ""},
                    confidence=0.85,
                ),
            )
            for address in item.get("addresses") or []:
                if not isinstance(address, dict):
                    continue
                ip = str(address.get("ip") or "").strip()
                if ip:
                    add_unique(
                        entities,
                        seen,
                        Entity(
                            type="ip",
                            value=ip,
                            normalized=ip,
                            meta={"from": "amass", "asn": address.get("asn") or ""},
                            confidence=0.85,
                        ),
                    )
                    rels.append(
                        Relationship(
                            src_value=name,
                            src_type="host",
                            dst_value=ip,
                            dst_type="ip",
                            rel_type="resolves_to",
                        )
                    )
                cidr = str(address.get("cidr") or "").strip()
                if cidr:
                    add_unique(
                        entities,
                        seen,
                        Entity(
                            type="cidr",
                            value=cidr,
                            normalized=cidr,
                            meta={"from": "amass"},
                            confidence=0.7,
                        ),
                    )
        return entities, rels
