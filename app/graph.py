"""Deterministic graph construction.

Entities are graph *nodes*; relationships are *edges*. Parsers only know what
they saw inside a single blob, so this module derives the edges that tie blobs
together: which subdomain belongs to which domain, which port sits on which
host, which URL lives on which host, which secret was found at which host, and
so on. Everything here is rule-based and offline -- no model involved.

Edge types
----------
part_of      child -> parent (sub.example.com -> example.com, ip -> cidr)
belongs_to   url/path/param -> host
has_port     host -> port
runs         port -> service
resolves_to  host/dns name -> ip or cname target
in_range     ip -> cidr
found_at     secret/credential -> host
alias_of     dns CNAME name -> target name
references   generic "mentions" link
"""

import ipaddress
from dataclasses import dataclass, field

from .scope import host_of

NODE_TYPES = [
    "target", "domain", "subdomain", "wildcard", "ip", "cidr",
    "dns_record", "port", "service", "tech", "url", "endpoint", "path", "param",
    "credential", "secret", "jwt", "hash", "cve", "email",
    "header", "cookie", "http_status", "finding", "evidence", "note",
]

EDGE_TYPES = [
    "part_of", "belongs_to", "has_port", "runs", "resolves_to", "in_range",
    "found_at", "leaks", "alias_of", "references", "leads_to", "proves", "spawned",
]

EDGE_LABELS = {
    "part_of": "part of",
    "belongs_to": "belongs to",
    "has_port": "has port",
    "runs": "runs",
    "resolves_to": "resolves to",
    "in_range": "in range",
    "found_at": "found at",
    "leaks": "leaks",
    "alias_of": "alias of",
    "references": "references",
    "leads_to": "leads to",
    "proves": "proves",
    "spawned": "spawned",
}

HOST_TYPES = {"domain", "subdomain", "wildcard", "ip"}
PARENT_TYPES = {"subdomain", "domain", "wildcard"}


@dataclass
class Edge:
    src_value: str
    src_type: str
    dst_value: str
    dst_type: str
    rel_type: str
    confidence: float = 0.7
    meta: dict = field(default_factory=dict)


def parent_hosts(host: str) -> list[str]:
    """Successive parents of a host: a.b.c -> [b.c, c]."""
    if not host or host.count(".") < 1:
        return []
    parts = host.split(".")
    if all(part.isdigit() for part in parts):
        return []
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]


class GraphIndex:
    """Lookup helper over a set of entities, used while deriving edges."""

    def __init__(self, entities):
        self.by_host: dict[str, object] = {}
        self.by_type_value: dict[tuple[str, str], object] = {}
        self.by_service: dict[str, object] = {}
        self.cidrs: list[tuple[object, object]] = []
        for ent in entities:
            etype = getattr(ent, "type", "")
            value = getattr(ent, "value", "")
            norm = (getattr(ent, "normalized", "") or value).lower()
            self.by_type_value.setdefault((etype, norm), ent)
            if etype in HOST_TYPES:
                host = host_of(value, etype)
                if host:
                    self.by_host.setdefault(host, ent)
            if etype == "service":
                self.by_service.setdefault(norm, ent)
            if etype == "cidr":
                try:
                    self.cidrs.append((ipaddress.ip_network(value, strict=False), ent))
                except ValueError:
                    pass

    def host(self, value: str, vtype: str = ""):
        return self.by_host.get(host_of(value, vtype))

    def typed(self, etype: str, value: str):
        return self.by_type_value.get((etype, (value or "").lower()))


def derive_edges(entities) -> list[Edge]:
    """Return deterministic edges among the supplied entities."""
    index = GraphIndex(entities)
    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()

    def add(src, dst, rel, conf=0.7, meta=None):
        if src is None or dst is None or src is dst:
            return
        key = (str(getattr(src, "id", id(src))), str(getattr(dst, "id", id(dst))), rel)
        if key in seen:
            return
        seen.add(key)
        edges.append(
            Edge(
                src_value=src.value,
                src_type=src.type,
                dst_value=dst.value,
                dst_type=dst.type,
                rel_type=rel,
                confidence=conf,
                meta=meta or {},
            )
        )

    for ent in entities:
        etype = ent.type
        meta = ent.meta or {}

        if etype in PARENT_TYPES:
            host = host_of(ent.value, etype)
            for parent in parent_hosts(host):
                node = index.by_host.get(parent)
                if node is not None:
                    add(ent, node, "part_of", 0.9)
                    break

        elif etype == "ip":
            try:
                candidate = ipaddress.ip_address(ent.value)
            except ValueError:
                candidate = None
            if candidate is not None:
                for network, node in index.cidrs:
                    if candidate in network:
                        add(ent, node, "in_range", 0.95)
                        add(ent, node, "part_of", 0.8)

        elif etype in {"url", "path", "param"}:
            host = meta.get("host")
            node = index.host(host, "url") if host else None
            if node is not None:
                add(ent, node, "belongs_to", 0.85)

        elif etype == "port":
            host = meta.get("host")
            node = index.host(host, "port") if host else None
            if node is not None:
                add(node, ent, "has_port", 0.95)
            service = (meta.get("service") or "").lower()
            service_node = index.by_service.get(service)
            if service_node is not None:
                add(ent, service_node, "runs", 0.7)

        elif etype == "dns_record":
            name = meta.get("name")
            rtype = (meta.get("rtype") or "").upper()
            value = meta.get("value") or ""
            src_node = index.host(name, "domain") if name else None
            if src_node is None:
                continue
            if rtype in {"A", "AAAA"}:
                dst_node = index.host(value, "ip")
                if dst_node is not None:
                    add(src_node, dst_node, "resolves_to", 0.9)
            elif rtype == "CNAME":
                dst_node = index.host(value, "domain")
                if dst_node is not None:
                    add(src_node, dst_node, "resolves_to", 0.85)
                    add(src_node, dst_node, "alias_of", 0.85)
            elif rtype in {"MX", "NS", "PTR", "SRV"}:
                dst_node = index.host(value.split()[-1], "domain")
                if dst_node is not None:
                    add(src_node, dst_node, "references", 0.6)

        elif etype in {"secret", "credential", "jwt"}:
            host = meta.get("host")
            node = index.host(host, "domain") if host else None
            if node is not None:
                add(ent, node, "found_at", 0.8)

    edges.sort(key=lambda edge: (edge.src_value, edge.rel_type, edge.dst_value))
    return edges
