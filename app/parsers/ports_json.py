"""Port-scanner output: naabu JSON/text and masscan text.

nmap has its own parser; these cover the other two scanners hunters reach for,
whose output shapes are otherwise silently reduced to a bare IP.
"""

import json
import re

from . import register
from .base import Entity, Parser, Relationship

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MASSCAN_RE = re.compile(
    r"Discovered open port\s+(?P<port>\d+)/(?P<proto>tcp|udp)\s+on\s+(?P<host>[0-9a-fA-F:.]+)"
)


def _iter_jsonl(text):
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except (ValueError, TypeError):
                continue


@register
class PortsParser(Parser):
    name = "ports"
    description = "naabu/masscan port scan output"

    def detect(self, text):
        score = 0.0
        if MASSCAN_RE.search(text):
            score += 3.0
        for obj in _iter_jsonl(text):
            if isinstance(obj, dict) and "port" in obj and ("host" in obj or "ip" in obj):
                score += 2.0
                if score >= 6.0:
                    break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen = set()

        def add_host_port(host, ip, port, proto="tcp", service=""):
            if ip and ip not in seen:
                seen.add(ip)
                entities.append(Entity(type="ip", value=ip, normalized=ip, confidence=0.9))
            target = host or ip
            if host and host != ip and not _IP_RE.match(host):
                key = host.lower()
                if key not in seen:
                    seen.add(key)
                    entities.append(Entity(
                        type="subdomain" if host.count(".") > 1 else "domain",
                        value=host, normalized=key, confidence=0.85))
            if not port:
                return
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                return
            norm = f"{target}:{port_int}"
            entities.append(Entity(
                type="port", value=f"{port_int}/{proto} {service}".strip(), normalized=norm,
                meta={"host": target, "port": port_int, "proto": proto,
                      "service": service, "state": "open"}, confidence=0.9))
            if target:
                rels.append(Relationship(src_value=target, src_type="host",
                                         dst_value=norm, dst_type="port", rel_type="has_port"))

        for match in MASSCAN_RE.finditer(text):
            add_host_port(None, match.group("host"), match.group("port"), match.group("proto"))

        for obj in _iter_jsonl(text):
            if not isinstance(obj, dict) or "port" not in obj:
                continue
            host = obj.get("host") or obj.get("ip") or ""
            ip = obj.get("ip") or (host if _IP_RE.match(host or "") else "")
            add_host_port(host if not _IP_RE.match(host) else None, ip,
                          obj.get("port"), obj.get("protocol") or "tcp")
        return entities, rels
