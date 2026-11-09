import re
import xml.etree.ElementTree as ET

from . import register
from .base import Entity, Parser, ParserIssue, ParseResult, Relationship

REPORT_RE = re.compile(
    r"Nmap scan report for[ \t]+(?P<host>.+?)(?:[ \t]+\((?P<ip>[0-9a-fA-F:.]+)\))?[ \t]*$",
    re.MULTILINE,
)
PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)[ \t]+"
    r"(?P<state>open|closed|filtered|open\|filtered|unfiltered)[ \t]+"
    r"(?P<service>\S+)[ \t]*(?P<version>.*)$",
    re.MULTILINE,
)
GREP_HOST_RE = re.compile(
    r"^Host:[ \t]+(?P<ip>\S+)[ \t]*(?:\((?P<name>[^)]*)\))?[ \t]*Ports:[ \t]*(?P<ports>.+)$",
    re.MULTILINE,
)


@register
class NmapParser(Parser):
    name = "nmap"
    description = "nmap text, greppable and XML output"

    def detect(self, text):
        score = 0.0
        if "Nmap scan report" in text or "Starting Nmap" in text:
            score += 3.0
        if "<nmaprun" in text:
            score += 3.0
        if "PORT" in text and "STATE" in text and "SERVICE" in text:
            score += 2.0
        score += min(len(GREP_HOST_RE.findall(text)), 3)
        return score

    def parse(self, text):
        if "<nmaprun" in text:
            try:
                return self._parse_xml(text)
            except ET.ParseError:
                pass
        return self._parse_text(text)

    def parse_detailed(self, text):
        issues: list[ParserIssue] = []
        if "<nmaprun" in text:
            try:
                entities, rels = self._parse_xml(text)
            except ET.ParseError as exc:
                issues.append(
                    ParserIssue(
                        self.name,
                        "skipped_row",
                        f"nmap XML could not be parsed ({exc}); fell back to text",
                    )
                )
                entities, rels = self._parse_text(text)
        else:
            entities, rels = self._parse_text(text)
        return ParseResult(
            entities=entities,
            relationships=rels,
            issues=issues,
            parser_version=self.parser_version,
            stats={"hosts": len({e.normalized for e in entities if e.type in {"ip", "domain", "subdomain"}})},
        )

    def _add_host(self, entities, seen, host_val, ip):
        if ip and ip not in seen:
            seen.add(ip)
            entities.append(
                Entity(type="ip", value=ip, normalized=ip, meta={"from": "nmap"}, confidence=0.95)
            )
        if host_val and host_val != ip and not re.fullmatch(r"[0-9.]+", host_val):
            key = host_val.lower()
            if key not in seen:
                seen.add(key)
                parts = host_val.split(".")
                entities.append(
                    Entity(
                        type="subdomain" if len(parts) > 2 else "domain",
                        value=host_val,
                        normalized=key,
                        meta={"from": "nmap"},
                        confidence=0.9,
                    )
                )
        return ip or host_val

    def _add_port(self, entities, rels, host, port, proto, service, version):
        if not host or not port:
            return
        version = (version or "").strip()
        port_norm = f"{host}:{port}"
        entities.append(
            Entity(
                type="port",
                value=f"{port}/{proto} {service}".strip(),
                normalized=port_norm,
                meta={
                    "host": host,
                    "port": int(port),
                    "proto": proto,
                    "state": "open",
                    "service": service,
                    "version": version,
                },
                confidence=0.95,
            )
        )
        if service and service.lower() not in {"unknown", "tcpwrapped"}:
            entities.append(
                Entity(
                    type="service",
                    value=service,
                    normalized=service.lower(),
                    meta={"version": version} if version else {},
                    confidence=0.7,
                )
            )
        rels.append(
            Relationship(
                src_value=host, src_type="host",
                dst_value=port_norm, dst_type="port", rel_type="has_port",
            )
        )

    def _parse_text(self, text):
        entities, rels = [], []
        seen = set()

        for match in GREP_HOST_RE.finditer(text):
            ip = match.group("ip")
            name = (match.group("name") or "").strip()
            host = self._add_host(entities, seen, name or ip, ip)
            for chunk in match.group("ports").split(","):
                parts = chunk.split("/")
                if len(parts) >= 3 and parts[1] == "open":
                    service = parts[4] if len(parts) > 4 else ""
                    version = parts[6] if len(parts) > 6 else ""
                    self._add_port(entities, rels, host, parts[0], parts[2], service, version)

        reports = list(REPORT_RE.finditer(text))
        for i, match in enumerate(reports):
            start = match.end()
            end = reports[i + 1].start() if i + 1 < len(reports) else len(text)
            block = text[start:end]
            ip = match.group("ip")
            host_val = (match.group("host") or "").strip()
            host = self._add_host(entities, seen, host_val, ip)
            for port in PORT_RE.finditer(block):
                self._add_port(
                    entities, rels, host,
                    port.group("port"), port.group("proto"),
                    port.group("service"), port.group("version"),
                )
        return entities, rels

    def _parse_xml(self, text):
        entities, rels = [], []
        seen = set()
        root = ET.fromstring(text)
        for host_el in root.findall("host"):
            addr = host_el.find("address")
            ip = addr.get("addr") if addr is not None else None
            names = [h.get("name") for h in host_el.findall("hostnames/hostname") if h.get("name")]
            host_val = names[0] if names else ip
            host = self._add_host(entities, seen, host_val, ip)
            for name in names[1:]:
                key = name.lower()
                if key not in seen:
                    seen.add(key)
                    entities.append(
                        Entity(
                            type="subdomain" if name.count(".") > 1 else "domain",
                            value=name, normalized=key,
                            meta={"from": "nmap"}, confidence=0.85,
                        )
                    )
            if ip and host_val and host_val != ip:
                rels.append(
                    Relationship(
                        src_value=host_val, src_type="host",
                        dst_value=ip, dst_type="ip", rel_type="resolves_to",
                    )
                )
            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                service = service_el.get("name") if service_el is not None else ""
                version = ""
                if service_el is not None:
                    version = " ".join(
                        v for v in (service_el.get("product"), service_el.get("version")) if v
                    )
                self._add_port(
                    entities, rels, host,
                    port_el.get("portid"), port_el.get("protocol", "tcp"), service, version,
                )
        return entities, rels
