"""BBOT JSON/JSONL output.

BBOT is the recursive scanner many hunters already run. Its event stream is
richer than a plain host list: DNS names carry resolved addresses, ports carry
hosts, HTTP responses carry status/title, and findings carry severity. This
parser keeps those relationships so a BBOT export is as useful as native
Breadcrumb captures.

Supported shapes: a JSON array, a single JSON object, or newline-delimited
objects. BBOT versions differ slightly; unknown event types are ignored, while
malformed JSON rows are reported as skipped rows by ``parse_detailed``.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from . import register
from .base import Entity, Parser, ParseResult, Relationship
from .jsonl import jsonl_issues
from .tool_json import add_unique, iter_json_values

KNOWN_EVENTS = {
    "DNS_NAME",
    "IP_ADDRESS",
    "OPEN_TCP_PORT",
    "TCP_PORT",
    "URL",
    "HTTP_RESPONSE",
    "TECHNOLOGY",
    "FINDING",
    "VULNERABILITY",
    "EMAIL_ADDRESS",
    "CIDR",
    "ASN",
    "STORAGE_BUCKET",
    "WEBSCREENSHOT",
    "PROTOCOL",
}


def _records(text):
    for item in iter_json_values(text):
        etype = str(item.get("type") or "").upper()
        if etype in KNOWN_EVENTS or "scope_description" in item:
            yield item


def _host_of(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" in value:
        try:
            return (urlparse(value).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    return value.split("/")[0].split(":")[0].lower().rstrip(".")


def _host_entity(host: str, *, parser: str, meta: dict | None = None) -> Entity | None:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return None
    if host.startswith("*."):
        return Entity(
            type="wildcard",
            value=host,
            normalized=host,
            meta={"from": parser, **(meta or {})},
            confidence=0.9,
        )
    return Entity(
        type="subdomain" if host.count(".") > 1 else "domain",
        value=host,
        normalized=host,
        meta={"from": parser, **(meta or {})},
        confidence=0.85,
    )


@register
class BbotParser(Parser):
    name = "bbot"
    description = "BBOT JSON/JSONL event output (DNS, IPs, ports, URLs, findings)"
    parser_version = "1"

    def detect(self, text):
        score = 0.0
        for item in _records(text):
            etype = str(item.get("type") or "").upper()
            if etype in KNOWN_EVENTS:
                score += 3.0
            if "scope_description" in item:
                score += 1.0
            if score >= 9.0:
                break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen: set[tuple[str, str]] = set()

        def add(entity: Entity | None):
            if entity is not None:
                add_unique(entities, seen, entity)

        for item in _records(text):
            etype = str(item.get("type") or "").upper()
            data = item.get("data")
            data = data if isinstance(data, str) else (str(data) if data is not None else "")
            host = _host_of(str(item.get("host") or item.get("url") or ""))
            parent = str(item.get("parent") or "").strip()

            if etype == "DNS_NAME":
                add(_host_entity(data, parser=self.name))
                if host and host != data.lower():
                    add(_host_entity(host, parser=self.name))
                resolved = item.get("resolved_hosts") or item.get("resolved-hosts") or []
                if isinstance(resolved, str):
                    resolved = [resolved]
                for ip in resolved:
                    ip = str(ip).strip()
                    if not ip:
                        continue
                    add(Entity(type="ip", value=ip, normalized=ip,
                               meta={"from": self.name}, confidence=0.85))
                    src = _host_entity(data, parser=self.name)
                    if src is not None:
                        rels.append(Relationship(src_value=src.value, src_type="host",
                                                 dst_value=ip, dst_type="ip",
                                                 rel_type="resolves_to"))

            elif etype == "IP_ADDRESS":
                ip = data.strip()
                if ip:
                    add(Entity(type="ip", value=ip, normalized=ip,
                               meta={"from": self.name}, confidence=0.9))
                    if parent:
                        rels.append(Relationship(src_value=parent, src_type="host",
                                                 dst_value=ip, dst_type="ip",
                                                 rel_type="resolves_to"))

            elif etype in {"OPEN_TCP_PORT", "TCP_PORT"}:
                value = data.strip()
                if ":" in value:
                    port_host, _, port = value.rpartition(":")
                else:
                    port_host, port = host, value
                port_host = _host_of(port_host)
                if port.isdigit():
                    add(Entity(type="port", value=port, normalized=f"{port_host}:{port}",
                               meta={"host": port_host, "port": int(port)},
                               confidence=0.8))
                    if port_host:
                        add(_host_entity(port_host, parser=self.name))
                        rels.append(Relationship(src_value=port_host, src_type="host",
                                                 dst_value=f"{port_host}:{port}",
                                                 dst_type="port", rel_type="has_port"))

            elif etype in {"URL", "HTTP_RESPONSE", "WEBSCREENSHOT"}:
                url = data.strip()
                if not url and item.get("url"):
                    url = str(item.get("url"))
                if url:
                    meta = {"from": self.name}
                    for key in ("status_code", "title", "content_length", "webserver"):
                        if item.get(key) not in (None, ""):
                            meta[key] = item.get(key)
                    add(Entity(type="url", value=url, normalized=url,
                               meta=meta, confidence=0.9))
                    uhost = _host_of(url)
                    add(_host_entity(uhost, parser=self.name))
                    try:
                        path = urlparse(url).path
                    except ValueError:
                        path = ""
                    if path and path != "/":
                        add(Entity(type="path", value=path, normalized=path,
                                   meta={"host": uhost}, confidence=0.7))

            elif etype == "TECHNOLOGY":
                tech = data.strip()
                if tech:
                    add(Entity(type="tech", value=tech, normalized=tech.lower(),
                               meta={"host": host} if host else {}, confidence=0.7))

            elif etype == "EMAIL_ADDRESS":
                email = data.strip()
                if email:
                    add(Entity(type="email", value=email, normalized=email.lower(),
                               confidence=0.8))

            elif etype == "CIDR":
                cidr = data.strip()
                if cidr:
                    add(Entity(type="cidr", value=cidr, normalized=cidr,
                               confidence=0.8))

            elif etype == "ASN":
                asn = data.strip()
                if asn:
                    add(Entity(type="asn", value=asn, normalized=asn.upper(),
                               meta={"host": host} if host else {}, confidence=0.7))

            elif etype == "STORAGE_BUCKET":
                bucket = data.strip()
                if bucket:
                    add(Entity(type="storage_bucket", value=bucket, normalized=bucket.lower(),
                               meta={"host": host} if host else {}, confidence=0.7))

            # Findings are emitted by ``findings()`` so re-import de-duplication
            # shares the same code path as nuclei.

        return entities, rels

    def findings(self, text):
        out: list[dict] = []
        for item in _records(text):
            etype = str(item.get("type") or "").upper()
            if etype not in {"FINDING", "VULNERABILITY"}:
                continue
            data = item.get("data")
            title = str(item.get("name") or data or etype).strip()
            if not title:
                continue
            severity = str(item.get("severity") or "info").lower()
            if severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
                severity = "info"
            target = _host_of(str(item.get("host") or item.get("url") or ""))
            description = str(item.get("description") or "")
            evidence = str(item.get("url") or item.get("data") or "")
            out.append(
                {
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "evidence": evidence,
                    "target": target,
                    "tags": item.get("tags") or [],
                    "rule_id": str(item.get("name") or title),
                    "dedup_key": f"bbot|{etype}|{title}|{target}|{evidence}",
                }
            )
        return out

    def parse_detailed(self, text):
        entities, rels = self.parse(text)
        issues, skipped = jsonl_issues(text, self.name)
        records = sum(1 for _ in _records(text))
        # A JSON array (not JSONL) cannot be diagnosed line-by-line; try one
        # whole-document parse so a truncated array is still explainable.
        if not records and text.strip().startswith(("[", "{")):
            try:
                json.loads(text)
            except (ValueError, TypeError) as exc:
                skipped += 1
                from .base import ParserIssue

                issues.append(
                    ParserIssue(self.name, "skipped_row", f"invalid JSON document ({exc})")
                )
        return ParseResult(
            entities=entities,
            relationships=rels,
            findings=self.findings(text),
            issues=issues,
            skipped_rows=skipped,
            parser_version=self.parser_version,
            stats={"records": records},
        )
