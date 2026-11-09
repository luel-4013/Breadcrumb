"""ProjectDiscovery httpx JSON output (one JSON object per line).

Carries the richest passive fingerprint available offline: status codes,
titles, web servers, technology stacks and CNAMEs (the raw material for
subdomain-takeover detection).
"""

import json
import re

from . import register
from .base import Entity, Parser, ParseResult, Relationship
from .jsonl import jsonl_issues

_IP_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")


def _iter_jsonl(text):
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except (ValueError, TypeError):
            continue


@register
class HttpxParser(Parser):
    name = "httpx"
    description = "ProjectDiscovery httpx -json probe results"

    def _records(self, text):
        for obj in _iter_jsonl(text):
            if not isinstance(obj, dict):
                continue
            if "status_code" in obj and ("url" in obj or "input" in obj):
                yield obj

    def detect(self, text):
        score = 0.0
        for obj in self._records(text):
            score += 3.0
            if "tech" in obj:
                score += 1.0
            if score >= 8.0:
                break
        return score

    def parse(self, text):
        entities, rels = [], []
        seen = set()

        def add(ent):
            key = (ent.type, ent.normalized.lower())
            if key in seen:
                return
            seen.add(key)
            entities.append(ent)

        for obj in self._records(text):
            url = obj.get("url") or obj.get("final_url") or obj.get("final-url") or ""
            host_field = obj.get("host") or ""
            input_host = (obj.get("input") or "").split("/")[0].split(":")[0]
            ip = host_field if _IP_RE.match(host_field or "") else ""
            port = obj.get("port")
            tech = obj.get("tech") or []
            if isinstance(tech, str):
                tech = [t.strip() for t in tech.split(",") if t.strip()]
            cnames = obj.get("cname") or []
            if isinstance(cnames, str):
                cnames = [cnames]

            url_meta = {
                "status_code": obj.get("status_code"),
                "title": obj.get("title") or "",
                "content_length": obj.get("content_length"),
                "webserver": obj.get("webserver") or "",
                "tech": tech,
            }
            hostname = input_host or (url.split("://", 1)[-1].split("/")[0].split(":")[0] if url else "")
            hostname = hostname.strip().lower()

            if url:
                add(Entity(type="url", value=url, normalized=url,
                           meta={k: v for k, v in url_meta.items() if v not in (None, "", [])},
                           confidence=0.95))
            if hostname:
                htype = "ip" if _IP_RE.match(hostname) else (
                    "subdomain" if hostname.count(".") > 1 else "domain")
                ent_meta = {"from": "httpx"}
                if cnames:
                    ent_meta["cname"] = cnames[0]
                add(Entity(type=htype, value=hostname, normalized=hostname,
                           meta=ent_meta, confidence=0.9))
            if ip:
                add(Entity(type="ip", value=ip, normalized=ip, meta={"from": "httpx"}))
            if port:
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    port_int = port
                add(Entity(type="port", value=str(port_int),
                           normalized=f"{hostname or ip}:{port_int}",
                           meta={"host": hostname or ip, "port": port_int,
                                 "service": obj.get("scheme") or ""},
                           confidence=0.7))
            for t in tech:
                add(Entity(type="tech", value=t, normalized=str(t).lower(),
                           meta={"host": hostname} if hostname else {}, confidence=0.6))
            for cn in cnames:
                cn = cn.strip().lower().rstrip(".")
                if not cn:
                    continue
                add(Entity(type="subdomain" if cn.count(".") > 1 else "domain",
                           value=cn, normalized=cn, meta={"from": "cname"}, confidence=0.8))
                if hostname:
                    rels.append(Relationship(src_value=hostname, src_type="host",
                                             dst_value=cn, dst_type="cname",
                                             rel_type="resolves_to"))
            if hostname and ip:
                rels.append(Relationship(src_value=hostname, src_type="host",
                                         dst_value=ip, dst_type="ip", rel_type="resolves_to"))
        return entities, rels

    def parse_detailed(self, text):
        entities, rels = self.parse(text)
        issues, skipped = jsonl_issues(text, self.name)
        records = sum(1 for _ in self._records(text))
        return ParseResult(
            entities=entities,
            relationships=rels,
            issues=issues,
            skipped_rows=skipped,
            parser_version=self.parser_version,
            stats={"records": records},
        )
