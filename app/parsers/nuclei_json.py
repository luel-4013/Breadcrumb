"""ProjectDiscovery nuclei JSONL output.

This is the lingua franca of modern bug hunting: every finding a hunter cares
about arrives here. Without it a notebook is a URL list, not a notebook.
"""

import json
from urllib.parse import urlparse

from . import register
from .base import Entity, Parser, ParseResult, Relationship
from .jsonl import jsonl_issues

_SEV = ("critical", "high", "medium", "low", "info", "unknown")


def _iter_jsonl(text):
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except (ValueError, TypeError):
            continue


def _host_of(value, fallback=""):
    if not value:
        return fallback
    if "://" in value:
        try:
            return urlparse(value).hostname or fallback
        except ValueError:
            return fallback
    return value.split("/")[0].split(":")[0] or fallback


@register
class NucleiParser(Parser):
    name = "nuclei"
    description = "ProjectDiscovery nuclei JSONL scan output"

    def _records(self, text):
        for obj in _iter_jsonl(text):
            if not isinstance(obj, dict):
                continue
            if "template-id" in obj or "templateID" in obj or (
                "info" in obj and "matched-at" in obj
            ):
                yield obj

    def detect(self, text):
        score = 0.0
        for obj in self._records(text):
            score += 3.0
            if isinstance(obj.get("info"), dict):
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
            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            matched = obj.get("matched-at") or obj.get("matched") or obj.get("host") or ""
            host = obj.get("host") or matched
            tid = obj.get("template-id") or obj.get("templateID") or ""
            severity = (info.get("severity") or "unknown").lower()
            name = info.get("name") or tid
            meta = {"template": tid, "name": name, "severity": severity}

            if tid and tid.upper().startswith("CVE-"):
                add(Entity(type="cve", value=tid.upper(), normalized=tid.upper(), confidence=0.95))
            classification = info.get("classification") or {}
            cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            for cve in cve_ids:
                if cve:
                    add(Entity(type="cve", value=str(cve).upper(), normalized=str(cve).upper()))

            if matched.startswith(("http://", "https://")):
                add(Entity(type="url", value=matched, normalized=matched, meta=dict(meta), confidence=0.95))
                try:
                    path = urlparse(matched).path
                except ValueError:
                    path = ""
                if path and path != "/":
                    add(Entity(type="path", value=path, normalized=path,
                               meta={"host": _host_of(matched)}, confidence=0.7))

            h = _host_of(host or matched)
            if h:
                add(Entity(type="subdomain" if h.count(".") > 1 else "domain",
                           value=h, normalized=h.lower(),
                           meta={"from": "nuclei"}, confidence=0.85))
            ip = obj.get("ip")
            if ip:
                add(Entity(type="ip", value=ip, normalized=ip, meta={"from": "nuclei"}))
            if obj.get("port"):
                add(Entity(type="port", value=str(obj["port"]), normalized=f"{h or ip}:{obj['port']}",
                           meta={"host": h or ip, "port": int(obj["port"])}, confidence=0.7))
        return entities, rels

    def findings(self, text):
        out = []
        for obj in self._records(text):
            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            tid = obj.get("template-id") or obj.get("templateID") or "unknown-template"
            matched = obj.get("matched-at") or obj.get("matched") or obj.get("host") or ""
            host = _host_of(obj.get("host") or matched)
            matcher = obj.get("matcher-name") or obj.get("matcher_name") or ""
            severity = (info.get("severity") or "info").lower()
            if severity not in _SEV:
                severity = "info"
            classification = info.get("classification") or {}
            cvss = classification.get("cvss-score") or classification.get("cvss_score")
            extracted = obj.get("extracted-results") or obj.get("extracted_results") or []
            if isinstance(extracted, str):
                extracted = [extracted]
            evidence = matched
            if matcher:
                evidence += f"  [matcher: {matcher}]"
            if extracted:
                evidence += "  -> " + ", ".join(str(x) for x in extracted[:5])
            out.append(
                {
                    "title": info.get("name") or tid,
                    "severity": severity,
                    "cvss": cvss,
                    "description": info.get("description") or "",
                    "evidence": evidence,
                    "tags": info.get("tags") or [],
                    "target": host,
                    "template": tid,
                    "dedup_key": f"nuclei|{tid}|{matched}|{matcher}",
                }
            )
        return out

    def parse_detailed(self, text):
        entities, rels = self.parse(text)
        findings = self.findings(text)
        issues, skipped = jsonl_issues(text, self.name)
        records = sum(1 for _ in self._records(text))
        return ParseResult(
            entities=entities,
            relationships=rels,
            findings=findings,
            issues=issues,
            skipped_rows=skipped,
            parser_version=self.parser_version,
            stats={"records": records},
        )
