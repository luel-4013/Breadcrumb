import re

from . import register
from .base import Entity, Parser

NTLM_RE = re.compile(r"\b([0-9A-Fa-f]{32}:[0-9A-Fa-f]{32})\b")
BCRYPT_RE = re.compile(r"(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})")
SHA256_RE = re.compile(r"\b([0-9A-Fa-f]{64})\b")
SHA1_RE = re.compile(r"\b([0-9A-Fa-f]{40})\b")
MD5_RE = re.compile(r"\b([0-9A-Fa-f]{32})\b")


@register
class HashParser(Parser):
    name = "hash"
    description = "MD5 / SHA1 / SHA256 / NTLM / bcrypt hashes"

    def detect(self, text):
        hits = (
            len(NTLM_RE.findall(text))
            + len(BCRYPT_RE.findall(text))
            + len(SHA256_RE.findall(text))
            + len(SHA1_RE.findall(text))
            + len(MD5_RE.findall(text))
        )
        return min(hits, 6.0)

    def parse(self, text):
        entities = []

        def add(value, algo, confidence):
            entities.append(
                Entity(
                    type="hash",
                    value=value,
                    normalized=value.lower(),
                    meta={"algo": algo},
                    confidence=confidence,
                )
            )

        masked = NTLM_RE.sub(lambda m: " " * len(m.group(0)), text)
        for value in NTLM_RE.findall(text):
            add(value, "ntlm", 0.9)
        for value in BCRYPT_RE.findall(masked):
            add(value, "bcrypt", 0.95)
        for value in SHA256_RE.findall(masked):
            add(value, "sha256", 0.9)
        for value in SHA1_RE.findall(masked):
            add(value, "sha1", 0.85)
        for value in MD5_RE.findall(masked):
            add(value, "md5", 0.8)
        return entities, []
