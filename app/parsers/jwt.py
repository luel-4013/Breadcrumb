import base64
import json
import re

from . import register
from .base import Entity, Parser

JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*)\b")


def _b64(segment):
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


@register
class JWTParser(Parser):
    name = "jwt"
    description = "JSON Web Tokens (decodes header/payload)"

    def detect(self, text):
        return min(len(JWT_RE.findall(text)), 5.0)

    def parse(self, text):
        entities = []
        for token in JWT_RE.findall(text):
            meta = {}
            try:
                header, payload = token.split(".")[:2]
                meta = {"header": json.loads(_b64(header)), "payload": json.loads(_b64(payload))}
            except Exception:
                pass
            entities.append(Entity(type="jwt", value=token, normalized=token, meta=meta, confidence=0.95))
        return entities, []
