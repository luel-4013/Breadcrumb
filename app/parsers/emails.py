import re

from . import register
from .base import Entity, Parser

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b")

_IMAGE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp"}


@register
class EmailParser(Parser):
    name = "email"
    description = "email addresses"

    def detect(self, text):
        return min(len(EMAIL_RE.findall(text)), 5.0)

    def parse(self, text):
        entities = []
        seen = set()
        for value in EMAIL_RE.findall(text):
            if value.rsplit(".", 1)[-1].lower() in _IMAGE_TLDS:
                continue
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)
            entities.append(
                Entity(
                    type="email",
                    value=value,
                    normalized=key,
                    meta={"domain": value.split("@", 1)[1]},
                    confidence=0.9,
                )
            )
        return entities, []
