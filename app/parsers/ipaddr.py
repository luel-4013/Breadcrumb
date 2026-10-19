import ipaddress
import re

from . import register
from .base import Entity, Parser

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?(?![\d.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![0-9A-Fa-f:.])"
)


@register
class IPParser(Parser):
    name = "ip"
    description = "IPv4 / IPv6 addresses and CIDR ranges"

    def detect(self, text):
        hits = len(IPV4_RE.findall(text)) + len(IPV6_RE.findall(text))
        return min(hits, 5.0)

    def parse(self, text):
        entities = []
        seen = set()
        for token in IPV4_RE.findall(text) + IPV6_RE.findall(text):
            token = token.strip().rstrip(".")
            if token in seen:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            seen.add(token)
            if "/" in token:
                entities.append(
                    Entity(
                        type="cidr",
                        value=token,
                        normalized=str(net),
                        meta={
                            "version": net.version,
                            "network": str(net.network_address),
                            "prefix": net.prefixlen,
                            "size": net.num_addresses,
                        },
                        confidence=0.9,
                    )
                )
            else:
                entities.append(
                    Entity(
                        type="ip",
                        value=token,
                        normalized=str(net.network_address),
                        meta={"version": net.version, "private": net.is_private},
                        confidence=0.9,
                    )
                )
        return entities, []
