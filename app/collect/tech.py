"""Technology and version fingerprinting.

Leadline's tech phase recognized a product from a banner or body marker. The
merge needs the *version* too, because CPE/version-range correlation is only
worth doing when the observed version is known. This module keeps the old
plain-name fingerprints and adds narrow, high-confidence version capture for
the places versions actually appear: ``Server``/``X-Powered-By`` headers,
generator meta tags, and a small set of framework assets.

The output is deliberately independent of any parser. ``http.py`` turns the
observations into canonical ``tech`` labels plus a ``tech_versions`` field in
the httpx JSONL record; the CVE collector consumes the latter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class TechObservation:
    product: str
    version: str = ""
    source: str = "body"
    confidence: str = "medium"


# Product names that appear in Server banners. The canonical spelling is what
# Breadcrumb stores, independent of the vendor's capitalization.
_SERVER_PRODUCTS = {
    "nginx": "nginx",
    "openresty": "OpenResty",
    "apache": "Apache",
    "apache-coyote": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "microsoft-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "lighttpd": "lighttpd",
    "litespeed": "LiteSpeed",
    "caddy": "Caddy",
    "jetty": "Jetty",
    "gunicorn": "Gunicorn",
    "uwsgi": "uWSGI",
    "werkzeug": "Werkzeug",
    "kestrel": "Kestrel",
    "cloudflare": "Cloudflare",
    "varnish": "Varnish",
    "amazons3": "Amazon S3",
    "github.com": "GitHub Pages",
}

SERVER_RE = re.compile(
    r"(?P<product>Microsoft-IIS|Apache-Coyote|Apache|nginx|openresty|lighttpd|"
    r"LiteSpeed|Caddy|Jetty|Tomcat|gunicorn|uWSGI|Werkzeug|Kestrel|cloudflare|"
    r"Varnish|AmazonS3|GitHub\.com)(?:/(?P<version>\d[\w.\-]*))?",
    re.IGNORECASE,
)

POWERED_RE = re.compile(
    r"(?P<product>PHP|ASP\.NET|Express|Servlet|Node\.js|PleskLin|Python)"
    r"(?:/(?P<version>\d[\w.\-]*))?",
    re.IGNORECASE,
)

GENERATOR_RE = re.compile(
    r"^(?P<product>WordPress|Joomla!?|Drupal|TYPO3|Ghost|Hugo|Gatsby|"
    r"Next\.js|Nuxt(?:\.js)?)\s*[/ ]?\s*v?(?P<version>\d[\w.\-]*)",
    re.IGNORECASE,
)

META_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r"([a-zA-Z:_-]+)\s*=\s*(['\"])(.*?)\2", re.DOTALL)

# Header names added by an edge/WAF layer. The header name is a much more
# reliable signal than a provider name appearing in some other header value.
CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "cf-request-id": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-amz-cf-pop": "Amazon CloudFront",
    "x-akamai-transformed": "Akamai",
    "akamai-x-cache": "Akamai",
    "x-akamai-waf-status": "Akamai (WAF)",
    "x-sucuri-id": "Sucuri (WAF)",
    "x-sucuri-cache": "Sucuri (WAF)",
    "x-fastly-request-id": "Fastly",
    "fastly-debug-digest": "Fastly",
    "x-azure-ref": "Azure Front Door/CDN",
    "x-msedge-ref": "Azure Front Door",
    "x-vercel-id": "Vercel",
    "x-vercel-cache": "Vercel",
    "x-datadome": "DataDome (WAF)",
    "x-incapsula-caused-issue": "Imperva Incapsula (WAF)",
    "x-iinfo": "Imperva Incapsula (WAF)",
    "x-cdn": "Generic CDN",
}

# Plain body markers retained from the Phase 4 collector.
BODY_SIGNATURES = (
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|react\.production", re.I), "React"),
    (re.compile(r"drupal-settings-json|sites/default/files", re.I), "Drupal"),
    (re.compile(r"Joomla!", re.I), "Joomla"),
    (re.compile(r"laravel_session|csrf-token", re.I), "Laravel"),
    (re.compile(r"csrftoken=.*django|__admin__", re.I), "Django"),
    (re.compile(r"X-Runtime", re.I), "Ruby on Rails"),
)

# Narrow version signals. Each regex has exactly one named ``version`` group.
VERSION_SIGNATURES = (
    (re.compile(r"ng-version\s*=\s*['\"](?P<version>\d[\w.\-]*)", re.I), "Angular", "high"),
    (re.compile(r"jquery[-.](?P<version>\d+\.\d+(?:\.\d+)?)", re.I), "jQuery", "high"),
    (re.compile(r"bootstrap(?:[/@.-]|\.min\.)(?P<version>\d+\.\d+(?:\.\d+)?)", re.I), "Bootstrap", "medium"),
    (re.compile(r"react(?:-dom)?@(?P<version>\d+\.\d+(?:\.\d+)?)", re.I), "React", "medium"),
    (re.compile(r"vue(?:@|[/-])(?P<version>\d+\.\d+(?:\.\d+)?)", re.I), "Vue.js", "medium"),
    (re.compile(r"next\.js[^\d]{0,12}(?P<version>\d+\.\d+(?:\.\d+)?)", re.I), "Next.js", "low"),
    (re.compile(r"drupal[^\d]{0,12}(?P<version>\d+\.\d+(?:\.\d+)?)", re.I), "Drupal", "low"),
)

MAX_OBSERVATIONS = 100


def _header_items(headers: Iterable) -> list[tuple[str, str]]:
    if hasattr(headers, "items"):
        raw = list(headers.items())
    else:
        raw = list(headers or [])
    return [(str(name), str(value)) for name, value in raw]


def _canonical(name: str) -> str:
    key = (name or "").strip().lower()
    return _SERVER_PRODUCTS.get(key, name.strip())


def _meta_generator(body: str) -> tuple[str, str]:
    for tag in META_RE.findall(body or "")[:500]:
        attrs = {name.lower(): value for name, _quote, value in ATTR_RE.findall(tag)}
        if attrs.get("name", "").lower() == "generator":
            value = attrs.get("content") or ""
            match = GENERATOR_RE.search(value)
            if match:
                return match.group("product").replace("!", ""), match.group("version")
    return "", ""


def detect_technologies(
    headers: Iterable | None, body: str = ""
) -> list[TechObservation]:
    """Return deduplicated product/version observations.

    Header signals win over body signals for the same product/version. A
    versioned observation suppresses an unversioned observation of the same
    product so downstream CVE matching never has to choose.
    """
    observations: list[TechObservation] = []
    seen: set[tuple[str, str]] = set()

    def add(product: str, version: str = "", source: str = "body", confidence: str = "medium") -> None:
        product = (product or "").strip()
        version = (version or "").strip()
        if not product:
            return
        key = (product.lower(), version)
        if key in seen:
            return
        seen.add(key)
        observations.append(TechObservation(product, version, source, confidence))

    items = _header_items(headers or [])
    header_map: dict[str, list[str]] = {}
    for name, value in items:
        header_map.setdefault(name.strip().lower(), []).append(value)

    for value in header_map.get("server", []):
        for match in SERVER_RE.finditer(value):
            product = _canonical(match.group("product"))
            add(product, match.group("version") or "", "server_header", "high")

    for value in header_map.get("x-powered-by", []):
        for match in POWERED_RE.finditer(value):
            add(match.group("product"), match.group("version") or "", "x-powered-by", "medium")

    for value in header_map.get("x-aspnet-version", []):
        add("ASP.NET", value.strip(), "x-aspnet-version", "high")
    for value in header_map.get("x-aspnetmvc-version", []):
        add("ASP.NET MVC", value.strip(), "x-aspnetmvc-version", "high")
    for value in header_map.get("x-generator", []):
        match = GENERATOR_RE.search(value)
        if match:
            add(match.group("product").replace("!", ""), match.group("version"), "x-generator", "high")

    for name, product in CDN_HEADERS.items():
        if name in header_map:
            add(product, "", "response_header", "high")

    generator, generator_version = _meta_generator(body)
    if generator:
        add(generator, generator_version, "generator_meta", "high")

    for pattern, product in BODY_SIGNATURES:
        if pattern.search(body or ""):
            add(product, "", "body", "medium")

    for pattern, product, confidence in VERSION_SIGNATURES:
        match = pattern.search(body or "")
        if match:
            add(product, match.group("version"), "body", confidence)

    versioned = {item.product.lower() for item in observations if item.version}
    result = [
        item for item in observations
        if item.version or item.product.lower() not in versioned
    ]
    return result[:MAX_OBSERVATIONS]


def tech_labels(observations: Iterable[TechObservation]) -> list[str]:
    labels: list[str] = []
    for item in observations:
        if item.product not in labels:
            labels.append(item.product)
    return labels


def tech_versions(observations: Iterable[TechObservation]) -> list[dict]:
    out: list[dict] = []
    for item in observations:
        if not item.version:
            continue
        out.append(
            {
                "product": item.product,
                "version": item.version,
                "source": item.source,
                "confidence": item.confidence,
            }
        )
    return out
