"""Local NVD cache and CPE/version-range correlation.

Leadline's CVE phase queried NVD live. Breadcrumb's contract is offline-first,
so the merge moves the data to the analyst's machine:

* ``NvdCache`` loads a local JSON file of NVD CVE 2.0 objects (the same shape
  as an API page or a downloaded feed) and builds a vendor/product index.
* A CPE match is only reported as *verified* when the observed product resolves
  to a CPE and the observed version falls inside the CPE's explicit version
  range (or equals an exact CPE version).
* Keyword searches are cached with a TTL. A stale or missing cache degrades to
  offline mode instead of failing a scan.

The cache is intentionally a file, not a database table: it can be copied
between engagements, imported from a downloaded NVD feed, and removed without
a schema migration. No network access happens here.
"""

from __future__ import annotations

import gzip
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CACHE_FORMAT = "breadcrumb-nvd-cache"
CACHE_VERSION = 1
DEFAULT_TTL_DAYS = 7.0
MAX_MATCHES = 200

# Product -> CPE 2.3 prefix. A wrong alias is worse than no alias, so this list
# stays deliberately small; unknown products are not matched locally.
CPE_ALIASES: dict[str, str] = {
    "nginx": "cpe:2.3:a:nginx:nginx",
    "openresty": "cpe:2.3:a:openresty:openresty",
    "apache": "cpe:2.3:a:apache:http_server",
    "apache httpd": "cpe:2.3:a:apache:http_server",
    "apache http server": "cpe:2.3:a:apache:http_server",
    "httpd": "cpe:2.3:a:apache:http_server",
    "apache tomcat": "cpe:2.3:a:apache:tomcat",
    "apache coyote": "cpe:2.3:a:apache:tomcat",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "microsoft iis": "cpe:2.3:a:microsoft:internet_information_services",
    "iis": "cpe:2.3:a:microsoft:internet_information_services",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "php": "cpe:2.3:a:php:php",
    "django": "cpe:2.3:a:djangoproject:django",
    "flask": "cpe:2.3:a:palletsprojects:flask",
    "express": "cpe:2.3:a:expressjs:express",
    "express.js": "cpe:2.3:a:expressjs:express",
    "next.js": "cpe:2.3:a:vercel:next.js",
    "react": "cpe:2.3:a:facebook:react",
    "vue.js": "cpe:2.3:a:vuejs:vue.js",
    "angular": "cpe:2.3:a:angular:angular",
    "jquery": "cpe:2.3:a:jquery:jquery",
    "wordpress": "cpe:2.3:a:wordpress:wordpress",
    "drupal": "cpe:2.3:a:drupal:drupal",
    "joomla": "cpe:2.3:a:joomla:joomla",
    "laravel": "cpe:2.3:a:laravel:laravel",
    "ruby on rails": "cpe:2.3:a:rubyonrails:rails",
    "rails": "cpe:2.3:a:rubyonrails:rails",
    "jetty": "cpe:2.3:a:eclipse:jetty",
    "gunicorn": "cpe:2.3:a:gunicorn:gunicorn",
    "uwsgi": "cpe:2.3:a:unbit:uwsgi",
    "mysql": "cpe:2.3:a:oracle:mysql",
    "mariadb": "cpe:2.3:a:mariadb:mariadb",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "postgres": "cpe:2.3:a:postgresql:postgresql",
    "redis": "cpe:2.3:a:redis:redis",
    "mongodb": "cpe:2.3:a:mongodb:mongodb",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "grafana": "cpe:2.3:a:grafana:grafana",
    "jenkins": "cpe:2.3:a:jenkins:jenkins",
    "gitlab": "cpe:2.3:a:gitlab:gitlab",
    "kubernetes": "cpe:2.3:a:kubernetes:kubernetes",
    "vsftpd": "cpe:2.3:a:vsftpd:vsftpd",
    "proftpd": "cpe:2.3:a:proftpd:proftpd",
    "pure-ftpd": "cpe:2.3:a:pureftpd:pure-ftpd",
    "postfix": "cpe:2.3:a:postfix:postfix",
    "exim": "cpe:2.3:a:exim:exim",
    "dovecot": "cpe:2.3:a:dovecot:dovecot",
    "samba": "cpe:2.3:a:samba:samba",
    "bind": "cpe:2.3:a:isc:bind",
    "ntp": "cpe:2.3:a:ntp:ntp",
}

_PRERELEASE_TOKENS = {
    "dev": -7,
    "snapshot": -6,
    "alpha": -5,
    "a": -5,
    "beta": -4,
    "b": -4,
    "pre": -3,
    "preview": -3,
    "rc": -2,
}

SSH_BANNER_PREFIX = re.compile(r"^SSH-\d+\.\d+-")
TECH_VERSION_RE = re.compile(
    r"^(?P<product>.+?)[/_ ]v?(?P<version>\d+(?:\.\d+){0,3}[A-Za-z0-9]*)$"
)
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class NvdCacheError(ValueError):
    """The cache file is missing, unreadable or not an NVD payload."""


@dataclass(frozen=True)
class IndexedCpe:
    cve_id: str
    cve: dict
    match: dict
    fields: tuple[str, ...]
    key: str


def default_cache_path() -> Path:
    value = os.environ.get("BREADCRUMB_NVD_CACHE", "").strip()
    if value:
        return Path(value).expanduser()
    return Path.cwd() / "breadcrumb.nvd.json"


def clean_for_matching(text: str) -> str:
    return SSH_BANNER_PREFIX.sub("", (text or "").strip())


def normalize_product(name: str) -> str:
    value = clean_for_matching(name).lower().strip()
    value = value.replace("_", " ").replace("-", " ")
    value = re.sub(r"[^a-z0-9. ]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def split_cpe(cpe_name: str) -> list[str]:
    """Split a CPE 2.3 string without breaking escaped colons."""
    parts = re.split(r"(?<!\\):", cpe_name or "")
    return [part.replace("\\:", ":").replace("\\\\", "\\") for part in parts]


def cpe_prefix(cpe_name: str) -> str | None:
    parts = split_cpe(cpe_name)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    if parts[2] not in ("a", "o", "h"):
        return None
    return ":".join(parts[:5])


def version_tokens(value: str) -> list[Any]:
    tokens: list[Any] = []
    for token in re.findall(r"\d+|[a-z]+", (value or "").lower().lstrip("v")):
        tokens.append(int(token) if token.isdigit() else token)
    return tokens


def compare_versions(left: str, right: str) -> int:
    """Compare loose software versions (dotted numeric, letters, pre-release).

    Trailing zero components are insignificant (1.24 == 1.24.0). This is not a
    distribution package comparator, but it is deterministic and dependency
    free, which is what a local cache needs.
    """
    a = version_tokens(left)
    b = version_tokens(right)
    for index in range(max(len(a), len(b))):
        ta = a[index] if index < len(a) else None
        tb = b[index] if index < len(b) else None

        if ta is None:
            if all(isinstance(token, int) and token == 0 for token in b[index:]):
                return 0
            if isinstance(tb, str) and tb in _PRERELEASE_TOKENS:
                return 1
            return -1
        if tb is None:
            if all(isinstance(token, int) and token == 0 for token in a[index:]):
                return 0
            if isinstance(ta, str) and ta in _PRERELEASE_TOKENS:
                return -1
            return 1
        if ta == tb:
            continue

        ta_num, tb_num = isinstance(ta, int), isinstance(tb, int)
        if ta_num and tb_num:
            return -1 if ta < tb else 1
        if ta_num and not tb_num:
            return 1 if tb in _PRERELEASE_TOKENS else -1
        if not ta_num and tb_num:
            return -1 if ta in _PRERELEASE_TOKENS else 1

        ta_rank = _PRERELEASE_TOKENS.get(ta, 0)
        tb_rank = _PRERELEASE_TOKENS.get(tb, 0)
        if ta_rank == tb_rank:
            return -1 if ta < tb else 1
        return -1 if ta_rank < tb_rank else 1
    return 0


def describe_range(match: dict | None) -> str:
    if not match:
        return "all versions"
    pieces: list[str] = []
    if match.get("versionStartIncluding"):
        pieces.append(f">={match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        pieces.append(f">{match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        pieces.append(f"<={match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        pieces.append(f"<{match['versionEndExcluding']}")
    return ", ".join(pieces) if pieces else "all versions"


def version_in_cpe_range(version: str, criteria: str, match: dict) -> bool:
    """Return True only when the observed version is inside the CPE range."""
    fields = split_cpe(criteria)
    if len(fields) < 7:
        return False
    cpe_version, cpe_update = fields[5], fields[6]
    if cpe_version == "-":
        return False

    if cpe_version not in ("*", ""):
        candidate = cpe_version
        if cpe_update not in ("*", "-", ""):
            candidate = f"{cpe_version}{cpe_update}"
        if compare_versions(version, candidate) == 0:
            return True
        lowered = (version or "").lower()
        prefix = candidate.lower()
        if lowered.startswith(prefix) and len(lowered) > len(prefix):
            if lowered[len(prefix)] in ("-", "+", "~"):
                return True
        return False

    lower = match.get("versionStartIncluding")
    if lower and compare_versions(version, lower) < 0:
        return False
    lower = match.get("versionStartExcluding")
    if lower and compare_versions(version, lower) <= 0:
        return False
    upper = match.get("versionEndIncluding")
    if upper and compare_versions(version, upper) > 0:
        return False
    upper = match.get("versionEndExcluding")
    if upper and compare_versions(version, upper) >= 0:
        return False
    return True


def extract_cvss(metrics: dict | None) -> tuple[float | None, str | None]:
    """Prefer the newest CVSS metric available in an NVD record."""
    metrics = metrics or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0] or {}
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = (entry.get("baseSeverity") or data.get("baseSeverity") or "").lower()
        if not severity and score is not None:
            severity = score_to_severity(float(score))
        return score, severity or None
    return None, None


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def english_description(cve: dict) -> str:
    for item in cve.get("descriptions") or []:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value") or "")[:1000]
    return ""


def _technology_pairs(values) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in values or []:
        if isinstance(item, dict):
            product = str(item.get("product") or item.get("technology") or item.get("name") or "").strip()
            version = str(item.get("version") or "").strip()
            if not version and "/" in product:
                parsed = TECH_VERSION_RE.match(clean_for_matching(product))
                if parsed:
                    product, version = parsed.group("product"), parsed.group("version")
        else:
            product = str(item or "").strip()
            version = ""
            parsed = TECH_VERSION_RE.match(clean_for_matching(product))
            if parsed:
                product, version = parsed.group("product"), parsed.group("version")
        product = product.strip()
        version = version.strip()
        key = (product.lower(), version.lower())
        if product and key not in seen:
            seen.add(key)
            pairs.append((product, version))
    return pairs


class NvdCache:
    """Indexed local NVD CVE cache plus a small keyword-result cache."""

    def __init__(
        self,
        cves: dict[str, dict],
        *,
        path: Path | None = None,
        keyword: dict[str, dict] | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        self.cves = cves
        self.path = path
        self.keyword = keyword or {}
        self.updated_at = updated_at or datetime.now(timezone.utc)
        self._index: dict[str, list[IndexedCpe]] = {}
        self._build_index()

    def _build_index(self) -> None:
        for cve_id, cve in self.cves.items():
            if not isinstance(cve, dict) or cve.get("vulnStatus") == "Rejected":
                continue
            for configuration in cve.get("configurations") or []:
                if not isinstance(configuration, dict):
                    continue
                for node in configuration.get("nodes") or []:
                    if not isinstance(node, dict) or node.get("negate"):
                        continue
                    for match in node.get("cpeMatch") or []:
                        if not isinstance(match, dict) or not match.get("vulnerable"):
                            continue
                        fields = split_cpe(str(match.get("criteria") or ""))
                        if len(fields) < 5 or fields[0] != "cpe" or fields[1] != "2.3":
                            continue
                        if fields[2] not in ("a", "o"):
                            continue
                        key = f"{fields[3]}:{fields[4]}"
                        self._index.setdefault(key, []).append(
                            IndexedCpe(cve_id, cve, match, tuple(fields), key)
                        )
        for entries in self._index.values():
            entries.sort(key=lambda entry: entry.cve_id)

    @property
    def count(self) -> int:
        return len(self.cves)

    def stats(self) -> dict:
        return {
            "path": str(self.path) if self.path else None,
            "format": CACHE_FORMAT,
            "version": CACHE_VERSION,
            "cves": len(self.cves),
            "indexed_products": len(self._index),
            "indexed_cpe_ranges": sum(len(items) for items in self._index.values()),
            "keyword_entries": len(self.keyword),
            "updated_at": self.updated_at.isoformat(),
        }

    def resolve_cpe(self, product: str) -> tuple[str, str, str] | None:
        """Return (cpe_prefix, index_key, resolution_confidence)."""
        key = normalize_product(product)
        if not key:
            return None
        alias = CPE_ALIASES.get(key)
        if alias:
            fields = split_cpe(alias)
            if len(fields) >= 5:
                return alias, f"{fields[3]}:{fields[4]}", "high"
        # Conservative whole-word fallback, never a short substring.
        for alias_key, cpe in CPE_ALIASES.items():
            if len(key) < 3 or len(alias_key) < 3:
                continue
            if key.startswith(alias_key + " ") or alias_key.startswith(key + " "):
                fields = split_cpe(cpe)
                if len(fields) >= 5:
                    return cpe, f"{fields[3]}:{fields[4]}", "medium"
        return None

    def _match_version(self, entry: IndexedCpe, version: str) -> dict | None:
        fields = entry.fields
        if len(fields) >= 5:
            criteria_prefix = ":".join(fields[:5])
            if not self._criteria_matches(entry, criteria_prefix):
                return None
        if version_in_cpe_range(version, str(entry.match.get("criteria") or ""), entry.match):
            return entry.match
        return None

    @staticmethod
    def _criteria_matches(entry: IndexedCpe, criteria_prefix: str) -> bool:
        criteria = str(entry.match.get("criteria") or "")
        return criteria == criteria_prefix or criteria.startswith(criteria_prefix + ":")

    def match_technologies(
        self, technologies, *, max_matches: int = MAX_MATCHES
    ) -> list[dict]:
        """Return verified CVE matches for versioned technologies."""
        matches: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for product, version in _technology_pairs(technologies):
            if not version:
                continue
            resolved = self.resolve_cpe(product)
            if resolved is None:
                continue
            cpe_name, key, confidence = resolved
            for entry in self._index.get(key, []):
                matched = self._match_version(entry, version)
                if matched is None:
                    continue
                dedup = (entry.cve_id, product.lower(), version.lower())
                if dedup in seen:
                    continue
                seen.add(dedup)
                matches.append(
                    self._build_match(
                        entry.cve,
                        matched,
                        cpe_name,
                        confidence,
                        product,
                        version,
                    )
                )
                if len(matches) >= max_matches:
                    return _sort_matches(matches)
        return _sort_matches(matches)

    def _build_match(
        self,
        cve: dict,
        cpe_match: dict,
        cpe_name: str,
        confidence: str,
        product: str,
        version: str,
    ) -> dict:
        cve_id = str(cve.get("id") or "").upper()
        score, severity = extract_cvss(cve.get("metrics") or {})
        return {
            "cve_id": cve_id,
            "description": english_description(cve),
            "cvss_score": score,
            "cvss_severity": severity,
            "published": cve.get("published"),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "exploitdb_search_url": f"https://www.exploit-db.com/search?cve={cve_id}",
            "matched_cpe": cpe_match.get("criteria"),
            "version_range": describe_range(cpe_match),
            "cpe_name": cpe_name,
            "cpe_confidence": confidence,
            "product": product,
            "version": version,
            "applicability_verified": True,
        }

    def keyword_get(self, product: str, *, ttl_days: float = DEFAULT_TTL_DAYS) -> list[str] | None:
        entry = self.keyword.get(normalize_product(product))
        if not isinstance(entry, dict):
            return None
        fetched = _parse_datetime(entry.get("fetched_at"))
        if fetched is None:
            return None
        if datetime.now(timezone.utc) - fetched > timedelta(days=max(0.0, ttl_days)):
            return None
        cves = [str(item).upper() for item in entry.get("cves") or [] if str(item).upper().startswith("CVE-")]
        return cves

    def keyword_put(self, product: str, cves: list[str]) -> None:
        key = normalize_product(product)
        if not key:
            return
        self.keyword[key] = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "cves": [str(item).upper() for item in cves if str(item).upper().startswith("CVE-")],
        }

    def to_payload(self) -> dict:
        return {
            "format": CACHE_FORMAT,
            "version": CACHE_VERSION,
            "updated_at": self.updated_at.isoformat(),
            "cves": self.cves,
            "keyword": self.keyword,
        }

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path or self.path or default_cache_path()).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self.to_payload(), handle, separators=(",", ":"), sort_keys=True)
        os.replace(tmp, target)
        self.path = target
        return target


def _sort_matches(matches: list[dict]) -> list[dict]:
    return sorted(
        matches,
        key=lambda item: (
            -(float(item.get("cvss_score") or 0.0)),
            item.get("cve_id") or "",
        ),
    )


def _parse_datetime(value) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cve_from_item(item) -> dict | None:
    if isinstance(item, dict):
        if isinstance(item.get("cve"), dict):
            return item["cve"]
        if str(item.get("id") or "").upper().startswith("CVE-"):
            return item
    return None


def cache_from_payload(payload, *, path: Path | None = None) -> NvdCache:
    """Accept a Breadcrumb cache, an NVD API page, a feed list or one record."""
    keyword: dict[str, dict] = {}
    updated = None
    cves: dict[str, dict] = {}

    if isinstance(payload, dict) and payload.get("format") == CACHE_FORMAT:
        raw_cves = payload.get("cves")
        if isinstance(raw_cves, dict):
            candidates = list(raw_cves.values())
        elif isinstance(raw_cves, list):
            candidates = raw_cves
        else:
            raise NvdCacheError("cache has no cves collection")
        keyword = payload.get("keyword") if isinstance(payload.get("keyword"), dict) else {}
        updated = _parse_datetime(payload.get("updated_at"))
    elif isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        candidates = payload["vulnerabilities"]
    elif isinstance(payload, dict) and isinstance(payload.get("cves"), list):
        candidates = payload["cves"]
    elif isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        candidates = [payload]
    else:
        raise NvdCacheError("payload is not an NVD CVE object or list")

    for item in candidates:
        cve = _cve_from_item(item)
        if cve is None:
            continue
        cve_id = str(cve.get("id") or "").upper()
        if _CVE_ID_RE.match(cve_id):
            cves[cve_id] = cve

    if not cves and not keyword:
        raise NvdCacheError("payload contains no CVE records")
    return NvdCache(cves, path=path, keyword=keyword, updated_at=updated)


def load_cache(path: str | Path) -> NvdCache:
    target = Path(path).expanduser()
    if not target.exists():
        raise NvdCacheError(f"cache not found: {target}")
    try:
        payload = _read_json(target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise NvdCacheError(f"cannot read cache {target}: {exc}") from exc
    return cache_from_payload(payload, path=target)


def _read_json(path: Path):
    raw = path.read_bytes()
    if path.suffix.lower() == ".gz" or raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8", errors="replace"))


def import_nvd(
    source: str | Path,
    destination: str | Path | None = None,
    *,
    merge: bool = True,
) -> dict:
    """Import an NVD JSON/JSON.GZ payload into the local cache.

    Returns a small report so the CLI can show exactly what changed. Importing
    the same feed twice is idempotent.
    """
    source_path = Path(source).expanduser()
    destination_path = Path(destination or default_cache_path()).expanduser()
    if not source_path.exists():
        raise NvdCacheError(f"import file not found: {source_path}")
    try:
        incoming = cache_from_payload(_read_json(source_path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, NvdCacheError):
            raise
        raise NvdCacheError(f"cannot read import file {source_path}: {exc}") from exc

    existing = None
    if merge and destination_path.exists():
        existing = load_cache(destination_path)
    cache = existing or NvdCache({})
    before = set(cache.cves)
    for cve_id, cve in incoming.cves.items():
        cache.cves[cve_id] = cve
    for product, entry in incoming.keyword.items():
        cache.keyword[product] = entry
    cache = NvdCache(
        cache.cves,
        path=destination_path,
        keyword=cache.keyword,
        updated_at=datetime.now(timezone.utc),
    )
    cache.save(destination_path)
    return {
        "path": str(destination_path),
        "imported": len(incoming.cves),
        "new": len(set(incoming.cves) - before),
        "total": len(cache.cves),
        "indexed_products": len(cache._index),
    }
