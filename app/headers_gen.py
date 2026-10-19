"""HTTP header profiles: randomized realistic user-agents + full header sets.

Fully offline: version pools are curated constants, randomness comes from
``random``. Used for header presets, the randomize button, and executor
contracts on scan jobs.
"""

import random
import re

CHROME = ["120.0.0.0", "124.0.0.0", "126.0.0.0", "128.0.0.0", "130.0.0.0", "131.0.0.0"]
FIREFOX = ["121.0", "124.0", "127.0", "130.0", "132.0", "133.0"]
SAFARI = ["17.1", "17.2", "17.4", "17.5", "18.0"]
WEBKIT = "605.1.15"
EDGE = ["120.0.0.0", "124.0.0.0", "128.0.0.0", "131.0.0.0"]
ANDROID = ["10", "11", "12", "13", "14"]
IOS = ["16_7", "17_1", "17_4", "17_5", "18_0"]
MACOS = ["10_15_7", "13_6", "14_1", "14_5"]
LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,de;q=0.6",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")


def _chrome_ua(platform: str, version: str, mobile: bool = False) -> str:
    base = (
        f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{version} Safari/537.36"
    )
    return base.replace("Safari/537.36", "Mobile Safari/537.36") if mobile else base


def _sec_ch_ua(version: str, brand: str = "Google Chrome") -> str:
    major = version.split(".")[0]
    return (
        f'"{brand}";v="{major}", "Chromium";v="{major}", '
        f'"Not_A Brand";v="24"'
    )


def _chrome_headers(platform: str, version: str, sec_platform: str, mobile: bool = False) -> dict:
    headers = {
        "User-Agent": _chrome_ua(platform, version, mobile),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(LANGS),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-CH-UA": _sec_ch_ua(version),
        "Sec-CH-UA-Mobile": "?1" if mobile else "?0",
        "Sec-CH-UA-Platform": f'"{sec_platform}"',
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    return headers


def _firefox_headers(platform: str, version: str) -> dict:
    return {
        "User-Agent": (
            f"Mozilla/5.0 ({platform}; rv:{version}) Gecko/20100101 Firefox/{version}"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(LANGS),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }


def _safari_headers(platform: str, version: str, mobile: bool = False) -> dict:
    return {
        "User-Agent": (
            f"Mozilla/5.0 ({platform}) AppleWebKit/{WEBKIT} (KHTML, like Gecko) "
            f"Version/{version} {'Mobile/15E148 ' if mobile else ''}Safari/{WEBKIT}"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(LANGS),
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
    }


def _edge_headers(version: str) -> dict:
    platform = "Windows NT 10.0; Win64; x64"
    return {
        "User-Agent": (
            f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version} Safari/537.36 Edg/{version}"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/webp,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(LANGS),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-CH-UA": _sec_ch_ua(version, "Microsoft Edge"),
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }


def _curl_headers() -> dict:
    return {"User-Agent": "curl/8.5.0", "Accept": "*/*"}


def _bot_headers() -> dict:
    return {
        "User-Agent": (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
    }


BUILDERS = {
    "chrome-windows": ("Chrome · Windows · desktop", lambda: _chrome_headers(
        "Windows NT 10.0; Win64; x64", random.choice(CHROME), "Windows")),
    "chrome-macos": ("Chrome · macOS · desktop", lambda: _chrome_headers(
        f"Macintosh; Intel Mac OS X {random.choice(MACOS)}", random.choice(CHROME), "macOS")),
    "chrome-linux": ("Chrome · Linux · desktop", lambda: _chrome_headers(
        "X11; Linux x86_64", random.choice(CHROME), "Linux")),
    "chrome-android": ("Chrome · Android · mobile", lambda: _chrome_headers(
        f"Linux; Android {random.choice(ANDROID)}; Pixel 8", random.choice(CHROME),
        "Android", mobile=True)),
    "firefox-windows": ("Firefox · Windows · desktop", lambda: _firefox_headers(
        "Windows NT 10.0; Win64; x64", random.choice(FIREFOX))),
    "firefox-linux": ("Firefox · Linux · desktop", lambda: _firefox_headers(
        "X11; Linux x86_64", random.choice(FIREFOX))),
    "safari-macos": ("Safari · macOS · desktop", lambda: _safari_headers(
        f"Macintosh; Intel Mac OS X {random.choice(MACOS)}", random.choice(SAFARI))),
    "safari-iphone": ("Safari · iPhone · mobile", lambda: _safari_headers(
        f"iPhone; CPU iPhone OS {random.choice(IOS)} like Mac OS X",
        random.choice(SAFARI), mobile=True)),
    "edge-windows": ("Edge · Windows · desktop", lambda: _edge_headers(
        random.choice(EDGE))),
    "curl-minimal": ("curl · minimal", _curl_headers),
    "bot-google": ("Googlebot", _bot_headers),
}

FAMILY_IDS = sorted(BUILDERS)


def family_label(family: str) -> str:
    return BUILDERS[family][0] if family in BUILDERS else family


def build_headers(family: str = "random") -> tuple[str, dict]:
    """Return (family_used, headers dict including User-Agent)."""
    if family in ("random", "", None):
        family = random.choice(FAMILY_IDS)
    if family not in BUILDERS:
        raise ValueError(f"Unknown header family: {family}")
    return family, BUILDERS[family][1]()


def parse_custom_headers(text: str) -> dict:
    """Parse `Name: value` lines into a dict. Raises ValueError on bad lines."""
    parsed: dict[str, str] = {}
    for lineno, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Line {lineno} is not 'Name: value': {line!r}")
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if not _HEADER_NAME_RE.match(name):
            raise ValueError(f"Line {lineno} has a bad header name: {name!r}")
        if not value:
            raise ValueError(f"Line {lineno} has an empty value: {name!r}")
        parsed[name] = value
    return parsed


def merge_headers(base: dict, custom: dict) -> dict:
    """Custom wins (case-insensitive); returns a fresh dict."""
    merged = dict(base)
    lowered = {k.lower(): k for k in merged}
    for key, value in custom.items():
        old = lowered.get(key.lower())
        if old is not None and old != key:
            del merged[old]
        merged[key] = value
        lowered[key.lower()] = key
    return merged


def user_agent_of(headers: dict) -> str:
    for key, value in headers.items():
        if key.lower() == "user-agent":
            return value
    return ""


def to_curl_args(headers: dict, proxy: str = "") -> str:
    parts = [f"-H '{k}: {v}'" for k, v in headers.items()]
    if proxy:
        parts.append(f"-x '{proxy}'")
    return " ".join(parts)
