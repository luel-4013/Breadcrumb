"""Scan-runner seam (Phase 1: descriptors + job queue, no execution).

Breadcrumb is import-first. Runners are external processes (a hunter's VPS,
CI job, or a future built-in executor) that:

1. poll ``GET /api/v1/jobs?status=queued`` (or are told about a job),
2. run their tool (nmap, subfinder, nuclei, httpx, ...),
3. POST the raw output back to ``POST /api/v1/pastes`` with the job's
   ``program_id``,
4. mark the job done via ``POST /api/v1/jobs/{id}/status``.

This module is the contract both sides code against. Adding a real runner
later means writing an *executor* that claims jobs — no web-app changes.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BaseRunner:
    """Descriptor for a supported external scanner."""

    id: str
    label: str
    description: str
    example: str
    output_hint: str = "pipe stdout back to POST /api/v1/pastes"
    kinds: tuple = ("domain", "ip", "cidr", "url")
    category: str = "misc"
    binary: str = ""  # executable to probe with shutil.which; defaults to example's first word


REGISTRY: dict[str, BaseRunner] = {}

# Built-ins active out of the box; everything else is opt-in on /runners.
DEFAULT_ACTIVE = {"nmap", "subfinder", "nuclei", "httpx"}


def register(runner: BaseRunner) -> BaseRunner:
    REGISTRY[runner.id] = runner
    return runner


def runner_binary(runner: BaseRunner) -> str:
    if runner.binary:
        return runner.binary
    return (runner.example.strip().split() or [""])[0]


def binary_found(binary: str) -> bool:
    import shutil

    return bool(binary) and shutil.which(binary) is not None


# ---------------- catalog ----------------
# Port / service discovery
register(BaseRunner("nmap", "Nmap", "Port/service discovery, OS detection, NSE scripts.",
    "nmap -sV -sC -oA scan target", kinds=("domain", "ip", "cidr"), category="port-scan"))
register(BaseRunner("naabu", "Naabu", "Fast SYN port scanner (ProjectDiscovery).",
    "naabu -host target.com -top-ports 1000", kinds=("domain", "ip"), category="port-scan"))
register(BaseRunner("masscan", "Masscan", "Internet-scale async port scanner.",
    "masscan 10.0.0.0/24 -p1-65535 --rate 10000", kinds=("ip", "cidr"), category="port-scan"))
register(BaseRunner("rustscan", "RustScan", "Fast port scanner that hands off to nmap.",
    "rustscan -a 10.0.0.1 -- -sV", kinds=("ip", "domain"), category="port-scan"))
# Subdomain enumeration
register(BaseRunner("subfinder", "Subfinder", "Passive subdomain enumeration (ProjectDiscovery).",
    "subfinder -d target.com -silent", kinds=("domain",), category="subdomain"))
register(BaseRunner("amass", "Amass", "Attack-surface mapping: intel + enum + track (OWASP).",
    "amass enum -d target.com", kinds=("domain", "ip", "cidr"), category="subdomain"))
register(BaseRunner("findomain", "Findomain", "Fast passive subdomain enumerator.",
    "findomain -t target.com", kinds=("domain",), category="subdomain"))
register(BaseRunner("assetfinder", "assetfinder", "Simple subdomain finder (Tom Hudson).",
    "assetfinder --subs-only target.com", kinds=("domain",), category="subdomain"))
register(BaseRunner("sublist3r", "Sublist3r", "Classic OSINT subdomain enumerator.",
    "sublist3r -d target.com", kinds=("domain",), category="subdomain"))
register(BaseRunner("puredns", "puredns", "Fast bruteforce resolver with wildcard filtering.",
    "puredns bruteforce wordlist.txt target.com", kinds=("domain",), category="subdomain"))
register(BaseRunner("dnsx", "dnsx", "Fast DNS toolkit: resolve, brute, wildcard checks (PD).",
    "dnsx -l subdomains.txt -silent", kinds=("domain",), category="subdomain"))
register(BaseRunner("chaos", "Chaos", "ProjectDiscovery's subdomain dataset API client.",
    "chaos -d target.com", kinds=("domain",), category="subdomain"))
register(BaseRunner("shuffledns", "shuffledns", "Mass DNS bruteforce with wildcard handling (PD).",
    "shuffledns -d target.com -w wordlist.txt -r resolvers.txt", kinds=("domain",), category="subdomain"))
# HTTP probing
register(BaseRunner("httpx", "httpx", "Live-host probing and tech fingerprinting (PD).",
    "httpx -l hosts.txt -json", kinds=("domain", "ip", "url"), category="http"))
register(BaseRunner("tlsx", "tlsx", "TLS grabber: certs, JARM, misconfigs (PD).",
    "tlsx -l hosts.txt -silent", kinds=("domain", "ip"), category="http"))
# Crawling / endpoints
register(BaseRunner("katana", "Katana", "Next-gen crawling and spidering (PD).",
    "katana -u https://target.com -d 3", kinds=("url", "domain"), category="crawl"))
register(BaseRunner("gau", "gau", "Fetch known URLs from AlienVault/Wayback/CommonCrawl.",
    "gau target.com", kinds=("domain",), category="crawl"))
register(BaseRunner("waybackurls", "waybackurls", "Wayback Machine URL fetcher (Tom Hudson).",
    "waybackurls target.com", kinds=("domain",), category="crawl"))
register(BaseRunner("hakrawler", "hakrawler", "Fast crawler for endpoints and JS files.",
    "echo https://target.com | hakrawler", kinds=("url",), category="crawl",
    binary="hakrawler"))
# Fuzzing / content discovery
register(BaseRunner("ffuf", "ffuf", "Fast web fuzzer: dirs, params, vhosts.",
    "ffuf -u https://target.com/FUZZ -w wordlist.txt", kinds=("url", "domain"), category="fuzz"))
register(BaseRunner("gobuster", "gobuster", "Directory/DNS/vhost busting (OJ Reeves).",
    "gobuster dir -u https://target.com -w wordlist.txt", kinds=("url", "domain"), category="fuzz"))
register(BaseRunner("feroxbuster", "feroxbuster", "Recursive content discovery with auto-tuning.",
    "feroxbuster -u https://target.com", kinds=("url",), category="fuzz"))
register(BaseRunner("dirsearch", "dirsearch", "Mature web path scanner.",
    "dirsearch -u https://target.com", kinds=("url",), category="fuzz"))
# Vulnerability scanning
register(BaseRunner("nuclei", "Nuclei", "Template-based vuln scanning, 6500+ checks (PD).",
    "nuclei -l targets.txt -jsonl", kinds=("domain", "ip", "url"), category="vuln"))
register(BaseRunner("dalfox", "Dalfox", "Parameter analysis and XSS scanner.",
    "dalfox url 'https://target.com/?q=1'", kinds=("url",), category="vuln"))
register(BaseRunner("nikto", "Nikto", "Venerable web-server scanner, 6700+ checks.",
    "nikto -h https://target.com", kinds=("url", "ip"), category="vuln"))
register(BaseRunner("wpscan", "WPScan", "WordPress vulnerability scanner.",
    "wpscan --url https://target.com", kinds=("url", "domain"), category="vuln"))
register(BaseRunner("sqlmap", "sqlmap", "Automatic SQL injection exploitation tool.",
    "sqlmap -u 'https://target.com/?id=1' --batch", kinds=("url",), category="vuln"))
# OSINT / takeover / net inventory
register(BaseRunner("theharvester", "theHarvester", "Emails, subdomains, IPs, people via OSINT.",
    "theHarvester -d target.com -b all", kinds=("domain",), category="osint"))
register(BaseRunner("subzy", "Subzy", "Subdomain takeover checker.",
    "subzy run --targets targets.txt", kinds=("domain",), category="takeover"))
register(BaseRunner("asnmap", "asnmap", "Map org/IP/ASN to CIDRs (PD).",
    "asnmap -org 'Org Name'", kinds=("domain", "ip"), category="net-inventory"))
register(BaseRunner("mapcidr", "mapcidr", "CIDR math: split, merge, filter IPs (PD).",
    "mapcidr -cidr 10.0.0.0/24", kinds=("cidr", "ip"), category="net-inventory"))


def list_runners() -> list[BaseRunner]:
    return [REGISTRY[key] for key in sorted(REGISTRY)]


def get_runner(runner_id: str) -> BaseRunner | None:
    return REGISTRY.get(runner_id)


def _toggle_map(session) -> dict[str, bool]:
    from .models import RunnerToggle
    from sqlmodel import select

    return {
        row.runner_id: row.enabled
        for row in session.exec(select(RunnerToggle)).all()
    }


def is_active(session, runner_id: str) -> bool:
    toggles = _toggle_map(session)
    if runner_id in toggles:
        return toggles[runner_id]
    return runner_id in DEFAULT_ACTIVE


def all_runners(session) -> list[BaseRunner]:
    """Active built-ins plus user-defined runners stored in the DB."""
    from .models import CustomRunner
    from sqlmodel import select

    seen = [r for r in list_runners() if is_active(session, r.id)]
    ids = set(REGISTRY)
    for custom in session.exec(select(CustomRunner).order_by(CustomRunner.runner_id)).all():
        if custom.runner_id in ids:
            continue
        kinds = custom.kinds if isinstance(custom.kinds, list) and custom.kinds else ["domain"]
        seen.append(
            BaseRunner(
                id=custom.runner_id,
                label=custom.label or custom.runner_id,
                description=custom.description or "User-defined runner.",
                example=custom.example or "",
                kinds=tuple(kinds),
                category="custom",
            )
        )
    return seen


def describe_all(session) -> list[dict]:
    """Every known runner with activation + validity info for the management UI."""
    from .models import CustomRunner
    from sqlmodel import select

    customs = {
        c.runner_id: c
        for c in session.exec(select(CustomRunner)).all()
    }
    out = []
    for runner in list_runners():
        binary = runner_binary(runner)
        custom = customs.get(runner.id)
        out.append(
            {
                "runner": runner,
                "enabled": is_active(session, runner.id),
                "custom": custom is not None,
                "custom_id": custom.id if custom else None,
                "binary": binary,
                "binary_found": binary_found(binary),
            }
        )
    for rid in sorted(set(customs) - set(REGISTRY)):
        custom = customs[rid]
        binary = (custom.example.strip().split() or [""])[0]
        out.append(
            {
                "runner": BaseRunner(
                    id=custom.runner_id,
                    label=custom.label or custom.runner_id,
                    description=custom.description or "User-defined runner.",
                    example=custom.example or "",
                    kinds=tuple(custom.kinds or ["domain"]),
                    category="custom",
                ),
                "enabled": True,
                "custom": True,
                "custom_id": custom.id,
                "binary": binary,
                "binary_found": binary_found(binary),
            }
        )
    return out


def find_runner(session, runner_id: str) -> BaseRunner | None:
    for runner in all_runners(session):
        if runner.id == runner_id:
            return runner
    return None


def validate_custom(runner_id: str, example: str, session) -> list[tuple[str, str]]:
    """Validity report for a user-provided runner: (ok|warn|err, message)."""
    import re

    from .models import CustomRunner
    from sqlmodel import select

    report: list[tuple[str, str]] = []
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,40}$", runner_id):
        report.append(("err", "id must be 2-41 chars: lowercase letters, digits, dashes"))
    else:
        report.append(("ok", "id format is valid"))
    if get_runner(runner_id) is not None:
        report.append(("err", f"id collides with built-in runner '{runner_id}'"))
    elif session.exec(
        select(CustomRunner).where(CustomRunner.runner_id == runner_id)
    ).first():
        report.append(("err", f"id '{runner_id}' is already registered"))
    else:
        report.append(("ok", "id is unique"))
    binary = (example.strip().split() or [""])[0]
    if not example.strip():
        report.append(("warn", "no example command — executors won't know what to run"))
    else:
        report.append(("ok", "example command present"))
        if binary_found(binary):
            report.append(("ok", f"binary '{binary}' found on this server"))
        else:
            report.append((
                "warn",
                f"binary '{binary}' not on this server's PATH — "
                "fine if the executor runs elsewhere, install it there",
            ))
    return report
