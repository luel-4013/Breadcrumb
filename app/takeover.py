"""Offline subdomain-takeover candidate detection.

Pure heuristics: a host whose CNAME points at a known takeover-prone service
(e.g. an unclaimed S3 bucket, Heroku app, GitHub Pages site). We cannot, and do
not, contact the target to confirm NXDOMAIN -- Breadcrumb is offline-first -- so
these surface as HIGH-severity findings needing a manual check. Fingerprints are
drawn from the public can-i-take-over-xyz project.
"""

# cname-suffix -> human name of the service.
# Curated from can-i-take-over-xyz (only services still marked "Vulnerable"
# and detectable purely from a CNAME, since Breadcrumb is offline).
FINGERPRINTS: dict[str, str] = {
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "s3.amazonaws.com": "AWS S3 bucket",
    "cloudapp.net": "Microsoft Azure",
    "cloudapp.azure.com": "Microsoft Azure",
    "azurewebsites.net": "Microsoft Azure",
    "blob.core.windows.net": "Microsoft Azure Blob",
    "azure-api.net": "Microsoft Azure API",
    "azurehdinsight.net": "Microsoft Azure HDInsight",
    "azureedge.net": "Microsoft Azure Edge",
    "azurecontainer.io": "Microsoft Azure Container",
    "database.windows.net": "Microsoft Azure Database",
    "search.windows.net": "Microsoft Azure Search",
    "azurecr.io": "Microsoft Azure Container Registry",
    "redis.cache.windows.net": "Microsoft Azure Redis",
    "servicebus.windows.net": "Microsoft Azure Service Bus",
    "visualstudio.com": "Microsoft Azure DevOps",
    "agilecrm.com": "Agile CRM",
    "airee.ru": "Airee.ru",
    "animaapp.io": "Anima",
    "bitbucket.io": "Bitbucket",
    "trydiscourse.com": "Discourse",
    "furyns.com": "Gemfury",
    "ghost.io": "Ghost",
    "hatenablog.com": "HatenaBlog",
    "helpjuice.com": "Help Juice",
    "helpscoutdocs.com": "Help Scout",
    "helprace.com": "Helprace",
    "youtrack.cloud": "JetBrains YouTrack",
    "launchrock.com": "LaunchRock",
    "ngrok.io": "Ngrok",
    "readme.io": "ReadMe.io",
    "na-west1.surge.sh": "Surge.sh",
    "surge.sh": "Surge.sh",
    "strikinglydns.com": "Strikingly",
    "surveysparrow.com": "SurveySparrow",
    "read.uberflip.com": "Uberflip",
    "uberflip.com": "Uberflip",
    "stats.uptimerobot.com": "UptimeRobot",
    "uptimerobot.com": "UptimeRobot",
    "wordpress.com": "WordPress.com",
    "worksites.net": "Worksites",
}
# dedupe longer suffixes first so "s3.amazonaws.com" wins over "amazonaws.com"
_ORDERED = sorted(FINGERPRINTS.items(), key=lambda kv: -len(kv[0]))


def _match(cname: str) -> str | None:
    cname = (cname or "").strip().lower().rstrip(".")
    if not cname:
        return None
    for suffix, service in _ORDERED:
        if cname == suffix or cname.endswith("." + suffix) or suffix in cname:
            return service
    return None


def _host_of_cname(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def detect_takeovers(entities) -> list[dict]:
    """Return finding dicts for CNAMEs pointing at takeover-prone services."""
    pairs: list[tuple[str, str]] = []  # (host, cname)
    seen: set[tuple[str, str]] = set()
    for ent in entities:
        meta = ent.meta or {}
        if ent.type == "dns_record" and str(meta.get("rtype", "")).upper() == "CNAME":
            host = _host_of_cname(str(meta.get("name", "")) or ent.value)
            cname = _host_of_cname(str(meta.get("value", "")))
            if host and cname and (host, cname) not in seen:
                seen.add((host, cname))
                pairs.append((host, cname))
        elif ent.type in {"subdomain", "domain"} and meta.get("cname"):
            host = _host_of_cname(ent.value)
            cname = _host_of_cname(str(meta.get("cname")))
            if host and cname and (host, cname) not in seen:
                seen.add((host, cname))
                pairs.append((host, cname))

    findings: list[dict] = []
    for host, cname in pairs:
        service = _match(cname)
        if not service:
            continue
        findings.append(
            {
                "title": f"Possible subdomain takeover: {host}",
                "severity": "high",
                "description": (
                    f"{host} is a CNAME to {cname}, a {service} endpoint. If that "
                    "resource is unclaimed, an attacker can serve content on the "
                    "hostname. Verify the target is unclaimed before reporting."
                ),
                "evidence": f"{host}  CNAME ->  {cname}  ({service})",
                "tags": ["takeover", "cname"],
                "target": host,
                "dedup_key": f"takeover|{host}|{cname}",
            }
        )
    return findings
