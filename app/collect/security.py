"""Security-header analysis shared by the native collectors.

A missing header is a hardening gap, not a vulnerability. Findings use low/info
severity and an explicit "indicative" note so a report cannot imply that an
absent header is exploitable on its own.
"""

from __future__ import annotations

import re

from .findings import nuclei_record

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "recommended": "default-src 'self'",
        "severity": "low",
        "description": "Restricts which sources can load scripts, styles, frames and other resources.",
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "recommended": "max-age=31536000; includeSubDomains",
        "severity": "low",
        "description": "Tells browsers to use HTTPS for future requests (HTTPS targets only).",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "recommended": "nosniff",
        "severity": "low",
        "description": "Prevents MIME type sniffing.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "low",
        "description": "Prevents clickjacking (or use CSP frame-ancestors).",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "info",
        "description": "Controls referrer information leakage.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "severity": "info",
        "description": "Controls access to browser features.",
    },
}

_WEIGHTS = {
    "content-security-policy": 3,
    "strict-transport-security": 2,
    "x-content-type-options": 1,
    "x-frame-options": 2,
    "referrer-policy": 1,
    "permissions-policy": 1,
}


def _properly_configured(name: str, value: str) -> bool:
    lowered = (value or "").lower()
    if name == "strict-transport-security":
        match = re.search(r"max-age\s*=\s*(\d+)", lowered)
        return bool(match) and int(match.group(1)) > 0
    if name == "content-security-policy":
        return bool(value.strip())
    if name == "x-content-type-options":
        return "nosniff" in lowered
    if name == "x-frame-options":
        return any(token in lowered for token in ("deny", "sameorigin"))
    if name == "referrer-policy":
        return bool(value.strip())
    if name == "permissions-policy":
        return bool(value.strip())
    return True


def analyze_security_headers(headers: dict[str, str], scheme: str) -> dict:
    lowered = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    csp = lowered.get("content-security-policy", "")
    present: list[dict] = []
    missing: list[dict] = []
    issues: list[dict] = []
    not_applicable: list[dict] = []

    for key, info in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and scheme != "https":
            not_applicable.append({
                "name": info["name"],
                "reason": "Target is served over HTTP; HSTS has no effect until HTTPS is enabled.",
            })
            continue
        if key == "x-frame-options" and not lowered.get(key) and "frame-ancestors" in csp.lower():
            present.append({
                "name": info["name"],
                "value": "covered by Content-Security-Policy frame-ancestors",
                "properly_configured": True,
            })
            continue
        value = lowered.get(key)
        if value:
            ok = _properly_configured(key, value)
            present.append({"name": info["name"], "value": value, "properly_configured": ok})
            if not ok:
                issues.append({
                    "header": info["name"],
                    "issue": "improperly configured",
                    "current_value": value,
                    "recommended": info["recommended"],
                    "severity": info["severity"],
                })
        else:
            missing.append({
                "name": info["name"],
                "severity": info["severity"],
                "description": info["description"],
                "recommended": info["recommended"],
            })
            issues.append({
                "header": info["name"],
                "issue": "missing",
                "severity": info["severity"],
                "recommended": info["recommended"],
            })

    available = sum(_WEIGHTS[key] for key, info in SECURITY_HEADERS.items()
                    if any(item["name"] == info["name"] for item in present))
    total = sum(_WEIGHTS.values())
    return {
        "present_headers": present,
        "present_count": len(present),
        "missing_headers": missing,
        "missing_count": len(missing),
        "issues": issues,
        "issue_count": len(issues),
        "not_applicable": not_applicable,
        "security_score": round((available / total) * 100) if total else 0,
        "score_note": (
            "Indicative hardening score only. A missing header is not a "
            "vulnerability, and a present header is not proof of correct "
            "configuration."
        ),
    }


def header_finding_records(
    analysis: dict, *, matched_at: str, host: str = ""
) -> list[dict]:
    records: list[dict] = []
    for item in analysis.get("missing_headers") or []:
        slug = re.sub(r"[^a-z0-9]+", "-", item["name"].lower()).strip("-")
        records.append(
            nuclei_record(
                template_id=f"native-header-missing-{slug}",
                name=f"Missing security header: {item['name']}",
                severity=item.get("severity") or "info",
                matched_at=matched_at,
                description=(
                    f"{item.get('description', '')} Missing headers are hardening "
                    "gaps; this is an indicative finding, not a confirmed vulnerability."
                ),
                tags=["native", "candidate", "security-header"],
                matcher="missing-header",
                extracted=[item["name"]],
                host=host,
            )
        )
    for item in analysis.get("issues") or []:
        if item.get("issue") != "improperly configured":
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", item["header"].lower()).strip("-")
        records.append(
            nuclei_record(
                template_id=f"native-header-misconfigured-{slug}",
                name=f"Misconfigured security header: {item['header']}",
                severity=item.get("severity") or "info",
                matched_at=matched_at,
                description=(
                    f"{item['header']} is present but may not provide the "
                    "intended protection. Recommended: " + item.get("recommended", "")
                ),
                tags=["native", "candidate", "security-header"],
                matcher="misconfigured-header",
                extracted=[f"{item['header']}: {item.get('current_value', '')}"],
                host=host,
            )
        )
    return records
