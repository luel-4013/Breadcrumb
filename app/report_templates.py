"""Report templates: small, local, deterministic.

Phase C deliberately does not embed a document editor. A report template is a
named set of sections plus a typed variable schema. Validation happens once,
the context is built once, and every format (Markdown, HTML, JSON, PDF) renders
from that same redacted context. That is what makes golden tests meaningful and
what prevents a secret from appearing in one export but not another.

Built-ins:

* ``hackerone`` — submission-oriented finding writeups with impact and repro.
* ``executive`` — risk, scope, highlights, recommendations, methodology.
* ``technical`` — full finding detail with evidence and remediation.
* ``recon`` — attack-surface inventory grouped by entity type.
* ``change`` — latest capture vs the previous capture (or explicit selectors).

Custom redaction rules are per-report and additive; the default secret rules
always run first. ``reveal=True`` is the only way to disable masking and is
never the default in a route, CLI command, bundle, or template.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlmodel import Session, func, select

from . import __version__, artifacts, history, reporting
from .models import Entity, Paste, Program
from .redaction import RedactionPolicy, policy_from
from .triage import triage_snapshot_fields

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
REPORT_VERSION = 1
MAX_GROUP_ITEMS = 250
MAX_CHANGE_ITEMS = 200
FLOOR_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


class TemplateError(ValueError):
    """Validation failure with field-level errors for the UI."""

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = list(errors or [message])


@dataclass(frozen=True)
class TemplateVariable:
    key: str
    label: str
    kind: str = "text"  # text | textarea | checkbox | choice | integer | date
    default: Any = ""
    required: bool = False
    choices: tuple[str, ...] = ()
    min_value: int | None = None
    max_value: int | None = None
    max_length: int = 4000
    help: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ReportTemplate:
    id: str
    name: str
    description: str
    sections: tuple[str, ...]
    variables: tuple[TemplateVariable, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "sections": list(self.sections),
            "variables": [variable.as_dict() for variable in self.variables],
        }


_COMMON = (
    TemplateVariable(
        "title",
        "Report title",
        default="",
        max_length=160,
        help="Defaults to “<program> — <template>”.",
    ),
    TemplateVariable("client", "Client / organization", max_length=160),
    TemplateVariable("author", "Author / researcher", max_length=160),
    TemplateVariable("engagement", "Engagement / program reference", max_length=160),
    TemplateVariable(
        "report_date",
        "Report date",
        kind="date",
        default="",
        help="YYYY-MM-DD; defaults to today (UTC).",
    ),
    TemplateVariable(
        "confidentiality",
        "Classification",
        kind="choice",
        default="confidential",
        choices=("confidential", "internal", "public"),
    ),
    TemplateVariable(
        "executive_summary",
        "Executive summary",
        kind="textarea",
        max_length=8000,
        help="Optional plain-text summary. HTML is escaped.",
    ),
    TemplateVariable(
        "methodology",
        "Methodology",
        kind="textarea",
        max_length=8000,
        help="Optional plain-text methodology. HTML is escaped.",
    ),
    TemplateVariable(
        "severity_floor",
        "Minimum severity",
        kind="choice",
        default="info",
        choices=("info", "low", "medium", "high", "critical"),
    ),
    TemplateVariable(
        "max_findings",
        "Maximum findings",
        kind="integer",
        default=50,
        min_value=1,
        max_value=250,
    ),
    TemplateVariable("include_scope", "Include scope", kind="checkbox", default=True),
    TemplateVariable("include_targets", "Include targets", kind="checkbox", default=True),
    TemplateVariable(
        "include_inventory",
        "Include entity inventory",
        kind="checkbox",
        default=False,
    ),
    TemplateVariable("include_findings", "Include findings", kind="checkbox", default=True),
    TemplateVariable("include_evidence", "Include evidence", kind="checkbox", default=True),
    TemplateVariable(
        "include_screenshots",
        "Include screenshots",
        kind="checkbox",
        default=False,
        help=(
            "Embeds imported screenshots in HTML and PDF. Images are included "
            "as-is; redaction cannot mask text inside a screenshot."
        ),
    ),
    TemplateVariable("include_changes", "Include change summary", kind="checkbox", default=False),
    TemplateVariable(
        "include_triaged",
        "Include false-positive / triaged findings",
        kind="checkbox",
        default=False,
        help="For internal review only.",
    ),
    TemplateVariable(
        "redaction_profile",
        "Redaction profile",
        kind="choice",
        default="default",
        choices=("default", "strict"),
        help="Strict also masks long opaque hex/base64 values.",
    ),
    TemplateVariable(
        "redaction_rules",
        "Custom redaction rules",
        kind="textarea",
        max_length=4000,
        help="One per line: literal:text=replacement or regex:pattern=replacement.",
    ),
    TemplateVariable(
        "reveal",
        "Reveal secrets (unsafe)",
        kind="checkbox",
        default=False,
        help="Explicitly disables all masking. Never use for a shared bundle.",
    ),
    TemplateVariable("footer", "Footer note", max_length=500),
)

_FINDING_ID = TemplateVariable(
    "finding_id",
    "Finding id",
    max_length=12,
    help="Optional: render one finding by database id. Empty = all findings.",
)

_VARIABLES = {
    "hackerone": _COMMON
    + (
        TemplateVariable("program_handle", "HackerOne program handle", max_length=120),
        TemplateVariable("submission_url", "Submission URL", max_length=300),
        TemplateVariable("researcher", "Researcher handle", max_length=120),
    ),
    "executive": _COMMON
    + (
        TemplateVariable(
            "business_context",
            "Business context",
            kind="textarea",
            max_length=4000,
        ),
        TemplateVariable(
            "recommendations",
            "Recommendations",
            kind="textarea",
            max_length=6000,
        ),
    ),
    "technical": _COMMON
    + (
        _FINDING_ID,
        TemplateVariable("affected_version", "Affected version / build", max_length=160),
        TemplateVariable("cwe", "CWE", max_length=40),
    ),
    "recon": _COMMON
    + (
        TemplateVariable("target_notes", "Target notes", kind="textarea", max_length=4000),
    ),
    "change": _COMMON
    + (
        TemplateVariable(
            "left_selector",
            "Left selector",
            max_length=80,
            help="Optional: paste:1, target:2, program:3, or job:4.",
        ),
        TemplateVariable(
            "right_selector",
            "Right selector",
            max_length=80,
            help="Optional; defaults to the previous and latest capture.",
        ),
    ),
}

TEMPLATES: dict[str, ReportTemplate] = {
    "hackerone": ReportTemplate(
        id="hackerone",
        name="HackerOne submission",
        description=(
            "Submission-ready Markdown: summary, affected assets, and one "
            "writeup per finding with impact, reproduction and remediation."
        ),
        sections=("summary", "scope", "targets", "findings"),
        variables=_VARIABLES["hackerone"],
    ),
    "executive": ReportTemplate(
        id="executive",
        name="Pentest executive summary",
        description=(
            "Risk posture, scope, top findings, recommendations and methodology "
            "for a client or program manager."
        ),
        sections=("summary", "risk", "scope", "highlights", "findings_table", "recommendations", "methodology"),
        variables=_VARIABLES["executive"],
    ),
    "technical": ReportTemplate(
        id="technical",
        name="Technical finding report",
        description=(
            "Full technical detail for one or all findings: description, steps, "
            "impact, evidence, remediation, CVSS/CWE and provenance."
        ),
        sections=("summary", "findings"),
        variables=_VARIABLES["technical"],
    ),
    "recon": ReportTemplate(
        id="recon",
        name="Recon inventory",
        description=(
            "Attack-surface inventory grouped by entity type with scope, HTTP "
            "status, tags and target attribution."
        ),
        sections=("summary", "scope", "targets", "inventory", "findings_table"),
        variables=_VARIABLES["recon"],
    ),
    "change": ReportTemplate(
        id="change",
        name="Change report",
        description=(
            "What changed between two captures (or two explicit selectors): "
            "findings, ports, DNS, endpoints, technologies, headers and risk."
        ),
        sections=("summary", "changes", "findings_table"),
        variables=_VARIABLES["change"],
    ),
}

TEMPLATE_IDS = tuple(TEMPLATES)


def get_template(template_id: str | None) -> ReportTemplate:
    key = (template_id or "hackerone").strip().lower()
    if key not in TEMPLATES:
        raise TemplateError(
            f"unknown report template {template_id!r}",
            [f"template must be one of: {', '.join(TEMPLATE_IDS)}"],
        )
    return TEMPLATES[key]


def list_templates() -> list[ReportTemplate]:
    return list(TEMPLATES.values())


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def validate_variables(
    template_id: str,
    values: dict[str, Any] | None = None,
    *,
    strict_unknown: bool = False,
) -> dict:
    """Validate and normalize a template's variables.

    Unknown keys are ignored by default because routes receive query parameters
    such as ``msg``. Invalid values raise :class:`TemplateError` with one error
    per field, so the builder can show all problems at once.
    """
    template = get_template(template_id)
    values = dict(values or {})
    known = {variable.key for variable in template.variables}
    errors: list[str] = []
    normalized: dict[str, Any] = {}

    if strict_unknown:
        unknown = sorted(set(values) - known)
        if unknown:
            errors.append(f"unknown variable(s): {', '.join(unknown)}")

    for variable in template.variables:
        raw = values.get(variable.key, variable.default)
        if variable.kind == "checkbox":
            normalized[variable.key] = _as_bool(raw)
            continue
        if variable.kind == "integer":
            if str(raw).strip() == "":
                raw = variable.default
            try:
                number = int(str(raw).strip())
            except (TypeError, ValueError):
                errors.append(f"{variable.label} must be an integer")
                normalized[variable.key] = variable.default
                continue
            if variable.min_value is not None and number < variable.min_value:
                errors.append(f"{variable.label} must be at least {variable.min_value}")
                number = variable.min_value
            if variable.max_value is not None and number > variable.max_value:
                errors.append(f"{variable.label} must be at most {variable.max_value}")
                number = variable.max_value
            normalized[variable.key] = number
            continue
        if variable.kind == "date":
            text = str(raw or "").strip()
            if not text:
                text = datetime.now(timezone.utc).date().isoformat()
            try:
                date.fromisoformat(text)
            except ValueError:
                errors.append(f"{variable.label} must be YYYY-MM-DD")
            normalized[variable.key] = text
            continue
        text = str(raw or "").strip()
        if len(text) > variable.max_length:
            errors.append(
                f"{variable.label} is too long (max {variable.max_length} characters)"
            )
        if variable.kind == "choice":
            text = text.lower()
            if text not in variable.choices:
                errors.append(
                    f"{variable.label} must be one of: {', '.join(variable.choices)}"
                )
                text = variable.default
        if variable.required and not text:
            errors.append(f"{variable.label} is required")
        normalized[variable.key] = text

    if "finding_id" in normalized and normalized["finding_id"]:
        try:
            value = int(normalized["finding_id"])
            if value <= 0:
                raise ValueError
        except (TypeError, ValueError):
            errors.append("Finding id must be a positive integer")
    if "left_selector" in normalized and normalized["left_selector"]:
        if not re.match(r"^[a-z]+:\d+$", normalized["left_selector"]):
            errors.append("Left selector must look like paste:1 or program:2")
    if "right_selector" in normalized and normalized["right_selector"]:
        if not re.match(r"^[a-z]+:\d+$", normalized["right_selector"]):
            errors.append("Right selector must look like paste:1 or program:2")
    if errors:
        raise TemplateError("; ".join(errors), errors)
    return normalized


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return value[:60] or "report"


def _finding_location(finding) -> str:
    meta = finding.meta or {}
    for key in ("location", "matched_at", "url", "host"):
        value = meta.get(key)
        if value:
            return str(value)
    evidence = (finding.evidence or "").strip()
    if not evidence:
        return ""
    return evidence.split("  [", 1)[0].split("  ->", 1)[0].splitlines()[0].strip()


def _cve(finding) -> str:
    meta = finding.meta or {}
    for key in ("cve", "cve_id"):
        if meta.get(key):
            return str(meta[key])
    match = re.search(r"\bCVE-\d{4}-\d{4,}\b", " ".join(
        [str(finding.title or ""), str(finding.evidence or ""), " ".join(finding.tags or [])]
    ))
    return match.group(0) if match else ""


def _safe_finding(finding, policy: RedactionPolicy, index: int, *, include_evidence: bool) -> dict:
    triage = triage_snapshot_fields(finding)
    severity = str(finding.severity or "info").lower()
    if severity not in FLOOR_RANK:
        severity = "info"
    return {
        "ref": f"F-{index:02d}",
        "id": finding.id,
        "title": policy.text(finding.title),
        "severity": severity,
        "cvss": policy.text(finding.cvss or ""),
        "status": finding.status,
        "verdict": triage["verdict"],
        "triage_status": triage["triage_status"],
        "is_false_positive": triage["is_false_positive"],
        "verified": reporting.finding_is_verified(finding),
        "description": policy.text(finding.description or ""),
        "steps": policy.text(finding.steps or ""),
        "impact": policy.text(finding.impact or ""),
        "evidence": policy.text(finding.evidence or "") if include_evidence else "",
        "remediation": policy.text(finding.remediation or ""),
        "tags": [policy.text(tag) for tag in (finding.tags or [])],
        "location": policy.text(_finding_location(finding)),
        "cve": policy.text(_cve(finding)),
        "source_tool": policy.text(finding.source_tool or ""),
        "rule_id": policy.text(finding.rule_id or ""),
        "created_at": finding.created_at.isoformat() if finding.created_at else "",
    }


def _entity_groups(entities, policy: RedactionPolicy) -> list[dict]:
    groups: dict[str, list] = {}
    for entity in entities:
        groups.setdefault(entity.type, []).append(entity)
    ordered = []
    for etype, items in groups.items():
        items.sort(key=lambda item: str(item.value or "").lower())
        values = []
        for entity in items[:MAX_GROUP_ITEMS]:
            values.append(
                {
                    "value": policy.value(entity.type, entity.value),
                    "scope_status": entity.scope_status or "unknown",
                    "scope_reason": entity.scope_reason or "",
                    "status_code": entity.status_code,
                    "tags": [policy.text(tag) for tag in (entity.tags or [])],
                    "confidence": entity.confidence,
                }
            )
        ordered.append(
            {
                "type": etype,
                "label": reporting.TYPE_LABELS.get(etype, etype.replace("_", " ").title()),
                "count": len(items),
                "shown": len(values),
                "truncated": max(0, len(items) - len(values)),
                "values": values,
            }
        )
    ordered.sort(key=lambda group: reporting.type_rank(group["type"]))
    return ordered


def _safe_diff_finding(item: dict, policy: RedactionPolicy, index: int) -> dict:
    severity = str(item.get("severity") or "info").lower()
    if severity not in FLOOR_RANK:
        severity = "info"
    return {
        "ref": f"C-{index:02d}",
        "title": policy.text(item.get("title") or ""),
        "severity": severity,
        "location": policy.text(item.get("location") or ""),
        "status": item.get("status") or "",
    }


def _safe_entity_pair(item, policy: RedactionPolicy) -> dict:
    if isinstance(item, dict):
        etype = str(item.get("type") or "")
        value = str(item.get("value") or "")
    elif isinstance(item, (tuple, list)) and len(item) >= 2:
        etype, value = str(item[0]), str(item[1])
    else:
        etype, _, value = str(item or "").partition("|")
    return {"type": etype, "value": policy.value(etype, value)}


def _changes_context(
    session: Session,
    program_id: int,
    variables: dict,
    policy: RedactionPolicy,
) -> dict:
    """Build a redacted change summary for the change template."""
    from . import diff as diff_mod

    pastes = session.exec(
        select(Paste).where(Paste.program_id == program_id).order_by(Paste.id)
    ).all()
    left = variables.get("left_selector") or ""
    right = variables.get("right_selector") or ""
    if left or right:
        if not (left and right):
            return {
                "available": False,
                "reason": "Provide both a left and right selector, or leave both empty.",
            }
    elif len(pastes) >= 2:
        left = f"paste:{pastes[-2].id}"
        right = f"paste:{pastes[-1].id}"
    else:
        return {
            "available": False,
            "reason": (
                "At least two captures are needed for a change report. Import the "
                "same target again, or choose two explicit selectors."
            ),
        }

    try:
        diff = diff_mod.diff_selectors(session, left, right)
    except ValueError as exc:
        return {"available": False, "reason": str(exc)}

    summary = dict(diff.get("summary") or {})
    include_triaged = bool(variables.get("include_triaged"))

    def keep(item: dict, *, nested: bool = False) -> bool:
        if include_triaged:
            return True
        payload = (item.get("after") or {}) if nested else item
        return not payload.get("is_false_positive")

    new_raw = [
        item
        for item in ((diff.get("findings") or {}).get("new") or [])
        if keep(item)
    ]
    removed_raw = [
        item
        for item in ((diff.get("findings") or {}).get("removed") or [])
        if keep(item)
    ]
    changed_raw = [
        item
        for item in ((diff.get("findings") or {}).get("changed") or [])
        if keep(item, nested=True)
    ]
    new = [
        _safe_diff_finding(item, policy, index)
        for index, item in enumerate(new_raw, 1)
    ][:MAX_CHANGE_ITEMS]
    removed = [
        _safe_diff_finding(item, policy, index)
        for index, item in enumerate(removed_raw, 1)
    ][:MAX_CHANGE_ITEMS]
    changed = []
    for index, item in enumerate(changed_raw, 1):
        after = item.get("after") or {}
        changed.append(
            {
                "ref": f"F-{index:02d}",
                "title": policy.text(after.get("title") or item.get("key") or ""),
                "severity": str(after.get("severity") or "info").lower(),
                "changes": [
                    {
                        "field": policy.text(change.get("field") or ""),
                        "before": policy.text(change.get("before") or ""),
                        "after": policy.text(change.get("after") or ""),
                    }
                    for change in (item.get("changes") or [])
                ],
            }
        )
    summary["new_findings"] = len(new_raw)
    summary["removed_findings"] = len(removed_raw)
    summary["changed_findings"] = len(changed_raw)

    def stable_label(entry, fallback: str) -> dict:
        """Strip local database ids from human-facing report labels.

        A change report is a deliverable; ``Capture #153`` means nothing to a
        reviewer and makes golden files depend on the test database sequence.
        The selector still carries the exact id for traceability.
        """
        payload = dict(entry or {"selector": fallback, "label": fallback})
        label = str(payload.get("label") or payload.get("selector") or fallback)
        label = re.sub(r"\bCapture #\d+\b", "Capture", label)
        label = re.sub(r"\bJob #\d+\b", "Job", label)
        payload["label"] = label
        return payload

    return {
        "available": True,
        "left": stable_label(diff.get("left"), left),
        "right": stable_label(diff.get("right"), right),
        "summary": summary,
        "risk": diff.get("risk") or {},
        "findings_new": new,
        "findings_removed": removed,
        "findings_changed": changed[:MAX_CHANGE_ITEMS],
        "ports_opened": [
            {
                "port": policy.text(item.get("port") or ""),
                "service": policy.text(item.get("service") or ""),
                "version": policy.text(item.get("version") or ""),
            }
            for item in (diff.get("ports") or {}).get("opened") or []
        ][:MAX_CHANGE_ITEMS],
        "ports_closed": [
            {"port": policy.text(item.get("port") or "")}
            for item in (diff.get("ports") or {}).get("closed") or []
        ][:MAX_CHANGE_ITEMS],
        "endpoints_added": [
            policy.text(value) for value in (diff.get("endpoints") or {}).get("added") or []
        ][:MAX_CHANGE_ITEMS],
        "endpoints_removed": [
            policy.text(value) for value in (diff.get("endpoints") or {}).get("removed") or []
        ][:MAX_CHANGE_ITEMS],
        "technologies_added": [
            policy.text(value) for value in (diff.get("technologies") or {}).get("added") or []
        ][:MAX_CHANGE_ITEMS],
        "technologies_removed": [
            policy.text(value) for value in (diff.get("technologies") or {}).get("removed") or []
        ][:MAX_CHANGE_ITEMS],
        "dns_added": [
            {
                "rtype": policy.text(item.get("rtype") or ""),
                "name": policy.text(item.get("name") or ""),
                "value": policy.text(item.get("value") or ""),
            }
            for item in (diff.get("dns") or {}).get("added") or []
        ][:MAX_CHANGE_ITEMS],
        "dns_removed": [
            {
                "rtype": policy.text(item.get("rtype") or ""),
                "name": policy.text(item.get("name") or ""),
                "value": policy.text(item.get("value") or ""),
            }
            for item in (diff.get("dns") or {}).get("removed") or []
        ][:MAX_CHANGE_ITEMS],
        "headers_added": [
            policy.text(value) for value in (diff.get("headers") or {}).get("added") or []
        ][:MAX_CHANGE_ITEMS],
        "headers_removed": [
            policy.text(value) for value in (diff.get("headers") or {}).get("removed") or []
        ][:MAX_CHANGE_ITEMS],
        "entities_added": [
            _safe_entity_pair(item, policy)
            for item in (diff.get("entities") or {}).get("added") or []
        ][:MAX_CHANGE_ITEMS],
        "entities_removed": [
            _safe_entity_pair(item, policy)
            for item in (diff.get("entities") or {}).get("removed") or []
        ][:MAX_CHANGE_ITEMS],
    }


def build_context(
    session: Session,
    program_id: int,
    template_id: str,
    values: dict[str, Any] | None = None,
    *,
    generated_at: str | datetime | None = None,
    include_triaged: bool | None = None,
) -> dict:
    """Build one redacted, format-independent report context."""
    template = get_template(template_id)
    variables = validate_variables(template.id, values)
    try:
        policy = policy_from(
            reveal=variables["reveal"],
            profile=variables["redaction_profile"],
            rules_text=variables["redaction_rules"],
        )
    except ValueError as exc:
        raise TemplateError(str(exc), [str(exc)]) from exc
    program = session.get(Program, program_id)
    if program is None:
        raise TemplateError("program not found", ["program not found"])

    _, targets, entities, _, findings = reporting.collect(session, program_id)
    if include_triaged is None:
        include_triaged = variables["include_triaged"]
    findings = reporting.filter_findings(findings, include_triaged)
    floor = FLOOR_RANK.get(variables["severity_floor"], 4)
    findings = [
        finding
        for finding in findings
        if FLOOR_RANK.get(str(finding.severity or "info").lower(), 4) <= floor
    ]
    findings.sort(
        key=lambda finding: (
            FLOOR_RANK.get(str(finding.severity or "info").lower(), 4),
            str(finding.title or "").lower(),
        )
    )
    if variables.get("finding_id"):
        wanted = int(variables["finding_id"])
        matching = [finding for finding in findings if finding.id == wanted]
        if not matching:
            raise TemplateError(
                f"finding #{wanted} was not found in this program at the selected severity",
                [f"finding #{wanted} was not found in this program"],
            )
        findings = matching

    total_findings = len(findings)
    shown = findings[: variables["max_findings"]]
    safe_findings = [
        _safe_finding(
            finding,
            policy,
            index,
            include_evidence=variables["include_evidence"],
        )
        for index, finding in enumerate(shown, 1)
    ]
    severity_counts = reporting.severity_counts(findings)
    risk_score, risk_level = history.compute_risk(findings)
    entity_counts: dict[str, int] = {}
    for entity in entities:
        entity_counts[entity.type] = entity_counts.get(entity.type, 0) + 1

    safe_scope_in = policy.text(program.scope_in or "")
    safe_scope_out = policy.text(program.scope_out or "")
    safe_targets = [
        {
            "id": target.id,
            "name": policy.text(target.name),
            "kind": target.kind,
            "notes": policy.text(target.notes or ""),
        }
        for target in targets
    ]

    highlights = []
    for index, finding in enumerate(findings[:5], 1):
        highlights.append(
            {
                "ref": f"F-{index:02d}",
                "title": policy.text(finding.title),
                "severity": str(finding.severity or "info").lower(),
                "verified": reporting.finding_is_verified(finding),
                "explanation": policy.text(reporting.risk_explanation(finding)),
            }
        )

    now = generated_at or datetime.now(timezone.utc).isoformat()
    if isinstance(now, datetime):
        now = now.isoformat()
    # Never echo the custom redaction rules: a rule may contain the literal
    # secret it is meant to remove. Counts are reported instead.
    safe_variables: dict[str, Any] = {}
    for key, value in variables.items():
        if key == "redaction_rules":
            continue
        safe_variables[key] = policy.text(value) if isinstance(value, str) else value
    title = safe_variables.get("title") or f"{policy.text(program.name)} — {template.name}"
    report_reference = (
        f"{_slug(policy.text(program.name))}-{template.id}-{safe_variables['report_date']}"
    )
    changes = None
    if "changes" in template.sections or variables.get("include_changes"):
        changes = _changes_context(session, program_id, variables, policy)
    screenshot_finding_ids = None
    if variables.get("finding_id"):
        screenshot_finding_ids = [finding.id for finding in findings if finding.id]
    screenshots = artifacts.report_artifacts(
        session,
        program_id,
        policy=policy,
        include_data=bool(variables.get("include_screenshots")),
        finding_ids=screenshot_finding_ids,
    )
    capture_count = int(
        session.exec(
            select(func.count()).select_from(Paste).where(Paste.program_id == program_id)
        ).one()
        or 0
    )

    context = {
        "report_version": REPORT_VERSION,
        "generator": {"name": "breadcrumb", "version": __version__},
        "template": template.as_dict(),
        "title": policy.text(title),
        "report_reference": report_reference,
        "program": {
            "id": program.id,
            "name": policy.text(program.name),
            "platform": policy.text(program.platform or ""),
            "scope_in": safe_scope_in,
            "scope_out": safe_scope_out,
        },
        "client": safe_variables.get("client", ""),
        "author": safe_variables.get("author", ""),
        "engagement": safe_variables.get("engagement", ""),
        "report_date": safe_variables["report_date"],
        "generated_at": now,
        "confidentiality": safe_variables["confidentiality"],
        "confidentiality_label": {
            "confidential": "CONFIDENTIAL",
            "internal": "INTERNAL",
            "public": "PUBLIC",
        }.get(safe_variables["confidentiality"], "CONFIDENTIAL"),
        "executive_summary": safe_variables.get("executive_summary", ""),
        "methodology": safe_variables.get("methodology", ""),
        "recommendations": safe_variables.get("recommendations", ""),
        "business_context": safe_variables.get("business_context", ""),
        "footer": safe_variables.get("footer", ""),
        "variables": safe_variables,
        "redaction": policy.describe(),
        "targets": safe_targets,
        "entity_groups": _entity_groups(entities, policy),
        "entity_counts": dict(sorted(entity_counts.items())),
        "findings": safe_findings,
        "findings_total": total_findings,
        "findings_shown": len(safe_findings),
        "screenshots": screenshots,
        "highlights": highlights,
        "summary": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "total_findings": total_findings,
            "shown_findings": len(safe_findings),
            "severity_counts": severity_counts,
            "verified_findings": sum(
                1 for finding in findings if reporting.finding_is_verified(finding)
            ),
            "entity_count": len(entities),
            "entity_counts": dict(sorted(entity_counts.items())),
            "target_count": len(targets),
            "capture_count": capture_count,
            "screenshot_count": screenshots["total"],
            "in_scope_entities": sum(1 for e in entities if e.scope_status == "in"),
            "out_of_scope_entities": sum(1 for e in entities if e.scope_status == "out"),
            "unknown_scope_entities": sum(1 for e in entities if e.scope_status == "unknown"),
        },
        "changes": changes,
    }
    context["filename_base"] = report_reference
    return context


def _md(text) -> str:
    """Escape text for Markdown/HTML safety without losing line structure."""
    return html.escape(str(text or ""), quote=False)


def _md_code(text) -> str:
    value = _md(text).replace("\r\n", "\n").replace("\r", "\n")
    longest = max((len(match) for match in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{value}\n{fence}"


def _md_inline(value) -> str:
    text = _md(value).replace("\n", " ")
    if "`" in text:
        return f"`` {text} ``"
    return f"`{text}`"


def _md_bullets(items: list[str], empty: str = "_None._") -> list[str]:
    return [f"- {item}" for item in items] if items else [empty]


def render_markdown(context: dict) -> str:
    template = context["template"]
    sections = set(template["sections"])
    variables = context["variables"]
    lines: list[str] = [f"# {context['title']}", ""]
    meta = []
    if context.get("client"):
        meta.append(f"- **Client:** {_md(context['client'])}")
    if context.get("author"):
        meta.append(f"- **Author:** {_md(context['author'])}")
    if context.get("engagement"):
        meta.append(f"- **Engagement:** {_md(context['engagement'])}")
    meta.append(f"- **Program:** {_md(context['program']['name'])}")
    meta.append(f"- **Report date:** {context['report_date']}")
    meta.append(f"- **Generated:** {context['generated_at']}")
    meta.append(f"- **Classification:** {context['confidentiality_label']}")
    meta.append(f"- **Reference:** `{context['report_reference']}`")
    lines.extend(meta)
    lines.append("")
    lines.append(
        f"> **{context['confidentiality_label']}.** This report contains "
        "security-sensitive information about the assessed target. Distribute "
        "only to authorized recipients."
    )
    lines.append("")
    if context["redaction"].get("enabled"):
        profile = context["redaction"].get("profile", "default")
        lines.append(
            f"_Redaction: {profile} profile, "
            f"{context['redaction'].get('custom_rules', 0)} custom rule(s). "
            "Auth headers, cookies, tokens and secret values are masked._"
        )
        lines.append("")
    elif variables.get("reveal"):
        lines.append(
            "> **WARNING:** secret masking is disabled for this report (`reveal`). "
            "Do not share it outside the authorized assessment team."
        )
        lines.append("")

    if context.get("executive_summary") and (
        "summary" in sections or "risk" in sections
    ):
        lines.extend(["## Executive summary", "", _md(context["executive_summary"]), ""])
    if context.get("business_context") and "risk" in sections:
        lines.extend(["## Business context", "", _md(context["business_context"]), ""])

    if "summary" in sections:
        summary = context["summary"]
        lines.extend(["## Summary", ""])
        lines.append(
            f"- **Risk:** {summary['risk_level']} "
            f"({summary['risk_score']}/100)"
        )
        lines.append(
            f"- **Findings:** {summary['total_findings']} active "
            f"({summary['shown_findings']} shown; {summary['verified_findings']} verified)"
        )
        counts = summary.get("severity_counts") or {}
        lines.append(
            "- **Severity:** "
            + (", ".join(f"{sev} × {n}" for sev, n in counts.items()) or "none")
        )
        lines.append(
            f"- **Surface:** {summary['entity_count']} entities · "
            f"{summary['target_count']} targets · {summary['capture_count']} captures"
        )
        lines.append(
            f"- **Scope:** {summary['in_scope_entities']} in · "
            f"{summary['out_of_scope_entities']} out · "
            f"{summary['unknown_scope_entities']} unknown"
        )
        if summary.get("entity_counts"):
            lines.append(
                "- **Entity types:** "
                + ", ".join(
                    f"{etype} × {count}"
                    for etype, count in summary["entity_counts"].items()
                )
            )
        lines.append("")

    if "risk" in sections:
        lines.extend(["## Risk overview", ""])
        lines.extend(
            _md_bullets(
                [
                    f"**{context['summary']['risk_level'].upper()}** — "
                    f"score {context['summary']['risk_score']}/100.",
                    "Scores are derived from active findings; false positives and "
                    "unverified CVE candidates are excluded.",
                    "Every finding below links back to sealed evidence in the local "
                    "Breadcrumb database.",
                ]
            )
        )
        lines.append("")

    if "highlights" in sections and context.get("highlights"):
        lines.extend(["## Top findings", ""])
        for item in context["highlights"]:
            flag = " *(verified)*" if item.get("verified") else ""
            lines.append(
                f"- **{item['severity'].upper()}** — {_md(item['title'])}{flag}: "
                f"{_md(item['explanation'])}"
            )
        lines.append("")

    if "scope" in sections and variables.get("include_scope"):
        if context["program"].get("scope_in") or context["program"].get("scope_out"):
            lines.extend(["## Scope", ""])
            lines.extend(["**In scope**", ""])
            lines.extend(
                _md_bullets(
                    [line for line in context["program"]["scope_in"].splitlines() if line.strip()]
                )
            )
            lines.extend(["", "**Out of scope**", ""])
            lines.extend(
                _md_bullets(
                    [line for line in context["program"]["scope_out"].splitlines() if line.strip()]
                )
            )
            lines.append("")

    if "targets" in sections and variables.get("include_targets") and context["targets"]:
        lines.extend(["## Targets", ""])
        for target in context["targets"]:
            note = f" — {_md(target['notes'])}" if target.get("notes") else ""
            lines.append(
                f"- {_md_inline(target['name'])} ({_md(target['kind'])}){note}"
            )
        lines.append("")

    if "inventory" in sections and variables.get("include_inventory"):
        lines.extend(["## Attack-surface inventory", ""])
        if not context["entity_groups"]:
            lines.extend(["_No entities collected._", ""])
        for group in context["entity_groups"]:
            lines.extend([f"### {group['label']} ({group['count']})", ""])
            for item in group["values"]:
                bits = [f"- {_md_inline(item['value'])}"]
                if item.get("scope_status"):
                    bits.append(f"`{_md(item['scope_status'])}`")
                if item.get("status_code"):
                    bits.append(f"`HTTP {item['status_code']}`")
                if item.get("tags"):
                    bits.append(" ".join(f"`#{_md(tag)}`" for tag in item["tags"]))
                lines.append(" ".join(bits))
            if group.get("truncated"):
                lines.append(f"- …and {group['truncated']} more (export JSON for the full list).")
            lines.append("")

    changes = context.get("changes")
    if "changes" in sections or variables.get("include_changes"):
        lines.extend(["## Change summary", ""])
        if not changes or not changes.get("available"):
            lines.extend(
                [
                    _md((changes or {}).get("reason") or "No change data is available."),
                    "",
                ]
            )
        else:
            left = changes.get("left") or {}
            right = changes.get("right") or {}
            lines.append(
                f"Compared **{_md(left.get('label') or left.get('selector'))}** → "
                f"**{_md(right.get('label') or right.get('selector'))}**."
            )
            lines.append("")
            summary = changes.get("summary") or {}
            lines.extend(
                _md_bullets(
                    [
                        f"Findings new: {summary.get('new_findings', 0)}; "
                        f"removed: {summary.get('removed_findings', 0)}; "
                        f"changed: {summary.get('changed_findings', 0)}; "
                        f"still open: {summary.get('still_open_findings', 0)}.",
                        f"Ports opened: {summary.get('ports_opened', 0)}; "
                        f"closed: {summary.get('ports_closed', 0)}.",
                        f"Endpoints added: {summary.get('endpoints_added', 0)}; "
                        f"removed: {summary.get('endpoints_removed', 0)}.",
                        f"Risk: {summary.get('risk_before', 0)} → "
                        f"{summary.get('risk_after', 0)} "
                        f"({(changes.get('risk') or {}).get('direction', 'unchanged')}).",
                    ]
                )
            )
            if changes.get("findings_new"):
                lines.extend(["", "### New findings", ""])
                for item in changes["findings_new"]:
                    lines.append(
                        f"- **{item['severity'].upper()}** {_md(item['title'])} "
                        f"({_md(item.get('location') or '—')})"
                    )
            if changes.get("findings_removed"):
                lines.extend(["", "### Disappeared findings", ""])
                for item in changes["findings_removed"]:
                    lines.append(
                        f"- **{item['severity'].upper()}** {_md(item['title'])}"
                    )
            if changes.get("findings_changed"):
                lines.extend(["", "### Changed findings", ""])
                for item in changes["findings_changed"]:
                    change_text = ", ".join(
                        f"{_md(change['field'])} {_md(change['before'])} → {_md(change['after'])}"
                        for change in item["changes"]
                    )
                    lines.append(f"- {_md(item['title'])}: {change_text}")
            if changes.get("ports_opened"):
                lines.extend(["", "### Ports opened", ""])
                for item in changes["ports_opened"]:
                    lines.append(
                        f"- {_md_inline(item['port'])} {_md(item.get('service') or '')} "
                        f"{_md(item.get('version') or '')}".rstrip()
                    )
            if changes.get("ports_closed"):
                lines.extend(["", "### Ports closed", ""])
                for item in changes["ports_closed"]:
                    lines.append(f"- {_md_inline(item['port'])}")
            if changes.get("endpoints_added"):
                lines.extend(["", "### Endpoints added", ""])
                for value in changes["endpoints_added"]:
                    lines.append(f"- {_md_inline(value)}")
            if changes.get("endpoints_removed"):
                lines.extend(["", "### Endpoints removed", ""])
                for value in changes["endpoints_removed"]:
                    lines.append(f"- {_md_inline(value)}")
            if changes.get("technologies_added") or changes.get("technologies_removed"):
                lines.extend(["", "### Technology changes", ""])
                for value in changes.get("technologies_added") or []:
                    lines.append(f"- added: {_md(value)}")
                for value in changes.get("technologies_removed") or []:
                    lines.append(f"- removed: {_md(value)}")
            if changes.get("dns_added") or changes.get("dns_removed"):
                lines.extend(["", "### DNS changes", ""])
                for item in changes.get("dns_added") or []:
                    lines.append(
                        f"- added: {_md(item['rtype'])} {_md(item['name'])} {_md(item['value'])}"
                    )
                for item in changes.get("dns_removed") or []:
                    lines.append(
                        f"- removed: {_md(item['rtype'])} {_md(item['name'])} {_md(item['value'])}"
                    )
            if changes.get("entities_added") or changes.get("entities_removed"):
                lines.extend(["", "### Entities added / removed", ""])
                for item in changes.get("entities_added") or []:
                    lines.append(f"- added: `{_md(item['type'])}` {_md(item['value'])}")
                for item in changes.get("entities_removed") or []:
                    lines.append(f"- removed: `{_md(item['type'])}` {_md(item['value'])}")
            lines.append("")

    if "findings" in sections and variables.get("include_findings"):
        lines.extend([f"## Findings ({context['findings_total']})", ""])
        if not context["findings"]:
            lines.extend(["_No active findings at the selected severity._", ""])
        for finding in context["findings"]:
            lines.extend(
                [
                    f"### {finding['ref']} — [{finding['severity'].upper()}] {_md(finding['title'])}",
                    "",
                ]
            )
            meta_bits = [f"**Status:** {_md(finding['status'])}"]
            if finding.get("verified"):
                meta_bits.append("**Verified:** yes")
            if finding.get("cvss"):
                meta_bits.append(f"**CVSS:** {_md(finding['cvss'])}")
            if finding.get("cve"):
                meta_bits.append(f"**CVE:** {_md(finding['cve'])}")
            if finding.get("location"):
                meta_bits.append(f"**Location:** {_md_inline(finding['location'])}")
            lines.append(" · ".join(meta_bits))
            lines.append("")
            if finding.get("description"):
                lines.extend(["**Description**", "", _md(finding["description"]), ""])
            if finding.get("steps"):
                lines.extend(["**Steps to reproduce**", "", _md(finding["steps"]), ""])
            if finding.get("impact"):
                lines.extend(["**Impact**", "", _md(finding["impact"]), ""])
            if finding.get("evidence"):
                lines.extend(["**Evidence**", "", _md_code(finding["evidence"]), ""])
            if finding.get("remediation"):
                lines.extend(["**Remediation**", "", _md(finding["remediation"]), ""])
            if finding.get("tags"):
                lines.append(
                    "**Tags:** " + " ".join(f"`#{_md(tag)}`" for tag in finding["tags"])
                )
                lines.append("")

    if "findings_table" in sections and variables.get("include_findings"):
        lines.extend([f"## Findings overview ({context['findings_total']})", ""])
        if context["findings"]:
            lines.extend(
                [
                    "| Ref | Severity | Finding | Status | Location |",
                    "|---|---|---|---|---|",
                ]
            )
            for finding in context["findings"]:
                lines.append(
                    f"| {finding['ref']} | {finding['severity']} | "
                    f"{_md(finding['title'])} | {_md(finding['status'])} | "
                    f"{_md(finding.get('location') or '—')} |"
                )
        else:
            lines.append("_No active findings at the selected severity._")
        lines.append("")

    screenshot_context = context.get("screenshots") or {}
    if variables.get("include_screenshots") and screenshot_context.get("items"):
        lines.extend(
            [
                f"## Screenshots ({screenshot_context.get('total', 0)})",
                "",
                "> Screenshots are evidence images captured from the target. "
                "Redaction masks text fields, not pixels; review every image "
                "before sharing. HTML and PDF exports embed the images.",
                "",
            ]
        )
        for index, item in enumerate(screenshot_context["items"], start=1):
            caption = _md(item.get("source_url") or item.get("filename") or "screenshot")
            lines.append(f"### Screenshot {index} — {caption}")
            lines.append("")
            lines.append(f"- **Source:** {_md_inline(item.get('source') or 'manual')}")
            if item.get("target"):
                lines.append(f"- **Target:** {_md_inline(item['target'])}")
            if item.get("finding_id"):
                lines.append(f"- **Finding:** #{item['finding_id']}")
            if item.get("captured_at"):
                lines.append(f"- **Captured:** {_md_inline(item['captured_at'])}")
            if item.get("width") and item.get("height"):
                lines.append(
                    f"- **Dimensions:** {item['width']} × {item['height']}"
                )
            lines.append(f"- **SHA-256:** `{_md(item.get('sha256') or '')}`")
            if item.get("error"):
                lines.append(f"- **Warning:** {_md(item['error'])}")
            lines.append("")
        if screenshot_context.get("total", 0) > screenshot_context.get("shown", 0):
            lines.append(
                f"_Showing the most recent {screenshot_context.get('shown', 0)} of "
                f"{screenshot_context.get('total', 0)} screenshots._"
            )
            lines.append("")

    if context.get("recommendations") and "recommendations" in sections:
        lines.extend(["## Recommendations", "", _md(context["recommendations"]), ""])

    if context.get("methodology") and "methodology" in sections:
        lines.extend(["## Methodology", "", _md(context["methodology"]), ""])

    lines.extend(
        [
            "---",
            f"Generated by Breadcrumb {__version__} on {context['generated_at']}.",
        ]
    )
    if context.get("footer"):
        lines.append(_md(context["footer"]))
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(context: dict) -> str:
    template = _env.get_template("report_document.html")
    return template.render(**context)


def render_json(context: dict) -> str:
    payload = {
        "report_version": context["report_version"],
        "generator": context["generator"],
        "template": context["template"],
        "title": context["title"],
        "report_reference": context["report_reference"],
        "program": context["program"],
        "client": context["client"],
        "author": context["author"],
        "engagement": context["engagement"],
        "report_date": context["report_date"],
        "generated_at": context["generated_at"],
        "confidentiality": context["confidentiality"],
        "executive_summary": context["executive_summary"],
        "methodology": context["methodology"],
        "recommendations": context["recommendations"],
        "business_context": context["business_context"],
        "variables": context["variables"],
        "redaction": context["redaction"],
        "summary": context["summary"],
        "targets": context["targets"],
        "entity_groups": context["entity_groups"],
        "findings": context["findings"],
        "screenshots": _json_screenshots(context.get("screenshots") or {}),
        "highlights": context["highlights"],
        "changes": context["changes"],
    }
    return json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"


def _json_screenshots(value: dict) -> dict:
    """Screenshot metadata without base64 bytes.

    The JSON export is for automation and should stay small; the binary lives
    in the review bundle or the artifact content endpoint. ``data_uri`` is an
    HTML/PDF rendering detail, not part of the evidence contract.
    """
    payload = dict(value or {})
    payload["items"] = [
        {key: item for key, item in (entry or {}).items() if key != "data_uri"}
        for entry in payload.get("items") or []
    ]
    return payload


def render_pdf(context: dict) -> bytes:
    from . import pdf_export

    return pdf_export.generate_document_pdf(context)


def render(context: dict, fmt: str) -> str | bytes:
    fmt = (fmt or "md").strip().lower()
    if fmt in {"md", "markdown"}:
        return render_markdown(context)
    if fmt in {"html", "htm"}:
        return render_html(context)
    if fmt == "json":
        return render_json(context)
    if fmt == "pdf":
        return render_pdf(context)
    raise TemplateError(f"unsupported report format {fmt!r}", [f"unsupported format: {fmt}"])


def render_report(
    session: Session,
    program_id: int,
    template_id: str,
    fmt: str = "md",
    values: dict[str, Any] | None = None,
) -> tuple[str | bytes, dict]:
    context = build_context(session, program_id, template_id, values)
    return render(context, fmt), context


def filename(context: dict, extension: str) -> str:
    base = context.get("filename_base") or "breadcrumb-report"
    return f"{base}.{extension.lstrip('.')}"
