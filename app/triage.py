"""Finding triage vocabulary and Leadline compatibility mapping.

Breadcrumb's original workflow uses ``Finding.status`` (open / in-progress /
resolved / wont-fix). Leadline uses a single ``triage_status`` (open /
acknowledged / false_positive). Phase 6 adds ``Finding.verdict`` so findings
share Entity's analyst vocabulary, then translates between the two shapes in
one place instead of letting routers invent their own mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# The only values the compatibility API accepts for Leadline triage_status.
TRIAGE_STATUSES = ("open", "acknowledged", "false_positive")

# Leadline triage_status -> (Breadcrumb status, Breadcrumb verdict)
_TO_BREADCRUMB = {
    "open": ("open", "none"),
    "acknowledged": ("in-progress", "needs-review"),
    "false_positive": ("wont-fix", "false-positive"),
}

# Breadcrumb status/verdict -> Leadline triage_status. ``resolved`` is closed
# work, so it is reported as acknowledged rather than making a closed finding
# look brand new in a diff.
_TO_LEADLINE = {
    ("open", "none"): "open",
    ("open", "confirmed"): "acknowledged",
    ("open", "needs-review"): "acknowledged",
    ("open", "false-positive"): "false_positive",
    ("in-progress", "none"): "acknowledged",
    ("in-progress", "confirmed"): "acknowledged",
    ("in-progress", "needs-review"): "acknowledged",
    ("in-progress", "false-positive"): "false_positive",
    ("resolved", "none"): "acknowledged",
    ("resolved", "confirmed"): "acknowledged",
    ("resolved", "needs-review"): "acknowledged",
    ("resolved", "false-positive"): "false_positive",
    ("wont-fix", "none"): "acknowledged",
    ("wont-fix", "confirmed"): "acknowledged",
    ("wont-fix", "needs-review"): "acknowledged",
    ("wont-fix", "false-positive"): "false_positive",
}


def triage_status(finding: Any) -> str:
    """Return Leadline's triage_status for a Breadcrumb finding."""
    status = str(getattr(finding, "status", "open") or "open").lower()
    verdict = str(getattr(finding, "verdict", "none") or "none").lower()
    if verdict == "false-positive":
        return "false_positive"
    if status == "wont-fix" and verdict == "false-positive":
        return "false_positive"
    return _TO_LEADLINE.get((status, verdict), "open")


def is_false_positive(finding: Any) -> bool:
    return triage_status(finding) == "false_positive"


def apply_triage(finding: Any, status: str, note: str | None = None) -> None:
    """Set status+verdict from a Leadline triage_status.

    ``note`` is stored on the finding's private ``notes`` field (the UI already
    exposes it). The caller owns the transaction.
    """
    key = (status or "").strip().lower()
    if key not in _TO_BREADCRUMB:
        raise ValueError(f"unknown triage status: {status!r}")
    breadcrumb_status, verdict = _TO_BREADCRUMB[key]
    finding.status = breadcrumb_status
    finding.verdict = verdict
    if note is not None:
        finding.notes = note.strip() or None
    finding.updated_at = datetime.now(timezone.utc)


def triage_snapshot_fields(finding: Any) -> dict:
    """Fields shared by snapshot serialization and compatibility responses."""
    return {
        "triage_status": triage_status(finding),
        "is_false_positive": is_false_positive(finding),
        "verdict": str(getattr(finding, "verdict", "none") or "none"),
    }
