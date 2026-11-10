"""Outbound notifications (opt-in, localhost-first).

Breadcrumb is offline by default. Notifications only fire when the operator
explicitly configures a target in Settings, at which point a small JSON POST
leaves the machine. This covers the most-requested integration feature
(Discord / Slack / Telegram / generic webhook) without adding dependencies.

Config lives in ``breadcrumb.notify.json`` at the repo root (git-ignored),
overridable with ``BREADCRUMB_NOTIFY_CONFIG``. Everything is best-effort:
a failed webhook never breaks an ingest or a page render.
"""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

CONFIG_PATH = Path(
    os.environ.get(
        "BREADCRUMB_NOTIFY_CONFIG",
        Path(__file__).resolve().parent.parent / "breadcrumb.notify.json",
    )
)

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DEFAULTS = {
    "enabled": False,
    "min_severity": "high",
    "on_new_findings": True,
    "on_scope_changes": True,
    "discord_url": "",
    "slack_url": "",
    "telegram_token": "",
    "telegram_chat": "",
    "webhook_url": "",
    "timeout": 6,
}


def load_config() -> dict:
    config = dict(DEFAULTS)
    try:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text())
            if isinstance(data, dict):
                config.update({k: data.get(k, v) for k, v in DEFAULTS.items()})
    except (OSError, ValueError):
        pass
    return config


def save_config(config: dict) -> None:
    merged = {k: config.get(k, v) for k, v in DEFAULTS.items()}
    CONFIG_PATH.write_text(json.dumps(merged, indent=2))


def targets(config: dict) -> list[str]:
    """Human labels for every configured channel."""
    out = []
    if config.get("discord_url"):
        out.append("discord")
    if config.get("slack_url"):
        out.append("slack")
    if config.get("telegram_token") and config.get("telegram_chat"):
        out.append("telegram")
    if config.get("webhook_url"):
        out.append("webhook")
    return out


def is_configured(config: dict) -> bool:
    return bool(targets(config))


def _post(url: str, payload: dict, timeout: float) -> tuple[bool, str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, f"cannot reach ({exc.reason})"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _line(title: str, text: str, fields: dict | None = None) -> str:
    parts = [f"**{title}**", text]
    for key, value in (fields or {}).items():
        parts.append(f"- {key}: {value}")
    return "\n".join(p for p in parts if p)


def send(config: dict, event: str, title: str, text: str, fields: dict | None = None):
    """Fire the notification at every configured channel. Never raises."""
    if not config.get("enabled"):
        return {"sent": False, "results": [], "reason": "disabled"}
    timeout = float(config.get("timeout") or 6)
    results = []
    message = _line(title, text, fields)

    if config.get("discord_url"):
        ok, detail = _post(config["discord_url"], {"content": message}, timeout)
        results.append({"channel": "discord", "ok": ok, "detail": detail})
    if config.get("slack_url"):
        ok, detail = _post(config["slack_url"], {"text": message}, timeout)
        results.append({"channel": "slack", "ok": ok, "detail": detail})
    if config.get("telegram_token") and config.get("telegram_chat"):
        url = f"https://api.telegram.org/bot{config['telegram_token']}/sendMessage"
        ok, detail = _post(
            url,
            {"chat_id": config["telegram_chat"], "text": message, "parse_mode": "Markdown"},
            timeout,
        )
        results.append({"channel": "telegram", "ok": ok, "detail": detail})
    if config.get("webhook_url"):
        ok, detail = _post(
            config["webhook_url"],
            {"event": event, "title": title, "text": text, "fields": fields or {}},
            timeout,
        )
        results.append({"channel": "webhook", "ok": ok, "detail": detail})

    return {"sent": any(r["ok"] for r in results), "results": results}


def should_notify(config: dict, severity: str) -> bool:
    if not config.get("enabled"):
        return False
    floor = SEVERITY_RANK.get(config.get("min_severity", "high"), 3)
    return SEVERITY_RANK.get(severity, 0) >= floor


def notify_finding(config: dict, finding, program_name: str = "") -> dict:
    """Called when a finding is created. Respects severity floor + toggle."""
    if not config.get("on_new_findings") or not should_notify(config, finding.severity):
        return {"sent": False, "results": [], "reason": "filtered"}
    title = f"[{finding.severity.upper()}] New finding: {finding.title}"
    text = finding.description or "(no description)"
    fields = {"program": program_name or "—", "status": finding.status}
    return send(config, "finding.created", title, text, fields)


def notify_changes(config: dict, program_name: str, added: int, removed: int) -> dict:
    """Called when a capture changes a program's surface meaningfully."""
    if not config.get("on_scope_changes"):
        return {"sent": False, "results": [], "reason": "filtered"}
    if added + removed == 0:
        return {"sent": False, "results": [], "reason": "no change"}
    title = f"Surface change in {program_name}"
    text = f"{added} new · {removed} gone since the previous capture."
    return send(config, "program.changed", title, text, {"program": program_name})


def notify_diff(config: dict, label: str, summary: dict) -> dict:
    """Called when an operator asks for a diff change alert (Diff v2)."""
    if not config.get("on_scope_changes"):
        return {"sent": False, "results": [], "reason": "filtered"}
    if not summary.get("has_changes"):
        return {"sent": False, "results": [], "reason": "no change"}
    title = f"Change detected: {label}"
    text = (
        f"{summary.get('new_findings', 0)} new / "
        f"{summary.get('removed_findings', 0)} gone findings · "
        f"{summary.get('ports_opened', 0)} ports opened · "
        f"{summary.get('endpoints_added', 0)} endpoints added · "
        f"risk {summary.get('risk_before', 0)} → {summary.get('risk_after', 0)}"
    )
    return send(
        config,
        "diff.changed",
        title,
        text,
        {
            "new findings": summary.get("new_findings", 0),
            "removed findings": summary.get("removed_findings", 0),
            "ports opened": summary.get("ports_opened", 0),
            "endpoints added": summary.get("endpoints_added", 0),
            "risk delta": summary.get("risk_delta", 0),
        },
    )


def test(config: dict):
    """Send a fixed test notification and report per-channel results."""
    probe = dict(config)
    probe["enabled"] = True
    return send(
        probe,
        "test",
        "Breadcrumb test notification",
        "If you can read this, notifications are wired up correctly.",
        {"source": "settings"},
    )
