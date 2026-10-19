"""AI task helpers: prompt construction + result parsing.

Kept separate from ``llm.py`` (which is pure transport/config). These functions
build prompts, choose a task class for routing, call the provider, and parse
results defensively so a model that ignores JSON instructions still yields
something usable.
"""

import json
import os
import re

from . import llm

# Bound local-model calls so a hung server can't hang the web worker forever.
AI_TIMEOUT = float(os.environ.get("BREADCRUMB_AI_TIMEOUT", "180"))

PASTE_SYSTEM = (
    "You are a bug-bounty recon assistant. You are given raw tool output and the "
    "entities Breadcrumb extracted. Reply with ONLY compact JSON, no prose, using "
    "this shape: "
    '{"summary": str, "observations": [str], "next_steps": [str], '
    '"severity_hint": "info|low|medium|high|critical"}.'
)

PROGRAM_SYSTEM = (
    "You are a bug-bounty recon analyst. Write a concise markdown briefing for the "
    "given program: what was collected, the most interesting assets, likely attack "
    "surface, and concrete next steps. Be specific and avoid filler."
)


def _extract_json(text: str) -> dict | None:
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        candidate = brace.group(0) if brace else None
    if candidate is None:
        return None
    try:
        data = json.loads(candidate)
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [line.strip(" -*•\t") for line in str(value).splitlines() if line.strip()]


def analyze_paste(text: str, entities: list[tuple[str, str]], config: dict | None = None) -> dict:
    """Run an AI analysis over one paste. Returns a normalized result dict."""
    config = config or llm.load_config()
    task = "long" if len(text) > 4000 else "fast"
    ent_lines = "\n".join(f"- {etype}: {value}" for etype, value in entities[:80])
    user = (
        f"RAW OUTPUT (truncated):\n{text[:6000]}\n\n"
        f"ENTITY SAMPLES:\n{ent_lines or '(none)'}"
    )
    result = llm.run_task(
        task,
        [{"role": "system", "content": PASTE_SYSTEM}, {"role": "user", "content": user}],
        config,
        temperature=0.2,
        max_tokens=900,
        timeout=AI_TIMEOUT,
    )
    out = {
        "ok": result["ok"],
        "model": result["model"],
        "task": task,
        "summary": "",
        "observations": [],
        "next_steps": [],
        "severity_hint": "info",
        "notes": "",
        "error": result["error"],
    }
    if not result["ok"]:
        return out
    parsed = _extract_json(result["text"])
    if parsed:
        out["summary"] = str(parsed.get("summary", "")).strip()
        out["observations"] = _as_list(parsed.get("observations") or parsed.get("findings"))
        out["next_steps"] = _as_list(parsed.get("next_steps") or parsed.get("recommendations"))
        sev = str(parsed.get("severity_hint", "")).strip().lower()
        if sev in {"info", "low", "medium", "high", "critical"}:
            out["severity_hint"] = sev
    else:
        out["summary"] = result["text"].strip()
        out["notes"] = "model did not return JSON"
    return out


def summarize_program(program, entity_groups: dict, findings: list, config: dict | None = None) -> dict:
    config = config or llm.load_config()
    parts = [f"Program: {program.name}"]
    if program.platform:
        parts.append(f"Platform: {program.platform}")
    if program.scope_in:
        parts.append(f"In scope:\n{program.scope_in.strip()[:1000]}")
    if program.scope_out:
        parts.append(f"Out of scope:\n{program.scope_out.strip()[:600]}")
    if findings:
        parts.append("Known findings: " + "; ".join(f"{f.severity}:{f.title}" for f in findings[:20]))
    for etype, items in entity_groups.items():
        values = ", ".join(getattr(e, "value", str(e)) for e in items[:25])
        parts.append(f"{etype} ({len(items)}): {values}")

    result = llm.run_task(
        "prose",
        [{"role": "system", "content": PROGRAM_SYSTEM},
         {"role": "user", "content": "\n".join(parts)}],
        config,
        temperature=0.3,
        max_tokens=1200,
        timeout=AI_TIMEOUT,
    )
    return {"ok": result["ok"], "model": result["model"], "text": result["text"], "error": result["error"]}
