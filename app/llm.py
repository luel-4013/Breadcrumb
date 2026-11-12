"""Local LLM integration.

Talks to any OpenAI-compatible endpoint (Jan at 127.0.0.1:1337, LM Studio at
127.0.0.1:1234, Ollama, or a cloud endpoint you opt into). Uses only the
standard library so there is nothing new to install and nothing leaves the
machine unless you add a remote provider yourself.

Responsibilities:
  * load/save provider + routing config (a local JSON file)
  * list models and test a provider connection
  * run a chat completion
  * pick the right model for a task class (fast / reason / long / prose)
"""

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent / "breadcrumb.llm.json"

TASK_CLASSES = ["fast", "reason", "long", "prose"]

TASK_LABELS = {
    "fast": "Fast / bulk (tagging, short summaries)",
    "reason": "Reasoning (CVE chains, severity rationale)",
    "long": "Long context / code (big dumps, JS, config)",
    "prose": "Prose / reports (narratives, writeups)",
}

ROLE_LABELS = {
    "analysis": "Analysis",
    "writing": "Writing",
    "reports": "Report compilation",
    "fast": "Fast / bulk",
    "code": "Code / config",
    "reasoning": "Deep reasoning",
    "vision": "Vision",
    "experimental": "Experimental",
    "embedding": "Embeddings",
}

# Curated, human-written guidance. Matching is deliberately conservative and
# ordered: the first match wins, so specific models come before family names.
MODEL_GUIDE = [
    {
        "matches": ("pentest", "red-team", "ctf", "r1r21nb"),
        "roles": ("experimental", "analysis"),
        "note": "Community security/uncensored 3B. Fine for experiments; weak provenance, not a trustworthy report writer.",
    },
    {
        "matches": ("qwen2.5-coder-3b", "qwen2.5 coder 3b", "coder-3b-instruct"),
        "roles": ("code", "long", "fast"),
        "note": "Official Qwen 3B Coder. Best small model for JS/config/code dumps; not for prose.",
    },
    {
        "matches": ("qwen3-4b-instruct-2507", "qwen3 4b instruct 2507"),
        "roles": ("analysis", "writing", "reports", "fast"),
        "note": "Best all-round 4 GB fit. Non-thinking, reliable JSON; good for analysis and report drafting.",
    },
    {
        "matches": ("claude-4.6-opus-reasoning", "reasoning-distilled", "jackrong"),
        "roles": ("reasoning", "analysis"),
        "note": "Thinking model. Observed reasoning-only output (empty content), so it is not suited to Breadcrumb's structured reports as-is.",
    },
    {
        "matches": ("gemma-4-12b", "gemma 4 12b"),
        "roles": ("writing", "reports", "analysis", "vision"),
        "note": "12B: does not fit 4 GB. 30% GPU offload measured 2.7-3.0 tok/s and returned reasoning-only content.",
    },
    {
        "matches": ("gemma-3-12b", "gemma 3 12b"),
        "roles": ("writing", "reports"),
        "note": "12B prose model; too large for 4 GB and will spill to RAM.",
    },
    {
        "matches": ("hauhaucs", "uncensored-hauhau"),
        "roles": ("experimental", "analysis"),
        "note": "Uncensored 4B. The installed Q6_K failed 4096-context KV allocation on this GPU; experimental only.",
    },
    {
        "matches": ("qwen2.5-3b-instruct", "qwen2.5 3b instruct"),
        "roles": ("fast", "analysis", "writing", "reports"),
        "note": "Official Qwen 3B generalist. Best speed/VRAM trade-off; slightly weaker prose than the 4B.",
    },
    {
        "matches": ("qwen3-8b", "qwen3 8b"),
        "roles": ("analysis", "reasoning"),
        "note": "8B: too large for 4 GB; will spill to RAM.",
    },
    {
        "matches": ("deepseek-r1-distill", "r1-distill"),
        "roles": ("reasoning", "analysis"),
        "note": "14B reasoning distill: too large for 4 GB and slower than the 4B.",
    },
    {
        "matches": ("qwen3-coder-30b", "qwen3 coder 30b"),
        "roles": ("code", "long"),
        "note": "30B MoE: far too large for 4 GB; only useful if you accept RAM/CPU offload.",
    },
    {
        "matches": ("glm-4.7", "glm 4.7"),
        "roles": ("experimental", "reasoning", "analysis"),
        "note": "Large experimental model; too large for this GPU.",
    },
    {
        "matches": ("sentence-transformer", "minilm", "embedding"),
        "roles": ("embedding",),
        "note": "Embedding model, not a chat/report model.",
    },
    {
        "matches": ("qwen3.5-4b", "qwen3.5 4b"),
        "roles": ("analysis", "writing", "vision"),
        "note": "4B Qwen3.5 with vision. Around 3.7 GB is a tight fit; auto-fit to find a safe context.",
    },
    {
        "matches": ("qwen3-4b", "qwen3 4b"),
        "roles": ("analysis", "writing", "fast"),
        "note": "4B generalist. Check quantisation and context with auto-fit.",
    },
]

# Static suggestions only. Breadcrumb never downloads anything automatically.
CURATED_SUGGESTIONS = [
    {
        "id": "qwen2.5-3b-instruct",
        "name": "Qwen2.5-3B-Instruct Q4_K_M (official)",
        "size": "2.10 GB",
        "roles": ("fast", "analysis", "writing", "reports"),
        "why": "Best 3B generalist. Use when you want faster summaries/tagging with more VRAM headroom.",
        "url": "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/blob/main/qwen2.5-3b-instruct-q4_k_m.gguf",
    },
    {
        "id": "qwen2.5-coder-3b-instruct",
        "name": "Qwen2.5-Coder-3B-Instruct Q4_K_M (official)",
        "size": "2.10 GB",
        "roles": ("code", "long", "fast"),
        "why": "Best small code specialist for JS, config and large dumps. Not a prose/report model.",
        "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/blob/main/qwen2.5-coder-3b-instruct-q4_k_m.gguf",
    },
    {
        "id": "qwen2.5-3b-instruct-pentest",
        "name": "Pentest AI 3B (community fine-tune)",
        "size": "1.93 GB",
        "roles": ("experimental", "analysis"),
        "why": "Security/CTF fine-tune. Experimental only: low validation and no report-writing guarantee.",
        "url": "https://huggingface.co/r1r21nb/qwen2.5-3b-instruct.Q4_K_M.gguf/blob/main/qwen2.5-3b-instruct.Q4_K_M.gguf",
    },
]

# Snapshot of the models found on this machine and what they are good for.
# Kept as data (not template prose) so the Settings page and tests can agree.
# Update the date/list when the local collection changes.
LOCAL_MODEL_NOTES = {
    "reviewed": "2026-11-12",
    "hardware": (
        "AMD Ryzen 5 5600H laptop · 18 GB RAM · "
        "NVIDIA GeForce GTX 1650 Laptop GPU, 4 GB VRAM"
    ),
    "summary": (
        "Snapshot of the Jan and LM Studio libraries on this laptop. The "
        "GTX 1650 Laptop GPU has 4 GB of VRAM, so 3–4B Q4/Q5 models are the "
        "practical daily drivers; larger models are batch/quality experiments "
        "or future-laptop targets. Task routing above is what Breadcrumb "
        "actually calls."
    ),
    "models": [
        {
            "id": "qwen3-4b-instruct-2507",
            "name": "Qwen3-4B-Instruct-2507 (UD-Q5_K_XL)",
            "provider": "LM Studio",
            "size": "2.9 GB",
            "best_for": "Best all-round 4 GB model: tagging, analysis, reasoning, long dumps and report prose.",
            "verdict": "Current default and the only model routed for all four tasks. Keep it as the daily driver.",
            "fit": "fits",
        },
        {
            "id": "qwen_qwen3.5-4b",
            "name": "Qwen3.5-4B (Q4_K_M, vision)",
            "provider": "LM Studio",
            "size": "3.0 GB + vision projector",
            "best_for": "General chat and screenshot/image understanding; newer than Qwen3-4B.",
            "verdict": "Tight fit at 4 GB. Use Auto-fit and a small context; good backup or vision option.",
            "fit": "tight",
        },
        {
            "id": "qwen3.5-4b-claude-4.6-opus-reasoning-distilled-v2",
            "name": "Qwen3.5-4B Claude 4.6 Opus Reasoning Distill v2",
            "provider": "LM Studio",
            "size": "3.4 GB",
            "best_for": "Reasoning experiments; not a reliable structured-output or report model.",
            "verdict": "Tested: produced reasoning-only/empty content. Do not route reports to it.",
            "fit": "tight",
        },
        {
            "id": "qwen3.5-4b-claude-4.6-opus-reasoning-distilled-v2-heretic",
            "name": "Qwen3.5-4B Claude 4.6 Opus Reasoning Distill v2 (heretic)",
            "provider": "LM Studio",
            "size": "3.0 GB",
            "best_for": "Experimental/uncensored reasoning only.",
            "verdict": "Not for evidence reports; use Qwen3-4B-Instruct-2507 for anything you will submit.",
            "fit": "tight",
        },
        {
            "id": "qwen3-4b-2507-instruct-uncensored-hauhaucs-aggressive",
            "name": "Qwen3-4B-2507 Instruct Uncensored (HauhauCS Aggressive, Q6_K)",
            "provider": "LM Studio",
            "size": "3.3 GB",
            "best_for": "Experimental/uncensored chat only.",
            "verdict": "Tested: Q6_K failed a 4096-context KV allocation on this GPU. Experimental; not a report writer.",
            "fit": "tight",
        },
        {
            "id": "qwen/qwen3.5-9b",
            "name": "Qwen3.5-9B (Q8_0, vision)",
            "provider": "LM Studio",
            "size": "9.5 GB + vision projector",
            "best_for": "General reasoning and vision; a strong 12 GB-class daily model.",
            "verdict": "Too large for 4 GB at Q8. Future 12 GB+ GPU; use a Q4/Q5 quant to fit smaller cards.",
            "fit": "too-large",
        },
        {
            "id": "deepseek/deepseek-r1-0528-qwen3-8b",
            "name": "DeepSeek-R1-0528-Qwen3-8B (Q8_0)",
            "provider": "LM Studio",
            "size": "8.7 GB",
            "best_for": "Step-by-step reasoning, CVE chains and severity rationale.",
            "verdict": "Too large at Q8 for 4 GB. A Q4 8B or this model on 8–12 GB VRAM is the reasoning upgrade.",
            "fit": "too-large",
        },
        {
            "id": "deepseek-r1-distill-qwen-14b",
            "name": "DeepSeek-R1-Distill-Qwen-14B (Q4_K_L)",
            "provider": "LM Studio",
            "size": "9.6 GB",
            "best_for": "Deeper reasoning when quality matters more than latency.",
            "verdict": "Tested: too large for 4 GB and slower than the 4B. Future 12–16 GB GPU.",
            "fit": "too-large",
        },
        {
            "id": "google/gemma-4-12b-qat",
            "name": "Gemma 4 12B IT QAT (Q4_0, vision)",
            "provider": "LM Studio",
            "size": "7.0 GB + vision projector",
            "best_for": "Report prose, summaries and image understanding.",
            "verdict": "Tested: 30% GPU offload ran at 2.7–3.0 tok/s and returned reasoning-only content. Future 12 GB+ prose model.",
            "fit": "too-large",
        },
        {
            "id": "qwen3-coder-30b-a3b-instruct",
            "name": "Qwen3-Coder-30B-A3B-Instruct (IQ4_XS)",
            "provider": "Jan",
            "size": "16.4 GB",
            "best_for": "Large code/config/JS dumps and long-context code work.",
            "verdict": "CPU-only on this PC (no GPU layers, 11.4k context). Usable for patient batch work; excellent on a future 24 GB+ GPU.",
            "fit": "too-large",
        },
        {
            "id": "text-embedding-nomic-embed-text-v1.5",
            "name": "Nomic Embed Text v1.5 (Q4_K_M)",
            "provider": "LM Studio",
            "size": "84 MB",
            "best_for": "Semantic search and embeddings; no chat output.",
            "verdict": "Bundled by LM Studio and CPU-friendly. Useful if you add vector/semantic search; Breadcrumb's core search works without it.",
            "fit": "fits",
        },
        {
            "id": "sentence-transformer-mini",
            "name": "all-MiniLM-L6-v2 (Jan entry)",
            "provider": "Jan",
            "size": "weights missing",
            "best_for": "Lightweight embeddings if the weights are installed.",
            "verdict": "Only model.yml is present; the .gguf weights are missing, so it cannot load yet. Use nomic-embed-text or re-download it in Jan.",
            "fit": "unknown",
        },
    ],
    "tasks": [
        {
            "task": "Fast / bulk tagging, short summaries",
            "pick": "3–4B non-thinking instruct, Q4/Q5",
            "why": "Cheapest per token and reliable JSON; Qwen3-4B-Instruct-2507 is the current pick.",
            "future": "16 GB RAM + 8 GB VRAM is already plenty",
        },
        {
            "task": "Reasoning / CVE chains / severity rationale",
            "pick": "8–14B reasoning model, Q4/Q5",
            "why": "More deliberate answers, but slower; keep the 4B for routine triage.",
            "future": "32 GB RAM + 12–16 GB VRAM for 8B Q8 or 14B Q4",
        },
        {
            "task": "Long context / code / JS / config dumps",
            "pick": "Coder 7–14B, or 30B-A3B MoE for batch",
            "why": "Code-specialist context handling; the 30B MoE is fast only with enough VRAM.",
            "future": "64 GB RAM + 24 GB VRAM for 30B-A3B Q4/Q5",
        },
        {
            "task": "Prose / reports / writeups",
            "pick": "12–32B instruct or Gemma-class prose model",
            "why": "Better narrative flow and fewer terse, reasoning-only outputs.",
            "future": "32–64 GB RAM + 16–24 GB VRAM for 12B Q8 or 27–32B Q4",
        },
        {
            "task": "Vision / screenshots",
            "pick": "4B–9B VLM (Qwen3.5 or Gemma 4)",
            "why": "Screenshot description and UI context; text redaction still does not redact pixels.",
            "future": "32 GB RAM + 8–12 GB VRAM for 4B–9B vision",
        },
        {
            "task": "Embeddings / search",
            "pick": "MiniLM or nomic-embed-text",
            "why": "Small, fast and CPU-friendly; no chat capability.",
            "future": "16 GB RAM is enough; GPU only helps bulk indexing",
        },
    ],
    "future_tiers": [
        {
            "ram": "16 GB",
            "vram": "8 GB",
            "good_for": "4B–8B Q5/Q8, 12B Q4 (tight)",
            "examples": "Qwen3-4B, Qwen3.5-9B Q4, 8B reasoning",
            "note": "The floor for a new machine, not a real upgrade from this 18 GB laptop. 16 GB is enough for 4B–8B; pick 32 GB if you want to keep 12B+ models loaded.",
        },
        {
            "ram": "32 GB",
            "vram": "12–16 GB",
            "good_for": "9B Q8, 14B Q5/Q6, 12B Q6/Q8",
            "examples": "Qwen3.5-9B, DeepSeek-R1 14B, Gemma 4 12B",
            "note": "The first meaningful upgrade: 16 GB VRAM runs a 9B Q8 or 12B Q6/Q8 at moderate context, with 32 GB RAM for long context and offload.",
        },
        {
            "ram": "64 GB",
            "vram": "24 GB",
            "good_for": "30B-A3B Q4/Q5 fully on GPU, 14B Q8, 12B vision",
            "examples": "Qwen3-Coder-30B-A3B, DeepSeek 14B, Gemma 4 12B",
            "note": "Top laptop tier (24 GB VRAM) or an eGPU/desktop. Fast 30B MoE plus a 12–14B quality model; 64 GB RAM keeps offload comfortable.",
        },
        {
            "ram": "64–128 GB",
            "vram": "32 GB+",
            "good_for": "32B Q5/Q6, 70B Q4 with offload",
            "examples": "Qwen 32B class, 70B Q4",
            "note": "Desktop/workstation territory; 32 GB VRAM is not a laptop part. Spend on RAM and NVMe if you run 70B.",
        },
        {
            "ram": "128 GB+",
            "vram": "64 GB+ unified",
            "good_for": "70B Q4/Q5, 100B+ MoE, very long context",
            "examples": "Unified-memory workstation or mini-PC",
            "note": "Only worth it for huge dumps; otherwise 24 GB VRAM is the value point.",
        },
    ],
    "buying_note": (
        "On a laptop, VRAM and often RAM are soldered, so buy the memory you "
        "expect to keep. 16 GB RAM is the floor; 32 GB is the first real "
        "upgrade for 9B–14B work, and 64 GB only matters if you offload "
        "30B+ models. For a future laptop, 16 GB VRAM is the practical sweet "
        "spot and 24 GB is the top tier; 32 GB+ VRAM means a desktop or "
        "eGPU. Keep models on NVMe; loading a 16 GB GGUF from a slow disk is "
        "the real delay."
    ),
}

# Largest first. Auto-fit stops at the first context that loads and answers.
# 2048 is always kept as the last-resort fallback for very tight cards.
CONTEXT_CANDIDATES = (32768, 16384, 8192, 6144, 4096, 2048)
AUTOFIT_MAX_ATTEMPTS = 6

DEFAULT_CONFIG = {
    "active_provider": "jan",
    "providers": [
        {
            "id": "jan",
            "label": "Jan (local)",
            "base_url": "http://127.0.0.1:1337/v1",
            "api_key": "",
            "enabled": True,
        },
        {
            "id": "lmstudio",
            "label": "LM Studio (local)",
            "base_url": "http://127.0.0.1:1234/v1",
            "api_key": "",
            "enabled": False,
        },
    ],
    "routing": {
        "fast": "qwen3-8b",
        "reason": "deepseek-r1-distill-14b",
        "long": "qwen3-coder-30b-a3b",
        "prose": "gemma-3-12b",
    },
    "autonomy": "suggest",
    "cloud_opt_in": False,
}


def default_config() -> dict:
    return json.loads(json.dumps(DEFAULT_CONFIG))


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        cfg = default_config()
        save_config(cfg)
        return cfg
    try:
        stored = json.loads(CONFIG_PATH.read_text())
    except (ValueError, OSError):
        return default_config()
    config = default_config()
    config.update({k: v for k, v in stored.items() if k in config})
    # keep routing keys complete
    routing = config.get("routing") or {}
    config["routing"] = {task: routing.get(task, config["routing"][task]) for task in TASK_CLASSES}
    return config


def save_config(config: dict) -> dict:
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    return config


def get_provider(config: dict, provider_id: str | None = None) -> dict | None:
    pid = provider_id or config.get("active_provider")
    for provider in config.get("providers", []):
        if provider.get("id") == pid:
            return provider
    return None


def _headers(provider: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    key = (provider or {}).get("api_key") or ""
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _request(method: str, url: str, provider: dict, payload=None, timeout: float = 30.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in _headers(provider).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw else {}


def _base(provider: dict) -> str:
    return (provider.get("base_url") or "").rstrip("/")


def _clean_cli(text: str, limit: int = 400) -> str:
    """Strip ANSI/progress noise from LM Studio CLI output."""
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text or "")
    text = text.replace("\r", "\n")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    joined = " · ".join(lines)
    return joined[-limit:]


def _json_blob(text: str):
    """Parse JSON even when a CLI prints a progress line before it."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    starts = [i for i in (text.find("["), text.find("{")) if i != -1]
    if not starts:
        return None
    start = min(starts)
    end = max(text.rfind("]"), text.rfind("}"))
    if end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except ValueError:
        return None


def _lms_path() -> str:
    """Locate the LM Studio CLI without assuming a global install."""
    candidates = [
        os.environ.get("BREADCRUMB_LMS_PATH", ""),
        shutil.which("lms") or "",
        str(Path.home() / ".lmstudio" / "bin" / "lms"),
        "/usr/local/bin/lms",
        "/usr/bin/lms",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _run_lms(args: list[str], timeout: float = 60.0) -> dict:
    path = _lms_path()
    if not path:
        return {"ok": False, "error": "LM Studio CLI (lms) not found", "stdout": "", "stderr": ""}
    try:
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"lms {' '.join(args)} timed out after {int(timeout)}s",
                "stdout": "", "stderr": ""}
    except OSError as exc:
        return {"ok": False, "error": f"cannot run lms: {exc}", "stdout": "", "stderr": ""}
    ok = proc.returncode == 0
    error = "" if ok else (_clean_cli(proc.stderr) or _clean_cli(proc.stdout) or f"lms exited {proc.returncode}")
    return {"ok": ok, "error": error, "stdout": proc.stdout or "", "stderr": proc.stderr or ""}


def gpu_info() -> dict:
    """Best-effort VRAM info. Never raises; an empty dict means unknown."""
    try:
        proc = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,memory.free",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    first = proc.stdout.strip().splitlines()[0]
    parts = [part.strip() for part in first.split(",")]
    if len(parts) < 3:
        return {}
    try:
        total_mb = int(float(parts[1]))
        free_mb = int(float(parts[2]))
    except ValueError:
        return {}
    return {
        "name": parts[0],
        "total_mb": total_mb,
        "free_mb": free_mb,
        "total_gb": round(total_mb / 1024.0, 2),
        "free_gb": round(free_mb / 1024.0, 2),
    }


def _size_gb(size_bytes) -> float | None:
    try:
        value = float(size_bytes)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return round(value / (1024.0 ** 3), 2)


def _human_size(size_bytes) -> str:
    try:
        value = float(size_bytes)
    except (TypeError, ValueError):
        return "size unknown"
    if value <= 0:
        return "size unknown"
    return f"{value / 1_000_000_000:.2f} GB"


def _human_ctx(value) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "?"
    if number >= 1024 and number % 1024 == 0:
        return f"{number // 1024}k"
    return str(number)


def _guide_for(text: str) -> dict | None:
    haystack = (text or "").lower()
    for entry in MODEL_GUIDE:
        if any(token in haystack for token in entry["matches"]):
            return entry
    return None


def model_roles(*parts) -> dict:
    """Return {roles, role_labels, note} for a model id/name/path."""
    text = " ".join(str(part) for part in parts if part)
    guide = _guide_for(text)
    if guide:
        roles = list(guide["roles"])
        note = guide["note"]
    else:
        lowered = text.lower()
        roles = []
        if any(token in lowered for token in ("embed", "minilm", "bge-")):
            roles = ["embedding"]
        if any(token in lowered for token in ("coder", "code", "starcoder", "deepseek-coder")):
            roles.append("code")
        if any(token in lowered for token in ("reason", "thinking", "r1-", "distill")):
            roles.append("reasoning")
        if any(token in lowered for token in ("uncensored", "heretic", "abliterated")):
            roles.append("experimental")
        if any(token in lowered for token in ("vision", "vlm", "vl-")):
            roles.append("vision")
        if not roles:
            roles = ["analysis", "writing"]
        roles = list(dict.fromkeys(roles))
        note = "General instruct model. Run Test to check output quality and speed on this machine."
    return {
        "roles": roles,
        "role_labels": [ROLE_LABELS.get(role, role) for role in roles],
        "note": note,
    }


def estimate_fit(size_bytes, gpu: dict | None = None) -> dict:
    """Heuristic VRAM fit for weights at a 4k context.

    This is intentionally conservative; the only authoritative answer is an
    actual load. ``auto-fit`` turns the heuristic into a real measurement.
    """
    size_gb = _size_gb(size_bytes)
    total_gb = None
    if gpu and gpu.get("total_mb"):
        total_gb = round(float(gpu["total_mb"]) / 1024.0, 2)
    if size_gb is None:
        return {"level": "unknown", "label": "Fit unknown", "size_gb": None,
                "vram_gb": total_gb,
                "note": "Size unknown. Run Auto-fit to probe a working context."}
    if not total_gb:
        return {"level": "unknown", "label": "Fit unknown", "size_gb": size_gb,
                "vram_gb": None,
                "note": "No NVIDIA GPU detected. Run Auto-fit to see what the machine can load."}
    ratio = size_gb / total_gb
    if ratio <= 0.73:
        return {"level": "fits", "label": "Fits 4 GB" if total_gb <= 4.5 else f"Fits {total_gb:.1f} GB",
                "size_gb": size_gb, "vram_gb": total_gb,
                "note": "Weights fit with room for a ~4k context. Auto-fit may find more."}
    if ratio <= 0.95:
        return {"level": "tight", "label": "Tight fit", "size_gb": size_gb,
                "vram_gb": total_gb,
                "note": "Close to the VRAM limit. Auto-fit to find a context that actually loads."}
    return {"level": "too-large", "label": "Too large", "size_gb": size_gb,
            "vram_gb": total_gb,
            "note": "Weights exceed VRAM. Partial offload works but is slow; use with a warning."}


def _is_lmstudio(provider: dict) -> bool:
    pid = str((provider or {}).get("id") or "").lower()
    url = str((provider or {}).get("base_url") or "").lower()
    return "lmstudio" in pid or "lm-studio" in pid or ":1234" in url


def _is_jan(provider: dict) -> bool:
    pid = str((provider or {}).get("id") or "").lower()
    url = str((provider or {}).get("base_url") or "").lower()
    return "jan" in pid or ":1337" in url


def _lmstudio_root(provider: dict) -> str:
    base = _base(provider)
    return base[:-3] if base.endswith("/v1") else base


def _lmstudio_native_metadata(provider: dict, timeout: float = 5.0) -> dict:
    if not _is_lmstudio(provider):
        return {}
    try:
        data = _request(
            "GET", f"{_lmstudio_root(provider)}/api/v0/models", provider, timeout=timeout
        )
    except Exception:  # noqa: BLE001  (native API is optional)
        return {}
    out = {}
    for item in data.get("data") or []:
        if not isinstance(item, dict):
            continue
        ident = item.get("id") or item.get("model") or item.get("name")
        if ident:
            out[str(ident)] = item
    return out


def _lmstudio_cli_metadata() -> dict:
    result = _run_lms(["ls", "--json"], timeout=8.0)
    if not result["ok"]:
        return {}
    data = _json_blob(result["stdout"])
    if not isinstance(data, list):
        return {}
    out = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        aliases = [
            item.get("modelKey"),
            item.get("displayName"),
            item.get("indexedModelIdentifier"),
        ]
        path = item.get("path")
        if path:
            aliases.append(Path(str(path)).stem)
        for alias in aliases:
            if alias:
                out[str(alias)] = item
                out[str(alias).lower()] = item
    return out


def _cli_lookup(cli: dict, ident: str) -> dict:
    if not cli:
        return {}
    return cli.get(ident) or cli.get(ident.lower()) or {}


def _loaded_lmstudio_models() -> dict:
    result = _run_lms(["ps", "--json"], timeout=5.0)
    if not result["ok"]:
        return {}
    data = _json_blob(result["stdout"])
    if not isinstance(data, list):
        return {}
    out = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        ident = (
            item.get("identifier")
            or item.get("modelKey")
            or item.get("model")
            or item.get("id")
            or item.get("path")
        )
        if not ident:
            continue
        context = (
            item.get("contextLength")
            or item.get("context_length")
            or item.get("context")
            or item.get("maxContextLength")
        )
        out[str(ident)] = {"raw": item, "context": context}
        out[str(ident).lower()] = out[str(ident)]
    return out


def _simple_yaml(path: Path) -> dict:
    """Tiny key: value reader for Jan's model.yml (no PyYAML dependency)."""
    try:
        text = path.read_text()
    except OSError:
        return {}
    out = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        value = value.strip().strip("'\"")
        if value.lower() in ("true", "false"):
            out[key.strip()] = value.lower() == "true"
            continue
        try:
            out[key.strip()] = int(value)
        except ValueError:
            out[key.strip()] = value
    return out


def _jan_metadata() -> dict:
    root = Path(
        os.environ.get(
            "BREADCRUMB_JAN_MODELS",
            str(Path.home() / ".local/share/Jan/data/llamacpp/models"),
        )
    ).expanduser()
    if not root.is_dir():
        return {}
    out = {}
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        meta = _simple_yaml(folder / "model.yml")
        if not meta:
            continue
        item = {
            "name": meta.get("name") or folder.name,
            "sizeBytes": meta.get("size_bytes"),
            "maxContextLength": meta.get("ctx_size"),
            "architecture": "llamacpp",
            "embedding": bool(meta.get("embedding")),
            "path": meta.get("model_path") or folder.name,
        }
        aliases = [folder.name, item["name"]]
        if meta.get("model_path"):
            aliases.append(Path(str(meta["model_path"])).stem)
        for alias in aliases:
            if alias:
                out[str(alias)] = item
                out[str(alias).lower()] = item
    return out


def _jan_lookup(jan: dict, ident: str) -> dict:
    if not jan:
        return {}
    key = ident.lower()
    if key in jan:
        return jan[key]
    # Jan can expose the folder name or the display name; fall back to a
    # conservative "contains" match so metadata is not silently lost.
    for alias, item in jan.items():
        if len(alias) > 4 and (alias in key or key in alias):
            return item
    return {}


def list_models_detailed(provider: dict, timeout: float = 15.0) -> dict:
    """Reachable model list plus metadata, roles, fit and curated downloads."""
    gpu = gpu_info()
    result = {
        "ok": False,
        "reachable": False,
        "provider": (provider or {}).get("id"),
        "provider_label": (provider or {}).get("label") or (provider or {}).get("id"),
        "base_url": _base(provider or {}),
        "gpu": gpu,
        "can_autofit": bool(_is_lmstudio(provider or {}) and _lms_path()),
        "autofit_hint": "",
        "count": 0,
        "models": [],
        "suggestions": [],
        "role_labels": ROLE_LABELS,
        "task_labels": TASK_LABELS,
        "notes": [
            "Only models reported by the running server are listed.",
            "Max context is the model's advertised limit, not what fits in VRAM. Use Auto-fit to measure the real limit.",
        ],
        "error": "",
    }
    if not provider or not provider.get("base_url"):
        result["error"] = "no provider configured"
        return result
    try:
        data = _request("GET", f"{_base(provider)}/models", provider, timeout=timeout)
    except urllib.error.HTTPError as exc:
        result["error"] = f"HTTP {exc.code} on /models"
        return result
    except urllib.error.URLError as exc:
        result["error"] = f"cannot reach {_base(provider)} ({exc.reason})"
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    ids = []
    for item in data.get("data") or data.get("models") or []:
        if isinstance(item, dict):
            ident = item.get("id") or item.get("name") or item.get("model")
        else:
            ident = item
        if ident and str(ident) not in ids:
            ids.append(str(ident))

    native = _lmstudio_native_metadata(provider)
    cli = _lmstudio_cli_metadata() if _is_lmstudio(provider) else {}
    jan = _jan_metadata() if _is_jan(provider) else {}
    loaded = _loaded_lmstudio_models() if _is_lmstudio(provider) else {}

    models = []
    for ident in ids:
        native_item = native.get(ident) or {}
        cli_item = _cli_lookup(cli, ident)
        jan_item = _jan_lookup(jan, ident)
        merged = {**jan_item, **cli_item, **native_item}
        display = (
            cli_item.get("displayName")
            or native_item.get("display_name")
            or jan_item.get("name")
            or ident
        )
        size_bytes = (
            cli_item.get("sizeBytes")
            or jan_item.get("sizeBytes")
            or native_item.get("size_bytes")
        )
        max_context = (
            native_item.get("max_context_length")
            or cli_item.get("maxContextLength")
            or jan_item.get("maxContextLength")
        )
        quant = cli_item.get("quantization")
        if isinstance(quant, dict):
            quant = quant.get("name")
        quant = quant or native_item.get("quantization") or ""
        state = native_item.get("state") or ("loaded" if ident in loaded or ident.lower() in loaded else "unknown")
        loaded_info = loaded.get(ident) or loaded.get(ident.lower()) or {}
        role_info = model_roles(ident, display, cli_item.get("path") or "")
        fit = estimate_fit(size_bytes, gpu)
        if role_info["roles"] == ["embedding"]:
            fit = {"level": "fits", "label": "Embedding", "size_gb": _size_gb(size_bytes),
                   "vram_gb": gpu.get("total_gb") if gpu else None,
                   "note": "Not a chat model; excluded from role recommendations."}
        models.append(
            {
                "id": ident,
                "display_name": display,
                "publisher": cli_item.get("publisher") or native_item.get("publisher") or "",
                "arch": native_item.get("arch") or cli_item.get("architecture") or "",
                "quantization": quant,
                "params": cli_item.get("paramsString") or "",
                "size_bytes": size_bytes,
                "size_gb": _size_gb(size_bytes),
                "size_label": _human_size(size_bytes),
                "max_context_length": max_context,
                "max_context_label": _human_ctx(max_context) if max_context else "?",
                "loaded_context": loaded_info.get("context"),
                "state": state,
                "capabilities": native_item.get("capabilities") or [],
                "vision": bool(cli_item.get("vision") or "vision" in role_info["roles"]),
                "roles": role_info["roles"],
                "role_labels": role_info["role_labels"],
                "note": role_info["note"],
                "fit": fit,
                "suggested_context": 4096 if fit["level"] in ("fits", "tight") else None,
                "can_autofit": result["can_autofit"],
            }
        )

    order = {"fits": 0, "tight": 1, "unknown": 2, "too-large": 3}
    models.sort(
        key=lambda model: (
            0 if str(model["state"]).lower() == "loaded" else 1,
            order.get(model["fit"]["level"], 2),
            (model["size_gb"] is None, model["size_gb"] or 0),
            model["id"].lower(),
        )
    )
    installed = {model["id"].lower() for model in models}
    suggestions = []
    for suggestion in CURATED_SUGGESTIONS:
        item = dict(suggestion)
        item["role_labels"] = [ROLE_LABELS.get(role, role) for role in suggestion["roles"]]
        item["installed"] = suggestion["id"].lower() in installed
        suggestions.append(item)

    result.update(
        {
            "ok": True,
            "reachable": True,
            "count": len(models),
            "models": models,
            "suggestions": suggestions,
        }
    )
    if not result["can_autofit"] and _is_lmstudio(provider):
        result["autofit_hint"] = "Auto-fit needs the LM Studio CLI (lms) on PATH or at ~/.lmstudio/bin/lms."
    return result


def list_models(provider: dict, timeout: float = 15.0) -> list[str]:
    data = _request("GET", f"{_base(provider)}/models", provider, timeout=timeout)
    models = data.get("data") or data.get("models") or []
    out = []
    for item in models:
        if isinstance(item, dict):
            ident = item.get("id") or item.get("name") or item.get("model")
            if ident:
                out.append(ident)
        elif isinstance(item, str):
            out.append(item)
    return out


def chat(provider: dict, model: str, messages: list, temperature: float = 0.2,
         max_tokens: int = 1024, timeout: float = 180.0) -> str:
    return chat_detailed(
        provider,
        model,
        messages,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )["content"]


def chat_detailed(provider: dict, model: str, messages: list, temperature: float = 0.2,
                  max_tokens: int = 1024, timeout: float = 180.0) -> dict:
    """Chat completion plus the fields Breadcrumb needs to judge a model.

    Thinking models put their output in ``reasoning_content`` and leave
    ``content`` empty. Returning both lets the picker warn about that instead
    of silently saving an empty report.
    """
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    started = time.time()
    data = _request("POST", f"{_base(provider)}/chat/completions", provider, payload, timeout=timeout)
    elapsed = round(time.time() - started, 2)
    choices = data.get("choices") or []
    choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") or {}
    content = (message.get("content") or "").strip()
    reasoning = (message.get("reasoning_content") or message.get("reasoning") or "").strip()
    usage = data.get("usage") or {}
    stats = data.get("stats") or {}
    completion_tokens = (
        usage.get("completion_tokens")
        or stats.get("tokens_generated")
        or stats.get("completion_tokens")
        or 0
    )
    try:
        completion_tokens = int(completion_tokens)
    except (TypeError, ValueError):
        completion_tokens = 0
    tok_per_s = (
        stats.get("tokens_per_second")
        or stats.get("tok_per_second")
        or stats.get("tokens_per_sec")
    )
    try:
        tok_per_s = float(tok_per_s) if tok_per_s else None
    except (TypeError, ValueError):
        tok_per_s = None
    if not tok_per_s and completion_tokens and elapsed > 0:
        tok_per_s = completion_tokens / elapsed
    return {
        "content": content,
        "reasoning": reasoning,
        "finish_reason": choice.get("finish_reason") or "",
        "completion_tokens": completion_tokens,
        "prompt_tokens": int(usage.get("prompt_tokens") or 0),
        "elapsed_s": elapsed,
        "tok_per_s": round(tok_per_s, 2) if tok_per_s else None,
        "empty_content": not bool(content),
        "reasoning_only": bool(not content and reasoning),
    }


def _describe_chat_error(exc: Exception, timeout: float | None = None) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        detail = ""
        try:
            detail = exc.read().decode()[:400]
        except Exception:  # noqa: BLE001
            pass
        return f"HTTP {exc.code}" + (f": {_clean_cli(detail)}" if detail else "")
    if isinstance(exc, urllib.error.URLError):
        return f"cannot reach provider ({exc.reason})"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        suffix = f" after {timeout}s" if timeout else ""
        return f"model timed out{suffix}"
    return str(exc)


def _model_max_context(provider: dict, model: str) -> int | None:
    native = _lmstudio_native_metadata(provider).get(model) or {}
    value = native.get("max_context_length")
    if value:
        return int(value)
    cli = _cli_lookup(_lmstudio_cli_metadata(), model)
    value = cli.get("maxContextLength")
    if value:
        return int(value)
    return None


def auto_fit_context(provider: dict, model: str, timeout: float = 180.0) -> dict:
    """Load a model at descending context sizes until one works and answers.

    This is an interactive, on-demand action. It unloads the current instance
    of the model and leaves the successful one loaded with a TTL.
    """
    result = {
        "ok": False,
        "model": model,
        "context": None,
        "context_label": "",
        "load_s": None,
        "attempts": [],
        "error": "",
    }
    if not _is_lmstudio(provider):
        result["error"] = "Auto-fit is only available for LM Studio providers."
        return result
    if not _lms_path():
        result["error"] = "LM Studio CLI (lms) not found. Install the CLI or set BREADCRUMB_LMS_PATH."
        return result

    max_context = _model_max_context(provider, model) or 32768
    candidates = [ctx for ctx in CONTEXT_CANDIDATES if ctx <= max_context]
    if not candidates:
        candidates = [2048]
    candidates = candidates[:AUTOFIT_MAX_ATTEMPTS]
    per_load_timeout = max(60.0, min(180.0, timeout))

    for context in candidates:
        _run_lms(["unload", model], timeout=30.0)  # ignore "not loaded"
        started = time.time()
        load = _run_lms(
            ["load", model, "--gpu", "max", "-c", str(context), "--ttl", "120", "-y"],
            timeout=per_load_timeout,
        )
        load_s = round(time.time() - started, 2)
        attempt = {"context": context, "context_label": _human_ctx(context),
                   "ok": False, "load_s": load_s, "error": ""}
        if not load["ok"]:
            attempt["error"] = load["error"]
            result["attempts"].append(attempt)
            continue

        # A successful load is not enough: verify the context can answer.
        try:
            probe = chat_detailed(
                provider,
                model,
                [{"role": "user", "content": "Reply with the single word: ok"}],
                max_tokens=8,
                timeout=min(60.0, per_load_timeout),
            )
        except Exception as exc:  # noqa: BLE001
            attempt["error"] = _describe_chat_error(exc, min(60.0, per_load_timeout))
            result["attempts"].append(attempt)
            continue
        if not (probe["content"] or probe["reasoning"]):
            attempt["error"] = "loaded but returned no content"
            result["attempts"].append(attempt)
            continue

        attempt["ok"] = True
        attempt["probe_reply"] = (probe["content"] or probe["reasoning"])[:120]
        result["attempts"].append(attempt)
        result.update(
            {
                "ok": True,
                "context": context,
                "context_label": _human_ctx(context),
                "load_s": load_s,
            }
        )
        return result

    last = next((a for a in reversed(result["attempts"]) if a.get("error")), {})
    tried = ", ".join(a["context_label"] for a in result["attempts"]) or "none"
    result["error"] = f"no context loaded (tried {tried})"
    if last.get("error"):
        result["error"] += f": {last['error']}"
    return result


def test_model(provider: dict, model: str, prompt: str | None = None,
               max_tokens: int = 64, timeout: float = 180.0,
               auto_fit: bool = False) -> dict:
    """Speed/output test used by the settings picker."""
    result = {
        "ok": False,
        "usable": False,
        "verdict": "error",
        "provider": (provider or {}).get("id"),
        "model": model,
        "content": "",
        "reasoning": "",
        "finish_reason": "",
        "completion_tokens": 0,
        "elapsed_s": None,
        "tok_per_s": None,
        "context": None,
        "context_label": "",
        "load_s": None,
        "auto_fit": None,
        "error": "",
    }
    if not provider or not provider.get("base_url"):
        result["error"] = "no provider configured"
        return result
    if not model:
        result["error"] = "no model selected"
        return result

    if auto_fit:
        fit = auto_fit_context(provider, model, timeout=timeout)
        result["auto_fit"] = fit
        if not fit.get("ok"):
            result["error"] = fit.get("error") or "auto-fit failed"
            return result
        result["context"] = fit.get("context")
        result["context_label"] = fit.get("context_label") or ""
        result["load_s"] = fit.get("load_s")

    messages = [
        {"role": "system", "content": "You are a concise technical assistant. Reply in one short sentence."},
        {"role": "user", "content": prompt or "Name one benefit of running a language model locally."},
    ]
    try:
        detail = chat_detailed(
            provider, model, messages, max_tokens=max(8, int(max_tokens)), timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001
        result["error"] = _describe_chat_error(exc, timeout)
        return result

    result.update(detail)
    if result["context"] is None and _is_lmstudio(provider):
        loaded = _loaded_lmstudio_models()
        info = loaded.get(model) or loaded.get(model.lower()) or {}
        if info.get("context"):
            result["context"] = info["context"]
            result["context_label"] = _human_ctx(info["context"])
    result["ok"] = True
    result["usable"] = bool(detail["content"]) and not detail["reasoning_only"]
    if detail["reasoning_only"]:
        result["verdict"] = "reasoning-only"
        result["error"] = (
            "Model returned reasoning tokens but empty content. "
            "Breadcrumb's report/JSON path cannot use this output as-is."
        )
    elif detail["empty_content"]:
        result["verdict"] = "empty"
        result["error"] = "Model returned an empty response."
    elif detail["finish_reason"] == "length":
        result["verdict"] = "truncated"
    else:
        result["verdict"] = "ok"
    return result


def test_connection(provider: dict, model: str | None = None, timeout: float = 15.0) -> dict:
    """Probe a provider: list models, then optionally a tiny chat ping."""
    if not provider or not provider.get("base_url"):
        return {"ok": False, "error": "no base_url configured"}

    started = time.time()
    result = {"ok": False, "models": [], "model_reply": "", "error": ""}
    try:
        result["models"] = list_models(provider, timeout=timeout)
    except urllib.error.HTTPError as exc:
        result["error"] = f"HTTP {exc.code} on /models"
        result["latency_ms"] = int((time.time() - started) * 1000)
        return result
    except urllib.error.URLError as exc:
        result["error"] = f"cannot reach {_base(provider)} ({exc.reason})"
        result["latency_ms"] = int((time.time() - started) * 1000)
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    ping_model = model or (result["models"][0] if result["models"] else "")
    if ping_model:
        try:
            reply = chat(provider, ping_model, [{"role": "user", "content": "Reply with the single word: ok"}],
                         max_tokens=8, timeout=timeout)
            result["model_reply"] = reply
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"chat failed: {exc}"

    result["latency_ms"] = int((time.time() - started) * 1000)
    result["ping_model"] = ping_model
    result["ok"] = not result["error"]
    return result


def pick_model(config: dict, task: str) -> str:
    routing = config.get("routing") or {}
    return routing.get(task) or routing.get("fast") or ""


def run_task(task: str, messages: list, config: dict | None = None, **kwargs) -> dict:
    """Run a routed chat task. Returns {ok, model, text, error}."""
    config = config or load_config()
    provider = get_provider(config)
    if provider is None:
        return {"ok": False, "model": "", "text": "", "error": "no active provider"}
    model = pick_model(config, task)
    if not model:
        return {"ok": False, "model": "", "text": "", "error": f"no model routed for task '{task}'"}
    try:
        text = chat(provider, model, messages, **kwargs)
        return {"ok": True, "model": model, "text": text, "error": ""}
    except urllib.error.URLError as exc:
        return {"ok": False, "model": model, "text": "", "error": f"cannot reach provider ({exc.reason})"}
    except (TimeoutError, socket.timeout) as exc:
        timeout = kwargs.get("timeout", "?")
        return {"ok": False, "model": model, "text": "",
                "error": f"model timed out after {timeout}s — try a smaller input or raise BREADCRUMB_AI_TIMEOUT ({exc})"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "model": model, "text": "", "error": str(exc)}
