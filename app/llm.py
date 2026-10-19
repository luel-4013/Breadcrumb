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
import socket
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
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    data = _request("POST", f"{_base(provider)}/chat/completions", provider, payload, timeout=timeout)
    choices = data.get("choices") or []
    if choices:
        message = choices[0].get("message") or {}
        return (message.get("content") or "").strip()
    return ""


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
