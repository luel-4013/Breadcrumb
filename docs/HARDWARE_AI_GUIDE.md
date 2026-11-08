# Hardware and local-AI guide

**Target machine:** GTX 1650 (4 GB VRAM), Ryzen 5 5600H, 20 GB RAM, Linux.
**Status:** measured/current for the Leadline merge (2026-11-08).

Breadcrumb’s scanning, parsing, evidence chain, reports and importer are
CPU/network/disk workloads. A GPU is **not required**. The local LLM is an
optional analyst that narrates captures and summaries; it never authorizes a
scan or changes triage state.

---

## 1. What each workload needs

| Workload | Bottleneck | Notes |
|---|---|---|
| Native recon (DNS/HTTP/ports/JS/params/API) | Network + CPU | Python `asyncio`/HTTP client; port scan is the slowest phase |
| Evidence sealing + SQLite | Disk + write lock | WAL, short write transactions, one writer |
| PDF/report generation | CPU | reportlab; seconds per report |
| NVD/CPE verification | CPU + RAM | Local cache; no network required |
| External tool adapters | The external binary | nmap/masscan/nuclei may use significant CPU/RAM |
| Local LLM | GPU/VRAM or CPU | Optional; 3–4B models fit 4 GB VRAM at modest context |

The worker is intentionally single-claim/single-writer. Running two workers
against the same SQLite file does not increase scan throughput and increases
lock contention. Queue multiple jobs and let one worker run them in order.

---

## 2. Recommended local model setup

Measured on the target 4 GB GTX 1650:

- **Default:** Unsloth **Qwen3-4B-Instruct-2507 UD-Q5_K_XL**, **4096 context**.
  This is the safe default for structured reports.
- **Fast/light:** official **Qwen2.5-3B-Instruct Q4_K_M** (~2.10 GB).
- **Code/JS/config dumps:** **Qwen2.5-Coder-3B-Instruct Q4_K_M** (~2.10 GB).
- **Experimental:** Pentest AI 3B (~1.93 GB). Treat outputs as unverified.

Do not assume a 7B+ model will fit. A 7B Q4 model is roughly 4+ GB before KV
cache and will not fit comfortably in 4 GB VRAM at useful context. The Settings
page’s model picker estimates fit and can auto-fit context when the LM Studio
CLI is available.

Provider defaults:

| Provider | Default endpoint | Notes |
|---|---|---|
| LM Studio | `http://127.0.0.1:1234/v1` | Default runtime; `lms` CLI enables model listing/auto-fit |
| Jan | `http://127.0.0.1:1337/v1` | Alternative; model folder via `BREADCRUMB_JAN_MODELS` |
| Ollama | `http://127.0.0.1:11434/v1` | Any OpenAI-compatible endpoint |
| Cloud | opt-in | Only if you explicitly configure a provider; data leaves the machine |

Environment variables:

| Variable | Purpose |
|---|---|
| `BREADCRUMB_LMS_PATH` | Path to the LM Studio `lms` CLI if not on `PATH` |
| `BREADCRUMB_JAN_MODELS` | Jan model directory (default `~/.local/share/Jan/data/llamacpp/models`) |
| `BREADCRUMB_AI_TIMEOUT` | Per-request timeout in seconds (default 180; raise for slow CPUs) |

The AI analyst is optional. Breadcrumb’s deterministic parsers, scope rules,
triage and evidence chain work with no model installed.

---

## 3. AI safety rules

- The LLM never grants scope, starts jobs, changes triage, edits evidence or
  bypasses the executor gate.
- Prompts are built from captured data; secrets are redacted before they reach
  a provider.
- AI output is labeled as narration/suggestion, not confirmed fact.
- A model timeout or malformed JSON degrades gracefully; it does not fail the
  capture or scan.
- Do not send engagement data to a cloud provider unless you have permission.

---

## 4. Performance expectations

On the target laptop, with a local fixture or small authorized target:

| Operation | Rough expectation |
|---|---|
| Single DNS/HTTP phase | sub-second to a few seconds |
| Port scan (curated list) | seconds to a few minutes depending on host/firewall |
| Full 12-phase recon | minutes; target-dependent |
| Snapshot build | milliseconds to seconds |
| PDF report | seconds |
| 4B model summary | tens of seconds at 4096 context |
| Leadline import (2 targets) | under a second in the verification run |
| Leadline import (large DB) | scales with rows; one transaction, so allow disk space |

Caps protect large targets: endpoints/subdomains/technologies/CVE matches/API
paths/graph nodes are capped; external adapter output defaults to 10 MB (some
tools 20 MB or 5 MB). Hitting a cap is recorded as a warning/truncation, not a
silent loss.

---

## 5. Tuning

- Keep `BREADCRUMB_EXECUTOR=off` until you are ready to scan.
- Run one `breadcrumb worker --poll 2 --lease 120`.
- Use `BREADCRUMB_EXTERNAL_TOOLS=1` only when adapters are needed.
- Use `BREADCRUMB_STRICT_MODE=1` on untrusted networks.
- Increase `BREADCRUMB_AI_TIMEOUT` for slow CPU-only inference; decrease context
  before increasing model size.
- Keep the database on local disk, not a network filesystem. SQLite WAL and
  locking assume local semantics.
- Leave headroom for the OS and the browser; a full 12-phase scan plus a 4B
  model can exhaust 20 GB RAM on a large target.

---

## 6. Troubleshooting hardware/AI issues

| Symptom | Likely cause | Action |
|---|---|---|
| Model loads but returns empty `content` | Reasoning-only model/output format | Use the default Qwen3-4B-Instruct or a known chat model |
| KV-cache allocation failure at 4096 | Model/quant too large for 4 GB VRAM | Reduce context or use the 3B model |
| AI request times out | CPU inference or large prompt | Raise `BREADCRUMB_AI_TIMEOUT`, reduce input, use a smaller model |
| `lms` not found | LM Studio CLI not on `PATH` | Set `BREADCRUMB_LMS_PATH` or add it to `PATH` |
| Jan models not listed | Model folder differs | Set `BREADCRUMB_JAN_MODELS` |
| Scan slows to a crawl | Port scan/adapters on a large target | Narrow scope/ports; let the worker run alone |
| `database is locked` | Two writers or a long transaction | Run one worker; stop extra app processes; see troubleshooting |

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for non-AI failures.
