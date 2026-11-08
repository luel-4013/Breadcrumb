Breadcrumb – Local LLM Model Collection

> **Status update (2026-11-03): measured on the actual 4 GB GTX 1650.**
> This file is an early proposal, not the current default. The safe default is
> **Unsloth Qwen3-4B-Instruct-2507 UD-Q5_K_XL at 4096 context**. Measured
> results: Jackrong and Gemma 4 12B returned reasoning-only output (`content`
> empty) and are not usable for Breadcrumb's structured reports as-is; the
> HauhauCS Q6_K failed 4096-context KV allocation. The Settings page now has an
> **Available models** picker with role labels, a 4 GB fit estimate, Test,
> Auto-fit context, and per-route selection. See `docs/LEADLINE_PARITY_MATRIX.md`
> (Q5) for the current decision record.
>
> Optional downloads (static links, nothing automatic):
> - Official **Qwen2.5-3B-Instruct Q4_K_M** (2.10 GB):
>   `https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/blob/main/qwen2.5-3b-instruct-q4_k_m.gguf`
> - Official **Qwen2.5-Coder-3B-Instruct Q4_K_M** (2.10 GB):
>   `https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/blob/main/qwen2.5-coder-3b-instruct-q4_k_m.gguf`
> - **Pentest AI 3B** (1.93 GB, experimental): `https://huggingface.co/r1r21nb/qwen2.5-3b-instruct.Q4_K_M.gguf/blob/main/qwen2.5-3b-instruct.Q4_K_M.gguf`

Your four models, their recommended roles and the tasks each should handle.

1. Your Four Models
1. HauhauCS – Qwen3 4B 2507 Instruct Uncensored Aggressive
Quantization: Q6_K
Size: 3.31 GB
Role: Recon planning and experimental analysis.

Recommended usage:

Recon investigation planning.
Choosing the correct tool.
Generating tool arguments.
Following complex instructions.
Analyzing technical scan output.

Purpose: Experimental recon assistant with fewer refusal behaviors.

2. Jackrong – Qwen3.5 4B Claude 4.6 Opus Reasoning Distilled v2
Quantization: Q4_K_M
Size: 3.38 GB (repository listing)
Role: Deep reasoning and evidence analysis.

Recommended usage:

Analyzing complicated evidence.
Comparing historical recon data.
Connecting related assets.
Identifying unusual changes.
Explaining vulnerability impact.
Writing detailed reports.

Purpose: Complex reasoning and investigation analysis.

3. bartowski – Qwen3.5 4B
Quantization: Q4_K_M
Size: 3.01 GB
Role: General analysis and reporting.

Recommended usage:

Organizing pasted scan output.
Analyzing Nmap and Subfinder results.
Summarizing technical information.
Explaining findings.
Writing vulnerability reports.

Purpose: Everyday recon analysis and report writing.

4. Unsloth – Qwen3 4B Instruct 2507
Quantization: UD-Q5_K_XL
Size: 2.90 GB
Role: Tool calling and routine agent operations.

Recommended usage:

Choosing the correct tool.
Generating tool arguments.
Following multi-step instructions.
Routine recon operations.
Interpreting tool execution results.

Purpose: Tool selection and routine agent operations.

2. Breadcrumb Workflow
mermaid
flowchart TD
    A["Breadcrumb Input<br/>Nmap · Subfinder · URLs · Findings · Raw Data"]

    A --> B["Unsloth – Qwen3<br/>Tool Selection · Arguments · Routine Operations"]

    B --> C["Breadcrumb Validation & Execution<br/>Scope Checks · Authorization · Tool Results"]

    C --> D["Jackrong – Qwen3.5<br/>Deep Reasoning · Evidence Analysis · Historical Comparisons"]

    D --> E["bartowski – Qwen3.5<br/>Reports · Summaries · Organization"]

    D --> F["HauhauCS – Qwen3<br/>Recon Planning · Experimental Analysis"]

    E --> G["Breadcrumb Final Output"]
    F --> G

    G["Breadcrumb Final Output<br/>Organized Evidence · Knowledge Graph · Vulnerability Reports"]


This is a proposed workflow, not a requirement to run four models for every request. Breadcrumb should select the appropriate model for each task.

3. Final Model Assignments
Model	Main Responsibility
Unsloth	Tool calling
Jackrong	Deep reasoning
bartowski	Analysis and reporting
HauhauCS	Recon planning and experimentation
4. My Recommendation

Start by testing Unsloth and bartowski. They cover two important everyday jobs in Breadcrumb:

Executing the correct tools.
Producing useful analysis and reports.

Add Jackrong when deeper reasoning is needed, and keep HauhauCS as your experimental model.

Important: All AI-generated tool calls must pass through Breadcrumb's own authorization, scope validation and argument validation. The LLM should never independently grant itself permission to execute an operation.
