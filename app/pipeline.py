"""Generate the exact recon command chain for a program.

The stickiest recon tools are the ones you live inside, not the ones you visit.
This turns a program's scope into a copy-paste pipeline (the ProjectDiscovery
chain) that feeds Breadcrumb back into itself -- closing the loop between
"run tooling" and "record findings".
"""

from . import headers_gen


def _apex(hosts: list[str]) -> str:
    domains = [h for h in hosts if h and not h.replace(".", "").isdigit()]
    if not domains:
        return "example.com"
    parts = domains[0].split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domains[0]


def build_pipeline(program, targets, header_profile=None) -> dict:
    """Return {'seed', 'targets': [...], 'steps': [{title, cmd, note}]}."""
    hosts = [t.name for t in targets if t.kind in ("domain", "ip", "cidr")]
    apex = _apex(hosts)
    pid = program.id
    cli = "python -m app.cli"
    curl = "curl -s -X POST http://127.0.0.1:8787/api/v1/pastes -H 'Content-Type: application/json'"

    hdr_flags = ""
    if header_profile is not None and getattr(header_profile, "headers", None):
        try:
            hdr_flags = " " + headers_gen.to_curl_args(
                header_profile.headers, getattr(header_profile, "proxy", "") or ""
            )
        except Exception:  # noqa: BLE001
            hdr_flags = ""
    ffuf_line = ""
    if header_profile is not None and getattr(header_profile, "headers", None):
        try:
            ffuf_line = "\n".join(
                f"-H '{k}: {v}'" for k, v in (header_profile.headers or {}).items()
            )
        except Exception:  # noqa: BLE001
            ffuf_line = ""

    steps = [
        {
            "title": "1. Enumerate subdomains",
            "cmd": f"subfinder -d {apex} -silent -o subs.txt",
            "note": "Swap in amass/assetfinder; anything that writes one host per line.",
        },
        {
            "title": "2. Probe for live hosts + fingerprints",
            "cmd": f"httpx -l subs.txt -json -o httpx.jsonl{hdr_flags}",
            "note": "Status codes, titles, tech and CNAMEs are parsed (CNAMEs -> takeover candidates).",
        },
        {
            "title": "3. Import the probe results",
            "cmd": f"{cli} ingest httpx.jsonl --program {pid}",
            "note": f"Or stream straight in: cat httpx.jsonl | {curl} "
                    f"-d '{{\"text\": \"...\", \"program_id\": {pid}}}'",
        },
        {
            "title": "4. Scan with nuclei",
            "cmd": f"nuclei -l subs.txt -jsonl -o nuclei.jsonl",
            "note": "Nuclei JSONL becomes severity-tagged findings, de-duplicated on re-import.",
        },
        {
            "title": "5. Import the findings",
            "cmd": f"{cli} ingest nuclei.jsonl --program {pid}",
            "note": "Re-running is safe: existing findings keep their status and notes.",
        },
        {
            "title": "6. Set it and forget it (drop folder)",
            "cmd": f"{cli} watch ~/recon-drop --program {pid}",
            "note": "Anything dropped in the folder is ingested automatically.",
        },
    ]
    if ffuf_line:
        steps.insert(4, {
            "title": "4b. Fuzz content with your header profile",
            "cmd": f"ffuf -u https://{apex}/FUZZ -w wordlist.txt {ffuf_line} -o ffuf.json",
            "note": "Output is a normal URL list Breadcrumb already parses.",
        })
    return {"seed": apex, "targets": hosts, "steps": steps}
