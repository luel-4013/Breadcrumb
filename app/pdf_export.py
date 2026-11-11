"""PDF report export using reportlab.

The renderer is deliberately data-in: it receives a report snapshot and
findings, never touches the network, and never re-parses a capture. That keeps
a PDF reproducible from the same evidence the JSON/Markdown exports use.

All captured text is escaped before it reaches a ``Paragraph``: findings come
from hostile response bodies, banners and JavaScript, and reportlab treats
paragraph text as XML-like markup.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Iterable, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#6b7280"),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
MAX_FINDINGS = 250
MAX_EVIDENCE = 2000
MAX_TEXT = 4000


def _escape(text: Optional[str], limit: int = MAX_TEXT) -> str:
    if text is None:
        return ""
    value = str(text)[:limit]
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def safe_filename(value: str, fallback: str = "report") -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip())
    value = re.sub(r"-+", "-", value).strip(".-")
    return value[:80] or fallback


def report_filename(
    target: str = "",
    scan_id: int | None = None,
    extension: str = "pdf",
) -> str:
    """Target/scan-based filename, e.g. ``app.example.com_8443-scan-7.pdf``."""
    host = (target or "").strip()
    if "://" in host:
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(host)
            host = parsed.hostname or host
            if parsed.port:
                host = f"{host}_{parsed.port}"
        except ValueError:
            pass
    base = safe_filename(host, "breadcrumb-report")
    if scan_id is not None:
        base = f"{base}-scan-{scan_id}"
    return f"{base}.{extension.lstrip('.')}"


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "Brand",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0e7490"),
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=23,
            leading=27,
            textColor=colors.HexColor("#111827"),
            spaceAfter=2,
            alignment=0,
        )
    )
    styles.add(
        ParagraphStyle(
            "TargetName",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#374151"),
            spaceAfter=1,
        )
    )
    styles.add(
        ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            spaceBefore=18,
            spaceAfter=8,
            textColor=colors.HexColor("#111827"),
            keepWithNext=1,
        )
    )
    styles.add(
        ParagraphStyle(
            "FindingTitle",
            parent=styles["Heading3"],
            fontSize=10.5,
            leading=13,
            spaceBefore=0,
            spaceAfter=1,
            textColor=colors.HexColor("#111827"),
        )
    )
    styles.add(
        ParagraphStyle(
            "Meta",
            parent=styles["Normal"],
            textColor=colors.HexColor("#6b7280"),
            fontSize=8.5,
            leading=11,
        )
    )
    styles.add(
        ParagraphStyle(
            "Label",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#4b5563"),
            spaceBefore=6,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            "CodeBlock",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1f2937"),
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontSize=8,
            leading=9.5,
            textColor=colors.HexColor("#374151"),
        )
    )
    styles.add(
        ParagraphStyle(
            "TableHead",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=9.5,
            textColor=colors.white,
        )
    )
    styles.add(
        ParagraphStyle(
            "Confidential",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#991b1b"),
        )
    )
    styles.add(
        ParagraphStyle(
            "Disclosure",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#4b5563"),
        )
    )
    return styles


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.setLineWidth(0.5)
    canvas.line(0.75 * inch, 0.62 * inch, letter[0] - 0.75 * inch, 0.62 * inch)

    x = 0.75 * inch
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(colors.HexColor("#b91c1c"))
    canvas.drawString(x, 0.46 * inch, "CONFIDENTIAL")
    x += canvas.stringWidth("CONFIDENTIAL", "Helvetica-Bold", 7.5) + 9

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#9ca3af"))
    label = getattr(
        doc,
        "breadcrumb_footer",
        "Generated by Breadcrumb -- authorized security assessments only",
    )
    page_label = f"Page {doc.page}"
    max_width = (
        letter[0]
        - 1.5 * inch
        - (x - 0.75 * inch)
        - canvas.stringWidth(page_label, "Helvetica", 7.5)
        - 12
    )
    while label and canvas.stringWidth(label, "Helvetica", 7.5) > max_width:
        label = label[:-1]
    canvas.drawString(x, 0.46 * inch, label)
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.46 * inch, page_label)
    canvas.restoreState()


def _code_block(text: str, styles, limit: int = MAX_EVIDENCE) -> Table:
    block = Table(
        [[Paragraph(_escape(text, limit), styles["CodeBlock"])]],
        colWidths=[6.95 * inch],
    )
    block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor("#9ca3af")),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return block


def _severity_badge_style(styles, severity: str) -> ParagraphStyle:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    return ParagraphStyle(
        f"severity_{severity}",
        parent=styles["Normal"],
        textColor=colors.white,
        backColor=color,
        alignment=TA_CENTER,
        fontSize=8,
        leading=14,
    )


def _as_utc(value: Any) -> str:
    if not value:
        return "-"
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.strftime("%Y-%m-%d %H:%M UTC")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return _escape(str(value), 80)


def _summary_rows(summary: dict) -> list[tuple[str, str]]:
    rows = [
        ("Findings", summary.get("total_findings", summary.get("finding_count", 0))),
        ("Critical", (summary.get("severity_counts") or {}).get("critical", 0)),
        ("High", (summary.get("severity_counts") or {}).get("high", 0)),
        ("Medium", (summary.get("severity_counts") or {}).get("medium", 0)),
        ("Low", (summary.get("severity_counts") or {}).get("low", 0)),
        ("Info", (summary.get("severity_counts") or {}).get("info", 0)),
        ("Verified CVEs", summary.get("verified_cves", 0)),
        ("Unverified CVEs", summary.get("unverified_cves", 0)),
        ("Endpoints", summary.get("endpoints", 0)),
        ("Subdomains", summary.get("subdomains", 0)),
        ("Open ports", summary.get("open_ports", 0)),
        ("Technologies", summary.get("technologies", 0)),
        ("Missing security headers", summary.get("missing_headers", 0)),
    ]
    return [(str(label), str(value)) for label, value in rows]


def generate_report_pdf(
    *,
    program_name: str,
    target_name: str = "",
    target_url: str = "",
    scan_id: Optional[int] = None,
    status: str = "",
    created_at: Any = None,
    completed_at: Any = None,
    summary: Optional[dict] = None,
    highlights: Optional[dict] = None,
    phases: Optional[Iterable[dict]] = None,
    findings: Optional[Iterable[dict]] = None,
    generated_at: Optional[datetime] = None,
) -> bytes:
    """Render a Breadcrumb report and return raw PDF bytes."""
    summary = summary or {}
    highlights = highlights or {}
    phases = list(phases or [])
    findings = list(findings or [])
    styles = _build_styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title=f"Breadcrumb Report - {target_name or program_name}",
        author="Breadcrumb",
        subject="CONFIDENTIAL - attack surface assessment report",
        keywords="confidential, security assessment, attack surface, Breadcrumb",
    )
    doc.breadcrumb_footer = (
        f"Breadcrumb | {target_url or target_name or program_name}"
        + (f" | Scan #{scan_id}" if scan_id is not None else "")
    )
    story = []

    story.append(Paragraph("BREADCRUMB", styles["Brand"]))
    story.append(Paragraph("Attack Surface Report", styles["ReportTitle"]))
    story.append(Paragraph(_escape(program_name, 200), styles["TargetName"]))
    if target_name or target_url:
        story.append(
            Paragraph(
                _escape(target_name or target_url, 300),
                styles["TargetName"],
            )
        )
    if target_url and target_url != target_name:
        story.append(Paragraph(_escape(target_url, 300), styles["Meta"]))
    story.append(Spacer(1, 10))

    meta_rows = [
        ["Report", f"Scan #{scan_id}" if scan_id is not None else "Program report"],
        ["Status", status or "-"],
        ["Started", _as_utc(created_at)],
        ["Completed", _as_utc(completed_at)],
        ["Generated", _as_utc(generated_at or datetime.now(timezone.utc))],
    ]
    meta_table = Table(meta_rows, colWidths=[1.5 * inch, 4.5 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
    story.append(Spacer(1, 10))

    notice = Table(
        [
            [
                Paragraph(
                    "<b>CONFIDENTIAL</b> &nbsp;|&nbsp; This report contains "
                    "security-sensitive information about the assessed target. "
                    "Distribution is limited to authorized recipients.",
                    styles["Confidential"],
                )
            ]
        ],
        colWidths=[6.95 * inch],
    )
    notice.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
                ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#dc2626")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(notice)

    risk_level = str(summary.get("risk_level") or "minimal").upper()
    risk_score = summary.get("risk_score", 0)
    risk_colors = {
        "CRITICAL": colors.HexColor("#dc2626"),
        "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#ca8a04"),
        "LOW": colors.HexColor("#2563eb"),
        "MINIMAL": colors.HexColor("#6b7280"),
    }
    risk_color = risk_colors.get(risk_level, colors.HexColor("#6b7280"))
    score_style = ParagraphStyle(
        "RiskScore",
        parent=styles["Title"],
        fontSize=30,
        leading=32,
        textColor=risk_color,
        alignment=0,
        spaceAfter=0,
    )
    level_style = ParagraphStyle(
        "RiskLevel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=risk_color,
    )
    risk_table = Table(
        [
            [
                Paragraph(_escape(str(risk_score), 10), score_style),
                Paragraph(
                    f"{_escape(risk_level, 20)}<br/>"
                    "<font size='8' color='#6b7280'>Derived from active findings; "
                    "false positives and unverified CVE candidates are excluded.</font>",
                    level_style,
                ),
            ]
        ],
        colWidths=[1.0 * inch, 6.0 * inch],
    )
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
                ("LINEBEFORE", (0, 0), (0, -1), 4, risk_color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (0, 0), 12),
                ("LEFTPADDING", (1, 0), (1, 0), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(Spacer(1, 10))
    story.append(risk_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Summary", styles["SectionHeading"]))
    sum_rows = [[label, value] for label, value in _summary_rows(summary)]
    sum_table = Table(sum_rows, colWidths=[3 * inch, 3 * inch])
    sum_table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ]
        )
    )
    story.append(sum_table)

    has_highlights = any(
        highlights.get(key)
        for key in (
            "technologies",
            "cdn_waf",
            "security_headers_present",
            "security_headers_missing",
            "resolved_ips",
            "hostnames",
            "subdomains",
            "open_ports",
            "discovered_endpoints",
        )
    )
    if has_highlights:
        story.append(Paragraph("Highlights", styles["SectionHeading"]))
        if highlights.get("technologies"):
            story.append(
                Paragraph(
                    f"<b>Technologies:</b> "
                    f"{_escape(', '.join(highlights['technologies']), 800)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 4))
        if highlights.get("cdn_waf"):
            story.append(
                Paragraph(
                    f"<b>CDN/WAF detected:</b> "
                    f"{_escape(', '.join(highlights['cdn_waf']), 400)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 4))
        if highlights.get("security_headers_present") or highlights.get(
            "security_headers_missing"
        ):
            present = ", ".join(highlights.get("security_headers_present") or []) or "none"
            missing = ", ".join(highlights.get("security_headers_missing") or []) or "none"
            story.append(
                Paragraph(
                    f"<b>Security headers present:</b> {_escape(present, 600)}",
                    styles["Normal"],
                )
            )
            story.append(
                Paragraph(
                    f"<b>Security headers missing:</b> {_escape(missing, 600)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 4))
        if highlights.get("resolved_ips") or highlights.get("hostnames"):
            if highlights.get("resolved_ips"):
                story.append(
                    Paragraph(
                        f"<b>Resolved IPs:</b> "
                        f"{_escape(', '.join(highlights['resolved_ips']), 400)}",
                        styles["Normal"],
                    )
                )
            if highlights.get("hostnames"):
                story.append(
                    Paragraph(
                        f"<b>Hostnames:</b> "
                        f"{_escape(', '.join(highlights['hostnames']), 400)}",
                        styles["Normal"],
                    )
                )
            story.append(Spacer(1, 4))
        if highlights.get("subdomains"):
            subs = highlights["subdomains"]
            line = ", ".join(subs[:50]) + (
                f" (+{len(subs) - 50} more)" if len(subs) > 50 else ""
            )
            story.append(
                Paragraph(
                    f"<b>Subdomains ({len(subs)}):</b> {_escape(line, 1500)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 4))
        if highlights.get("open_ports"):
            head, cell = styles["TableHead"], styles["TableCell"]
            rows = [[Paragraph("Port", head), Paragraph("Service", head), Paragraph("Detail", head)]]
            for port, info in (highlights["open_ports"] or {}).items():
                info = info or {}
                detail = (
                    info.get("version")
                    or info.get("tls_subject")
                    or info.get("banner")
                    or ""
                )
                rows.append(
                    [
                        Paragraph(_escape(str(port), 20), cell),
                        Paragraph(_escape(info.get("service") or "", 40), cell),
                        Paragraph(_escape(detail, 160), cell),
                    ]
                )
            port_table = Table(rows, colWidths=[0.7 * inch, 1.4 * inch, 4.9 * inch])
            port_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ]
                )
            )
            story.append(port_table)
            story.append(Spacer(1, 4))
        if highlights.get("discovered_endpoints"):
            endpoints = highlights["discovered_endpoints"]
            story.append(
                Paragraph(
                    f"<b>Endpoints observed ({len(endpoints)}):</b> "
                    f"{_escape(', '.join(endpoints[:60]), 1200)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 4))

    if phases:
        story.append(Paragraph("Scan Phases", styles["SectionHeading"]))
        head, cell = styles["TableHead"], styles["TableCell"]
        rows = [
            [
                Paragraph("#", head),
                Paragraph("Phase", head),
                Paragraph("Status", head),
                Paragraph("Findings", head),
            ]
        ]
        for phase in sorted(phases, key=lambda item: item.get("phase_order") or 0):
            rows.append(
                [
                    Paragraph(_escape(str(phase.get("phase_order", "")), 5), cell),
                    Paragraph(
                        _escape(
                            (phase.get("phase_name") or "").replace("_", " ").title(),
                            80,
                        ),
                        cell,
                    ),
                    Paragraph(_escape(phase.get("status") or "", 20), cell),
                    Paragraph(_escape(str(phase.get("findings_count", 0)), 10), cell),
                ]
            )
        phase_table = Table(
            rows, colWidths=[0.5 * inch, 4.0 * inch, 1.5 * inch, 1.0 * inch]
        )
        phase_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ]
            )
        )
        story.append(phase_table)

    story.append(PageBreak())
    story.append(Paragraph(f"Findings ({len(findings)})", styles["SectionHeading"]))
    if not findings:
        story.append(Paragraph("No active findings were recorded.", styles["Normal"]))
    else:
        ordered = sorted(
            findings,
            key=lambda finding: (
                SEVERITY_ORDER.index(str(finding.get("severity") or "info").lower())
                if str(finding.get("severity") or "info").lower() in SEVERITY_ORDER
                else len(SEVERITY_ORDER),
                str(finding.get("title") or "").lower(),
            ),
        )
        if len(ordered) > MAX_FINDINGS:
            story.append(
                Paragraph(
                    f"Showing the first {MAX_FINDINGS} of {len(ordered)} findings; "
                    "the JSON/Markdown exports contain the full list.",
                    styles["Meta"],
                )
            )
            story.append(Spacer(1, 6))
            ordered = ordered[:MAX_FINDINGS]

        for finding in ordered:
            severity = str(finding.get("severity") or "info").lower()
            if severity not in SEVERITY_ORDER:
                severity = "info"
            badge = Paragraph(
                severity.upper()[:12], _severity_badge_style(styles, severity)
            )
            title = Paragraph(
                _escape(finding.get("title") or "Finding", 300), styles["FindingTitle"]
            )
            header_table = Table(
                [[badge, title]], colWidths=[0.85 * inch, 6.15 * inch]
            )
            header_table.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (0, 0), 0),
                        ("LEFTPADDING", (1, 0), (1, 0), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )
            head = [header_table]
            meta_bits = []
            if finding.get("verified"):
                meta_bits.append("verified")
            triage = str(finding.get("triage_status") or "open").replace("_", " ")
            if triage != "open":
                meta_bits.append(f"triage: {triage}")
            if finding.get("cve_id"):
                meta_bits.append(str(finding["cve_id"]))
            if meta_bits:
                head.append(
                    Paragraph(_escape(" · ".join(meta_bits), 200), styles["Meta"])
                )
            location = finding.get("location")
            if location:
                head.append(Paragraph(_escape(location, 300), styles["Meta"]))
            if finding.get("description"):
                head.append(
                    Paragraph(_escape(finding["description"], 2000), styles["Normal"])
                )
            story.append(KeepTogether(head))
            story.append(Spacer(1, 4))
            if finding.get("evidence"):
                story.append(Paragraph("Evidence", styles["Label"]))
                story.append(_code_block(str(finding["evidence"]), styles))
            if finding.get("remediation"):
                story.append(Paragraph("Remediation", styles["Label"]))
                story.append(
                    Paragraph(_escape(finding["remediation"]), styles["Normal"])
                )
            story.append(Spacer(1, 8))
            story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
            story.append(Spacer(1, 6))

    disclosure = Table(
        [
            [
                Paragraph(
                    "<b>CONFIDENTIAL.</b> This report contains security-sensitive "
                    "information about the assessed target. It was generated by "
                    "Breadcrumb for an authorized security assessment and is intended "
                    "only for the target owner and explicitly authorized recipients. "
                    "Do not publish, redistribute, or disclose this document without "
                    "written permission.<br/><br/>"
                    "Findings are based on automated reconnaissance and may include "
                    "false positives. Candidate and unverified CVE rows must be "
                    "manually validated before being treated as confirmed "
                    "vulnerabilities. Scan only systems you own or have explicit "
                    "permission to assess.<br/><br/>"
                    f"<font size='7.5' color='#6b7280'>Report reference: "
                    f"{('Scan #' + str(scan_id)) if scan_id is not None else 'Program report'}"
                    f" · {_escape(target_url or target_name or program_name, 300)}</font>",
                    styles["Disclosure"],
                )
            ]
        ],
        colWidths=[6.95 * inch],
    )
    disclosure.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#9ca3af")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(Spacer(1, 16))
    story.append(disclosure)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def generate_document_pdf(context: dict) -> bytes:
    """Render a report-template context to PDF.

    This is intentionally separate from the legacy job-report renderer: it
    consumes the same redacted, format-independent context as the Markdown,
    HTML and JSON exporters, so a template's PDF cannot contain a value that a
    reviewer would not see in the other formats.

    Every value is escaped before it reaches reportlab. Evidence is rendered as
    a code table, not as paragraph markup.
    """
    context = context or {}
    styles = _build_styles()
    program = context.get("program") or {}
    template = context.get("template") or {}
    summary = context.get("summary") or {}
    redaction = context.get("redaction") or {}
    title = str(context.get("title") or "Breadcrumb report")
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.72 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.72 * inch,
        rightMargin=0.72 * inch,
        title=f"Breadcrumb Report - {title}",
        author="Breadcrumb",
        subject=f"{context.get('confidentiality_label') or 'CONFIDENTIAL'} report",
        keywords="security assessment, report, Breadcrumb",
    )
    doc.breadcrumb_footer = (
        f"Breadcrumb | {program.get('name') or 'report'} | "
        f"{context.get('report_reference') or ''}"
    )
    story: list[Any] = []
    story.append(Paragraph("BREADCRUMB", styles["Brand"]))
    story.append(Paragraph(_escape(title, 300), styles["ReportTitle"]))
    if program.get("name"):
        story.append(Paragraph(_escape(program["name"], 300), styles["TargetName"]))
    if program.get("platform"):
        story.append(Paragraph(_escape(program["platform"], 200), styles["Meta"]))
    story.append(Spacer(1, 8))

    meta_rows = [
        ["Classification", context.get("confidentiality_label") or "CONFIDENTIAL"],
        ["Template", template.get("name") or "report"],
        ["Report date", context.get("report_date") or "-"],
        ["Generated", context.get("generated_at") or "-"],
        ["Reference", context.get("report_reference") or "-"],
    ]
    for label in ("client", "author", "engagement"):
        if context.get(label):
            meta_rows.append([label.title(), context[label]])
    meta_table = Table(
        [[Paragraph(_escape(label, 80), styles["TableCell"]),
          Paragraph(_escape(str(value), 300), styles["TableCell"])]
         for label, value in meta_rows],
        colWidths=[1.4 * inch, 5.5 * inch],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 8))
    notice = Table(
        [[Paragraph(
            "<b>CONFIDENTIAL</b> &nbsp;|&nbsp; This report contains "
            "security-sensitive information about the assessed target. "
            "Distribute only to authorized recipients.",
            styles["Confidential"],
        )]],
        colWidths=[6.95 * inch],
    )
    notice.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
                ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#dc2626")),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(notice)
    story.append(Spacer(1, 7))
    if redaction.get("enabled"):
        story.append(
            Paragraph(
                _escape(
                    f"Redaction: {redaction.get('profile', 'default')} profile; "
                    f"{redaction.get('custom_rules', 0)} custom rule(s). "
                    "Authentication headers, cookies, tokens and secret values "
                    "are masked.",
                    600,
                ),
                styles["Meta"],
            )
        )
    elif (context.get("variables") or {}).get("reveal"):
        story.append(
            Paragraph(
                "<b>WARNING:</b> secret masking is disabled for this report.",
                styles["Confidential"],
            )
        )

    if context.get("executive_summary"):
        story.append(Paragraph("Executive summary", styles["SectionHeading"]))
        story.append(Paragraph(_escape(context["executive_summary"]), styles["Normal"]))

    story.append(Paragraph("Summary", styles["SectionHeading"]))
    risk_level = str(summary.get("risk_level") or "minimal").upper()
    story.append(
        Paragraph(
            f"<b>Risk:</b> {_escape(risk_level, 20)} "
            f"({_escape(str(summary.get('risk_score', 0)), 10)}/100)",
            styles["Normal"],
        )
    )
    counts = summary.get("severity_counts") or {}
    story.append(
        Paragraph(
            "<b>Findings:</b> "
            + _escape(
                ", ".join(f"{key} x {value}" for key, value in counts.items()) or "none",
                400,
            ),
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            "<b>Surface:</b> "
            + _escape(
                f"{summary.get('entity_count', 0)} entities, "
                f"{summary.get('target_count', 0)} targets, "
                f"{summary.get('capture_count', 0)} captures",
                300,
            ),
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 5))

    if context.get("business_context"):
        story.append(Paragraph("Business context", styles["SectionHeading"]))
        story.append(Paragraph(_escape(context["business_context"]), styles["Normal"]))

    highlights = context.get("highlights") or []
    if highlights:
        story.append(Paragraph("Top findings", styles["SectionHeading"]))
        for item in highlights:
            story.append(
                Paragraph(
                    f"<b>{_escape(str(item.get('severity') or 'info').upper(), 20)}</b> "
                    f"{_escape(item.get('title') or '', 300)} — "
                    f"{_escape(item.get('explanation') or '', 600)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 3))

    scope_in = (context.get("program") or {}).get("scope_in") or ""
    scope_out = (context.get("program") or {}).get("scope_out") or ""
    if scope_in or scope_out:
        story.append(Paragraph("Scope", styles["SectionHeading"]))
        if scope_in:
            story.append(Paragraph("In scope", styles["Label"]))
            story.append(_code_block(scope_in, styles, limit=3000))
        if scope_out:
            story.append(Paragraph("Out of scope", styles["Label"]))
            story.append(_code_block(scope_out, styles, limit=3000))

    targets = context.get("targets") or []
    if targets:
        story.append(Paragraph("Targets", styles["SectionHeading"]))
        for target in targets[:100]:
            story.append(
                Paragraph(
                    f"- <font name='Courier'>{_escape(target.get('name') or '', 200)}</font> "
                    f"({_escape(target.get('kind') or '', 40)})",
                    styles["Normal"],
                )
            )

    groups = context.get("entity_groups") or []
    if groups:
        story.append(Paragraph("Attack-surface inventory", styles["SectionHeading"]))
        for group in groups[:15]:
            story.append(
                Paragraph(
                    f"<b>{_escape(group.get('label') or '', 100)}</b> "
                    f"({_escape(str(group.get('count', 0)), 20)})",
                    styles["Label"],
                )
            )
            rows = [["Value", "Scope", "HTTP", "Tags"]]
            for item in (group.get("values") or [])[:40]:
                rows.append(
                    [
                        _escape(item.get("value") or "", 500),
                        _escape(item.get("scope_status") or "", 20),
                        _escape(str(item.get("status_code") or ""), 10),
                        _escape(", ".join(item.get("tags") or []), 120),
                    ]
                )
            table = Table(rows, colWidths=[3.9 * inch, 0.9 * inch, 0.6 * inch, 1.5 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                    ]
                )
            )
            story.append(table)
            if group.get("truncated"):
                story.append(
                    Paragraph(
                        _escape(f"…and {group['truncated']} more.", 100),
                        styles["Meta"],
                    )
                )

    changes = context.get("changes")
    if changes and changes.get("available"):
        story.append(Paragraph("Change summary", styles["SectionHeading"]))
        left = changes.get("left") or {}
        right = changes.get("right") or {}
        story.append(
            Paragraph(
                _escape(
                    f"Compared {left.get('label') or left.get('selector')} -> "
                    f"{right.get('label') or right.get('selector')}.",
                    500,
                ),
                styles["Normal"],
            )
        )
        summary = changes.get("summary") or {}
        story.append(
            Paragraph(
                _escape(
                    f"New findings {summary.get('new_findings', 0)}, "
                    f"removed {summary.get('removed_findings', 0)}, "
                    f"ports opened {summary.get('ports_opened', 0)}, "
                    f"endpoints added {summary.get('endpoints_added', 0)}, "
                    f"risk {summary.get('risk_before', 0)} -> {summary.get('risk_after', 0)}.",
                    600,
                ),
                styles["Normal"],
            )
        )
        for item in (changes.get("findings_new") or [])[:50]:
            story.append(
                Paragraph(
                    f"- [{_escape(str(item.get('severity') or 'info').upper(), 20)}] "
                    f"{_escape(item.get('title') or '', 300)}",
                    styles["Normal"],
                )
            )
        for item in (changes.get("ports_opened") or [])[:100]:
            story.append(
                Paragraph(
                    _escape(f"- port {item.get('port')} {item.get('service') or ''}", 200),
                    styles["Normal"],
                )
            )
    elif changes:
        story.append(Paragraph("Change summary", styles["SectionHeading"]))
        story.append(Paragraph(_escape(changes.get("reason") or "No change data."), styles["Normal"]))

    findings = context.get("findings") or []
    story.append(Paragraph(f"Findings ({context.get('findings_total', len(findings))})", styles["SectionHeading"]))
    if not findings:
        story.append(Paragraph("No active findings at the selected severity.", styles["Normal"]))
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity not in SEVERITY_ORDER:
            severity = "info"
        badge = Paragraph(severity.upper()[:12], _severity_badge_style(styles, severity))
        finding_title = Paragraph(
            _escape(f"{finding.get('ref') or ''} — {finding.get('title') or 'Finding'}", 400),
            styles["FindingTitle"],
        )
        header_table = Table([[badge, finding_title]], colWidths=[0.85 * inch, 6.15 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (0, 0), 0),
                    ("LEFTPADDING", (1, 0), (1, 0), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        head = [header_table]
        meta_bits = []
        if finding.get("verified"):
            meta_bits.append("verified")
        if finding.get("cvss"):
            meta_bits.append(f"CVSS {finding['cvss']}")
        if finding.get("cve"):
            meta_bits.append(str(finding["cve"]))
        if finding.get("location"):
            meta_bits.append(str(finding["location"]))
        if meta_bits:
            head.append(Paragraph(_escape(" · ".join(meta_bits), 400), styles["Meta"]))
        for label, key in (
            ("Description", "description"),
            ("Steps to reproduce", "steps"),
            ("Impact", "impact"),
        ):
            if finding.get(key):
                head.append(Paragraph(label, styles["Label"]))
                head.append(Paragraph(_escape(finding[key]), styles["Normal"]))
        story.append(KeepTogether(head))
        if finding.get("evidence"):
            story.append(Paragraph("Evidence", styles["Label"]))
            story.append(_code_block(str(finding["evidence"]), styles))
        if finding.get("remediation"):
            story.append(Paragraph("Remediation", styles["Label"]))
            story.append(Paragraph(_escape(finding["remediation"]), styles["Normal"]))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
        story.append(Spacer(1, 5))

    if context.get("recommendations"):
        story.append(Paragraph("Recommendations", styles["SectionHeading"]))
        story.append(Paragraph(_escape(context["recommendations"]), styles["Normal"]))
    if context.get("methodology"):
        story.append(Paragraph("Methodology", styles["SectionHeading"]))
        story.append(Paragraph(_escape(context["methodology"]), styles["Normal"]))

    story.append(Spacer(1, 14))
    story.append(
        Paragraph(
            _escape(
                f"{context.get('confidentiality_label') or 'CONFIDENTIAL'} · "
                f"Generated by Breadcrumb on {context.get('generated_at')}. "
                "Findings are based on reconnaissance and may include false positives; "
                "validate before submission.",
                600,
            ),
            styles["Meta"],
        )
    )
    if context.get("footer"):
        story.append(Paragraph(_escape(context["footer"], 500), styles["Meta"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
