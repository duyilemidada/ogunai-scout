# engine/ogunai/report.py
"""
Report Generation — Markdown with CBN/NDPR Compliance Mapping

Generates the primary deliverable: a structured Markdown report
that developers can act on and CTOs can put in front of regulators.

The compliance section is what makes this commercially valuable in Nigeria.
It maps technical findings to CBN Cybersecurity Framework and NDPR obligations —
so "you're missing HSTS" becomes "you may be non-compliant with CBN AS-3".
"""

import json
import os
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional

from .config import get_config

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "PASS": 4}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "PASS": "✅"}
SEVERITY_DESCRIPTION = {
    "CRITICAL": "Immediate action required (< 24 hours)",
    "HIGH": "Significant risk — fix within 1 week",
    "MEDIUM": "Moderate risk — address in next sprint",
    "LOW": "Informational — fix in next quarter",
    "PASS": "No vulnerability detected"
}


def generate_markdown_report(
    findings: List[Dict[str, Any]],
    target_url: str,
    client_name: str = "Unknown",
    session_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate a complete Markdown audit report.

    Sections:
    1. Header and metadata table
    2. Executive summary (non-technical, 1 paragraph)
    3. Risk score with visual bar
    4. Detailed findings (technical, with evidence)
    5. Compliance impact (CBN/NDPR mapping)
    6. Remediation roadmap (prioritised to-do list)
    7. Appendix (methodology, disclaimer)
    """
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "LOW"), 99))

    # Count by severity
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    sections = [
        _header(client_name, target_url, now, counts, session_metadata),
        _executive_summary(counts),
        _risk_score(counts),
        _findings_detail(sorted_findings),
        _compliance_section(sorted_findings),
        _remediation_roadmap(sorted_findings),
        _appendix()
    ]
    return "\n\n".join(s for s in sections if s)


def _header(client_name, target_url, timestamp, counts, metadata):
    lines = [
        "# 🛡️ OgunAI Passive Security Audit Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Client** | {client_name} |",
        f"| **Target** | {target_url} |",
        f"| **Generated** | {timestamp} |",
        f"| **Total Findings** | {sum(v for k, v in counts.items() if k != 'PASS')} "
        f"({counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH, "
        f"{counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW) |",
    ]
    if metadata:
        duration = metadata.get("duration_seconds", 0)
        lines.append(f"| **Audit Duration** | {duration:.0f}s ({duration/60:.1f} min) |")

    lines.extend(["", "---"])
    return "\n".join(lines)


def _executive_summary(counts):
    lines = ["## Executive Summary", ""]

    critical_high = counts["CRITICAL"] + counts["HIGH"]

    if counts["CRITICAL"] > 0:
        lines.append(
            f"**{SEVERITY_EMOJI['CRITICAL']} CRITICAL RISK DETECTED.** "
            f"This audit found {counts['CRITICAL']} critical issue(s) requiring immediate attention. "
            f"These represent real attack paths that an adversary could exploit today."
        )
    elif counts["HIGH"] > 0:
        lines.append(
            f"**{SEVERITY_EMOJI['HIGH']} HIGH RISK DETECTED.** "
            f"This audit found {counts['HIGH']} high-severity issue(s) "
            f"that pose significant risk and should be fixed within one week."
        )
    elif counts["MEDIUM"] > 0:
        lines.append(
            f"**{SEVERITY_EMOJI['MEDIUM']} MEDIUM RISK.** "
            f"{counts['MEDIUM']} medium-severity configuration gap(s) found. "
            f"These are not immediately exploitable but reduce your defence depth."
        )
    elif sum(counts.values()) == 0:
        lines.append(
            "**✅ NO SIGNIFICANT ISSUES FOUND.** "
            "This audit did not identify security gaps in the checked areas. "
            "Continue running regular audits as your system evolves."
        )
    else:
        lines.append(
            f"**{SEVERITY_EMOJI['LOW']} LOW RISK.** "
            f"{counts['LOW']} low-severity informational issue(s) found."
        )

    return "\n".join(lines)


def _risk_score(counts):
    # Score: CRITICAL×25, HIGH×10, MEDIUM×3, LOW×1, capped at 100
    score = min(100, counts["CRITICAL"] * 25 + counts["HIGH"] * 10 +
                counts["MEDIUM"] * 3 + counts["LOW"] * 1)

    if score >= 75:
        level, emoji = "CRITICAL", "🔴"
    elif score >= 50:
        level, emoji = "HIGH", "🟠"
    elif score >= 25:
        level, emoji = "MEDIUM", "🟡"
    elif score > 0:
        level, emoji = "LOW", "🟢"
    else:
        level, emoji = "PASS", "✅"

    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)

    lines = [
        "## Risk Score",
        "",
        f"**Overall Risk: {emoji} {score}/100 ({level})**",
        "",
        f"`{bar}`",
        "",
        "| Severity | Count | Points Each | Subtotal |",
        "|----------|-------|-------------|---------|",
        f"| CRITICAL | {counts['CRITICAL']} | 25 | {counts['CRITICAL'] * 25} |",
        f"| HIGH | {counts['HIGH']} | 10 | {counts['HIGH'] * 10} |",
        f"| MEDIUM | {counts['MEDIUM']} | 3 | {counts['MEDIUM'] * 3} |",
        f"| LOW | {counts['LOW']} | 1 | {counts['LOW'] * 1} |",
        "",
        "---"
    ]
    return "\n".join(lines)


def _findings_detail(findings):
    if not findings:
        return "## Detailed Findings\n\nNo findings recorded in this session."

    lines = ["## Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "LOW")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")

        lines.extend([
            f"### {i}. {emoji} [{sev}] {f.get('title', 'Untitled')}",
            "",
            f"**Severity:** {sev} — {SEVERITY_DESCRIPTION.get(sev, '')}",
            f"**Attack Family:** `{f.get('attack_family', 'Unknown')}`",
            f"**Endpoint/Target:** `{f.get('endpoint', 'N/A')}`",
            "",
            "**What was found:**",
            f.get("description", ""),
            "",
            "**Evidence:**",
            "```json",
            json.dumps(f.get("evidence", {}), indent=2),
            "```",
            "",
            f"**How to fix it:** {f.get('recommendation', '')}",
            "",
            "---",
            ""
        ])
    return "\n".join(lines)


def _compliance_section(findings):
    """
    Map findings to CBN Cybersecurity Framework and NDPR requirements.
    This is what makes the report useful beyond the engineering team —
    it gives the CTO language to use with regulators and investors.
    """
    all_refs: Dict[str, List[str]] = {}
    for finding in findings:
        # compliance_references are auto-populated by write_finding() in tools_passive.py
        refs = finding.get("compliance_references", [])
        for ref in refs:
            if ref not in all_refs:
                all_refs[ref] = []
            all_refs[ref].append(finding.get("title", "Untitled"))

    if not all_refs:
        return ""

    lines = [
        "## Compliance Impact",
        "",
        "The following regulatory requirements are affected by findings in this report.",
        "Nigerian fintechs operating under CBN licensing and NDPR obligations should",
        "address these findings as part of their compliance program.",
        "",
        "| Requirement | Affected Findings |",
        "|-------------|-------------------|"
    ]
    for ref, affected in sorted(all_refs.items()):
        findings_list = ", ".join(affected[:3])
        if len(affected) > 3:
            findings_list += f" (+{len(affected) - 3} more)"
        lines.append(f"| {ref} | {findings_list} |")

    lines.extend([
        "",
        "> **Note:** This mapping is indicative guidance, not formal legal advice.",
        "> For formal compliance assessment, engage a qualified information security auditor.",
        "",
        "---"
    ])
    return "\n".join(lines)


def _remediation_roadmap(findings):
    if not findings:
        return ""

    lines = ["## Remediation Roadmap", "",
             "Fix in this order to maximise risk reduction per hour of engineering time:", ""]

    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        sev = f.get("severity", "LOW")
        by_severity.get(sev, by_severity["LOW"]).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = by_severity[sev]
        if not items:
            continue
        emoji = SEVERITY_EMOJI[sev]
        lines.extend([f"### {emoji} {sev} Priority ({len(items)} items)", ""])
        for i, f in enumerate(items, 1):
            lines.append(f"{i}. **{f.get('title', 'Untitled')}**")
            lines.append(f"   - Location: `{f.get('endpoint', 'N/A')}`")
            rec = f.get('recommendation', 'Fix the issue.')
            lines.append(f"   - Fix: {rec[:120]}...")
            lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _appendix():
    lines = [
        "## Appendix",
        "",
        "### Methodology",
        "",
        "This report was produced by OgunAI — an automated passive security audit engine.",
        "All checks are purely observational: no attack payloads, no credential stuffing,",
        "no injection attempts. Every finding is based on what the server voluntarily",
        "broadcasts in response to normal GET requests.",
        "",
        "### Checks Performed",
        "",
        "- HTTP Security Headers (CSP, HSTS, X-Frame-Options, etc.)",
        "- Sensitive Path Exposure (.env, .git, backup files, admin panels)",
        "- SSL/TLS Certificate and Configuration",
        "- DNS and Email Security (SPF, DMARC, MX)",
        "- CORS Policy",
        "- Rate Limiting Detection",
        "- Information Disclosure via Error Responses",
        "- Dependency Vulnerability Scanning (OSV.dev)",
        "",
        "### Disclaimer",
        "",
        "Findings are based on passive observation at the time of the audit.",
        "Absence of a finding does not guarantee absence of a vulnerability.",
        "Manual review by a qualified security professional is recommended for",
        "CRITICAL and HIGH findings before remediation planning.",
        "",
        "---",
        "",
        f"*Generated by OgunAI — Built by Dada Duyilemi Israel*"
    ]
    return "\n".join(lines)


def save_report(report_text: str, client_name: Optional[str] = None,
                reports_dir: Optional[str] = None) -> str:
    """Save report to disk, return the file path."""
    if reports_dir is None:
        reports_dir = get_config("reports_dir", "./reports")

    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    safe_name = (client_name or "unknown").lower().replace(" ", "_").replace("/", "_")
    filename = f"ogunai_audit_{safe_name}_{timestamp}.md"
    filepath = os.path.join(reports_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[REPORT] Saved: {filepath}")
    return filepath

