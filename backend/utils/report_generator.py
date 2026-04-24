"""Generate markdown and JSON reports from scan sessions."""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

from models.scan_result import Finding, ScanSession, Severity


SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def generate_markdown(session: ScanSession) -> str:
    lines: list[str] = []
    lines.append(f"# Bug Hunting Report — {session.target}")
    lines.append(f"\n**Scan ID:** `{session.scan_id}`")
    lines.append(f"**Started:** {session.started_at.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Provider:** {session.provider}")
    lines.append(f"**Status:** {session.status.value}")
    lines.append(f"\n---\n")

    # Summary counts
    by_severity: dict[Severity, list[Finding]] = {s: [] for s in Severity}
    for f in session.findings:
        by_severity[f.severity].append(f)

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        count = len(by_severity[sev])
        emoji = SEVERITY_EMOJI[sev]
        lines.append(f"| {emoji} {sev.value.title()} | {count} |")

    if session.recon:
        lines.append(f"\n## Reconnaissance\n")
        lines.append(f"- **Subdomains discovered:** {len(session.recon.subdomains)}")
        lines.append(f"- **Live subdomains:** {len(session.recon.live_subdomains)}")
        if session.recon.dangling_cnames:
            lines.append(f"- **Dangling CNAMEs:** {len(session.recon.dangling_cnames)}")

    lines.append(f"\n## Findings\n")
    if not session.findings:
        lines.append("_No vulnerabilities found._")
    else:
        for idx, finding in enumerate(
            sorted(session.findings, key=lambda x: list(Severity).index(x.severity)), 1
        ):
            emoji = SEVERITY_EMOJI[finding.severity]
            lines.append(f"### {idx}. {emoji} [{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"\n**URL:** `{finding.url}`")
            lines.append(f"\n**Scanner:** {finding.scanner}")
            lines.append(f"\n{finding.description}")
            if finding.evidence:
                lines.append(f"\n**Evidence:**\n```\n{finding.evidence}\n```")
            if finding.remediation:
                lines.append(f"\n**Remediation:** {finding.remediation}")
            if finding.ai_analysis:
                lines.append(f"\n**AI Analysis:** _{finding.ai_analysis}_")
            lines.append("\n---")

    if session.ai_summary:
        lines.append(f"\n## AI Executive Summary\n\n{session.ai_summary}")

    return "\n".join(lines)


def generate_json(session: ScanSession) -> str:
    return json.dumps(session.model_dump(mode="json"), indent=2, default=str)


def save_report(session: ScanSession, output_dir: str = "reports") -> dict[str, str]:
    """Save both markdown and JSON reports. Returns paths."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = f"{output_dir}/{session.target.replace('.', '_')}_{ts}"

    md_path = f"{base}.md"
    json_path = f"{base}.json"

    Path(md_path).write_text(generate_markdown(session), encoding="utf-8")
    Path(json_path).write_text(generate_json(session), encoding="utf-8")

    return {"markdown": md_path, "json": json_path}
