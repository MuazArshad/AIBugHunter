"""
Abstract base class for all AI providers.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from models.scan_result import Finding


class BaseLLMProvider(ABC):
    """All AI providers implement this interface."""

    name: str = "base"

    @abstractmethod
    async def analyze_findings(self, findings: list[Finding], target: str) -> str:
        """
        Given a list of findings, produce an AI-generated analysis/summary.
        Returns a markdown-formatted string.
        """
        ...

    @abstractmethod
    async def triage_finding(self, finding: Finding) -> str:
        """
        Provide a brief AI triage comment for a single finding.
        Returns a short string (1-3 sentences).
        """
        ...

    def _build_findings_prompt(self, findings: list[Finding], target: str) -> str:
        findings_text = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title} at {f.url}: {f.description[:200]}"
            for f in findings
        )
        return (
            f"You are a senior security researcher performing a bug bounty audit on {target}.\n\n"
            f"The automated scanner found the following vulnerabilities:\n\n"
            f"{findings_text}\n\n"
            "Please provide:\n"
            "1. An executive summary of the security posture\n"
            "2. The most critical issues to report immediately\n"
            "3. Suggested attack chains or vulnerability combinations\n"
            "4. Business impact assessment\n\n"
            "Format your response in markdown."
        )

    def _build_triage_prompt(self, finding: Finding) -> str:
        return (
            f"As a bug bounty expert, briefly triage this finding in 2-3 sentences:\n\n"
            f"Title: {finding.title}\n"
            f"URL: {finding.url}\n"
            f"Severity: {finding.severity.value}\n"
            f"Description: {finding.description}\n"
            f"Evidence: {finding.evidence or 'N/A'}\n\n"
            "Focus on: exploitability, real-world impact, and whether it's likely to be accepted "
            "as a valid bug bounty finding. Be concise."
        )
