"""
Anthropic Claude AI Provider
"""

from __future__ import annotations
import os
from agent.ai_providers.base_provider import BaseLLMProvider
from models.scan_result import Finding


class ClaudeProvider(BaseLLMProvider):
    name = "claude"

    def __init__(self):
        self.api_key = os.getenv("CLAUDE_API_KEY", "")

    async def analyze_findings(self, findings: list[Finding], target: str) -> str:
        if not self.api_key:
            return "_Claude API key not configured. Add CLAUDE_API_KEY to your .env file._"
        if not findings:
            return "_No findings to analyze._"
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            prompt = self._build_findings_prompt(findings, target)
            message = await client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception as e:
            return f"_Claude analysis failed: {e}_"

    async def triage_finding(self, finding: Finding) -> str:
        if not self.api_key:
            return ""
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            prompt = self._build_triage_prompt(finding)
            message = await client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text.strip()
        except Exception:
            return ""
