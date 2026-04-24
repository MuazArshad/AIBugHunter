"""
xAI Grok AI Provider
Uses the OpenAI-compatible API endpoint.
"""

from __future__ import annotations
import os
from agent.ai_providers.base_provider import BaseLLMProvider
from models.scan_result import Finding


class GrokProvider(BaseLLMProvider):
    name = "grok"
    BASE_URL = "https://api.x.ai/v1"

    def __init__(self):
        self.api_key = os.getenv("GROK_API_KEY", "")

    def _get_client(self):
        from openai import AsyncOpenAI
        return AsyncOpenAI(api_key=self.api_key, base_url=self.BASE_URL)

    async def analyze_findings(self, findings: list[Finding], target: str) -> str:
        if not self.api_key:
            return "_Grok API key not configured. Add GROK_API_KEY to your .env file._"
        if not findings:
            return "_No findings to analyze._"
        try:
            client = self._get_client()
            prompt = self._build_findings_prompt(findings, target)
            response = await client.chat.completions.create(
                model="grok-beta",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"_Grok analysis failed: {e}_"

    async def triage_finding(self, finding: Finding) -> str:
        if not self.api_key:
            return ""
        try:
            client = self._get_client()
            prompt = self._build_triage_prompt(finding)
            response = await client.chat.completions.create(
                model="grok-beta",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256,
            )
            return (response.choices[0].message.content or "").strip()
        except Exception:
            return ""
