"""
OpenAI GPT AI Provider
"""

from __future__ import annotations
import os
from agent.ai_providers.base_provider import BaseLLMProvider
from models.scan_result import Finding


class OpenAIProvider(BaseLLMProvider):
    name = "openai"

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")

    def _get_client(self):
        from openai import AsyncOpenAI
        return AsyncOpenAI(api_key=self.api_key)

    async def analyze_findings(self, findings: list[Finding], target: str) -> str:
        if not self.api_key:
            return "_OpenAI API key not configured. Add OPENAI_API_KEY to your .env file._"
        if not findings:
            return "_No findings to analyze._"
        try:
            client = self._get_client()
            prompt = self._build_findings_prompt(findings, target)
            response = await client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"_OpenAI analysis failed: {e}_"

    async def triage_finding(self, finding: Finding) -> str:
        if not self.api_key:
            return ""
        try:
            client = self._get_client()
            prompt = self._build_triage_prompt(finding)
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256,
            )
            return (response.choices[0].message.content or "").strip()
        except Exception:
            return ""
