"""
xAI Grok & Groq AI Provider
Uses OpenAI-compatible API endpoints for xAI Grok or Groq Cloud.
Auto-detects Groq key prefix (gsk_) vs xAI key.
"""

from __future__ import annotations
import os
from agent.ai_providers.base_provider import BaseLLMProvider
from models.scan_result import Finding


class GrokProvider(BaseLLMProvider):
    name = "grok"

    def __init__(self):
        self.api_key = os.getenv("GROK_API_KEY") or os.getenv("GROQ_API_KEY", "")

    def _get_config(self) -> tuple[str, str]:
        # Auto-detect Groq vs xAI Grok based on key prefix
        if self.api_key.startswith("gsk_"):
            return "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"
        return "https://api.x.ai/v1", "grok-beta"

    def _get_client(self):
        from openai import AsyncOpenAI
        base_url, _ = self._get_config()
        return AsyncOpenAI(api_key=self.api_key, base_url=base_url)

    async def analyze_findings(self, findings: list[Finding], target: str) -> str:
        if not self.api_key:
            return "_Grok/Groq API key not configured. Add GROK_API_KEY or GROQ_API_KEY to your .env file._"
        if not findings:
            return "_No findings to analyze._"
        try:
            client = self._get_client()
            _, model = self._get_config()
            prompt = self._build_findings_prompt(findings, target)
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"_Grok/Groq analysis failed: {e}_"

    async def triage_finding(self, finding: Finding) -> str:
        if not self.api_key:
            return ""
        try:
            client = self._get_client()
            _, model = self._get_config()
            prompt = self._build_triage_prompt(finding)
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256,
            )
            return (response.choices[0].message.content or "").strip()
        except Exception:
            return ""


class GroqProvider(GrokProvider):
    name = "groq"
