"""
Google Gemini AI Provider
"""

from __future__ import annotations
import os
from agent.ai_providers.base_provider import BaseLLMProvider
from models.scan_result import Finding


class GeminiProvider(BaseLLMProvider):
    name = "gemini"

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")

    def _get_client(self):
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        return genai.GenerativeModel("gemini-1.5-flash")

    async def analyze_findings(self, findings: list[Finding], target: str) -> str:
        if not self.api_key:
            return "_Gemini API key not configured. Add GEMINI_API_KEY to your .env file._"
        if not findings:
            return "_No findings to analyze._"
        try:
            import asyncio
            model = self._get_client()
            prompt = self._build_findings_prompt(findings, target)
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: model.generate_content(prompt)
            )
            return response.text
        except Exception as e:
            return f"_Gemini analysis failed: {e}_"

    async def triage_finding(self, finding: Finding) -> str:
        if not self.api_key:
            return ""
        try:
            import asyncio
            model = self._get_client()
            prompt = self._build_triage_prompt(finding)
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: model.generate_content(prompt)
            )
            return response.text.strip()
        except Exception:
            return ""
