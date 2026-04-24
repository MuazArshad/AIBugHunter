"""Pydantic models for incoming scan requests."""

from pydantic import BaseModel, field_validator
from typing import Optional


class ScanRequest(BaseModel):
    target: str                        # e.g. "example.com" or "*.example.com"
    provider: str = "gemini"           # AI provider id
    recon_mode: str = "passive"        # passive | active | both
    scanners: list[str] = [            # Which scanners to enable
        "headers",
        "cors",
        "open_redirect",
        "xss",
        "info_disclosure",
        "subdomain_takeover",
        "sqli",
    ]
    scope_domains: list[str] = []      # Extra in-scope domains/wildcards
    authorized: bool = False           # User must confirm authorization

    @field_validator("target")
    @classmethod
    def strip_target(cls, v: str) -> str:
        return v.strip().lstrip("https://").lstrip("http://").rstrip("/")

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = {"gemini", "claude", "grok", "openai"}
        if v not in allowed:
            raise ValueError(f"Provider must be one of {allowed}")
        return v
