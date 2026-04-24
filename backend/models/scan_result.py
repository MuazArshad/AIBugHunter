"""Pydantic models for scan results and sessions."""

from __future__ import annotations
from enum import Enum
from typing import Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    STOPPED = "stopped"
    ERROR = "error"


class Finding(BaseModel):
    id: str
    scanner: str                    # Which scanner found it
    severity: Severity
    title: str
    description: str
    url: str
    evidence: Optional[str] = None  # Request/response snippet
    remediation: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ai_analysis: Optional[str] = None  # AI-generated triage comment


class ReconResult(BaseModel):
    subdomains: list[str] = []
    live_subdomains: list[str] = []
    dangling_cnames: list[dict] = []


class ScanSession(BaseModel):
    scan_id: str
    target: str
    provider: str
    status: ScanStatus = ScanStatus.PENDING
    recon: Optional[ReconResult] = None
    findings: list[Finding] = []
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    ai_summary: Optional[str] = None
    error: Optional[str] = None
