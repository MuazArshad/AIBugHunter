"""
Abstract base class for all vulnerability scanners.
"""

from __future__ import annotations
import uuid
from abc import ABC, abstractmethod
from typing import Callable, Awaitable

from models.scan_result import Finding, Severity


class BaseScannerModule(ABC):
    """All scanners extend this class."""

    id: str = "base"
    name: str = "Base Scanner"

    def __init__(self, emit: Callable[[dict], Awaitable[None]] | None = None):
        self.emit = emit or (lambda _: None)  # type: ignore

    @abstractmethod
    async def scan(self, url: str) -> list[Finding]:
        """Run scan against a single URL. Returns list of findings."""
        ...

    def make_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        url: str,
        evidence: str | None = None,
        remediation: str | None = None,
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            scanner=self.id,
            severity=severity,
            title=title,
            description=description,
            url=url,
            evidence=evidence,
            remediation=remediation,
        )

    async def notify(self, url: str, finding: Finding):
        """Emit a real-time finding event."""
        await self.emit({
            "type": "finding",
            "scanner": self.id,
            "severity": finding.severity.value,
            "title": finding.title,
            "url": url,
            "finding_id": finding.id,
        })
