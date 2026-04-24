"""
Open Redirect Scanner
Tests common redirect parameters for unvalidated redirection.
"""

from __future__ import annotations
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
import httpx

from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from utils.http_client import get_client

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next",
    "return", "return_url", "returnTo", "goto", "go", "target",
    "dest", "destination", "link", "checkout_url", "continue",
    "view", "from", "to", "out", "exit", "ref", "callback",
]

PAYLOAD = "https://evil.com"


class OpenRedirectScanner(BaseScannerModule):
    id = "open_redirect"
    name = "Open Redirect Scanner"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        client = await get_client()

        for param in REDIRECT_PARAMS:
            test_url = f"{url}?{param}={PAYLOAD}"
            try:
                # Don't follow redirects — we want to see the Location header
                resp = await client.get(
                    test_url,
                    follow_redirects=False,
                )
                location = resp.headers.get("Location", "")

                if resp.status_code in (301, 302, 303, 307, 308) and PAYLOAD in location:
                    f = self.make_finding(
                        severity=Severity.MEDIUM,
                        title=f"Open Redirect via '{param}' Parameter",
                        description=(
                            f"The application redirects to an attacker-controlled URL when "
                            f"the `{param}` parameter is set. This can be used in phishing "
                            "attacks to redirect users from a trusted domain to a malicious site."
                        ),
                        url=test_url,
                        evidence=(
                            f"GET {test_url}\n"
                            f"HTTP {resp.status_code}\n"
                            f"Location: {location}"
                        ),
                        remediation=(
                            "Validate redirect targets against a whitelist of allowed domains. "
                            "Never redirect to user-supplied URLs without validation."
                        ),
                    )
                    findings.append(f)
                    await self.notify(url, f)

            except Exception:
                continue

        return findings
