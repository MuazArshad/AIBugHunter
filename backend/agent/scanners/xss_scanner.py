"""
Reflected XSS Scanner
Tests URL parameters for basic reflected cross-site scripting.
Uses non-executing probes to detect reflection without actual execution.
"""

from __future__ import annotations
import re
from urllib.parse import urlencode, urlparse, parse_qs

from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from utils.http_client import get_client

# Non-executing reflection probe (safe for bug bounty)
PROBE = "<xss-test-zqr9/"
# XSS payloads for confirmed reflection (only used if probe reflects)
XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'><svg onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

COMMON_PARAMS = [
    "q", "s", "search", "query", "keyword", "term", "name", "id",
    "page", "cat", "category", "tag", "lang", "locale", "callback",
    "jsonp", "ref", "source", "msg", "message", "error", "info",
    "title", "text", "content", "data", "input", "value", "param",
]


def build_test_url(base_url: str, param: str, payload: str) -> str:
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = "&".join(f"{k}={v[0]}" for k, v in qs.items())
    return parsed._replace(query=new_query).geturl()


class XSSScanner(BaseScannerModule):
    id = "xss"
    name = "Reflected XSS Scanner"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        client = await get_client()

        # First, detect what params the page already has
        parsed = urlparse(url)
        existing_params = list(parse_qs(parsed.query).keys())
        test_params = list(set(existing_params + COMMON_PARAMS))

        for param in test_params:
            # Phase 1: Probe for reflection
            probe_url = build_test_url(url, param, PROBE)
            try:
                resp = await client.get(probe_url)
                if PROBE.lower() in resp.text.lower():
                    # Phase 2: Attempt payload
                    for payload in XSS_PAYLOADS:
                        payload_url = build_test_url(url, param, payload)
                        try:
                            resp2 = await client.get(payload_url)
                            if payload.lower() in resp2.text.lower():
                                f = self.make_finding(
                                    severity=Severity.HIGH,
                                    title=f"Reflected XSS in '{param}' Parameter",
                                    description=(
                                        f"The `{param}` parameter reflects user input without "
                                        "sanitization. An attacker can inject arbitrary HTML/JS "
                                        "that executes in victims' browsers, enabling session "
                                        "hijacking, credential theft, and more."
                                    ),
                                    url=payload_url,
                                    evidence=(
                                        f"Parameter: {param}\n"
                                        f"Payload: {payload}\n"
                                        f"Reflected in response body"
                                    ),
                                    remediation=(
                                        "Encode all user-supplied output using context-appropriate "
                                        "encoding (HTML entity encoding). Implement a strict "
                                        "Content-Security-Policy."
                                    ),
                                )
                                findings.append(f)
                                await self.notify(url, f)
                                break  # One confirmed finding per param is enough
                        except Exception:
                            continue
                elif PROBE[:-1] in resp.text:
                    # Partial reflection — possible XSS with encoding bypass (report as Medium)
                    f = self.make_finding(
                        severity=Severity.MEDIUM,
                        title=f"Possible XSS Reflection in '{param}' Parameter",
                        description=(
                            f"The `{param}` parameter partially reflects input. Manual "
                            "verification recommended to confirm exploitability."
                        ),
                        url=probe_url,
                        evidence=f"Probe partially reflected in response for param: {param}",
                        remediation="Review output encoding for this parameter.",
                    )
                    findings.append(f)
                    await self.notify(url, f)

            except Exception:
                continue

        return findings
