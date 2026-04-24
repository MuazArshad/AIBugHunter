"""
CORS Misconfiguration Scanner
Checks for wildcard origins and credentialed CORS abuse.
"""

from __future__ import annotations
from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from utils.http_client import get_client


class CORSScanner(BaseScannerModule):
    id = "cors"
    name = "CORS Misconfiguration Scanner"

    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        client = await get_client()

        for origin in self.TEST_ORIGINS:
            try:
                resp = await client.get(
                    url,
                    headers={"Origin": origin},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                # Wildcard CORS
                if acao == "*":
                    f = self.make_finding(
                        severity=Severity.LOW,
                        title="CORS: Wildcard Origin Allowed",
                        description=(
                            "The server sets Access-Control-Allow-Origin: * which allows "
                            "any website to read responses. Combined with sensitive endpoints "
                            "this can lead to data exfiltration."
                        ),
                        url=url,
                        evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                        remediation=(
                            "Use a whitelist of trusted origins. Do not use * for "
                            "authenticated endpoints."
                        ),
                    )
                    findings.append(f)
                    await self.notify(url, f)

                # Reflected origin + credentials — HIGH severity
                elif acao == origin and acac.lower() == "true":
                    f = self.make_finding(
                        severity=Severity.HIGH,
                        title="CORS: Arbitrary Origin Reflected with Credentials",
                        description=(
                            f"The server reflects the attacker-controlled origin '{origin}' "
                            "and sets Access-Control-Allow-Credentials: true. An attacker "
                            "can make cross-origin requests on behalf of authenticated users "
                            "and read sensitive responses."
                        ),
                        url=url,
                        evidence=(
                            f"Request Origin: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        remediation=(
                            "Validate the Origin header against a strict whitelist. "
                            "Never combine wildcard or reflected origins with credentials: true."
                        ),
                    )
                    findings.append(f)
                    await self.notify(url, f)
                    break  # One high finding is enough

                # Reflected origin without credentials — MEDIUM
                elif acao == origin:
                    f = self.make_finding(
                        severity=Severity.MEDIUM,
                        title="CORS: Arbitrary Origin Reflected",
                        description=(
                            f"The server reflects the attacker-controlled origin '{origin}'. "
                            "While credentials are not explicitly allowed, this may still "
                            "expose public API responses to unauthorized third parties."
                        ),
                        url=url,
                        evidence=(
                            f"Request Origin: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}"
                        ),
                        remediation=(
                            "Validate the Origin header against a strict whitelist "
                            "instead of reflecting it."
                        ),
                    )
                    findings.append(f)
                    await self.notify(url, f)

                # null origin accepted
                if origin == "null" and acao == "null":
                    f = self.make_finding(
                        severity=Severity.MEDIUM,
                        title="CORS: null Origin Accepted",
                        description=(
                            "The server accepts 'null' as a valid CORS origin. "
                            "Sandboxed iframes and local HTML files send Origin: null, "
                            "which can be abused for CORS attacks."
                        ),
                        url=url,
                        evidence=f"Origin: null\nAccess-Control-Allow-Origin: null",
                        remediation="Do not accept 'null' as a valid CORS origin.",
                    )
                    findings.append(f)
                    await self.notify(url, f)

            except Exception:
                continue

        return findings
