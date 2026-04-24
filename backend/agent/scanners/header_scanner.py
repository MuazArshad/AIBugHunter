"""
Security Headers Scanner
Checks for missing/misconfigured HTTP security headers.
Low-hanging fruit: very common and easy to report.
"""

from __future__ import annotations
from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from utils.http_client import safe_get


REQUIRED_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": Severity.MEDIUM,
        "description": (
            "HTTP Strict Transport Security (HSTS) is not set. Without this header, "
            "browsers may load the site over plain HTTP, making users vulnerable to "
            "man-in-the-middle attacks."
        ),
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "name": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "description": (
            "X-Frame-Options is missing. The page may be embeddable in an iframe, "
            "enabling clickjacking attacks where users are tricked into clicking "
            "hidden buttons."
        ),
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "description": (
            "X-Content-Type-Options is missing. Browsers may MIME-sniff responses "
            "and execute uploaded files as executable content, enabling certain XSS attacks."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "name": "Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "description": (
            "Content-Security-Policy (CSP) header is missing. Without CSP, "
            "the application is more susceptible to XSS and data injection attacks."
        ),
        "remediation": "Implement a Content-Security-Policy header appropriate for your app.",
    },
    {
        "name": "Referrer-Policy",
        "severity": Severity.LOW,
        "description": (
            "Referrer-Policy is missing. The browser may send the full URL as a "
            "Referer header to third parties, leaking sensitive URL parameters."
        ),
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "name": "Permissions-Policy",
        "severity": Severity.INFO,
        "description": (
            "Permissions-Policy (formerly Feature-Policy) is not set. "
            "This header allows you to restrict which browser features can be used."
        ),
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
]

DANGEROUS_HEADERS = [
    {
        "name": "Server",
        "severity": Severity.INFO,
        "description": "Server header reveals web server version, aiding attackers in fingerprinting.",
        "remediation": "Remove or obfuscate the Server header.",
    },
    {
        "name": "X-Powered-By",
        "severity": Severity.INFO,
        "description": "X-Powered-By header reveals the technology stack (e.g. PHP version).",
        "remediation": "Remove the X-Powered-By header.",
    },
]


class HeaderScanner(BaseScannerModule):
    id = "headers"
    name = "Security Headers Scanner"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        resp = await safe_get(url)
        if not resp:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing required headers
        for check in REQUIRED_HEADERS:
            if check["name"].lower() not in headers:
                f = self.make_finding(
                    severity=check["severity"],
                    title=f"Missing Security Header: {check['name']}",
                    description=check["description"],
                    url=url,
                    evidence=f"Header '{check['name']}' not present in response",
                    remediation=check["remediation"],
                )
                findings.append(f)
                await self.notify(url, f)

        # Check information-leaking headers
        for check in DANGEROUS_HEADERS:
            hval = headers.get(check["name"].lower())
            if hval:
                f = self.make_finding(
                    severity=check["severity"],
                    title=f"Information Disclosure via '{check['name']}' Header",
                    description=check["description"],
                    url=url,
                    evidence=f"{check['name']}: {hval}",
                    remediation=check["remediation"],
                )
                findings.append(f)
                await self.notify(url, f)

        # Check for overly permissive HSTS
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            try:
                max_age = int(
                    next(
                        p.split("=")[1]
                        for p in hsts.split(";")
                        if "max-age" in p.lower()
                    )
                )
                if max_age < 15552000:  # Less than 6 months
                    f = self.make_finding(
                        severity=Severity.LOW,
                        title="HSTS max-age Too Short",
                        description="HSTS max-age is less than 6 months, reducing protection.",
                        url=url,
                        evidence=f"Strict-Transport-Security: {hsts}",
                        remediation="Set max-age to at least 31536000 (1 year).",
                    )
                    findings.append(f)
                    await self.notify(url, f)
            except (StopIteration, ValueError, IndexError):
                pass

        return findings
