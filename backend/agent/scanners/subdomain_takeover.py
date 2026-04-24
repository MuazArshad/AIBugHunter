"""
Subdomain Takeover Scanner
Checks subdomains with dangling CNAMEs for evidence of unclaimed services.
"""

from __future__ import annotations
from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from agent.recon.dns_lookup import TAKEOVER_SIGNATURES, resolve_domain
from utils.http_client import get_client


class SubdomainTakeoverScanner(BaseScannerModule):
    id = "subdomain_takeover"
    name = "Subdomain Takeover Scanner"

    async def scan(self, url: str) -> list[Finding]:
        """
        For this scanner, 'url' is treated as a full URL.
        We extract the hostname and check for dangling CNAME.
        """
        from urllib.parse import urlparse
        findings: list[Finding] = []

        parsed = urlparse(url)
        hostname = parsed.hostname or url

        dns_info = await resolve_domain(hostname)
        cname = dns_info.get("cname")

        if not cname:
            return findings

        # Check if CNAME points to a known vulnerable service
        for service_suffix, signature in TAKEOVER_SIGNATURES.items():
            if service_suffix in cname:
                # Fetch the page and look for the takeover signature
                try:
                    client = await get_client()
                    resp = await client.get(url)
                    body = resp.text

                    if signature.lower() in body.lower():
                        f = self.make_finding(
                            severity=Severity.HIGH,
                            title=f"Subdomain Takeover Possible — {service_suffix}",
                            description=(
                                f"The subdomain `{hostname}` has a CNAME pointing to "
                                f"`{cname}` ({service_suffix}), but the resource does not "
                                "appear to be claimed. An attacker could register this resource "
                                "and serve arbitrary content under the victim's subdomain."
                            ),
                            url=url,
                            evidence=(
                                f"CNAME: {hostname} → {cname}\n"
                                f"Service: {service_suffix}\n"
                                f"Takeover signature found: '{signature}'"
                            ),
                            remediation=(
                                "Either remove the dangling DNS CNAME record, or "
                                f"claim/recreate the {service_suffix} resource."
                            ),
                        )
                        findings.append(f)
                        await self.notify(url, f)
                        break
                except Exception:
                    pass

        return findings
