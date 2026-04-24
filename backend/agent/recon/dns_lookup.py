"""
DNS Lookup utilities
- Resolve subdomains to IPs
- Detect dangling CNAMEs (subdomain takeover candidates)
"""

from __future__ import annotations
import asyncio
from typing import Optional


# Services known to be takeover-vulnerable when CNAME points to them
TAKEOVER_SIGNATURES = {
    "github.io":          "There isn't a GitHub Pages site here.",
    "heroku.com":         "No such app",
    "amazonaws.com":      "NoSuchBucket",
    "azurewebsites.net":  "404 Web Site not found",
    "cloudfront.net":     "Bad request",
    "shopify.com":        "Sorry, this shop is currently unavailable",
    "fastly.net":         "Fastly error: unknown domain",
    "pantheon.io":        "The gods are wise",
    "readthedocs.io":     "unknown to Read the Docs",
    "ghost.io":           "The thing you were looking for is no longer here",
    "surge.sh":           "project not found",
    "netlify.app":        "Not Found",
    "bitbucket.io":       "Repository not found",
    "helpscoutdocs.com":  "No settings were found for this company",
    "zendesk.com":        "Help Center Closed",
    "freshdesk.com":      "There is no helpdesk here",
    "smartling.com":      "Domain is not configured",
    "wordpress.com":      "Do you want to register",
    "tumblr.com":         "Whatever you were looking for doesn't currently exist",
}


async def resolve_domain(domain: str) -> dict:
    """Resolve a domain to its A records and CNAME chain."""
    result = {"domain": domain, "ips": [], "cname": None, "alive": False}
    try:
        import dns.asyncresolver
        import dns.exception

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5

        # Try CNAME first
        try:
            cname_answer = await resolver.resolve(domain, "CNAME")
            result["cname"] = str(cname_answer[0].target).rstrip(".")
        except Exception:
            pass

        # Try A records
        try:
            a_answer = await resolver.resolve(domain, "A")
            result["ips"] = [str(r) for r in a_answer]
            result["alive"] = True
        except Exception:
            pass

    except Exception:
        pass
    return result


async def check_dangling_cname(domain: str, cname: str, body: str) -> Optional[dict]:
    """
    Check if a CNAME pointing to a third-party service is dangling.
    Returns a finding dict if vulnerable, None otherwise.
    """
    for service_suffix, signature in TAKEOVER_SIGNATURES.items():
        if service_suffix in cname:
            if signature.lower() in body.lower():
                return {
                    "domain": domain,
                    "cname": cname,
                    "service": service_suffix,
                    "signature": signature,
                }
    return None


async def probe_live_subdomains(
    subdomains: list[str],
    emit=None,
) -> tuple[list[str], list[dict]]:
    """
    HTTP-probe a list of subdomains to find which are live.
    Also check for dangling CNAMEs.
    Returns (live_subdomains, dangling_cnames)
    """
    import httpx

    live: list[str] = []
    dangling: list[dict] = []
    semaphore = asyncio.Semaphore(20)

    async def probe(sub: str):
        async with semaphore:
            dns_info = await resolve_domain(sub)
            if not dns_info["alive"] and not dns_info["ips"]:
                return

            # Try HTTP then HTTPS
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                try:
                    async with httpx.AsyncClient(
                        timeout=8, verify=False, follow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 BugHunterAgent/1.0"}
                    ) as client:
                        resp = await client.get(url)
                        live.append(url)

                        if emit:
                            await emit({
                                "type": "recon",
                                "event": "live_found",
                                "url": url,
                                "status": resp.status_code,
                            })

                        # Check for dangling CNAME
                        if dns_info.get("cname"):
                            d = await check_dangling_cname(sub, dns_info["cname"], resp.text)
                            if d:
                                dangling.append(d)
                                if emit:
                                    await emit({
                                        "type": "recon",
                                        "event": "dangling_cname",
                                        "domain": sub,
                                        "cname": dns_info["cname"],
                                    })
                        break
                except Exception:
                    continue

    await asyncio.gather(*[probe(s) for s in subdomains])
    return live, dangling
