"""
Subdomain Enumeration
- Passive: crt.sh certificate transparency + HackerTarget API
- Active: DNS brute-force with configurable wordlists
"""

from __future__ import annotations
import asyncio
import json
import os
from typing import Callable, Awaitable

import httpx

from utils.http_client import get_client

# ─── Wordlists ───────────────────────────────────────────────────────────────

SMALL_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "dns",
    "vpn", "remote", "api", "dev", "test", "staging", "admin", "portal",
    "app", "web", "cdn", "static", "assets", "media", "images", "shop",
    "store", "blog", "news", "docs", "support", "help", "status", "m",
    "mobile", "secure", "login", "auth", "sso", "id", "account", "accounts",
    "git", "gitlab", "github", "jira", "confluence", "jenkins", "ci",
    "prod", "qa", "uat", "beta", "demo", "old", "new", "backup", "db",
    "mysql", "postgres", "redis", "elastic", "kibana", "grafana", "monitor",
    "metrics", "logs", "cloud", "aws", "azure", "gcp", "internal", "intranet",
]

MEDIUM_WORDLIST = SMALL_WORDLIST + [
    "webmail", "exchange", "autodiscover", "cpanel", "whm", "plesk",
    "phpmyadmin", "adminer", "wp", "wordpress", "drupal", "joomla",
    "magento", "shopify", "woocommerce", "upload", "uploads", "files",
    "file", "download", "downloads", "data", "reports", "reporting",
    "analytics", "track", "tracking", "pixel", "ad", "ads", "click",
    "survey", "forms", "form", "api2", "apiv2", "v2", "v1", "graphql",
    "rest", "ws", "wss", "socket", "chat", "live", "stream", "video",
    "img", "thumbnail", "preview", "cache", "proxy", "gateway", "router",
    "firewall", "fw", "bastion", "jump", "relay", "smtp2", "mx", "mx1", "mx2",
    "ns3", "ns4", "ldap", "ad1", "ad2", "dc", "dc1", "dc2", "pki", "crl",
    "ocsp", "sip", "voip", "pbx", "asterisk", "wiki", "kb", "knowledge",
    "helpdesk", "tickets", "crm", "erp", "hr", "payroll", "finance",
]

WORDLISTS = {
    "small": SMALL_WORDLIST,
    "medium": MEDIUM_WORDLIST,
    "large": MEDIUM_WORDLIST,  # Would load from file in production
}


# ─── Passive Recon ────────────────────────────────────────────────────────────

async def crtsh_subdomains(domain: str) -> set[str]:
    """Query crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.").lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            found.add(sub)
    except Exception:
        pass
    return found


async def hackertarget_subdomains(domain: str) -> set[str]:
    """Query HackerTarget's free subdomain lookup API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub:
                            found.add(sub)
    except Exception:
        pass
    return found


# ─── Active Recon ─────────────────────────────────────────────────────────────

async def dns_brute_force(
    domain: str,
    wordlist_size: str = "small",
    emit: Callable[[dict], Awaitable[None]] | None = None,
) -> set[str]:
    """Brute-force subdomains via DNS A record lookups."""
    import dns.asyncresolver
    import dns.exception

    wordlist = WORDLISTS.get(wordlist_size, SMALL_WORDLIST)
    found: set[str] = set()
    semaphore = asyncio.Semaphore(30)

    async def check(word: str):
        subdomain = f"{word}.{domain}"
        async with semaphore:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = 3
                await resolver.resolve(subdomain, "A")
                found.add(subdomain)
                if emit:
                    await emit({
                        "type": "recon",
                        "event": "subdomain_found",
                        "source": "brute_force",
                        "subdomain": subdomain,
                    })
            except Exception:
                pass

    await asyncio.gather(*[check(w) for w in wordlist])
    return found


# ─── Main Entry Point ─────────────────────────────────────────────────────────

async def enumerate_subdomains(
    domain: str,
    recon_mode: str = "passive",
    wordlist_size: str = "small",
    emit: Callable[[dict], Awaitable[None]] | None = None,
) -> list[str]:
    """
    Enumerate subdomains using passive and/or active techniques.
    Returns a sorted, deduplicated list.
    """
    all_found: set[str] = {domain}  # Always include the root

    if emit:
        await emit({"type": "recon", "event": "start", "message": f"Starting subdomain enumeration for {domain}"})

    if recon_mode in ("passive", "both"):
        if emit:
            await emit({"type": "recon", "event": "passive_start", "message": "Querying crt.sh & HackerTarget..."})

        results = await asyncio.gather(
            crtsh_subdomains(domain),
            hackertarget_subdomains(domain),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, set):
                all_found.update(r)
                for sub in r:
                    if emit:
                        await emit({
                            "type": "recon",
                            "event": "subdomain_found",
                            "source": "passive",
                            "subdomain": sub,
                        })

    if recon_mode in ("active", "both"):
        if emit:
            await emit({"type": "recon", "event": "brute_start", "message": f"DNS brute-force ({wordlist_size} wordlist)..."})
        bf_results = await dns_brute_force(domain, wordlist_size, emit)
        all_found.update(bf_results)

    sorted_list = sorted(all_found)
    if emit:
        await emit({
            "type": "recon",
            "event": "complete",
            "message": f"Found {len(sorted_list)} subdomains",
            "count": len(sorted_list),
        })
    return sorted_list
