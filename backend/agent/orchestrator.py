"""
Scan Orchestrator
Central agent loop that coordinates recon → scanning → AI triage.
"""

from __future__ import annotations
import asyncio
from typing import Callable, Awaitable

from models.scan_request import ScanRequest
from models.scan_result import ScanSession, ReconResult, Finding
from agent.recon.subdomain_enum import enumerate_subdomains
from agent.recon.dns_lookup import probe_live_subdomains
from agent.recon.scope_parser import filter_in_scope

# Scanner registry
from agent.scanners.header_scanner import HeaderScanner
from agent.scanners.cors_scanner import CORSScanner
from agent.scanners.open_redirect import OpenRedirectScanner
from agent.scanners.xss_scanner import XSSScanner
from agent.scanners.info_disclosure import InfoDisclosureScanner
from agent.scanners.subdomain_takeover import SubdomainTakeoverScanner
from agent.scanners.sqli_scanner import SQLiScanner

# AI provider registry
from agent.ai_providers.gemini import GeminiProvider
from agent.ai_providers.claude import ClaudeProvider
from agent.ai_providers.grok import GrokProvider
from agent.ai_providers.openai_provider import OpenAIProvider

SCANNER_MAP = {
    "headers": HeaderScanner,
    "cors": CORSScanner,
    "open_redirect": OpenRedirectScanner,
    "xss": XSSScanner,
    "info_disclosure": InfoDisclosureScanner,
    "subdomain_takeover": SubdomainTakeoverScanner,
    "sqli": SQLiScanner,
}

PROVIDER_MAP = {
    "gemini": GeminiProvider,
    "claude": ClaudeProvider,
    "grok": GrokProvider,
    "openai": OpenAIProvider,
}


class ScanOrchestrator:
    def __init__(
        self,
        request: ScanRequest,
        session: ScanSession,
        emit: Callable[[dict], Awaitable[None]],
    ):
        self.request = request
        self.session = session
        self.emit = emit
        self._stopped = False

        # Instantiate AI provider
        provider_cls = PROVIDER_MAP.get(request.provider, GeminiProvider)
        self.ai_provider = provider_cls()

    def stop(self):
        self._stopped = True

    async def run(self):
        """Main agent loop."""
        req = self.request
        target = req.target

        await self.emit({"type": "status", "message": f"🎯 Target: {target}", "phase": "init"})

        # ── Phase 1: Subdomain Enumeration ──────────────────────────────────
        await self.emit({"type": "status", "message": "🔍 Phase 1: Subdomain Enumeration", "phase": "recon"})

        subdomains = await enumerate_subdomains(
            domain=target,
            recon_mode=req.recon_mode,
            wordlist_size="small",
            emit=self.emit,
        )

        if self._stopped:
            return

        # ── Phase 2: HTTP Probing ────────────────────────────────────────────
        await self.emit({
            "type": "status",
            "message": f"🌐 Phase 2: Probing {len(subdomains)} subdomains for live hosts...",
            "phase": "probing",
        })

        live_urls, dangling_cnames = await probe_live_subdomains(subdomains, self.emit)

        # Apply scope filter
        scope = req.scope_domains or [f"*.{target}", target]
        live_urls = filter_in_scope(live_urls, scope)

        recon_result = ReconResult(
            subdomains=subdomains,
            live_subdomains=live_urls,
            dangling_cnames=dangling_cnames,
        )
        self.session.recon = recon_result

        await self.emit({
            "type": "recon_summary",
            "subdomains": len(subdomains),
            "live": len(live_urls),
            "dangling_cnames": len(dangling_cnames),
        })

        if self._stopped:
            return

        # ── Phase 3: Vulnerability Scanning ─────────────────────────────────
        await self.emit({
            "type": "status",
            "message": f"🔬 Phase 3: Running {len(req.scanners)} scanners on {len(live_urls)} targets...",
            "phase": "scanning",
        })

        all_findings: list[Finding] = []
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent scanner-URL combos

        async def run_scanner_on_url(scanner_id: str, url: str):
            if self._stopped:
                return
            scanner_cls = SCANNER_MAP.get(scanner_id)
            if not scanner_cls:
                return
            async with semaphore:
                try:
                    scanner = scanner_cls(emit=self.emit)
                    await self.emit({
                        "type": "scanner_start",
                        "scanner": scanner_id,
                        "url": url,
                    })
                    findings = await scanner.scan(url)
                    all_findings.extend(findings)
                    self.session.findings.extend(findings)
                except Exception as e:
                    await self.emit({
                        "type": "scanner_error",
                        "scanner": scanner_id,
                        "url": url,
                        "error": str(e),
                    })

        tasks = [
            run_scanner_on_url(sid, url)
            for url in live_urls
            for sid in req.scanners
        ]
        await asyncio.gather(*tasks)

        if self._stopped:
            return

        # ── Phase 4: AI Triage ───────────────────────────────────────────────
        if all_findings:
            await self.emit({
                "type": "status",
                "message": f"🤖 Phase 4: AI triage of {len(all_findings)} findings with {req.provider}...",
                "phase": "ai_triage",
            })

            # Triage each finding individually (batch to avoid rate limits)
            for finding in all_findings[:20]:  # Cap at 20 individual triages
                if self._stopped:
                    break
                try:
                    ai_comment = await self.ai_provider.triage_finding(finding)
                    if ai_comment:
                        finding.ai_analysis = ai_comment
                        await self.emit({
                            "type": "ai_triage",
                            "finding_id": finding.id,
                            "analysis": ai_comment,
                        })
                except Exception:
                    pass

            # Full executive summary
            try:
                summary = await self.ai_provider.analyze_findings(all_findings, target)
                self.session.ai_summary = summary
                await self.emit({
                    "type": "ai_summary",
                    "summary": summary,
                })
            except Exception as e:
                await self.emit({"type": "ai_error", "error": str(e)})

        else:
            await self.emit({"type": "status", "message": "✅ No vulnerabilities found.", "phase": "done"})

        await self.emit({
            "type": "status",
            "message": f"✅ Scan complete. Found {len(all_findings)} vulnerabilities.",
            "phase": "done",
        })
