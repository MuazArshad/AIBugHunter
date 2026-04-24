"""
Information Disclosure Scanner
Checks for sensitive files/paths accidentally exposed on the web server.
Very effective low-hanging fruit for bug bounties.
"""

from __future__ import annotations
import asyncio
from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from utils.http_client import get_client

# (path, severity, title, description, remediation)
SENSITIVE_PATHS = [
    (".git/HEAD", Severity.HIGH, "Exposed .git Directory",
     "The .git directory is publicly accessible. Attackers can download the entire source code "
     "using tools like git-dumper, potentially exposing credentials, API keys, and business logic.",
     "Block access to .git in your web server config (deny from all for Apache, location ~ /\\.git { deny all; } for Nginx)."),

    (".env", Severity.CRITICAL, "Exposed .env File",
     "The .env file is publicly accessible. This file typically contains database credentials, "
     "API keys, secret tokens, and other sensitive configuration that can lead to full system compromise.",
     "Serve only files in the public web root. Never place .env in a publicly accessible directory."),

    (".env.local", Severity.CRITICAL, "Exposed .env.local File",
     "Local environment file is publicly accessible, likely containing sensitive credentials.",
     "Never expose environment files publicly."),

    (".env.production", Severity.CRITICAL, "Exposed .env.production File",
     "Production environment file is publicly accessible.",
     "Restrict access to all dot-files."),

    ("config.php", Severity.HIGH, "Exposed config.php",
     "Configuration file may contain database credentials or API keys.",
     "Restrict access to configuration files."),

    ("wp-config.php.bak", Severity.CRITICAL, "Exposed WordPress Config Backup",
     "WordPress configuration backup file is accessible, exposing DB credentials.",
     "Remove backup files and restrict access."),

    ("backup.zip", Severity.HIGH, "Exposed Backup Archive",
     "A backup archive is publicly accessible and may contain full source code or data.",
     "Remove backup files from web root or restrict access."),

    ("backup.sql", Severity.CRITICAL, "Exposed SQL Backup",
     "An SQL backup file is publicly accessible, potentially exposing all database data.",
     "Remove database dumps from web root immediately."),

    ("database.sql", Severity.CRITICAL, "Exposed Database Dump",
     "SQL database dump is accessible, exposing potentially all application data.",
     "Never store database dumps in the web root."),

    ("phpinfo.php", Severity.HIGH, "Exposed phpinfo() Page",
     "phpinfo() exposes PHP configuration, loaded modules, server environment variables, "
     "and other sensitive information useful for attackers.",
     "Remove or restrict access to phpinfo() pages."),

    ("server-status", Severity.MEDIUM, "Apache server-status Exposed",
     "Apache mod_status page is publicly accessible, leaking request counts, "
     "client IPs, and current requests.",
     "Restrict /server-status to localhost only."),

    ("robots.txt", Severity.INFO, "robots.txt Contains Hidden Paths",
     "robots.txt discloses paths the site owner wants to hide from crawlers. "
     "These paths may point to admin panels, staging environments, or sensitive directories.",
     "Review robots.txt entries and ensure disallowed paths are properly restricted."),

    (".DS_Store", Severity.MEDIUM, "Exposed .DS_Store File",
     ".DS_Store files created by macOS reveal directory listing information that can help "
     "attackers map the application file structure.",
     "Add .DS_Store to .gitignore and remove from server."),

    ("crossdomain.xml", Severity.LOW, "Permissive crossdomain.xml",
     "Flash crossdomain policy set to wildcard (*) may allow cross-domain data reading.",
     "Restrict crossdomain.xml to trusted domains only."),

    ("api/swagger.json", Severity.INFO, "Swagger API Docs Exposed",
     "Swagger/OpenAPI spec is publicly accessible, revealing all API endpoints, parameters, "
     "and authentication mechanisms.",
     "Restrict Swagger UI to internal/authenticated users only in production."),

    ("swagger.json", Severity.INFO, "Swagger API Docs Exposed (root)",
     "OpenAPI specification exposed at root.",
     "Restrict access in production."),

    ("api-docs", Severity.INFO, "API Documentation Exposed",
     "API documentation is publicly accessible.",
     "Restrict API docs in production."),

    (".htaccess", Severity.MEDIUM, "Exposed .htaccess File",
     ".htaccess reveals Apache rewrite rules, access restrictions, and potentially credentials.",
     "Configure Apache to deny access to .htaccess files."),

    ("web.config", Severity.HIGH, "Exposed web.config",
     "ASP.NET web.config is accessible and may contain connection strings, "
     "API keys, and other sensitive configuration.",
     "Restrict access to web.config in IIS."),

    ("Dockerfile", Severity.MEDIUM, "Exposed Dockerfile",
     "Dockerfile reveals the application stack, base images, and build configuration.",
     "Remove Dockerfiles from the web root."),

    ("docker-compose.yml", Severity.MEDIUM, "Exposed docker-compose.yml",
     "Docker Compose file reveals service configuration, possibly including credentials.",
     "Remove compose files from web root."),
]


class InfoDisclosureScanner(BaseScannerModule):
    id = "info_disclosure"
    name = "Information Disclosure Scanner"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        client = await get_client()
        semaphore = asyncio.Semaphore(10)

        base = url.rstrip("/")

        async def check_path(path_info: tuple):
            path, severity, title, desc, remediation = path_info
            async with semaphore:
                target = f"{base}/{path}"
                try:
                    resp = await client.get(target, follow_redirects=False)
                    if resp.status_code in (200, 206):
                        # Extra check: ensure it's not just a catch-all 200
                        body = resp.text[:2000]

                        # Special robots.txt logic
                        if path == "robots.txt":
                            if "Disallow:" in body:
                                disallowed = [
                                    line.split(":", 1)[1].strip()
                                    for line in body.splitlines()
                                    if line.startswith("Disallow:") and line.split(":", 1)[1].strip()
                                ]
                                if disallowed:
                                    f = self.make_finding(
                                        severity=severity,
                                        title=title,
                                        description=desc,
                                        url=target,
                                        evidence=f"Disallowed paths: {', '.join(disallowed[:10])}",
                                        remediation=remediation,
                                    )
                                    findings.append(f)
                                    await self.notify(url, f)
                            return

                        f = self.make_finding(
                            severity=severity,
                            title=title,
                            description=desc,
                            url=target,
                            evidence=f"HTTP {resp.status_code} — {len(body)} bytes returned\n{body[:300]}",
                            remediation=remediation,
                        )
                        findings.append(f)
                        await self.notify(url, f)
                except Exception:
                    pass

        await asyncio.gather(*[check_path(p) for p in SENSITIVE_PATHS])
        return findings
