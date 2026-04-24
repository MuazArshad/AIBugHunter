"""
SQL Injection Scanner (Error-based, Basic)
Tests URL parameters for error-based SQL injection signatures.
Focuses on detection, not exploitation.
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs

from agent.scanners.base_scanner import BaseScannerModule
from models.scan_result import Finding, Severity
from utils.http_client import get_client

# Basic SQLi probes (error-inducing, not destructive)
SQLI_PROBES = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1", "1'", "1\"", "\\"]

# Database error signatures to look for in responses
ERROR_SIGNATURES = [
    ("MySQL", ["you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows",
               "supplied argument is not a valid mysql", "mysql server version"]),
    ("PostgreSQL", ["pg_query()", "pg_exec()", "query failed:", "unterminated quoted string",
                    "syntax error at or near", "postgresql"]),
    ("MSSQL", ["microsoft ole db provider for sql server", "odbc sql server driver",
               "unclosed quotation mark", "[microsoft][odbc sql server driver]",
               "incorrect syntax near"]),
    ("Oracle", ["ora-", "oracle error", "oracle database", "quoted string not properly terminated"]),
    ("SQLite", ["sqlite error", "sqlite3::", "unknown column", 'near "syntax"']),
    ("Generic", ["sql syntax", "sql error", "sql statement", "sqlexception",
                 "database error", "syntax error", "unrecognized expression"]),
]

COMMON_PARAMS = [
    "id", "page", "cat", "category", "product", "item", "user",
    "article", "news", "post", "thread", "forum", "q", "search",
    "query", "tag", "type", "sort", "order", "filter",
]


class SQLiScanner(BaseScannerModule):
    id = "sqli"
    name = "SQL Injection Scanner"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        client = await get_client()

        parsed = urlparse(url)
        existing = list(parse_qs(parsed.query).keys())
        test_params = list(set(existing + COMMON_PARAMS))

        for param in test_params:
            for probe in SQLI_PROBES:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={probe}"
                try:
                    resp = await client.get(test_url)
                    body = resp.text.lower()

                    for db_name, signatures in ERROR_SIGNATURES:
                        for sig in signatures:
                            if sig.lower() in body:
                                f = self.make_finding(
                                    severity=Severity.HIGH,
                                    title=f"SQL Injection — Error-based ({db_name}) in '{param}'",
                                    description=(
                                        f"The `{param}` parameter appears to be vulnerable to "
                                        f"SQL injection. A {db_name} error was triggered by the "
                                        f"probe `{probe}`, indicating unsanitized input is passed "
                                        "directly to a database query."
                                    ),
                                    url=test_url,
                                    evidence=(
                                        f"Parameter: {param}\n"
                                        f"Probe: {probe}\n"
                                        f"DB Signature: '{sig}'\n"
                                        f"Response snippet: {resp.text[:500]}"
                                    ),
                                    remediation=(
                                        "Use parameterized queries (prepared statements) for all "
                                        "database interactions. Never interpolate user input "
                                        "directly into SQL strings."
                                    ),
                                )
                                findings.append(f)
                                await self.notify(url, f)
                                return findings  # Stop on first confirmed finding

                except Exception:
                    continue

        return findings
