"""
Scope Parser — validates targets and subdomains against user-defined scope.
"""

from __future__ import annotations
import fnmatch
import re


def normalize_domain(domain: str) -> str:
    """Strip scheme, path, wildcards for comparison."""
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    return d


def is_in_scope(target: str, scope: list[str]) -> bool:
    """
    Check if a target domain is within the allowed scope list.
    Scope entries support wildcards like *.example.com
    """
    if not scope:
        return True  # No scope restrictions → everything is in scope

    target_norm = normalize_domain(target)

    for entry in scope:
        entry_norm = normalize_domain(entry)
        # fnmatch handles *.example.com patterns
        if fnmatch.fnmatch(target_norm, entry_norm):
            return True
        # Exact match
        if target_norm == entry_norm:
            return True
        # Subdomain of entry (e.g. api.example.com is in scope if example.com is)
        if target_norm.endswith(f".{entry_norm}"):
            return True

    return False


def filter_in_scope(targets: list[str], scope: list[str]) -> list[str]:
    """Filter a list of targets to only those within scope."""
    if not scope:
        return targets
    return [t for t in targets if is_in_scope(t, scope)]


def parse_scope_from_text(text: str) -> list[str]:
    """
    Parse a scope block pasted from HackerOne/Bugcrowd.
    Extracts domains and wildcard entries like *.example.com
    """
    domains = []
    pattern = re.compile(
        r"(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    )
    for match in pattern.finditer(text):
        domains.append(match.group(0))
    return list(set(domains))
