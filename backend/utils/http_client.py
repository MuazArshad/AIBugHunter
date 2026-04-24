"""Shared async HTTP client using httpx."""

import os
import httpx

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))

# Shared async client for all scanners (connection pooling)
_client: httpx.AsyncClient | None = None


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            verify=False,  # Bug bounty often tests internal staging with self-signed certs
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; BugHunterAgent/1.0; "
                    "+https://github.com/bugagent)"
                )
            },
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
    return _client


async def safe_get(url: str, **kwargs) -> httpx.Response | None:
    """GET request that swallows network errors and returns None on failure."""
    try:
        client = await get_client()
        return await client.get(url, **kwargs)
    except Exception:
        return None


async def safe_post(url: str, **kwargs) -> httpx.Response | None:
    """POST request that swallows network errors."""
    try:
        client = await get_client()
        return await client.post(url, **kwargs)
    except Exception:
        return None
