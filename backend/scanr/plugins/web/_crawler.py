"""Lightweight single-origin crawler for web plugins."""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

_HREF_RE = re.compile(r'href=["\']([^"\'#>]+)["\']', re.I)
_ACTION_RE = re.compile(r'action=["\']([^"\'#>]*)["\']', re.I)
_INPUT_RE = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
_SELECT_RE = re.compile(r'<select[^>]+name=["\']([^"\']+)["\']', re.I)
_TEXTAREA_RE = re.compile(r'<textarea[^>]+name=["\']([^"\']+)["\']', re.I)

_MAX_CRAWL = 15


def create_web_client(context: "ScanContext | None" = None, with_limits: bool = False) -> httpx.AsyncClient:
    """Create an httpx client with auth headers from scan credentials."""
    kwargs: dict = {"verify": False, "timeout": 10.0, "follow_redirects": False}
    if with_limits:
        kwargs["limits"] = httpx.Limits(max_connections=30, max_keepalive_connections=20)
    if context:
        auth_headers = context.web_auth_headers()
        if auth_headers:
            kwargs["headers"] = auth_headers
    return httpx.AsyncClient(**kwargs)


@dataclass
class CrawlResult:
    paths: list[str] = field(default_factory=list)
    get_params: list[str] = field(default_factory=list)
    form_paths: list[str] = field(default_factory=list)
    form_fields: list[str] = field(default_factory=list)


async def crawl(base_url: str, client: httpx.AsyncClient) -> CrawlResult:
    result = CrawlResult()
    seen: set[str] = set()       # visited + queued, O(1) lookup
    queue: deque[str] = deque(["/"])
    seen.add("/")

    origin_host = urlparse(base_url).hostname or ""

    while queue and len(seen) <= _MAX_CRAWL:
        path = queue.popleft()

        try:
            resp = await client.get(f"{base_url}{path}", timeout=5.0)
            if resp.status_code != 200:
                continue
            if "text/html" not in resp.headers.get("content-type", ""):
                continue
            body = resp.text
        except Exception:
            continue

        for href in _HREF_RE.findall(body):
            parsed = urlparse(urljoin(f"{base_url}{path}", href))
            # Same origin — compare hostname only, ignore port differences
            if parsed.hostname and parsed.hostname != origin_host:
                continue
            p = parsed.path or "/"
            if p not in result.paths:
                result.paths.append(p)
            if p not in seen:
                seen.add(p)
                queue.append(p)
            for param in parse_qs(parsed.query):
                if param not in result.get_params:
                    result.get_params.append(param)

        for action in _ACTION_RE.findall(body):
            parsed = urlparse(urljoin(f"{base_url}{path}", action))
            fp = parsed.path or path
            if fp not in result.form_paths:
                result.form_paths.append(fp)

        for tag_re in (_INPUT_RE, _SELECT_RE, _TEXTAREA_RE):
            for name in tag_re.findall(body):
                if name not in result.form_fields:
                    result.form_fields.append(name)

    if "/" not in result.paths:
        result.paths.insert(0, "/")

    return result
