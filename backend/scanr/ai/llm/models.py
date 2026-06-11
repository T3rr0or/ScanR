"""Fetch available models from each provider's API.

Each provider gets a dedicated fetcher so we can handle auth, pagination,
and filtering differently per provider. Results are cached for 5 minutes
to avoid spamming provider APIs on dropdown opens.
"""

from __future__ import annotations

import asyncio
import time

logger = __import__("logging").getLogger(__name__)

_CACHE_TTL = 300  # seconds
_cache: dict[str, tuple[float, list[dict]]] = {}


def _cached_get(cache_key: str, fetcher):
    """Return cached result if fresh, else call fetcher and cache."""
    now = time.time()
    if cache_key in _cache:
        ts, result = _cache[cache_key]
        if now - ts < _CACHE_TTL:
            return result
    result = fetcher()
    _cache[cache_key] = (now, result)
    return result


async def list_anthropic_models(api_key: str) -> list[dict]:
    """Fetch available Claude models from Anthropic API."""

    def _fetch():
        try:
            from anthropic import Anthropic
        except ImportError:
            raise RuntimeError("The 'anthropic' package is required. Install with: pip install 'scanr[ai]'")
        client = Anthropic(api_key=api_key)
        resp = client.models.list()
        models = []
        for m in resp.data:
            models.append({"id": m.id, "display_name": m.display_name})
        # Sort: latest models first, then alphabetically
        models.sort(key=lambda x: x["id"], reverse=True)
        return models

    return await asyncio.to_thread(_cached_get, f"anthropic:{api_key[:12]}", _fetch)


async def list_openai_models(api_key: str) -> list[dict]:
    """Fetch available models from OpenAI API."""

    def _fetch():
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError("The 'openai' package is required. Install with: pip install 'scanr[ai]'")
        client = OpenAI(api_key=api_key)
        resp = client.models.list()
        models = []
        for m in resp.data:
            mid = m.id
            # Only show chat-capable models (filter out embeddings, tts, etc.)
            if any(mid.startswith(p) for p in ("gpt-", "o1", "o3", "o4")):
                models.append({"id": mid, "display_name": mid})
        models.sort(key=lambda x: x["id"], reverse=True)
        return models

    return await asyncio.to_thread(_cached_get, f"openai:{api_key[:12]}", _fetch)


async def list_deepseek_models(api_key: str) -> list[dict]:
    """Fetch available models from DeepSeek API (OpenAI-compatible)."""

    def _fetch():
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError("The 'openai' package is required. Install with: pip install 'scanr[ai]'")
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        resp = client.models.list()
        models = []
        for m in resp.data:
            models.append({"id": m.id, "display_name": m.id})
        models.sort(key=lambda x: x["id"], reverse=True)
        return models

    return await asyncio.to_thread(_cached_get, f"deepseek:{api_key[:12]}", _fetch)


FETCHERS = {
    "anthropic": list_anthropic_models,
    "openai": list_openai_models,
    "deepseek": list_deepseek_models,
}


async def list_models(provider: str, api_key: str) -> list[dict]:
    """Fetch available models for a provider. Returns list of {id, display_name}."""
    fetcher = FETCHERS.get(provider)
    if not fetcher:
        raise ValueError(f"Unknown provider: {provider}")
    return await fetcher(api_key)
