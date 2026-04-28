"""Stealth scan utilities.

Used by web plugins when context.stealth_mode is True:
- User-agent rotation
- Randomized inter-request delays
- HTTP header order shuffling
- WAF bypass payload encoding variants

Import pattern in plugins:
    if context.stealth_mode:
        from scanr.core.stealth import random_delay, stealth_headers, encode_payload
        await asyncio.sleep(random_delay())
        headers = stealth_headers()
"""
from __future__ import annotations

import random
import urllib.parse

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "curl/7.88.1",
    "python-httpx/0.27.0",
    "Go-http-client/1.1",
]

_REFERRERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "",
    "",  # weight toward no referrer
    "",
]

_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,fr;q=0.3",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en-US;q=0.8",
    "*",
]


def random_user_agent() -> str:
    return random.choice(_USER_AGENTS)


def random_delay(min_s: float = 0.3, max_s: float = 2.5) -> float:
    """Return a jittered delay in seconds."""
    return random.uniform(min_s, max_s)


def stealth_headers(base: dict | None = None) -> dict:
    """Return headers with randomized User-Agent, optional Referer and Accept-Language."""
    h = dict(base or {})
    h["User-Agent"] = random_user_agent()
    referrer = random.choice(_REFERRERS)
    if referrer:
        h["Referer"] = referrer
    h["Accept-Language"] = random.choice(_ACCEPT_LANGS)
    h["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    # Shuffle header order (Python 3.7+ dicts preserve insertion order)
    items = list(h.items())
    random.shuffle(items)
    return dict(items)


# WAF bypass encoding strategies
def _url_encode(p: str) -> str:
    return urllib.parse.quote(p, safe="")


def _double_url_encode(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def _html_entity_encode(p: str) -> str:
    return "".join(f"&#x{ord(c):x};" if c.isalpha() else c for c in p)


def _case_mutate(p: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))


def _null_byte_insert(p: str) -> str:
    return p.replace("'", "%00'").replace(" ", "%00 ")


_ENCODINGS = [_url_encode, _double_url_encode, _html_entity_encode, _case_mutate, _null_byte_insert]


def encode_payload(payload: str, strategy: str = "random") -> str:
    """Return a WAF-bypass-encoded variant of the payload."""
    if strategy == "url":
        return _url_encode(payload)
    if strategy == "double":
        return _double_url_encode(payload)
    if strategy == "entity":
        return _html_entity_encode(payload)
    if strategy == "case":
        return _case_mutate(payload)
    # random
    return random.choice(_ENCODINGS)(payload)
