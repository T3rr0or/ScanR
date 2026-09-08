"""Unrestricted file upload testing.

Two separate questions, two separate findings: whether a dangerous extension
is *accepted* at all, and — a materially worse outcome, scored higher — whether
the stored file can then be *fetched back*. The mock server below behaves like
a real (if naive) upload handler: it inspects the multipart body for a
filename and, when configured to disclose a storage path, actually serves the
bytes back from it, so the plugin's own extraction/verification logic is
exercised rather than a canned answer.
"""
from __future__ import annotations

import re

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import file_upload as fu
from scanr.plugins.web._crawler import CrawlResult

_FILENAME_RE = re.compile(r'filename="([^"]+)"')


class _Ctx:
    def proxy_config(self):
        return {}

    def web_auth_headers(self):
        return {}


@pytest.fixture(autouse=True)
def _no_crawl(monkeypatch):
    """No forms discovered by crawling; the plugin falls back to its own list
    of common upload paths (/upload, /api/upload, ...)."""
    async def fake_crawl(base_url, client):
        return CrawlResult(paths=["/"])
    monkeypatch.setattr(fu, "crawl", fake_crawl)


def _install(monkeypatch, handler):
    def factory(*_a, **_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(fu, "create_web_client", factory)


async def _run(base="http://192.0.2.10:80"):
    return await fu.FileUploadPlugin()._test_host(_Ctx(), base, 80)


def _make_handler(*, accept_dangerous: bool, retrievable: bool):
    """A stateful mock upload endpoint at /upload.

    Accepts a .txt control unconditionally (Guard 1 in the plugin needs that
    to trust anything else this endpoint says). Dangerous extensions are
    accepted or rejected per `accept_dangerous`; when `retrievable` is set,
    accepted files are actually stored and served back from /uploads/<name>,
    the way a real misconfigured handler would.
    """
    storage: dict[str, str] = {}

    def handler(request):
        path = request.url.path

        if request.method == "GET" and path == "/":
            return httpx.Response(200, text="<html><body>home</body></html>")

        if request.method == "GET" and path == "/upload":
            # Distinguishes a real POST handler from a SPA catch-all: this
            # must differ from the POST control response (it does: 404).
            return httpx.Response(404, text="method not allowed")

        if request.method == "POST" and path == "/upload":
            body = request.content.decode(errors="ignore")
            match = _FILENAME_RE.search(body)
            filename = match.group(1) if match else "unknown"
            ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
            marker_start = body.find("SCANR-UPLOAD-TEST-")
            stored_text = body[marker_start:].split("\r\n--")[0] if marker_start >= 0 else ""

            if ext == ".txt":
                return httpx.Response(200, text='{"status":"stored"}')
            if not accept_dangerous:
                return httpx.Response(400, text='{"error":"file type not allowed"}')
            if retrievable:
                storage[filename] = stored_text
                return httpx.Response(200, text=f'{{"status":"stored","path":"/uploads/{filename}"}}')
            return httpx.Response(200, text='{"status":"stored"}')

        if request.method == "GET" and path.startswith("/uploads/"):
            name = path.rsplit("/", 1)[-1]
            if name in storage:
                content_type = {
                    "svg": "image/svg+xml", "html": "text/html",
                }.get(name.rsplit(".", 1)[-1], "application/octet-stream")
                return httpx.Response(200, text=storage[name], headers={"content-type": content_type})
            return httpx.Response(404, text="not found")

        return httpx.Response(404, text="not found")

    return handler


# ── acceptance ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dangerous_extension_accepted_is_reported(monkeypatch):
    _install(monkeypatch, _make_handler(accept_dangerous=True, retrievable=False))
    findings = await _run()

    assert len(findings) == 1
    assert findings[0].title == "File upload accepts dangerous extensions"
    assert findings[0].severity is Severity.medium
    assert ".php" in findings[0].evidence


@pytest.mark.asyncio
async def test_endpoint_rejecting_dangerous_extensions_produces_nothing(monkeypatch):
    _install(monkeypatch, _make_handler(accept_dangerous=False, retrievable=False))
    findings = await _run()
    assert findings == []


# ── retrievability changes the score ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_stored_and_retrievable_file_is_scored_higher_than_merely_accepted(monkeypatch):
    _install(monkeypatch, _make_handler(accept_dangerous=True, retrievable=True))
    findings = await _run()

    assert len(findings) == 2
    accepted = next(f for f in findings if "accepts dangerous extensions" in f.title)
    retrievable = next(f for f in findings if "publicly retrievable" in f.title)

    assert accepted.severity is Severity.medium
    assert retrievable.severity is Severity.high
    assert retrievable.cvss_score > accepted.cvss_score


# ── uploaded content is inert ────────────────────────────────────────────────

def test_uploaded_payloads_contain_no_executable_code():
    """Nothing this plugin writes to a target may be a working webshell --
    the check must prove the policy gap without leaving a backdoor behind."""
    forbidden = ("<?php", "<%", "<script", "eval(", "system(", "exec(", "passthru(")
    token = "deadbeefcafe"

    marker = fu._marker_body(token)
    assert not any(bad in marker for bad in forbidden), marker

    for ext, _content_type, _label in fu._DANGEROUS:
        payload = fu._payload_for(ext, token)
        assert not any(bad in payload for bad in forbidden), (ext, payload)
