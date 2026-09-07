"""Headless Chromium driver used to reproduce findings.

Separate from plugins/web/screenshot.py because the two want opposite things.
The screenshot plugin renders a page with **JavaScript disabled** — it wants a
safe static snapshot of a hostile target. Validation has to run the page's
script, because "the payload executed" is the whole question. So this module
turns JS on and instruments the channels a payload can announce itself through:
dialogs, the console, and uncaught errors.

Everything here is best-effort and never raises: a validation attempt that could
not run must come back as ``inconclusive``, which is the caller's job to decide
(core/validation.py), not something to signal by blowing up a scan.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from pathlib import Path
from urllib.parse import urlparse

__all__ = ["BROWSER_ARGS", "observe_url"]

logger = logging.getLogger(__name__)

#: --no-sandbox is required to run Chromium as a non-root user in a container;
#: the OS sandbox needs SYS_ADMIN or user namespaces, which we don't grant.
BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-webrtc",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
]

#: Caps on what we bring back. A hostile page can emit console output forever;
#: this content ends up in a finding and in the model's context.
MAX_DIALOGS = 10
MAX_CONSOLE = 50
MAX_ERRORS = 20
MAX_TEXT = 2000
MAX_REMOTE_RESPONSE = 8 * 1024 * 1024


#: Hard ceiling on one whole attempt, enforced outside Playwright.
#:
#: ``timeout_ms`` only ever bounded ``goto``. Everything after it — title(),
#: content(), screenshot() — ran with Playwright's default (no cap once
#: set_default_timeout is unset), so the *target* decided when a worker was
#: released: a page with an infinite JS loop held one at 99.8% CPU for 242s and
#: counting, and a server that accepts then stalls held one for exactly the 120s
#: it chose. Per-call timeouts fix the ordinary cases; this wall-clock cap is
#: what makes the worst case bounded regardless of what the page does.
OVERALL_TIMEOUT_SECONDS = 60.0

#: Default concurrent validations **per event loop**, overridable via
#: BROWSER_VALIDATION_CONCURRENCY.
#:
#: The wall-clock cap above makes one hostile page *survivable*, not cheap: a page
#: spinning in a JS loop still pins a core for the full 60 seconds. Unbounded
#: concurrency turns that into an amplifier — the target picks the multiplier by
#: choosing which of its pages hang.
#:
#: Be precise about what this bounds. It is per event loop, which under Celery's
#: prefork pool means per worker *process*, so the deployment ceiling is this
#: value × the worker's --concurrency. At the shipped defaults (2 × 4) that is 8
#: concurrent spinning browsers, ~8 cores for a minute — half of a 16-core host,
#: not two cores. Raising --concurrency raises this ceiling linearly.
#:
#: A genuinely global cap would need a cross-process primitive (a file lock, a
#: POSIX semaphore, a Redis lease) rather than an asyncio one; the per-loop
#: design is what keeps it correct across the multiple loops a worker creates.
#: Making the number configurable is the honest middle: the ceiling is a
#: deliberate choice per deployment rather than an accident of pool size.
#:
#: If you are checking whether this cap works, do not count processes. Chromium
#: forks helpers, so the count scales at roughly 6 per browser plus a baseline —
#: measured 7 / 13 / 19 processes at caps of 1 / 2 / 3. A `pgrep chromium | wc -l`
#: sanity check therefore reads as though the cap were broken when it is holding
#: exactly. Count concurrent *launches* instead, as tests/unit/test_validation.py
#: does.
MAX_CONCURRENT = 2
MAX_CONFIGURED_CONCURRENT = 16
_slots: "asyncio.Semaphore | None" = None
_slots_loop: object = None


def _slot() -> "asyncio.Semaphore":
    """One semaphore per event loop.

    Built lazily rather than at import: a module-level Semaphore binds to
    whichever loop imported it, and Celery workers do not share one loop.
    """
    global _slots, _slots_loop

    loop = asyncio.get_running_loop()
    if _slots is None or _slots_loop is not loop:
        _slots = asyncio.Semaphore(_configured_concurrency())
        _slots_loop = loop
    return _slots


def _configured_concurrency() -> int:
    raw = os.environ.get("BROWSER_VALIDATION_CONCURRENCY")
    if raw is not None:
        try:
            return max(1, min(int(raw), MAX_CONFIGURED_CONCURRENT))
        except ValueError:
            return MAX_CONCURRENT
    try:
        from scanr.config import get_settings

        return max(
            1,
            min(
                int(get_settings().browser_validation_concurrency),
                MAX_CONFIGURED_CONCURRENT,
            ),
        )
    except Exception:  # noqa: BLE001 - a config problem must not disable the cap
        return MAX_CONCURRENT


async def observe_url(
    url: str,
    canary: str,
    *,
    timeout_ms: int = 15_000,
    settle_seconds: float = 1.5,
    screenshot_path: str | None = None,
    overall_timeout: float = OVERALL_TIMEOUT_SECONDS,
    java_script_enabled: bool = True,
) -> dict:
    """Load ``url`` with JavaScript enabled and report what the page did.

    Returns the observation dict consumed by ``core.validation.evaluate``:
    dialogs, console messages, page errors, whether ``canary`` reached the
    rendered DOM, plus status/title/final URL for the evidence record.
    """
    service_url = os.environ.get("BROWSER_SERVICE_URL", "").rstrip("/")
    if service_url:
        return await _observe_remote(
            service_url,
            url,
            canary,
            timeout_ms=timeout_ms,
            settle_seconds=settle_seconds,
            screenshot_path=screenshot_path,
            overall_timeout=overall_timeout,
            java_script_enabled=java_script_enabled,
        )
    if os.environ.get("SCANR_REQUIRE_BROWSER_SERVICE", "").lower() in {"1", "true", "yes"}:
        return _empty_observation(url, "isolated browser service is required but unavailable")
    return await _observe_url_local(
        url,
        canary,
        timeout_ms=timeout_ms,
        settle_seconds=settle_seconds,
        screenshot_path=screenshot_path,
        overall_timeout=overall_timeout,
        java_script_enabled=java_script_enabled,
    )


def _empty_observation(url: str, error: str | None = None) -> dict:
    return {
        "url": url,
        "final_url": None,
        "status": None,
        "content_type": None,
        "title": None,
        "dialogs": [],
        "console": [],
        "page_errors": [],
        "canary_in_dom": False,
        "screenshot": None,
        "error": error,
    }


async def _observe_remote(
    service_url: str,
    url: str,
    canary: str,
    *,
    timeout_ms: int,
    settle_seconds: float,
    screenshot_path: str | None,
    overall_timeout: float,
    java_script_enabled: bool,
) -> dict:
    """Ask the secret-free browser sidecar to render hostile content."""
    obs = _empty_observation(url)
    token = os.environ.get("BROWSER_SERVICE_TOKEN", "")
    if not token:
        obs["error"] = "browser service token is not configured"
        return obs
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(overall_timeout + 15.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with client.stream(
                "POST",
                f"{service_url}/observe",
                headers={"X-Browser-Token": token},
                json={
                    "url": url,
                    "canary": canary,
                    "timeout_ms": timeout_ms,
                    "settle_seconds": settle_seconds,
                    "overall_timeout": overall_timeout,
                    "java_script_enabled": java_script_enabled,
                    "screenshot": screenshot_path is not None,
                },
            ) as response:
                response.raise_for_status()
                raw_response = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(raw_response) + len(chunk) > MAX_REMOTE_RESPONSE:
                        raise ValueError("browser service response exceeded 8 MiB")
                    raw_response.extend(chunk)
        payload = json.loads(raw_response)
        if not isinstance(payload, dict):
            raise ValueError("browser service returned a non-object response")
        screenshot_b64 = payload.pop("screenshot_b64", None)
        obs.update({key: payload[key] for key in obs if key in payload})
        if screenshot_path and screenshot_b64:
            raw = base64.b64decode(screenshot_b64, validate=True)
            if len(raw) > 5 * 1024 * 1024:
                raise ValueError("browser screenshot exceeded 5 MiB")
            destination = Path(screenshot_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(destination.write_bytes, raw)
            obs["screenshot"] = screenshot_path
        return obs
    except Exception as exc:  # noqa: BLE001 - validation is best-effort
        obs["error"] = f"browser service unavailable: {exc}"[:256]
        return obs


async def _observe_url_local(
    url: str,
    canary: str,
    *,
    timeout_ms: int = 15_000,
    settle_seconds: float = 1.5,
    screenshot_path: str | None = None,
    overall_timeout: float = OVERALL_TIMEOUT_SECONDS,
    java_script_enabled: bool = True,
    pinned_host: tuple[str, str] | None = None,
) -> dict:
    """Local renderer used by the dedicated browser service and development tests."""
    obs = _empty_observation(url)

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        obs["error"] = "playwright is not installed"
        return obs

    # Queue outside the browser so a spinning page occupies a slot, not a core
    # each. Acquired before launch: the launch itself is the expensive part.
    async with _slot():
        return await _run(
            obs, async_playwright, url, canary, timeout_ms, settle_seconds,
            screenshot_path, overall_timeout, java_script_enabled, pinned_host,
        )


async def _run(obs, async_playwright, url, canary, timeout_ms, settle_seconds,
               screenshot_path, overall_timeout, java_script_enabled,
               pinned_host) -> dict:
    try:
        async with async_playwright() as pw:
            try:
                browser_args = list(BROWSER_ARGS)
                if pinned_host:
                    hostname, ip = pinned_host
                    # Chromium keeps the original URL/Host/SNI but never performs a
                    # second DNS lookup, closing the validation-to-connect rebind gap.
                    browser_args.append(f"--host-resolver-rules=MAP {hostname} {ip}")
                browser = await pw.chromium.launch(args=browser_args, headless=True)
            except Exception as exc:  # noqa: BLE001 - reported as inconclusive
                obs["error"] = f"chromium unavailable: {exc}"[:256]
                return obs
            try:
                await asyncio.wait_for(
                    _observe(
                        browser, url, canary, obs, timeout_ms, settle_seconds,
                        screenshot_path, java_script_enabled,
                    ),
                    timeout=overall_timeout,
                )
            except asyncio.TimeoutError:
                # Whatever was captured before the cap still counts — a page that
                # popped our dialog and then hung has already proved the point.
                obs["error"] = obs["error"] or (
                    f"gave up after {overall_timeout:.0f}s — the page never settled"
                )
            finally:
                # close() itself can hang on a wedged renderer, so it is bounded too.
                try:
                    await asyncio.wait_for(browser.close(), timeout=10)
                except Exception:  # noqa: BLE001
                    pass
    except Exception as exc:  # noqa: BLE001 - never let a target break the caller
        obs["error"] = obs["error"] or str(exc)[:256]
    return obs


async def _observe(
    browser, url, canary, obs, timeout_ms, settle_seconds, screenshot_path,
    java_script_enabled=True,
):
    ctx = await browser.new_context(
        viewport={"width": 1280, "height": 800},
        ignore_https_errors=True,
        java_script_enabled=java_script_enabled,
        service_workers="block",
        extra_http_headers={"User-Agent": "Mozilla/5.0 ScanR/0.1"},
    )
    try:
        allowed = urlparse(url)

        async def constrain_request(route) -> None:
            """Keep redirects and subresources on the exact authorized origin."""
            if not _same_http_origin(route.request.url, allowed):
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        # Context-level routing also covers popups and worker requests; page-only
        # routing would let hostile JavaScript open a second, unrestricted page.
        await ctx.route("**/*", constrain_request)
        # Playwright routes WebSockets through a separate API: HTTP request
        # routing does not see their handshakes. Browser validation does not
        # need a bidirectional channel, so block every WebSocket rather than
        # risk a hostile page probing or exfiltrating to a different host.
        await ctx.route_web_socket("**/*", _block_web_socket)
        page = await ctx.new_page()
        # Applies to every subsequent page call, not just goto. Without it, an
        # unresponsive renderer makes title()/content()/screenshot() wait forever.
        page.set_default_timeout(timeout_ms)

        # Dialogs must be dismissed explicitly or navigation blocks until the
        # timeout — and an undismissed dialog also hides everything after it.
        async def on_dialog(dialog):
            if len(obs["dialogs"]) < MAX_DIALOGS:
                obs["dialogs"].append({
                    "type": dialog.type,
                    "message": (dialog.message or "")[:MAX_TEXT],
                    "default_value": (dialog.default_value or "")[:200],
                })
            try:
                await dialog.dismiss()
            except Exception:  # noqa: BLE001
                pass

        page.on("dialog", lambda d: asyncio.ensure_future(on_dialog(d)))
        page.on("console", lambda m: _append(
            obs["console"], {"type": m.type, "text": (m.text or "")[:MAX_TEXT]}, MAX_CONSOLE))
        page.on("pageerror", lambda e: _append(
            obs["page_errors"], {"text": str(e)[:MAX_TEXT]}, MAX_ERRORS))

        try:
            resp = await page.goto(url, timeout=timeout_ms, wait_until="load")
            obs["status"] = resp.status if resp else None
            obs["content_type"] = resp.headers.get("content-type", "") if resp else None
        except Exception as exc:  # noqa: BLE001
            # A navigation timeout is not necessarily a failure: a payload that
            # opens a modal dialog stalls load. Keep going and let what we did
            # capture speak — but record why in case nothing did.
            obs["error"] = str(exc)[:256]

        # Give deferred script (and any dialog it opens) a moment to run.
        await asyncio.sleep(settle_seconds)

        try:
            obs["final_url"] = page.url
            obs["title"] = (await page.title())[:200]
            content = await page.content()
            obs["canary_in_dom"] = bool(canary) and canary in content
        except Exception:  # noqa: BLE001 - the page may be gone; observations stand
            pass

        if screenshot_path:
            try:
                await page.screenshot(path=screenshot_path, full_page=False)
                obs["screenshot"] = screenshot_path
            except Exception:  # noqa: BLE001 - a screenshot is a nicety, not the proof
                pass

        # Something was captured, so the navigation error is noise — clearing it
        # matters because evaluate() treats a load error as inconclusive, and we
        # do not want a dialog-induced timeout to mask actual proof.
        if obs["error"] and (obs["dialogs"] or obs["console"] or obs["canary_in_dom"]):
            obs["error"] = None
    finally:
        # Bounded as well: this runs on the cancellation path when the overall
        # cap fires, and asyncio.wait_for does not return until the cancelled
        # task finishes — an unbounded close here would defeat the whole cap.
        try:
            await asyncio.wait_for(ctx.close(), timeout=5)
        except Exception:  # noqa: BLE001
            pass


async def _block_web_socket(web_socket) -> None:
    """Close browser-created WebSockets before Playwright connects upstream."""
    await web_socket.close(code=1008, reason="Blocked by ScanR origin policy")


def _same_http_origin(requested_url: str, allowed) -> bool:
    """Fail-closed exact-origin comparison for every browser HTTP request."""
    requested = urlparse(requested_url)
    if requested.scheme not in {"http", "https"} or requested.scheme != allowed.scheme:
        return False
    if requested.hostname != allowed.hostname:
        return False
    try:
        allowed_port = allowed.port or (443 if allowed.scheme == "https" else 80)
        requested_port = requested.port or (443 if requested.scheme == "https" else 80)
    except ValueError:
        return False
    return requested_port == allowed_port


def _append(bucket: list, item: dict, cap: int) -> None:
    if len(bucket) < cap:
        bucket.append(item)
