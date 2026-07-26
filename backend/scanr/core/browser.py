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
import logging

__all__ = ["BROWSER_ARGS", "observe_url"]

logger = logging.getLogger(__name__)

#: --no-sandbox is required to run Chromium as a non-root user in a container;
#: the OS sandbox needs SYS_ADMIN or user namespaces, which we don't grant.
BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]

#: Caps on what we bring back. A hostile page can emit console output forever;
#: this content ends up in a finding and in the model's context.
MAX_DIALOGS = 10
MAX_CONSOLE = 50
MAX_ERRORS = 20
MAX_TEXT = 2000


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

#: How many attempts may hold a browser at once, per worker process.
#:
#: The wall-clock cap above makes one hostile page *survivable*, not cheap: a page
#: spinning in a JS loop still pins a core for the full 60 seconds. Unbounded
#: concurrency turns that into an amplifier — N validations against a target that
#: chooses to spin cost N cores for a minute, and the target picks N by deciding
#: which of its pages hang. Serialising past a small number caps the damage at a
#: predictable slice of the host, at the cost of queueing validations, which are
#: not latency-sensitive.
MAX_CONCURRENT = 2
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
        _slots = asyncio.Semaphore(MAX_CONCURRENT)
        _slots_loop = loop
    return _slots


async def observe_url(
    url: str,
    canary: str,
    *,
    timeout_ms: int = 15_000,
    settle_seconds: float = 1.5,
    screenshot_path: str | None = None,
    overall_timeout: float = OVERALL_TIMEOUT_SECONDS,
) -> dict:
    """Load ``url`` with JavaScript enabled and report what the page did.

    Returns the observation dict consumed by ``core.validation.evaluate``:
    dialogs, console messages, page errors, whether ``canary`` reached the
    rendered DOM, plus status/title/final URL for the evidence record.
    """
    obs: dict = {
        "url": url,
        "final_url": None,
        "status": None,
        "title": None,
        "dialogs": [],
        "console": [],
        "page_errors": [],
        "canary_in_dom": False,
        "screenshot": None,
        "error": None,
    }

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        obs["error"] = "playwright is not installed"
        return obs

    # Queue outside the browser so a spinning page occupies a slot, not a core
    # each. Acquired before launch: the launch itself is the expensive part.
    async with _slot():
        return await _run(obs, async_playwright, url, canary, timeout_ms,
                          settle_seconds, screenshot_path, overall_timeout)


async def _run(obs, async_playwright, url, canary, timeout_ms, settle_seconds,
               screenshot_path, overall_timeout) -> dict:
    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(args=BROWSER_ARGS, headless=True)
            except Exception as exc:  # noqa: BLE001 - reported as inconclusive
                obs["error"] = f"chromium unavailable: {exc}"[:256]
                return obs
            try:
                await asyncio.wait_for(
                    _observe(browser, url, canary, obs, timeout_ms, settle_seconds, screenshot_path),
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


async def _observe(browser, url, canary, obs, timeout_ms, settle_seconds, screenshot_path):
    ctx = await browser.new_context(
        viewport={"width": 1280, "height": 800},
        ignore_https_errors=True,
        java_script_enabled=True,
        extra_http_headers={"User-Agent": "Mozilla/5.0 ScanR/0.1"},
    )
    try:
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
            obs["canary_in_dom"] = canary in content
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


def _append(bucket: list, item: dict, cap: int) -> None:
    if len(bucket) < cap:
        bucket.append(item)
