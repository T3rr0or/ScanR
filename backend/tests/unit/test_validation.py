"""What counts as proof that a finding is real.

These tests exist because the `validated` flag is only worth anything if it is
hard to earn. The two rules that matter: reflection is not execution, and a
browser that could not load the page says `inconclusive` — never "not
vulnerable".
"""
import pytest

from scanr.core.validation import evaluate, new_canary


def obs(**kw):
    base = {
        "url": "http://192.0.2.10/search?q=x",
        "final_url": "http://192.0.2.10/search?q=x",
        "status": 200,
        "title": "Search",
        "dialogs": [],
        "console": [],
        "page_errors": [],
        "canary_in_dom": False,
        "error": None,
    }
    base.update(kw)
    return base


CANARY = "scanr0123456789abcdef"


# ── proof ────────────────────────────────────────────────────────────────────

def test_dialog_carrying_the_canary_is_proof():
    r = evaluate(obs(dialogs=[{"type": "alert", "message": CANARY}]), CANARY)
    assert r.verdict == "proved" and r.proved
    assert r.method == "browser-dialog"
    assert CANARY in r.evidence


def test_prompt_default_value_also_counts():
    """alert() is the common payload, but prompt()/confirm() prove the same thing."""
    r = evaluate(obs(dialogs=[{"type": "prompt", "message": "hi", "default_value": CANARY}]), CANARY)
    assert r.proved


def test_console_output_is_proof_but_named_separately():
    r = evaluate(obs(console=[{"type": "log", "text": f"xss {CANARY}"}]), CANARY)
    assert r.proved
    assert r.method == "browser-console", "a reader should be able to tell which channel proved it"


def test_dialog_wins_over_console_when_both_fire():
    r = evaluate(
        obs(dialogs=[{"type": "alert", "message": CANARY}],
            console=[{"type": "log", "text": CANARY}]),
        CANARY,
    )
    assert r.method == "browser-dialog"


# ── not proof ────────────────────────────────────────────────────────────────

def test_reflection_alone_is_not_a_vulnerability():
    """The single most common false positive in web scanning: the parameter is
    echoed, in a context where it can never execute."""
    r = evaluate(obs(canary_in_dom=True), CANARY)
    assert r.verdict == "reflected"
    assert not r.proved
    assert r.method is None


def test_nothing_at_all_is_not_reproduced():
    r = evaluate(obs(), CANARY)
    assert r.verdict == "not_reproduced" and not r.proved


def test_a_dialog_without_our_canary_proves_nothing():
    """Plenty of sites pop their own dialogs; that is not our payload running."""
    r = evaluate(obs(dialogs=[{"type": "alert", "message": "Cookies?"}]), CANARY)
    assert r.verdict == "not_reproduced"


def test_page_errors_alone_are_not_proof():
    r = evaluate(obs(page_errors=[{"text": "ReferenceError: foo is not defined"}]), CANARY)
    assert not r.proved
    assert "ReferenceError" in r.evidence, "still worth recording for the reader"


# ── inconclusive ─────────────────────────────────────────────────────────────

def test_a_page_that_would_not_load_is_inconclusive_not_clean():
    """Same rule as an unreachable host in a retest: absence of a result is not
    a result. Reporting this as 'not_reproduced' would let a firewall or a
    momentary outage silently downgrade a real finding."""
    r = evaluate(obs(error="net::ERR_CONNECTION_REFUSED"), CANARY)
    assert r.verdict == "inconclusive" and not r.proved
    assert "ERR_CONNECTION_REFUSED" in r.summary


def test_missing_observations_are_inconclusive():
    for bad in (None, "", [], {}):
        assert evaluate(bad, CANARY).verdict == "inconclusive"


def test_malformed_observation_entries_do_not_raise():
    r = evaluate(obs(dialogs=["not a dict", None], console="nope", page_errors=42), CANARY)
    assert r.verdict == "not_reproduced"


# ── the canary itself ────────────────────────────────────────────────────────

def test_canaries_are_unique_and_well_formed():
    tokens = {new_canary() for _ in range(200)}
    assert len(tokens) == 200, "a replayed token could manufacture a proof"
    assert all(t.startswith("scanr") and len(t) == 21 for t in tokens)
    assert all(t.isalnum() for t in tokens), "must survive HTML/JS/URL encoding intact"


@pytest.mark.parametrize("needle", ["", None, "admin", "scanr", "scanrZZZZZZZZZZZZZZZZ", "<script>"])
def test_only_a_canary_we_issued_can_prove_anything(needle):
    """Otherwise a caller could pass a string it knows is on the page — e.g. the
    site's own name — and call the result proof."""
    r = evaluate(obs(dialogs=[{"type": "alert", "message": str(needle)}]), needle)
    assert r.verdict == "inconclusive"
    assert not r.proved


def test_a_generated_canary_is_accepted():
    canary = new_canary()
    assert evaluate(obs(dialogs=[{"type": "alert", "message": canary}]), canary).proved


# ── evidence ─────────────────────────────────────────────────────────────────

def test_evidence_records_what_a_reader_needs_to_believe_it():
    r = evaluate(
        obs(url="http://192.0.2.10/q?s=X", final_url="http://192.0.2.10/login",
            status=302, title="Login", dialogs=[{"type": "alert", "message": CANARY}]),
        CANARY,
    )
    assert "http://192.0.2.10/q?s=X" in r.evidence
    assert "Redirected to: http://192.0.2.10/login" in r.evidence
    assert "302" in r.evidence
    assert "alert()" in r.evidence


def test_evidence_is_bounded():
    r = evaluate(obs(console=[{"type": "log", "text": "x" * 5000} for _ in range(50)]), CANARY)
    assert len(r.evidence) <= 4000


# ── the browser driver's time budget ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_hanging_page_cannot_hold_a_worker(monkeypatch):
    """Regression: only goto was bounded, so everything after it ran with no
    timeout at all. A page with an infinite JS loop held a worker at ~100% CPU
    for 242s and counting; a server that accepts and stalls held one for exactly
    the delay it chose. The target must not decide when we let go."""
    import asyncio
    import time

    from scanr.core import browser

    class HangingPage:
        url = "http://192.0.2.10/"

        def __init__(self):
            self.timeout_ms = None

        def set_default_timeout(self, ms):
            self.timeout_ms = ms

        def on(self, *_a):
            pass

        async def goto(self, *_a, **_kw):
            return None

        async def title(self):
            await asyncio.sleep(3600)  # renderer wedged

        async def content(self):
            await asyncio.sleep(3600)

        async def screenshot(self, **_kw):
            await asyncio.sleep(3600)

    class Ctx:
        def __init__(self, page):
            self._page = page

        async def new_page(self):
            return self._page

        async def close(self):
            return None

    class Browser:
        def __init__(self, page):
            self._page = page

        async def new_context(self, **_kw):
            return Ctx(self._page)

        async def close(self):
            return None

    page = HangingPage()

    class PW:
        class chromium:
            @staticmethod
            async def launch(**_kw):
                return Browser(page)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    monkeypatch.setattr(browser, "async_playwright", lambda: PW(), raising=False)
    monkeypatch.setitem(__import__("sys").modules, "playwright.async_api",
                        type("m", (), {"async_playwright": lambda: PW()}))

    started = time.monotonic()
    obs = await browser.observe_url("http://192.0.2.10/", "scanr0123456789abcdef",
                                    settle_seconds=0, overall_timeout=1.0)
    elapsed = time.monotonic() - started

    assert elapsed < 10, f"the cap did not fire — took {elapsed:.1f}s"
    assert obs["error"], "a run that gave up must not look like a clean observation"
    assert page.timeout_ms == 15_000, "per-call timeouts must be armed too"
    from scanr.core.validation import evaluate
    assert evaluate(obs, "scanr0123456789abcdef").verdict == "inconclusive"


@pytest.mark.asyncio
async def test_concurrent_validations_are_bounded(monkeypatch):
    """The 60s cap makes one hostile page survivable, not cheap — a page spinning
    in a JS loop pins a core for the whole 60s. Unbounded concurrency lets the
    *target* pick the multiplier by choosing which of its pages hang."""
    import asyncio

    from scanr.core import browser

    live = 0
    peak = 0

    class Page:
        url = "http://192.0.2.10/"

        def set_default_timeout(self, ms):
            pass

        def on(self, *_a):
            pass

        async def goto(self, *_a, **_kw):
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.15)
            return None

        async def title(self):
            return "t"

        async def content(self):
            return ""

    class Ctx:
        async def new_page(self):
            return Page()

        async def close(self):
            nonlocal live
            live -= 1

    class Browser:
        async def new_context(self, **_kw):
            return Ctx()

        async def close(self):
            return None

    class PW:
        class chromium:
            @staticmethod
            async def launch(**_kw):
                return Browser()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    monkeypatch.setitem(__import__("sys").modules, "playwright.async_api",
                        type("m", (), {"async_playwright": lambda: PW()}))
    # Reset the per-loop semaphore so the cap under test is the one asserted.
    monkeypatch.setattr(browser, "_slots", None)
    monkeypatch.setattr(browser, "_configured_concurrency", lambda: 2)

    await asyncio.gather(*[
        browser.observe_url("http://192.0.2.10/", "scanr0123456789abcdef", settle_seconds=0)
        for _ in range(10)
    ])
    assert peak <= 2, f"{peak} browsers ran at once against a cap of 2"


def test_the_concurrency_cap_is_configurable():
    """The deployment ceiling is this × the Celery pool size, so an operator on a
    small host needs to be able to turn it down without editing code."""
    from scanr.core import browser
    from scanr.config import get_settings

    assert get_settings().browser_validation_concurrency == browser.MAX_CONCURRENT
    assert browser._configured_concurrency() >= 1


def test_a_broken_setting_does_not_remove_the_cap(monkeypatch):
    """Falling open here would restore the unbounded amplifier."""
    from scanr.core import browser

    def boom():
        raise RuntimeError("no settings")

    monkeypatch.setattr("scanr.config.get_settings", boom)
    assert browser._configured_concurrency() == browser.MAX_CONCURRENT

    class Zero:
        browser_validation_concurrency = 0

    monkeypatch.setattr("scanr.config.get_settings", lambda: Zero())
    assert browser._configured_concurrency() == 1, "zero would mean a deadlock, not no limit"
