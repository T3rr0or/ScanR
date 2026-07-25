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
