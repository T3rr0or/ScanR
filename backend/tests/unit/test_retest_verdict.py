"""Retest verdict logic.

"Resolved" is a claim a client acts on — they close the ticket — so the bar for
returning it is deliberately high, and these tests pin that. The expensive
failure mode is not a missed fix; it is calling a live vulnerability fixed.
"""
import pytest

from scanr.core.retest import decide_verdict, summarise_observations


def obs(title, severity="high", port=None, evidence=None):
    return {"title": title, "severity": severity, "port_number": port, "evidence": evidence}


# ── still present ────────────────────────────────────────────────────────────

def test_identical_finding_is_still_present():
    out = decide_verdict(
        original_title="Anonymous FTP login allowed",
        original_port=21,
        observations=[obs("Anonymous FTP login allowed", port=21)],
    )
    assert out.verdict == "still_present"
    assert "Anonymous FTP" in out.evidence


def test_title_containment_matches_either_direction():
    """Titles often gain or lose a port/version between runs; exact equality
    would report a live issue as fixed."""
    for original, observed in [
        ("Anonymous FTP login allowed", "Anonymous FTP login allowed on port 21"),
        ("Anonymous FTP login allowed on port 21", "Anonymous FTP login allowed"),
    ]:
        out = decide_verdict(original_title=original, original_port=None,
                             observations=[obs(observed)])
        assert out.verdict == "still_present", f"{original!r} vs {observed!r}"


def test_matching_is_case_and_whitespace_insensitive():
    out = decide_verdict(
        original_title="Redis   accessible without authentication",
        original_port=None,
        observations=[obs("redis accessible WITHOUT authentication")],
    )
    assert out.verdict == "still_present"


# ── resolved ─────────────────────────────────────────────────────────────────

def test_nothing_reported_is_resolved():
    out = decide_verdict(
        original_title="Anonymous FTP login allowed", original_port=21, observations=[]
    )
    assert out.verdict == "resolved"


def test_other_findings_but_not_this_one_is_resolved_and_says_so():
    """Evidence that the plugin ran makes 'resolved' much stronger than silence."""
    out = decide_verdict(
        original_title="Anonymous FTP login allowed",
        original_port=21,
        observations=[obs("FTP server allows cleartext credentials", port=21)],
    )
    assert out.verdict == "resolved"
    assert "1 other finding" in out.evidence
    assert "cleartext" in out.evidence


def test_same_plugin_different_port_is_resolved_for_this_finding():
    out = decide_verdict(
        original_title="Weak cipher supported",
        original_port=443,
        observations=[obs("Weak cipher supported", port=8443)],
    )
    assert out.verdict == "resolved"


# ── inconclusive ─────────────────────────────────────────────────────────────

def test_unreachable_host_is_never_resolved():
    """A box switched off during the retest window has not been remediated.
    Reporting it as fixed is how a live vulnerability gets closed."""
    out = decide_verdict(
        original_title="Anonymous FTP login allowed",
        original_port=21,
        observations=[],
        host_reachable=False,
    )
    assert out.verdict == "inconclusive"
    assert "not evidence of remediation" in out.evidence


def test_unreachable_host_is_inconclusive_even_with_observations():
    out = decide_verdict(
        original_title="X", original_port=None,
        observations=[obs("X")], host_reachable=False,
    )
    assert out.verdict == "inconclusive"


@pytest.mark.parametrize("title", ["", "   "])
def test_untitled_observation_does_not_match(title):
    """A blank title must not silently satisfy the containment check —
    '' in 'anything' is True in Python, which would mark everything present."""
    out = decide_verdict(
        original_title="Anonymous FTP login allowed",
        original_port=None,
        observations=[obs(title)],
    )
    assert out.verdict == "resolved"


def test_blank_original_title_does_not_match_everything():
    out = decide_verdict(original_title="  ", original_port=None,
                         observations=[obs("Something else entirely")])
    assert out.verdict == "resolved"


# ── evidence rendering ───────────────────────────────────────────────────────

def test_summary_truncates_long_lists():
    out = summarise_observations([obs(f"Finding {i}") for i in range(12)], limit=3)
    assert out.count("\n- ") <= 3
    assert "and 9 more" in out


def test_summary_includes_severity_port_and_evidence():
    out = summarise_observations([obs("Weak cipher", severity="medium", port=443,
                                      evidence="TLS_RSA_WITH_3DES_EDE_CBC_SHA")])
    assert "[medium]" in out and "port 443" in out and "3DES" in out


def test_summary_of_nothing_is_empty():
    assert summarise_observations([]) == ""
