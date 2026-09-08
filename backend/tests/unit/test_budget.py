"""The wall-clock budget payload plugins use to stop themselves.

Without it, paths x params x payloads can exceed a plugin's own declared
timeout, and the engine cancels the check mid-iteration — recorded as a timeout,
but with no partial result for that host.
"""
import time

from scanr.plugins.web._budget import Budget


def test_a_fresh_budget_has_time_and_is_not_spent():
    b = Budget(10.0)
    assert 0 < b.remaining <= 10.0
    assert b.spent() is False
    assert b.expired_early is False


def test_a_zero_budget_is_immediately_spent():
    b = Budget(0.0)
    assert b.spent() is True
    assert b.remaining == 0.0


def test_spent_latches_expired_early_for_the_caller():
    """The plugin reports partial coverage, so the flag must persist."""
    b = Budget(0.0)
    b.spent()
    assert b.expired_early is True


def test_checking_a_live_budget_does_not_latch_the_flag():
    b = Budget(30.0)
    for _ in range(3):
        assert b.spent() is False
    assert b.expired_early is False


def test_clamp_never_waits_longer_than_the_budget_has_left():
    b = Budget(2.0)
    assert b.clamp(60.0) <= 2.0


def test_clamp_leaves_a_usable_floor_on_an_empty_budget():
    """Clamping to zero would turn every request into an instant failure."""
    b = Budget(0.0)
    assert b.clamp(30.0) == 0.5


def test_clamp_leaves_a_shorter_timeout_alone():
    b = Budget(60.0)
    assert b.clamp(5.0) == 5.0


def test_remaining_decreases_over_time():
    b = Budget(5.0)
    first = b.remaining
    time.sleep(0.05)
    assert b.remaining < first


def test_note_names_the_allowance_and_says_coverage_is_partial():
    note = Budget(210.0).note()
    assert "210s" in note
    assert "partial" in note
