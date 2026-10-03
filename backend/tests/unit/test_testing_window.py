from datetime import date, datetime, timezone

import pytest

from scanr.core.testing_window import TestingWindow, closed_message, from_profile

AMS = "Europe/Amsterdam"


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def business_hours(**kw):
    return TestingWindow(timezone=AMS, days=[0, 1, 2, 3, 4], start="09:00", end="17:00", **kw)


def test_business_hours_in_local_time():
    w = business_hours()
    # Thu 1 Oct 2026; Amsterdam is UTC+2 in October.
    assert w.is_open(utc(2026, 10, 1, 7, 0))       # 09:00 local
    assert not w.is_open(utc(2026, 10, 1, 6, 59))  # 08:59 local
    assert not w.is_open(utc(2026, 10, 1, 15, 0))  # 17:00 local: end is exclusive
    assert not w.is_open(utc(2026, 10, 3, 10, 0))  # Saturday


def test_overnight_window_belongs_to_the_day_it_starts():
    w = TestingWindow(timezone="UTC", days=[4], start="22:00", end="06:00")  # Friday night only
    assert w.is_open(utc(2026, 10, 2, 23, 0))   # Fri 23:00
    assert w.is_open(utc(2026, 10, 3, 5, 0))    # Sat 05:00, still Friday's window
    assert not w.is_open(utc(2026, 10, 3, 23, 0))  # Sat night
    assert not w.is_open(utc(2026, 10, 2, 12, 0))


def test_engagement_dates_and_next_opening():
    w = business_hours(not_before=date(2026, 10, 5), not_after=date(2026, 10, 9))
    assert not w.is_open(utc(2026, 10, 2, 10, 0))  # Friday before the engagement
    assert w.next_opening(utc(2026, 10, 2, 10, 0)) == utc(2026, 10, 5, 7, 0)
    assert w.is_open(utc(2026, 10, 9, 10, 0))
    assert not w.is_open(utc(2026, 10, 12, 10, 0))
    assert w.next_opening(utc(2026, 10, 12, 10, 0)) is None
    assert "engagement period has ended" in closed_message(w, utc(2026, 10, 12, 10, 0))
    assert "opens next on Mon 05 Oct 2026 09:00" in closed_message(w, utc(2026, 10, 2, 10, 0))


def test_describe():
    assert business_hours().describe() == "Mon–Fri 09:00–17:00 (Europe/Amsterdam)"
    assert TestingWindow(days=[5, 6], start="08:00", end="20:00").describe() == "Sat–Sun 08:00–20:00 (UTC)"


@pytest.mark.parametrize("kw", [
    {"timezone": "Mars/Olympus"}, {"start": "09:00", "end": "09:00"}, {"days": [7]},
    {"start": "9:00"}, {"not_before": date(2026, 10, 9), "not_after": date(2026, 10, 1)},
])
def test_validation(kw):
    with pytest.raises(ValueError):
        TestingWindow(**kw)


def test_from_profile_and_profile_validation():
    from scanr.schemas.profile import validate_profile_dict

    profile = validate_profile_dict({"testing_window": {"timezone": AMS, "days": [0], "start": "09:00", "end": "17:00"}})
    assert profile["testing_window"]["timezone"] == AMS
    assert from_profile(profile).days == [0]
    assert from_profile('{"stealth": true}') is None and from_profile(None) is None
    with pytest.raises(ValueError):
        validate_profile_dict({"testing_window": {"timezone": "nowhere"}})
