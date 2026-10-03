"""Agreed testing windows: when a scan may send traffic.

A window has weekdays and a daily time range in a time zone, plus optional
first and last dates of the engagement. A range whose end is before its start
runs overnight (22:00-06:00). The window is stored in the scan's profile_json,
so reruns, clones, templates and schedules carry it automatically.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, field_validator, model_validator

_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class TestingWindow(BaseModel):
    timezone: str = "UTC"
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6], min_length=1, max_length=7)
    start: str = Field("00:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    end: str = Field("23:59", pattern=r"^([01]\d|2[0-3]):[0-5]\d$|^24:00$")
    not_before: date | None = None
    not_after: date | None = None

    @field_validator("timezone")
    @classmethod
    def _zone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Unknown time zone {v!r}") from exc
        return v

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if any(d < 0 or d > 6 for d in v):
            raise ValueError("days are 0 (Monday) to 6 (Sunday)")
        return sorted(set(v))

    @model_validator(mode="after")
    def _dates(self) -> "TestingWindow":
        if self.not_before and self.not_after and self.not_after < self.not_before:
            raise ValueError("The last testing day is before the first")
        if self.start == self.end:
            raise ValueError("The daily window needs a different start and end time")
        return self

    # ── evaluation ──────────────────────────────────────────────────────────

    def _zone_info(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @staticmethod
    def _t(value: str) -> time:
        return time(23, 59, 59) if value == "24:00" else time.fromisoformat(value)

    def is_open(self, when: datetime | None = None) -> bool:
        local = (when or datetime.now(timezone.utc)).astimezone(self._zone_info())
        start, end = self._t(self.start), self._t(self.end)
        now_t = local.time()
        if start < end:
            day = local.date()
            in_hours = start <= now_t < end or (self.end == "24:00" and now_t >= start)
        else:  # overnight: the window belongs to the day it started on
            if now_t >= start:
                day, in_hours = local.date(), True
            elif now_t < end:
                day, in_hours = local.date() - timedelta(days=1), True
            else:
                return False
        if not in_hours or day.weekday() not in self.days:
            return False
        if self.not_before and day < self.not_before:
            return False
        if self.not_after and day > self.not_after:
            return False
        return True

    def next_opening(self, when: datetime | None = None) -> datetime | None:
        """The next moment the window opens (UTC), or None if it never will."""
        now = when or datetime.now(timezone.utc)
        zone = self._zone_info()
        local_today = now.astimezone(zone).date()
        for offset in range(0, 400):
            day = local_today + timedelta(days=offset)
            if day.weekday() not in self.days:
                continue
            if self.not_before and day < self.not_before:
                continue
            if self.not_after and day > self.not_after:
                return None
            opening = datetime.combine(day, self._t(self.start), tzinfo=zone).astimezone(timezone.utc)
            if opening > now:
                return opening
        return None

    def describe(self) -> str:
        days = self.days
        if days == list(range(7)):
            day_text = "every day"
        elif days == [0, 1, 2, 3, 4]:
            day_text = "Mon–Fri"
        elif len(days) > 1 and days == list(range(days[0], days[-1] + 1)):
            day_text = f"{_DAYS[days[0]]}–{_DAYS[days[-1]]}"
        else:
            day_text = ", ".join(_DAYS[d] for d in days)
        text = f"{day_text} {self.start}–{self.end} ({self.timezone})"
        if self.not_before or self.not_after:
            first = self.not_before.isoformat() if self.not_before else "…"
            last = self.not_after.isoformat() if self.not_after else "…"
            text += f", {first} to {last}"
        return text


def from_profile(profile_json: str | dict | None) -> TestingWindow | None:
    import json

    if not profile_json:
        return None
    data = json.loads(profile_json) if isinstance(profile_json, str) else profile_json
    raw = data.get("testing_window") if isinstance(data, dict) else None
    return TestingWindow.model_validate(raw) if raw else None


def closed_message(window: TestingWindow, when: datetime | None = None) -> str:
    message = f"Outside the agreed testing window ({window.describe()})."
    opening = window.next_opening(when)
    if opening:
        local = opening.astimezone(ZoneInfo(window.timezone))
        message += f" It opens next on {local.strftime('%a %d %b %Y %H:%M')} {window.timezone}."
    else:
        message += " The engagement period has ended."
    return message
