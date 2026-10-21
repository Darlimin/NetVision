"""Hysteresis-based grouping for repeated network-quality disturbances."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Episode:
    started_at: datetime
    last_over_at: datetime
    peak: float
    peak_at: datetime
    samples_over: int
    ended_at: datetime | None = None
    closed_by: str | None = None


class EpisodeTracker:
    """Group threshold crossings into one episode with a quiet-period close."""

    def __init__(
        self,
        open_above: float,
        close_at_or_below: float,
        quiet_samples: int,
        *,
        break_on_none: bool = False,
    ) -> None:
        if quiet_samples < 1:
            raise ValueError("quiet_samples must be at least 1")
        if close_at_or_below > open_above:
            raise ValueError("close_at_or_below cannot exceed open_above")
        self._open_above = float(open_above)
        self._close_at_or_below = float(close_at_or_below)
        self._quiet_samples = quiet_samples
        self._break_on_none = break_on_none
        self._active: Episode | None = None
        self._quiet_count = 0

    @property
    def active(self) -> Episode | None:
        return self._active

    def update(self, value: float | None, at: datetime) -> tuple[str | None, Episode | None]:
        if value is None:
            if self._break_on_none:
                episode = self.close("break", at)
                return ("closed", episode) if episode is not None else (None, None)
            return None, self._active

        numeric_value = float(value)
        if self._active is None:
            if numeric_value <= self._open_above:
                return None, None
            self._active = Episode(at, at, numeric_value, at, 1)
            self._quiet_count = 0
            return "opened", self._active

        if numeric_value > self._open_above:
            previous = self._active
            self._quiet_count = 0
            self._active = replace(
                previous,
                last_over_at=at,
                peak=max(previous.peak, numeric_value),
                peak_at=at if numeric_value > previous.peak else previous.peak_at,
                samples_over=previous.samples_over + 1,
            )
            return ("peak" if numeric_value > previous.peak else None), self._active

        if numeric_value <= self._close_at_or_below:
            self._quiet_count += 1
            if self._quiet_count >= self._quiet_samples:
                return "closed", self.close("quiet", at)
        else:
            self._quiet_count = 0
        return None, self._active

    def close(self, reason: str, at: datetime | None = None) -> Episode | None:
        if self._active is None:
            return None
        closed = replace(
            self._active,
            ended_at=at or datetime.now(),
            closed_by=reason,
        )
        self._active = None
        self._quiet_count = 0
        return closed
