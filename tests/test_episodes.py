from __future__ import annotations

from datetime import datetime, timedelta

from netvision.core.episodes import EpisodeTracker


def _time(index: int) -> datetime:
    return datetime(2026, 10, 20, 12, 0, 0) + timedelta(seconds=index)


def test_many_samples_above_threshold_form_one_episode() -> None:
    tracker = EpisodeTracker(15.0, 10.0, 3)

    steps = [tracker.update(16.0, _time(index))[0] for index in range(40)]

    assert steps.count("opened") == 1
    assert tracker.active is not None
    assert tracker.active.samples_over == 40


def test_hysteresis_band_does_not_close_an_active_episode() -> None:
    tracker = EpisodeTracker(15.0, 10.0, 3)
    tracker.update(16.0, _time(0))
    tracker.update(11.0, _time(1))
    tracker.update(10.0, _time(2))
    tracker.update(11.0, _time(3))

    step, active = tracker.update(10.0, _time(4))

    assert step is None
    assert active is not None
    assert tracker.active is not None


def test_episode_closes_on_exactly_third_quiet_sample() -> None:
    tracker = EpisodeTracker(15.0, 10.0, 3)
    tracker.update(20.0, _time(0))

    assert tracker.update(10.0, _time(1))[0] is None
    assert tracker.update(10.0, _time(2))[0] is None
    step, episode = tracker.update(10.0, _time(3))

    assert step == "closed"
    assert episode is not None
    assert episode.closed_by == "quiet"
    assert episode.ended_at == _time(3)
    assert tracker.active is None
