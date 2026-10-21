"""Lightweight game-process launch monitoring and session statistics."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import socket
import time
from collections.abc import Sequence

import psutil

from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds


DEFAULT_GAME_PROCESSES: tuple[str, ...] = ("HuntGame.exe", "Hunt.exe")
DEFAULT_TARGET = ("1.1.1.1", 53)
SAMPLES_PER_PROBE = 2
PROBE_TIMEOUT = 1.2
SPIKE_MINIMUM_MS = DEFAULT_THRESHOLDS.rtt_high_ms
SPIKE_DELTA_MS = 50.0


@dataclass(frozen=True, slots=True)
class GameSessionSummary:
    process_name: str
    pid: int
    started_at: datetime
    ended_at: datetime
    baseline_latency_ms: float | None
    samples: int
    failed_samples: int
    spike_count: int

    @property
    def loss_percent(self) -> float:
        if not self.samples:
            return 0.0
        return round(self.failed_samples / self.samples * 100.0, 1)


@dataclass(frozen=True, slots=True)
class GameMonitorEvent:
    kind: str
    observed_at: datetime
    process_name: str
    pid: int
    baseline_latency_ms: float | None = None
    latency_ms: float | None = None
    connected: bool = False
    loss_percent: float = 0.0
    spike_count: int = 0
    summary: GameSessionSummary | None = None


@dataclass(slots=True)
class _ActiveSession:
    process_name: str
    pid: int
    started_at: datetime
    baseline_latency_ms: float | None
    samples: int = 0
    failed_samples: int = 0
    spike_count: int = 0


class GameLaunchMonitor:
    """Poll a small process allowlist and track one game session at a time."""

    def __init__(
        self,
        process_names: Sequence[str] = DEFAULT_GAME_PROCESSES,
        target: tuple[str, int] = DEFAULT_TARGET,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        self._process_names = {name.casefold() for name in process_names}
        self._target_host, self._target_port = target
        self._thresholds = th
        self._session: _ActiveSession | None = None

    def poll(self) -> GameMonitorEvent | None:
        process = self._find_process()
        if self._session is None:
            if process is None:
                return None
            name, pid = process
            baseline = _measure_latency(self._target_host, self._target_port)
            self._session = _ActiveSession(
                process_name=name,
                pid=pid,
                started_at=datetime.now(),
                baseline_latency_ms=baseline,
            )
            return GameMonitorEvent(
                kind="started",
                observed_at=datetime.now(),
                process_name=name,
                pid=pid,
                baseline_latency_ms=baseline,
                latency_ms=baseline,
                connected=baseline is not None,
            )

        if process is None or process[1] != self._session.pid:
            ended = self._finish_session()
            self._session = None
            return ended

        latency = _measure_latency(self._target_host, self._target_port)
        session = self._session
        session.samples += 1
        if latency is None:
            session.failed_samples += 1
        elif (
            latency >= self._thresholds.rtt_high_ms
            or session.baseline_latency_ms is not None
            and latency - session.baseline_latency_ms >= SPIKE_DELTA_MS
        ):
            session.spike_count += 1

        loss_percent = round(session.failed_samples / session.samples * 100.0, 1)
        return GameMonitorEvent(
            kind="spike"
            if latency is not None and _is_spike(latency, session.baseline_latency_ms, self._thresholds)
            else "sample",
            observed_at=datetime.now(),
            process_name=session.process_name,
            pid=session.pid,
            baseline_latency_ms=session.baseline_latency_ms,
            latency_ms=latency,
            connected=latency is not None,
            loss_percent=loss_percent,
            spike_count=session.spike_count,
        )

    def close(self) -> GameMonitorEvent | None:
        if self._session is None:
            return None
        event = self._finish_session()
        self._session = None
        return event

    def _find_process(self) -> tuple[str, int] | None:
        if not self._process_names:
            return None
        try:
            for process in psutil.process_iter(["pid", "name"]):
                try:
                    name = str(process.info.get("name") or "")
                    if name.casefold() in self._process_names:
                        return name, int(process.info["pid"])
                except (KeyError, TypeError, ValueError, psutil.Error, OSError):
                    continue
        except (psutil.Error, OSError):
            return None
        return None

    def _finish_session(self) -> GameMonitorEvent:
        session = self._session
        assert session is not None
        summary = GameSessionSummary(
            process_name=session.process_name,
            pid=session.pid,
            started_at=session.started_at,
            ended_at=datetime.now(),
            baseline_latency_ms=session.baseline_latency_ms,
            samples=session.samples,
            failed_samples=session.failed_samples,
            spike_count=session.spike_count,
        )
        return GameMonitorEvent(
            kind="ended",
            observed_at=summary.ended_at,
            process_name=summary.process_name,
            pid=summary.pid,
            baseline_latency_ms=summary.baseline_latency_ms,
            loss_percent=summary.loss_percent,
            spike_count=summary.spike_count,
            summary=summary,
        )


def _measure_latency(host: str, port: int) -> float | None:
    samples: list[float] = []
    for _ in range(SAMPLES_PER_PROBE):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
                pass
        except OSError:
            continue
        samples.append((time.perf_counter() - started) * 1000.0)
    return round(sum(samples) / len(samples), 1) if samples else None


def _is_spike(
    latency: float,
    baseline: float | None,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> bool:
    return latency >= th.rtt_high_ms or (
        baseline is not None and latency - baseline >= SPIKE_DELTA_MS
    )
