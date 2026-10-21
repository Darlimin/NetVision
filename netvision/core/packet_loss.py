from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import socket
from time import perf_counter

from netvision.core.probes import probe_ping
from netvision.core.episodes import Episode, EpisodeTracker
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds
from netvision.models import HopResult, PingResult


@dataclass(frozen=True, slots=True)
class LossSample:
    success: bool
    latency_ms: float | None = None


@dataclass(frozen=True, slots=True)
class PacketLossSnapshot:
    sent: int
    received: int
    lost: int
    loss_percent: float
    burst_count: int
    longest_burst: int
    jitter_drops: int
    current_burst: int
    status: str


@dataclass(frozen=True, slots=True)
class LossEvent:
    observed_at: datetime
    kind: str
    message: str
    snapshot: PacketLossSnapshot
    started_at: datetime | None = None
    lost: int = 0


@dataclass(frozen=True, slots=True)
class HopLossResult:
    hop: int
    address: str | None
    sent: int
    received: int
    loss_percent: float | None
    average_ms: float | None
    status: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class StressTestResult:
    protocol: str
    target: str
    sent: int
    received: int
    loss_percent: float | None
    average_ms: float | None
    status: str
    note: str | None = None
    error: str | None = None


class PacketLossAnalyzer:
    """Keep a bounded live window and classify loss bursts without GUI state."""

    def __init__(
        self,
        max_samples: int = 60,
        jitter_threshold_ms: float | None = None,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        jitter_threshold_ms = th.jitter_critical_ms if jitter_threshold_ms is None else jitter_threshold_ms
        if max_samples < 1 or jitter_threshold_ms < 0:
            raise ValueError("Параметры анализатора потерь некорректны")
        self._max_samples = max_samples
        self._thresholds = th
        self._jitter_threshold_ms = jitter_threshold_ms
        self._samples: list[LossSample] = []
        self._events: list[LossEvent] = []
        self._loss_episode_tracker = self._new_loss_episode_tracker()

    @property
    def samples(self) -> tuple[LossSample, ...]:
        return tuple(self._samples)

    @property
    def events(self) -> tuple[LossEvent, ...]:
        return tuple(self._events)

    def reset(self) -> None:
        self._samples.clear()
        self._events.clear()
        self._loss_episode_tracker = self._new_loss_episode_tracker()

    def observe(self, success: bool, latency_ms: float | None = None) -> tuple[PacketLossSnapshot, LossEvent | None]:
        sample = LossSample(success, float(latency_ms) if latency_ms is not None else None)
        self._samples.append(sample)
        if len(self._samples) > self._max_samples:
            del self._samples[:-self._max_samples]

        snapshot = summarize_loss(
            self._samples,
            jitter_threshold_ms=self._jitter_threshold_ms,
            th=self._thresholds,
        )
        observed_at = datetime.now()
        step, episode = self._loss_episode_tracker.update(0.0 if success else 1.0, observed_at)
        event: LossEvent | None = None
        if step == "opened" and episode is not None:
            event = self._loss_event(
                observed_at,
                "drop",
                "Одиночная потеря пакета",
                snapshot,
                episode,
            )
        elif not success and episode is not None and snapshot.current_burst == 2:
            event = self._loss_event(
                observed_at,
                "burst",
                f"Потеря пакета · подряд: {snapshot.current_burst}",
                snapshot,
                episode,
            )
        elif step == "closed" and episode is not None:
            event = self._loss_event(
                observed_at,
                "burst_end",
                f"Серия потерь завершена · потеряно: {episode.samples_over}",
                snapshot,
                episode,
            )
        elif snapshot.jitter_drops > 0 and len(self._samples) >= 2:
            previous = self._samples[-2].latency_ms
            if previous is not None and latency_ms is not None and abs(latency_ms - previous) >= self._jitter_threshold_ms:
                event = LossEvent(
                    observed_at,
                    "jitter",
                    f"Резкое изменение RTT: {previous:.1f} → {latency_ms:.1f} ms",
                    snapshot,
                )
        if event is not None:
            self._events.append(event)
            self._events = self._events[-100:]
        return snapshot, event

    @staticmethod
    def _new_loss_episode_tracker() -> EpisodeTracker:
        return EpisodeTracker(0.0, 0.0, 3)

    @staticmethod
    def _loss_event(
        observed_at: datetime,
        kind: str,
        message: str,
        snapshot: PacketLossSnapshot,
        episode: Episode,
    ) -> LossEvent:
        return LossEvent(
            observed_at,
            kind,
            message,
            snapshot,
            started_at=episode.started_at,
            lost=episode.samples_over,
        )


def summarize_loss(
    samples: tuple[LossSample, ...] | list[LossSample],
    *,
    jitter_threshold_ms: float | None = None,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> PacketLossSnapshot:
    jitter_threshold_ms = th.jitter_critical_ms if jitter_threshold_ms is None else jitter_threshold_ms
    if jitter_threshold_ms < 0:
        raise ValueError("Порог jitter не может быть отрицательным")
    values = tuple(samples)
    sent = len(values)
    received = sum(1 for sample in values if sample.success)
    lost = sent - received
    loss_percent = round(lost * 100 / sent, 1) if sent else 0.0
    bursts = 0
    longest_burst = 0
    current_burst = 0
    jitter_drops = 0
    previous_latency: float | None = None
    for sample in values:
        if not sample.success:
            current_burst += 1
            if current_burst == 1:
                bursts += 1
            longest_burst = max(longest_burst, current_burst)
        else:
            current_burst = 0
            if (
                previous_latency is not None
                and sample.latency_ms is not None
                and abs(sample.latency_ms - previous_latency) >= jitter_threshold_ms
            ):
                jitter_drops += 1
            previous_latency = sample.latency_ms
    if not sent:
        status = "Ожидание данных"
    elif loss_percent == 0:
        status = "Связь стабильная"
    elif longest_burst >= 3 or loss_percent >= 20:
        status = "Критическая потеря"
    else:
        status = "Есть микропотери"
    return PacketLossSnapshot(
        sent,
        received,
        lost,
        loss_percent,
        bursts,
        longest_burst,
        jitter_drops,
        current_burst,
        status,
    )


def run_hop_loss_breakdown(
    hops: tuple[HopResult, ...] | list[HopResult],
    *,
    count: int = 3,
    wait_ms: int = 650,
) -> tuple[HopLossResult, ...]:
    """Ping each addressed traceroute hop in parallel and preserve hop order."""
    if count < 1 or wait_ms < 1:
        raise ValueError("Параметры hop-проверки некорректны")
    ordered = tuple(hops)
    results: dict[int, HopLossResult] = {}
    addressed = [hop for hop in ordered if hop.address]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(addressed)))) as executor:
        futures = {
            executor.submit(probe_ping, hop.address or "", count, wait_ms): hop
            for hop in addressed
        }
        for future in as_completed(futures):
            hop = futures[future]
            try:
                ping = future.result()
            except Exception as exc:
                results[hop.index] = HopLossResult(
                    hop.index, hop.address, count, 0, 100.0, None, "Ошибка", str(exc)
                )
            else:
                results[hop.index] = _hop_result(hop, ping)
    for hop in ordered:
        if hop.index in results:
            continue
        if hop.timed_out:
            results[hop.index] = HopLossResult(
                hop.index, hop.address, count, 0, 100.0, None, "Нет ответа", "Traceroute: timeout"
            )
        else:
            results[hop.index] = HopLossResult(
                hop.index, hop.address, 0, 0, None, hop.latency_ms, "Не определено", "Адрес hop не получен"
            )
    return tuple(results[hop.index] for hop in ordered)


def run_icmp_stress_test(host: str, *, count: int = 10, wait_ms: int = 500) -> StressTestResult:
    if not host.strip():
        raise ValueError("Укажите адрес для ICMP-теста")
    ping = probe_ping(host.strip(), count, wait_ms)
    return _stress_from_ping("ICMP", host.strip(), ping)


def run_udp_stress_test(
    host: str,
    port: int,
    *,
    count: int = 20,
    payload_size: int = 64,
    timeout: float = 0.5,
) -> StressTestResult:
    """Send UDP datagrams and count local send errors; UDP has no generic ACK."""
    if not host.strip() or not 1 <= port <= 65535 or count < 1 or payload_size < 1:
        raise ValueError("Параметры UDP-теста некорректны")
    payload = b"N" * payload_size
    sent = 0
    errors = 0
    elapsed: list[float] = []
    error_text: str | None = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            for _ in range(count):
                started = perf_counter()
                try:
                    connection.sendto(payload, (host.strip(), port))
                except OSError as exc:
                    errors += 1
                    error_text = str(exc)
                else:
                    sent += 1
                    elapsed.append((perf_counter() - started) * 1000)
    except OSError as exc:
        return StressTestResult("UDP", f"{host.strip()}:{port}", 0, 0, None, None, "Ошибка", error=str(exc))
    average = round(sum(elapsed) / len(elapsed), 1) if elapsed else None
    status = "Отправка успешна" if sent else "Ошибка"
    note = "UDP не подтверждает доставку без ACK приложения; учтены только локальные sendto."
    return StressTestResult("UDP", f"{host.strip()}:{port}", count, sent, None, average, status, note, error_text)


def _hop_result(hop: HopResult, ping: PingResult) -> HopLossResult:
    status = "Стабильно" if ping.loss_percent == 0 else ("Есть потери" if ping.received else "Нет ответа")
    return HopLossResult(
        hop.index,
        hop.address,
        ping.sent,
        ping.received,
        ping.loss_percent,
        ping.average_ms,
        status,
        ping.error,
    )


def _stress_from_ping(protocol: str, host: str, ping: PingResult) -> StressTestResult:
    return StressTestResult(
        protocol,
        host,
        ping.sent,
        ping.received,
        ping.loss_percent,
        ping.average_ms,
        "Стабильно" if ping.loss_percent == 0 else "Есть потери",
        error=ping.error,
    )
