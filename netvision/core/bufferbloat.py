"""Cancellation-aware Bufferbloat measurements without Qt dependencies."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Event, Lock
import ipaddress
import socket
import time
from urllib.request import Request, build_opener, ProxyHandler, urlopen

from netvision.core.probes import probe_ping
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds


ProgressCallback = Callable[[str], None]
DEFAULT_TARGETS: tuple[tuple[str, str, int], ...] = (
    ("Cloudflare DNS", "1.1.1.1", 53),
    ("Google DNS", "8.8.8.8", 53),
)
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=4000000"
UPLOAD_URL = "https://speed.cloudflare.com/__up"
TRANSFER_CHUNK_BYTES = 4_000_000
TRANSFER_TIMEOUT = 20.0
RTT_TIMEOUT = 0.5


@dataclass(frozen=True, slots=True)
class BufferbloatSeries:
    """Percentile data from one independent RTT measurement series."""

    name: str
    p50_ms: float | None = None
    p95_ms: float | None = None
    max_ms: float | None = None
    samples: int = 0


@dataclass(frozen=True, slots=True)
class BufferbloatPhase:
    latency_ms: float | None
    speed_mbps: float | None = None
    delta_ms: float | None = None
    error: str | None = None
    p50_ms: float | None = None
    p95_ms: float | None = None
    max_ms: float | None = None
    samples: int = 0
    series: tuple[BufferbloatSeries, ...] = ()

    def measurement(self, name: str) -> BufferbloatSeries | None:
        return next((item for item in self.series if item.name == name), None)


@dataclass(frozen=True, slots=True)
class BufferbloatReport:
    unloaded: BufferbloatPhase
    download_active: BufferbloatPhase
    upload_active: BufferbloatPhase
    grade: str
    verdict: str
    recommendations: tuple[str, ...]
    error: str | None = None
    target_ip: str | None = None
    gateway: str | None = None
    target_delta_ms: float | None = None
    gateway_delta_ms: float | None = None


class _ByteBudget:
    """Shares a strict transfer quota between concurrent load streams."""

    def __init__(self, maximum: int, stop_event: Event) -> None:
        self._maximum = maximum
        self._stop_event = stop_event
        self._lock = Lock()
        self._reserved = 0
        self._completed = 0

    def reserve(self, maximum: int) -> int:
        with self._lock:
            remaining = self._maximum - self._completed - self._reserved
            if remaining <= 0:
                self._stop_event.set()
                return 0
            size = min(maximum, remaining)
            self._reserved += size
            return size

    def commit(self, reserved: int, completed: int) -> None:
        with self._lock:
            self._reserved -= reserved
            self._completed += min(max(0, completed), reserved)
            if self._completed >= self._maximum:
                self._stop_event.set()

    @property
    def completed(self) -> int:
        with self._lock:
            return self._completed


def resolve_target_ipv4(target: str | None) -> str | None:
    """Resolve a target once and return an IPv4 address suitable for ICMP."""
    if not target or not target.strip():
        return None
    try:
        parsed = ipaddress.ip_address(target.strip())
    except ValueError:
        parsed = None
    if parsed is not None:
        return str(parsed) if parsed.version == 4 else None
    try:
        records = socket.getaddrinfo(target.strip(), None, socket.AF_INET)
    except OSError:
        return None
    return next((record[4][0] for record in records if record[4]), None)


def run_bufferbloat_test(
    progress: ProgressCallback | None = None,
    targets: tuple[tuple[str, str, int], ...] = DEFAULT_TARGETS,
    *,
    target: str | None = None,
    gateway: str | None = None,
    stop_event: Event | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> BufferbloatReport:
    """Measure latency distributions at rest and during timed transfer load."""
    callback = progress or (lambda _message: None)
    cancelled = stop_event or Event()
    reference_host, reference_port = _reference_target(targets)
    target_ip = resolve_target_ipv4(target)

    callback("Фаза 1/3: базовая задержка")
    unloaded = _sample_phase(
        reference_host,
        reference_port,
        target_ip=target_ip,
        gateway=gateway,
        duration_s=thresholds.bufferbloat_baseline_s,
        stop_event=cancelled,
        interval_s=thresholds.bufferbloat_sample_interval_s,
    )
    target_ip = target_ip if _series_has_samples(unloaded, "target") else None
    gateway = gateway if _series_has_samples(unloaded, "gateway") else None

    callback("Фаза 2/3: скачивание под нагрузкой")
    download = _load_phase(
        "download",
        reference_host,
        reference_port,
        target_ip=target_ip,
        gateway=gateway,
        stop_event=cancelled,
        thresholds=thresholds,
    )
    callback("Фаза 3/3: отдача под нагрузкой")
    upload = _load_phase(
        "upload",
        reference_host,
        reference_port,
        target_ip=target_ip,
        gateway=gateway,
        stop_event=cancelled,
        thresholds=thresholds,
    )

    download = _with_delta(download, unloaded)
    upload = _with_delta(upload, unloaded)
    target_delta = _maximum_delta(unloaded, download, upload, "target")
    gateway_delta = _maximum_delta(unloaded, download, upload, "gateway")
    grade = _grade(download.delta_ms, upload.delta_ms, thresholds)
    error = _first_error(unloaded, download, upload)
    if cancelled.is_set() and error is None:
        error = "Тест отменён"
    return BufferbloatReport(
        unloaded=unloaded,
        download_active=download,
        upload_active=upload,
        grade=grade,
        verdict=_verdict(grade),
        recommendations=_recommendations(grade),
        error=error,
        target_ip=target_ip,
        gateway=gateway,
        target_delta_ms=target_delta,
        gateway_delta_ms=gateway_delta,
    )


def _reference_target(targets: tuple[tuple[str, str, int], ...]) -> tuple[str, int]:
    if not targets:
        return "1.1.1.1", 53
    _name, host, port = targets[0]
    return host, port


def _sample_phase(
    reference_host: str,
    reference_port: int,
    *,
    target_ip: str | None,
    gateway: str | None,
    duration_s: float,
    stop_event: Event,
    interval_s: float,
) -> BufferbloatPhase:
    values: dict[str, list[float]] = {"ref": [], "target": [], "gateway": []}
    started = time.monotonic()
    while not stop_event.is_set():
        _sample_series_once(
            values,
            reference_host,
            reference_port,
            target_ip=target_ip,
            gateway=gateway,
            stop_event=stop_event,
        )
        elapsed = time.monotonic() - started
        if elapsed >= max(0.0, duration_s):
            break
        stop_event.wait(min(interval_s, max(0.0, duration_s - elapsed)))
    return _phase_from_samples(values)


def _load_phase(
    direction: str,
    reference_host: str,
    reference_port: int,
    *,
    target_ip: str | None,
    gateway: str | None,
    stop_event: Event,
    thresholds: Thresholds,
) -> BufferbloatPhase:
    phase_stop = Event()
    values: dict[str, list[float]] = {"ref": [], "target": [], "gateway": []}
    budget = _ByteBudget(thresholds.bufferbloat_max_bytes, phase_stop)
    started = time.monotonic()
    executor = ThreadPoolExecutor(max_workers=max(1, thresholds.bufferbloat_streams))
    try:
        for _ in range(thresholds.bufferbloat_streams):
            executor.submit(_load_stream, direction, budget, stop_event, phase_stop)
        while not stop_event.is_set() and not phase_stop.is_set():
            _sample_series_once(
                values,
                reference_host,
                reference_port,
                target_ip=target_ip,
                gateway=gateway,
                stop_event=stop_event,
            )
            if time.monotonic() - started >= thresholds.bufferbloat_load_s:
                phase_stop.set()
                break
            stop_event.wait(thresholds.bufferbloat_sample_interval_s)
    finally:
        phase_stop.set()
        # A transfer may still be inside a socket read. Do not make shutdown or closeEvent
        # wait for its network timeout; every subsequent stream observes phase_stop first.
        executor.shutdown(wait=False, cancel_futures=True)
    duration = max(time.monotonic() - started, 0.001)
    speed = round(budget.completed * 8.0 / duration / 1_000_000.0, 1)
    phase = _phase_from_samples(values, speed_mbps=speed)
    if phase.latency_ms is None:
        return BufferbloatPhase(
            latency_ms=phase.latency_ms,
            speed_mbps=phase.speed_mbps,
            delta_ms=phase.delta_ms,
            error="Не удалось измерить контрольную задержку",
            p50_ms=phase.p50_ms,
            p95_ms=phase.p95_ms,
            max_ms=phase.max_ms,
            samples=phase.samples,
            series=phase.series,
        )
    return phase


def _load_stream(direction: str, budget: _ByteBudget, stop_event: Event, phase_stop: Event) -> None:
    transfer = _download if direction == "download" else _upload
    url = DOWNLOAD_URL if direction == "download" else UPLOAD_URL
    while not stop_event.is_set() and not phase_stop.is_set():
        reserved = budget.reserve(TRANSFER_CHUNK_BYTES)
        if not reserved:
            return
        try:
            completed, _duration = _invoke_transfer(transfer, url, phase_stop, reserved)
        except OSError:
            completed = 0
        budget.commit(reserved, completed)


def _invoke_transfer(
    transfer: Callable[..., tuple[int, float]],
    url: str,
    stop_event: Event,
    maximum: int,
) -> tuple[int, float]:
    try:
        return transfer(url, stop_event=stop_event, max_bytes=maximum)
    except TypeError:
        # Existing integrations and unit tests may provide the former one-argument helper.
        return transfer(url)


def _measure_tcp_latency(host: str, port: int) -> float | None:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=RTT_TIMEOUT):
            return round((time.perf_counter() - started) * 1000.0, 1)
    except OSError:
        return None


def _measure_icmp_latency(host: str) -> float | None:
    result = probe_ping(host, count=1, wait_ms=int(RTT_TIMEOUT * 1000))
    return result.average_ms if result.received else None


def _sample_series_once(
    values: dict[str, list[float]],
    reference_host: str,
    reference_port: int,
    *,
    target_ip: str | None,
    gateway: str | None,
    stop_event: Event,
) -> None:
    tasks: dict[str, Callable[[], float | None]] = {
        "ref": lambda: _measure_tcp_latency(reference_host, reference_port),
    }
    if target_ip:
        tasks["target"] = lambda: _measure_icmp_latency(target_ip)
    if gateway:
        tasks["gateway"] = lambda: _measure_icmp_latency(gateway)
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {name: executor.submit(measure) for name, measure in tasks.items()}
        for name, future in futures.items():
            if stop_event.is_set():
                break
            try:
                _append_sample(values, name, future.result())
            except OSError:
                continue


def _append_sample(values: dict[str, list[float]], name: str, value: float | None) -> None:
    if value is not None:
        values[name].append(value)


def _phase_from_samples(
    values: dict[str, list[float]],
    *,
    speed_mbps: float | None = None,
) -> BufferbloatPhase:
    series = tuple(_series_from_samples(name, samples) for name, samples in values.items() if samples)
    reference = next((item for item in series if item.name == "ref"), None)
    return BufferbloatPhase(
        latency_ms=reference.p50_ms if reference else None,
        speed_mbps=speed_mbps,
        error=None if reference else "Контрольный DNS не ответил",
        p50_ms=reference.p50_ms if reference else None,
        p95_ms=reference.p95_ms if reference else None,
        max_ms=reference.max_ms if reference else None,
        samples=reference.samples if reference else 0,
        series=series,
    )


def _series_from_samples(name: str, samples: Sequence[float]) -> BufferbloatSeries:
    return BufferbloatSeries(
        name=name,
        p50_ms=_percentile(samples, 0.50),
        p95_ms=_percentile(samples, 0.95),
        max_ms=round(max(samples), 1),
        samples=len(samples),
    )


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int((len(ordered) * percentile + 0.999999) - 1)))
    return round(ordered[rank], 1)


def _with_delta(active: BufferbloatPhase, unloaded: BufferbloatPhase) -> BufferbloatPhase:
    return BufferbloatPhase(
        latency_ms=active.latency_ms,
        speed_mbps=active.speed_mbps,
        delta_ms=_series_delta(unloaded, active, "ref"),
        error=active.error,
        p50_ms=active.p50_ms,
        p95_ms=active.p95_ms,
        max_ms=active.max_ms,
        samples=active.samples,
        series=active.series,
    )


def _series_delta(
    baseline: BufferbloatPhase,
    active: BufferbloatPhase,
    name: str,
) -> float | None:
    baseline_series = baseline.measurement(name)
    active_series = active.measurement(name)
    if not baseline_series or not active_series:
        return None
    if baseline_series.p50_ms is None or active_series.p95_ms is None:
        return None
    return round(max(0.0, active_series.p95_ms - baseline_series.p50_ms), 1)


def _maximum_delta(
    baseline: BufferbloatPhase,
    download: BufferbloatPhase,
    upload: BufferbloatPhase,
    name: str,
) -> float | None:
    values = [_series_delta(baseline, phase, name) for phase in (download, upload)]
    return max((value for value in values if value is not None), default=None)


def _series_has_samples(phase: BufferbloatPhase, name: str) -> bool:
    measurement = phase.measurement(name)
    return bool(measurement and measurement.samples)


def _download(
    url: str,
    *,
    stop_event: Event | None = None,
    max_bytes: int = TRANSFER_CHUNK_BYTES,
) -> tuple[int, float]:
    started = time.perf_counter()
    request = Request(url, headers={"User-Agent": "NetVision/Bufferbloat"})
    received = 0
    with _open(request) as response:
        while received < max_bytes and not (stop_event and stop_event.is_set()):
            chunk = response.read(min(128 * 1024, max_bytes - received))
            if not chunk:
                break
            received += len(chunk)
    return received, time.perf_counter() - started


def _upload(
    url: str,
    *,
    stop_event: Event | None = None,
    max_bytes: int = TRANSFER_CHUNK_BYTES,
) -> tuple[int, float]:
    if stop_event and stop_event.is_set():
        return 0, 0.0
    payload = b"0" * max_bytes
    started = time.perf_counter()
    request = Request(
        url,
        data=payload,
        method="POST",
        headers={"User-Agent": "NetVision/Bufferbloat", "Content-Type": "application/octet-stream"},
    )
    with _open(request) as response:
        response.read(1024)
    return len(payload), time.perf_counter() - started


def _open(request: Request):
    try:
        return urlopen(request, timeout=TRANSFER_TIMEOUT)
    except OSError:
        return build_opener(ProxyHandler({})).open(request, timeout=TRANSFER_TIMEOUT)


def _grade(
    download_delta: float | None,
    upload_delta: float | None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> str:
    deltas = [value for value in (download_delta, upload_delta) if value is not None]
    if not deltas:
        return "N/A"
    value = max(deltas)
    grades = ("A+", "A", "B", "C", "D")
    for limit, grade in zip(thresholds.bufferbloat_grade_steps_ms, grades):
        if value <= limit:
            return grade
    return "F"


def _verdict(grade: str) -> str:
    return {
        "A+": "Отлично для игр: минимальное влияние нагрузки",
        "A": "Отлично для игр: минимальное влияние нагрузки",
        "B": "Хорошо: небольшое влияние на игровой ping",
        "C": "Есть задержка под нагрузкой: возможны короткие лаги",
        "D": "Сильное раздутие буфера: заметные лаги в Hunt: Showdown",
        "F": "Критично: нагрузка вызывает выраженные лаги и потерю отзывчивости",
    }.get(grade, "Недостаточно данных для оценки bufferbloat")


def _recommendations(grade: str) -> tuple[str, ...]:
    if grade in {"A+", "A"}:
        return ("Ваша сеть отлично настроена, дополнительных действий не требуется.",)
    if grade == "B":
        return (
            "Небольшое влияние нагрузки обнаружено. Проверьте обновление прошивки роутера.",
            "Для игр по возможности используйте проводное подключение или Wi-Fi 5 ГГц.",
        )
    if grade == "C":
        return (
            "Обнаружено умеренное раздутие буфера. Включите SQM или QoS на роутере.",
            "Ограничьте скорость загрузки и отдачи примерно до 85–90% канала.",
            "Не запускайте тяжёлые загрузки одновременно с игрой.",
        )
    if grade in {"D", "F"}:
        return (
            "Обнаружено сильное раздутие буфера.",
            "Включите Smart Queue Management (SQM) или QoS в настройках роутера.",
            "Избегайте тяжёлых загрузок и раздачи торрентов во время игры.",
            "По возможности используйте проводное подключение вместо Wi-Fi.",
        )
    return ("Повторите тест при стабильном подключении: данных для рекомендаций недостаточно.",)


def _first_error(*phases: BufferbloatPhase) -> str | None:
    return next((phase.error for phase in phases if phase.error), None)
