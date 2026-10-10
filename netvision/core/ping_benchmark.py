from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import os
import subprocess

from netvision.core.probes import _oem_encoding, parse_ping_samples, probe_ping
from netvision.models import PingResult, ProbeStatus


@dataclass(frozen=True, slots=True)
class RegionalPingTarget:
    region: str
    host: str
    note: str


@dataclass(frozen=True, slots=True)
class RegionalPingResult:
    target: RegionalPingTarget
    ping: PingResult

    @property
    def latency_ms(self) -> float | None:
        return self.ping.average_ms

    @property
    def success(self) -> bool:
        return self.ping.average_ms is not None


@dataclass(frozen=True, slots=True)
class MtuProbeResult:
    payload_size: int
    received: int
    sent: int
    loss_percent: float
    average_ms: float | None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.received > 0


@dataclass(frozen=True, slots=True)
class LatencyStatistics:
    minimum_ms: float | None
    maximum_ms: float | None
    average_ms: float | None
    jitter_ms: float | None
    loss_percent: float
    stability: str


# These are public regional network reference endpoints, not game server IPs.
# CDN/Anycast routing may select a nearby point of presence; users can inspect a
# game's actual server IP with the process inspector for a precise comparison.
REGIONAL_GAMING_TARGETS: tuple[RegionalPingTarget, ...] = (
    RegionalPingTarget("Европа / Amsterdam", "ams-nl-ping.vultr.com", "Региональный опорный узел"),
    RegionalPingTarget("Frankfurt", "fra-de-ping.vultr.com", "Региональный опорный узел"),
    RegionalPingTarget("Stockholm", "sto-se-ping.vultr.com", "Региональный опорный узел"),
    RegionalPingTarget("Москва", "ya.ru", "Региональный ориентир CDN"),
    RegionalPingTarget("CIS / Warsaw", "waw-pl-ping.vultr.com", "Ближайший европейский ориентир"),
)


def benchmark_regional_targets(
    targets: tuple[RegionalPingTarget, ...] | list[RegionalPingTarget] = REGIONAL_GAMING_TARGETS,
    *,
    count: int = 3,
    wait_ms: int = 650,
) -> tuple[RegionalPingResult, ...]:
    """Run independent ICMP checks in parallel, preserving the original target order."""
    if not targets:
        return ()

    results: dict[int, RegionalPingResult] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:
        futures = {
            executor.submit(probe_ping, target.host, count, wait_ms): (index, target)
            for index, target in enumerate(targets)
        }
        for future in as_completed(futures):
            index, target = futures[future]
            try:
                ping = future.result()
            except Exception as exc:  # Keep one unreachable hub from aborting the matrix.
                ping = _failed_ping(target.host, count, str(exc))
            results[index] = RegionalPingResult(target, ping)
    return tuple(results[index] for index in range(len(targets)))


def run_mtu_stress_test(
    host: str,
    payload_sizes: tuple[int, ...] = (32, 512, 1472),
    *,
    count: int = 2,
    wait_ms: int = 650,
) -> tuple[MtuProbeResult, ...]:
    """Probe ICMP payload sizes with the Don't Fragment flag on Windows."""
    if not host.strip():
        raise ValueError("Укажите адрес для MTU-проверки")
    if count < 1 or wait_ms < 1 or not payload_sizes:
        raise ValueError("Параметры MTU-проверки некорректны")

    return tuple(
        _probe_mtu_size(host.strip(), size, count=count, wait_ms=wait_ms)
        for size in payload_sizes
    )


def latency_statistics(
    samples: tuple[float, ...] | list[float],
    *,
    sent: int | None = None,
) -> LatencyStatistics:
    values = tuple(float(value) for value in samples)
    total = sent if sent is not None else len(values)
    total = max(total, len(values))
    loss_percent = round((total - len(values)) * 100 / total, 1) if total else 0.0
    if not values:
        return LatencyStatistics(None, None, None, None, loss_percent, "Нет ответов")
    average = round(sum(values) / len(values), 1)
    jitter = (
        round(sum(abs(right - left) for left, right in zip(values, values[1:])) / (len(values) - 1), 1)
        if len(values) > 1
        else 0.0
    )
    stability = _stability_label(average, jitter, loss_percent)
    return LatencyStatistics(min(values), max(values), average, jitter, loss_percent, stability)


def _probe_mtu_size(host: str, payload_size: int, *, count: int, wait_ms: int) -> MtuProbeResult:
    if payload_size < 1 or payload_size > 65500:
        return MtuProbeResult(payload_size, 0, count, 100.0, None, "Размер пакета вне допустимого диапазона")
    command = _mtu_ping_command(host, payload_size, count, wait_ms)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=_oem_encoding(),
            errors="replace",
            timeout=count * (wait_ms / 1000) + 5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return MtuProbeResult(payload_size, 0, count, 100.0, None, str(exc))

    output = completed.stdout + "\n" + completed.stderr
    samples = parse_ping_samples(output)
    received = min(len(samples), count)
    loss_percent = round((count - received) * 100 / count, 1)
    average = round(sum(samples) / received, 1) if received else None
    error = None if received else _mtu_error(output, completed.returncode)
    return MtuProbeResult(payload_size, received, count, loss_percent, average, error)


def _mtu_ping_command(host: str, payload_size: int, count: int, wait_ms: int) -> list[str]:
    if os.name == "nt":
        return ["ping", "-n", str(count), "-w", str(wait_ms), "-f", "-l", str(payload_size), host]
    return ["ping", "-c", str(count), "-W", str(max(1, wait_ms // 1000)), "-s", str(payload_size), host]


def _mtu_error(output: str, return_code: int) -> str:
    lowered = output.casefold()
    if any(marker in lowered for marker in ("fragment", "фрагмент", "packet needs", "требуется")):
        return "Пакет требует фрагментации"
    return "Нет ICMP-ответа" if return_code else "Нет измерений"


def _failed_ping(host: str, sent: int, error: str) -> PingResult:
    return PingResult(host, sent, 0, 100.0, None, None, None, None, (), ProbeStatus.ERROR, error)


def _stability_label(average_ms: float, jitter_ms: float, loss_percent: float) -> str:
    if loss_percent > 0:
        return "Есть потери"
    if average_ms > 100 or jitter_ms > 25:
        return "Нестабильно"
    if average_ms > 50 or jitter_ms > 12:
        return "Есть колебания"
    return "Стабильно"
