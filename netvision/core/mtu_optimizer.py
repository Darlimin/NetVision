"""Route-aware IPv4 Path MTU discovery using ICMP Don't Fragment probes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
import re
import socket
import subprocess
import time

from netvision.core.probes import _oem_encoding, parse_ping_samples
from netvision.core.system import collect_system_snapshot
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds
from netvision.models import SystemSnapshot


_IPV4_HEADER_SIZE = 20
_ICMP_HEADER_SIZE = 8
_MIN_MTU = 576


@dataclass(frozen=True, slots=True)
class MtuOptimizerProbe:
    mtu: int
    payload_size: int
    success: bool
    latency_ms: float | None
    error: str | None = None
    outcome: str = "no_reply"
    attempts: int = 1


@dataclass(frozen=True, slots=True)
class MtuOptimizerReport:
    target: str
    current_mtu: int | None
    optimal_mtu: int | None
    probes: tuple[MtuOptimizerProbe, ...]
    error: str | None = None
    target_ip: str | None = None
    route_interface: str | None = None
    decision: str = "UNKNOWN"
    error_code: str | None = None
    inferred_by_timeout: bool = False


def run_mtu_optimizer(
    target_host: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    timeout_ms: int | None = None,
    progress: Callable[[str], None] | None = None,
    snapshot: SystemSnapshot | None = None,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> MtuOptimizerReport:
    """Find the largest DF-safe MTU for the IPv4 route to *target_host*."""
    host = target_host.strip()
    lower = th.mtu_search_min if minimum is None else minimum
    upper = th.mtu_search_max if maximum is None else maximum
    probe_timeout = th.mtu_probe_timeout_ms if timeout_ms is None else timeout_ms
    if not host:
        return _failure_report(host, (), "invalid_target", "Укажите целевой хост для MTU-проверки")
    if lower < _MIN_MTU or upper < lower or probe_timeout < 100:
        return _failure_report(host, (), "invalid_parameters", "Параметры MTU-проверки некорректны")

    target_ip = _resolve_target_ipv4(host)
    if target_ip is None:
        return _failure_report(host, (), "no_ipv4", "Для цели не найден IPv4-адрес")
    route_interface = _route_interface(
        _route_local_ipv4(target_ip), snapshot or collect_system_snapshot()
    )
    current_mtu = detect_system_mtu(route_interface)
    started_at = time.monotonic()
    probes: list[MtuOptimizerProbe] = []

    def failure(code: str, message: str, *, inferred: bool = False) -> MtuOptimizerReport:
        return _failure_report(
            host, tuple(probes), code, message, target_ip=target_ip,
            route_interface=route_interface, current_mtu=current_mtu,
            inferred_by_timeout=inferred,
        )

    barrier = [_probe_mtu(target_ip, lower, probe_timeout) for _ in range(3)]
    probes.extend(barrier)
    if not any(probe.success for probe in barrier):
        return failure("icmp_no_reply", "Целевой узел не отвечает на ICMP DF-пробы")

    low, high, best = lower + 1, upper, lower
    inferred_by_timeout = False
    while low <= high:
        if time.monotonic() - started_at > th.mtu_probe_budget_s:
            return failure("budget", "Превышен лимит времени MTU-проверки", inferred=inferred_by_timeout)
        candidate = (low + high) // 2
        _emit(progress, f"Проверяем MTU {candidate}")
        probe, used_timeout_inference = _probe_with_retries(
            target_ip, candidate, probe_timeout, th.mtu_probe_retries
        )
        probes.append(probe)
        inferred_by_timeout = inferred_by_timeout or used_timeout_inference
        if probe.success:
            best = candidate
            low = candidate + 1
        else:
            high = candidate - 1

    controls = [_probe_mtu(target_ip, best, probe_timeout) for _ in range(3)]
    next_controls = [_probe_mtu(target_ip, best + 1, probe_timeout) for _ in range(3)]
    probes.extend((*controls, *next_controls))
    if time.monotonic() - started_at > th.mtu_probe_budget_s:
        return failure("budget", "Превышен лимит времени MTU-проверки", inferred=inferred_by_timeout)
    if sum(probe.success for probe in controls) < 2 or any(probe.success for probe in next_controls):
        return failure("unstable", "Результат MTU-проверки нестабилен", inferred=inferred_by_timeout)
    return MtuOptimizerReport(
        host, current_mtu, best, tuple(probes), target_ip=target_ip,
        route_interface=route_interface, decision=_mtu_decision(current_mtu, best, th),
        inferred_by_timeout=inferred_by_timeout,
    )


def detect_system_mtu(route_interface: str | None) -> int | None:
    """Read the IPv4 MTU for the interface carrying the target route."""
    if os.name != "nt" or not route_interface or not route_interface.strip():
        return None
    try:
        completed = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    for mtu, interface_name in _parse_subinterfaces(_decode_output(completed.stdout)):
        if interface_name.casefold() == route_interface.strip().casefold():
            return mtu
    return None


def detect_active_adapter() -> str | None:
    """Compatibility helper for callers outside route-aware MTU discovery."""
    if os.name != "nt":
        return None
    powershell = (
        "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and "
        "$_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1 -ExpandProperty InterfaceAlias"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", powershell],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = _decode_output(completed.stdout).strip()
    return next((line.strip() for line in value.splitlines() if line.strip()), None) if completed.returncode == 0 else None


def probe_path_mtu(target_ip: str, mtu: int, timeout_ms: int) -> MtuOptimizerProbe:
    """Run one DF probe for post-apply verification."""
    return _probe_mtu(target_ip, mtu, timeout_ms)


def _resolve_target_ipv4(host: str) -> str | None:
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
    except socket.gaierror:
        return None
    return next((str(result[4][0]) for result in results if result[4]), None)


def _route_local_ipv4(target_ip: str) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_ip, 9))
            return str(sock.getsockname()[0])
    except OSError:
        return None


def _route_interface(local_ip: str | None, snapshot: SystemSnapshot) -> str | None:
    if not local_ip:
        return None
    return next((interface.name for interface in snapshot.interfaces if local_ip in interface.ipv4), None)


def _probe_with_retries(
    target_ip: str, mtu: int, timeout_ms: int, retries: int
) -> tuple[MtuOptimizerProbe, bool]:
    attempts = [_probe_mtu(target_ip, mtu, timeout_ms)]
    while attempts[-1].outcome == "no_reply" and len(attempts) <= retries:
        attempts.append(_probe_mtu(target_ip, mtu, timeout_ms))
    successful = next((probe for probe in attempts if probe.success), None)
    if successful is not None:
        return _with_attempts(successful, len(attempts)), False
    fragmented = next((probe for probe in attempts if probe.outcome == "too_big"), None)
    if fragmented is not None:
        return _with_attempts(fragmented, len(attempts)), False
    latest = attempts[-1]
    return MtuOptimizerProbe(
        latest.mtu, latest.payload_size, False, None,
        "Нет ICMP-ответа; размер ограничен по тайм-ауту", "too_big", len(attempts),
    ), True


def _with_attempts(probe: MtuOptimizerProbe, attempts: int) -> MtuOptimizerProbe:
    return MtuOptimizerProbe(
        probe.mtu, probe.payload_size, probe.success, probe.latency_ms,
        probe.error, probe.outcome, attempts,
    )


def _probe_mtu(target_ip: str, mtu: int, timeout_ms: int) -> MtuOptimizerProbe:
    payload_size = mtu - _IPV4_HEADER_SIZE - _ICMP_HEADER_SIZE
    try:
        completed = subprocess.run(
            _ping_command(target_ip, payload_size, timeout_ms),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=max(2, timeout_ms / 1000 + 1),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return MtuOptimizerProbe(mtu, payload_size, False, None, str(exc))
    output = _decode_output(completed.stdout)
    samples = parse_ping_samples(output)
    if samples:
        return MtuOptimizerProbe(mtu, payload_size, True, round(sum(samples) / len(samples), 1), outcome="ok")
    if _contains_fragmentation_message(output):
        return MtuOptimizerProbe(mtu, payload_size, False, None, "Пакет требует фрагментации", "too_big")
    return MtuOptimizerProbe(mtu, payload_size, False, None, "Нет ICMP-ответа", "no_reply")


def _ping_command(target_ip: str, payload_size: int, timeout_ms: int) -> list[str]:
    if os.name == "nt":
        return ["ping", "-4", "-n", "1", "-w", str(timeout_ms), "-f", "-l", str(payload_size), target_ip]
    return ["ping", "-4", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), "-M", "do", "-s", str(payload_size), target_ip]


def _parse_subinterfaces(output: str) -> tuple[tuple[int, str], ...]:
    rows: list[tuple[int, str]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+(.+?)\s*$", line)
        if match is not None and _MIN_MTU <= int(match.group(1)) <= 9000:
            rows.append((int(match.group(1)), match.group(2)))
    return tuple(rows)


def _mtu_decision(current: int | None, found: int | None, th: Thresholds) -> str:
    if current is None or found is None:
        return "UNKNOWN"
    if found == current:
        return "NO_CHANGE"
    return "LOWER" if current - found >= th.mtu_apply_min_delta else "HIGHER"


def _failure_report(
    target: str, probes: tuple[MtuOptimizerProbe, ...], error_code: str, error: str, *,
    target_ip: str | None = None, route_interface: str | None = None,
    current_mtu: int | None = None, inferred_by_timeout: bool = False,
) -> MtuOptimizerReport:
    return MtuOptimizerReport(
        target, current_mtu, None, probes, error, target_ip, route_interface,
        "UNKNOWN", error_code, inferred_by_timeout,
    )


def _contains_fragmentation_message(output: str) -> bool:
    lowered = output.casefold()
    return any(marker in lowered for marker in ("fragment", "фрагмент", "packet needs", "требуется"))


def _decode_output(value: bytes) -> str:
    return value.decode(_oem_encoding(), errors="replace")


def _emit(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)
