"""Streaming traceroute data for the Visual Traceroute workspace."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import ctypes
import ipaddress
import locale
import re
import socket
import struct
import subprocess
import sys

from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds


class TracerouteHop:
    __slots__ = ("index", "address", "hostname", "latency_ms", "status", "timed_out")

    def __init__(
        self,
        index: int,
        address: str | None,
        hostname: str | None,
        latency_ms: float | None,
        status: str,
        timed_out: bool,
    ) -> None:
        self.index = index
        self.address = address
        self.hostname = hostname
        self.latency_ms = latency_ms
        self.status = status
        self.timed_out = timed_out


@dataclass(frozen=True, slots=True)
class HopProbe:
    ttl: int
    address: str | None
    latency_ms: float | None
    status: str
    error: str | None = None
    is_destination: bool = False


@dataclass(frozen=True, slots=True)
class MtrHopStats:
    ttl: int
    addresses: tuple[str, ...]
    sent: int
    recv: int
    loss_pct: float
    last_ms: float | None
    avg_ms: float | None
    best_ms: float | None
    worst_ms: float | None
    jitter_ms: float | None
    real_loss: bool = False
    icmp_limited: bool = False


@dataclass(frozen=True, slots=True)
class MtrEvent:
    kind: str
    hop: int
    loss_pct: float | None = None
    previous_address: str | None = None
    address: str | None = None
    duration_s: float | None = None


@dataclass(frozen=True, slots=True)
class MtrSnapshot:
    target_ip: str
    at: datetime
    hops: tuple[MtrHopStats, ...]
    destination_reached: bool
    undetermined: bool
    real_loss_start_hop: int | None = None
    real_loss_pct: float | None = None
    events: tuple[MtrEvent, ...] = ()


class MtrAccumulator:
    """Aggregate TTL probes in a bounded window and classify path-wide loss."""

    def __init__(
        self,
        window_cycles: int = 100,
        *,
        thresholds: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        if window_cycles < 1:
            raise ValueError("MTR window must be positive")
        self._cycles: deque[tuple[HopProbe, ...]] = deque(maxlen=window_cycles)
        self._thresholds = thresholds
        self._last_addresses: dict[int, str] = {}
        self._candidate_start: int | None = None
        self._candidate_cycles = 0
        self._active_start: int | None = None
        self._active_at: datetime | None = None

    def update(
        self,
        target_ip: str,
        probes: Iterable[HopProbe],
        *,
        at: datetime | None = None,
    ) -> MtrSnapshot:
        timestamp = at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        cycle = tuple(probes)
        events: list[MtrEvent] = []
        for probe in cycle:
            if probe.address is None:
                continue
            previous = self._last_addresses.get(probe.ttl)
            if previous is not None and previous != probe.address:
                events.append(
                    MtrEvent(
                        "route_changed",
                        probe.ttl,
                        previous_address=previous,
                        address=probe.address,
                    )
                )
            self._last_addresses[probe.ttl] = probe.address
        self._cycles.append(cycle)

        hops, destination_reached = self._build_hops(target_ip)
        real_start = next((hop for hop in hops if hop.real_loss), None)
        if real_start is not None:
            if self._candidate_start == real_start.ttl:
                self._candidate_cycles += 1
            else:
                self._candidate_start = real_start.ttl
                self._candidate_cycles = 1
            if (
                self._active_start is None
                and self._candidate_cycles >= self._thresholds.mtr_confirm_cycles
            ):
                self._active_start = real_start.ttl
                self._active_at = timestamp
                events.append(MtrEvent("loss_opened", real_start.ttl, real_start.loss_pct))
        else:
            self._candidate_start = None
            self._candidate_cycles = 0

        if self._active_start is not None:
            active = next((hop for hop in hops if hop.ttl == self._active_start), None)
            if active is not None and active.loss_pct < self._thresholds.mtr_loss_clear_pct:
                duration = (
                    (timestamp - self._active_at).total_seconds()
                    if self._active_at is not None
                    else None
                )
                events.append(
                    MtrEvent("loss_closed", active.ttl, active.loss_pct, duration_s=duration)
                )
                self._active_start = None
                self._active_at = None

        current = next((hop for hop in hops if hop.real_loss), None)
        return MtrSnapshot(
            target_ip=target_ip,
            at=timestamp,
            hops=tuple(hops),
            destination_reached=destination_reached,
            undetermined=not destination_reached,
            real_loss_start_hop=current.ttl if current else None,
            real_loss_pct=current.loss_pct if current else None,
            events=tuple(events),
        )

    def _build_hops(self, target_ip: str) -> tuple[list[MtrHopStats], bool]:
        destination_ttls = [
            probe.ttl
            for cycle in self._cycles
            for probe in cycle
            if probe.is_destination or probe.address == target_ip
        ]
        destination_reached = bool(destination_ttls)
        maximum_ttl = max(destination_ttls, default=0)
        if not maximum_ttl:
            maximum_ttl = max((probe.ttl for cycle in self._cycles for probe in cycle), default=0)

        stats: list[MtrHopStats] = []
        for ttl in range(1, maximum_ttl + 1):
            probes = [probe for cycle in self._cycles for probe in cycle if probe.ttl == ttl]
            if not probes:
                continue
            received = [probe for probe in probes if probe.latency_ms is not None]
            latencies = [probe.latency_ms for probe in received if probe.latency_ms is not None]
            addresses = tuple(sorted({probe.address for probe in received if probe.address}))
            loss_pct = round((len(probes) - len(received)) * 100.0 / len(probes), 1)
            jitter = (
                round(
                    sum(abs(right - left) for left, right in zip(latencies, latencies[1:]))
                    / (len(latencies) - 1),
                    1,
                )
                if len(latencies) > 1
                else None
            )
            stats.append(
                MtrHopStats(
                    ttl=ttl,
                    addresses=addresses,
                    sent=len(probes),
                    recv=len(received),
                    loss_pct=loss_pct,
                    last_ms=latencies[-1] if latencies else None,
                    avg_ms=round(sum(latencies) / len(latencies), 1) if latencies else None,
                    best_ms=min(latencies) if latencies else None,
                    worst_ms=max(latencies) if latencies else None,
                    jitter_ms=jitter,
                )
            )

        if not destination_reached:
            return stats, False
        tail_has_loss = True
        classified: list[MtrHopStats] = []
        for hop in reversed(stats):
            above_warning = hop.loss_pct >= self._thresholds.mtr_loss_warn_pct
            real_loss = above_warning and tail_has_loss
            classified.append(
                replace(
                    hop,
                    real_loss=real_loss,
                    icmp_limited=above_warning and not real_loss,
                )
            )
            tail_has_loss = tail_has_loss and above_warning
        classified.reverse()
        return classified, True


class _IpOptionInformation(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IpOptionInformation),
    ]


def probe_hop(target_ip: str, ttl: int, timeout_ms: int) -> HopProbe:
    """Send one Windows ICMP echo with an explicit TTL for MTR monitoring."""
    if sys.platform != "win32":
        raise RuntimeError("Непрерывный MTR поддерживается только в Windows")
    if not 1 <= ttl <= 255 or timeout_ms < 1:
        raise ValueError("Некорректные параметры MTR-пробы")
    try:
        target = struct.unpack("I", socket.inet_aton(target_ip))[0]
    except OSError as exc:
        raise ValueError(f"Некорректный IPv4-адрес MTR: {target_ip}") from exc

    iphlpapi = ctypes.windll.iphlpapi
    create_file = iphlpapi.IcmpCreateFile
    create_file.restype = ctypes.c_void_p
    send_echo = iphlpapi.IcmpSendEcho
    send_echo.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    send_echo.restype = ctypes.c_ulong
    close_handle = iphlpapi.IcmpCloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_bool
    handle = create_file()
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in (0, invalid_handle):
        raise RuntimeError(f"Не удалось создать ICMP-handle: {ctypes.get_last_error()}")
    try:
        payload = b"NetVision-MTR"
        payload_buffer = ctypes.create_string_buffer(payload)
        reply_buffer = ctypes.create_string_buffer(ctypes.sizeof(_IcmpEchoReply) + len(payload) + 8)
        options = _IpOptionInformation(ttl, 0, 0, 0, None)
        replies = send_echo(
            handle,
            target,
            payload_buffer,
            len(payload),
            ctypes.byref(options),
            reply_buffer,
            len(reply_buffer),
            timeout_ms,
        )
        if not replies:
            error = ctypes.get_last_error()
            return HopProbe(ttl, None, None, "timeout", f"ICMP error {error}")
        reply = ctypes.cast(reply_buffer, ctypes.POINTER(_IcmpEchoReply)).contents
        address = socket.inet_ntoa(struct.pack("I", reply.Address))
        status = int(reply.Status)
        if status == 0:
            return HopProbe(ttl, address, float(reply.RoundTripTime), "success", is_destination=True)
        if status == 11013:  # IP_TTL_EXPIRED_TRANSIT
            return HopProbe(ttl, address, float(reply.RoundTripTime), "ttl_expired")
        return HopProbe(ttl, address or None, None, "timeout", f"ICMP status {status}")
    finally:
        close_handle(handle)


def run_visual_traceroute(
    host: str,
    *,
    max_hops: int = 20,
    wait_ms: int = 700,
    on_hop: Callable[[TracerouteHop], None] | None = None,
) -> tuple[TracerouteHop, ...]:
    """Run the platform traceroute command and emit each parsed hop as it arrives."""
    host = host.strip()
    if not host:
        raise ValueError("Целевой хост не указан")
    if max_hops < 1 or wait_ms < 1:
        raise ValueError("Параметры трассировки должны быть положительными")

    if sys.platform == "win32":
        command = ["tracert", "-w", str(wait_ms), "-h", str(max_hops), host]
    else:
        command = ["traceroute", "-n", "-w", str(max(1, wait_ms // 1000)), "-m", str(max_hops), host]

    hops: list[TracerouteHop] = []
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding=_console_encoding(),
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as exc:
        raise RuntimeError(f"Не удалось запустить traceroute: {exc}") from exc

    try:
        if process.stdout is not None:
            for line in process.stdout:
                hop = parse_traceroute_line(line)
                if hop is None:
                    continue
                hops.append(hop)
                if on_hop is not None:
                    on_hop(hop)
        process.wait(timeout=max_hops * max(1.0, wait_ms / 1000) + 10)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise RuntimeError("Трассировка превысила допустимое время ожидания") from exc
    finally:
        if process.stdout is not None:
            process.stdout.close()

    return tuple(hops)


def parse_traceroute_line(line: str) -> TracerouteHop | None:
    """Parse one Windows tracert or Unix traceroute hop line."""
    match = re.match(r"^\s*(\d+)\s+(.+)$", line)
    if not match:
        return None
    index = int(match.group(1))
    body = match.group(2).strip()
    latency_values = [
        float(value.replace(",", "."))
        for value in re.findall(r"<?(\d+(?:[.,]\d+)?)\s*(?:ms|мс)", body, re.IGNORECASE)
    ]
    latency_ms = round(sum(latency_values) / len(latency_values), 1) if latency_values else None
    addresses = re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", body)
    address = None
    for candidate in reversed(addresses):
        try:
            if ipaddress.ip_address(candidate).version == 4:
                address = candidate
                break
        except ValueError:
            continue
    timed_out = address is None and ("*" in body or "timed out" in body.casefold() or "превыш" in body.casefold())
    hostname = _extract_hostname(body, address)
    status = "Тайм-аут" if timed_out else "Доступен" if address else "Не определён"
    return TracerouteHop(index, address, hostname, latency_ms, status, timed_out)


def _extract_hostname(body: str, address: str | None) -> str | None:
    value = re.sub(r"<?\d+(?:[.,]\d+)?\s*(?:ms|мс)", " ", body, flags=re.IGNORECASE)
    value = value.replace("*", " ")
    value = re.sub(r"(?:Request timed out\.|Превышено время ожидания\.?|timed out)", " ", value, flags=re.IGNORECASE)
    if address:
        value = value.replace(f"[{address}]", " ").replace(address, " ")
    value = re.sub(r"\s+", " ", value).strip(" []")
    return value or address


def _console_encoding() -> str:
    try:
        code_page = int(ctypes.windll.kernel32.GetOEMCP())
        if code_page > 0:
            return f"cp{code_page}"
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return locale.getpreferredencoding(False) or "utf-8"
