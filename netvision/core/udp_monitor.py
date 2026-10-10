"""Windows UDP port monitoring for a selected process.

The Windows UDP table only exposes local bound ports and their owning PID. UDP
has no connection state comparable to TCP ESTABLISHED, so the monitor presents
these ports as local UDP activity rather than inventing remote endpoints.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ctypes
from ctypes import wintypes
import os
import socket
from threading import Event, RLock, Thread, current_thread

import psutil


AF_INET = 2
ERROR_INSUFFICIENT_BUFFER = 122
UDP_TABLE_OWNER_PID = 1


@dataclass(frozen=True, slots=True)
class UdpPortSnapshot:
    """A point-in-time list of local UDP ports owned by one process."""

    pid: int
    ports: tuple[int, ...]
    warning: str | None = None


class UdpPortAnomaly(str, Enum):
    """A significant port-set change observed between two valid samples."""

    ALL_PORTS_LOST = "all_ports_lost"
    FULL_PORT_ROTATION = "full_port_rotation"


@dataclass(frozen=True, slots=True)
class UdpPortActivity:
    """One sample together with its delta from the previous valid sample."""

    snapshot: UdpPortSnapshot
    observed_at: datetime
    opened_ports: tuple[int, ...] = ()
    closed_ports: tuple[int, ...] = ()
    anomaly: UdpPortAnomaly | None = None

    @property
    def potential_disconnect(self) -> bool:
        return self.anomaly is not None


class UdpPortHistory:
    """Keep a bounded UDP activity history and detect abrupt port changes."""

    def __init__(self, max_entries: int = 120) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._entries: deque[UdpPortActivity] = deque(maxlen=max_entries)
        self._previous_ports: frozenset[int] | None = None

    @property
    def entries(self) -> tuple[UdpPortActivity, ...]:
        return tuple(self._entries)

    @property
    def latest(self) -> UdpPortActivity | None:
        return self._entries[-1] if self._entries else None

    def observe(
        self,
        snapshot: UdpPortSnapshot,
        observed_at: datetime | None = None,
    ) -> UdpPortActivity:
        """Record a snapshot and return opened/closed ports with any anomaly."""

        timestamp = observed_at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        current_ports = frozenset(snapshot.ports)
        opened: tuple[int, ...] = ()
        closed: tuple[int, ...] = ()
        anomaly: UdpPortAnomaly | None = None

        # An access error is not evidence that the game closed every UDP port.
        if snapshot.warning is None and self._previous_ports is not None:
            opened = tuple(sorted(current_ports - self._previous_ports))
            closed = tuple(sorted(self._previous_ports - current_ports))
            if self._previous_ports and not current_ports:
                anomaly = UdpPortAnomaly.ALL_PORTS_LOST
            elif self._previous_ports and current_ports and not (current_ports & self._previous_ports):
                anomaly = UdpPortAnomaly.FULL_PORT_ROTATION

        activity = UdpPortActivity(snapshot, timestamp, opened, closed, anomaly)
        self._entries.append(activity)
        if snapshot.warning is None:
            self._previous_ports = current_ports
        return activity


class UdpPortMonitorManager:
    """Poll one PID or process name on a daemon thread and emit activity events.

    The class is UI-framework agnostic. Qt callers can use the same tracker in
    a QThread, while services and scripts can pass a normal Python callback.
    """

    def __init__(
        self,
        *,
        pid: int | None = None,
        process_name: str | None = None,
        interval_s: float = 2.0,
        max_history: int = 120,
        on_activity: Callable[[UdpPortActivity], None] | None = None,
        reader: Callable[[int], UdpPortSnapshot] | None = None,
    ) -> None:
        if (pid is None) == (process_name is None):
            raise ValueError("Specify exactly one of pid or process_name")
        if pid is not None and pid <= 0:
            raise ValueError("pid must be positive")
        if interval_s <= 0:
            raise ValueError("interval_s must be positive")

        self._pid = pid
        self._process_name = process_name.casefold() if process_name else None
        self._interval_s = interval_s
        self._on_activity = on_activity
        self._reader = reader or get_process_udp_ports
        self._history = UdpPortHistory(max_history)
        self._stop_event = Event()
        self._lock = RLock()
        self._thread: Thread | None = None

    @property
    def history(self) -> tuple[UdpPortActivity, ...]:
        with self._lock:
            return self._history.entries

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = Thread(target=self._run, name="netvision-udp-monitor", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not current_thread():
            thread.join(timeout)
        with self._lock:
            if thread is self._thread and (thread is None or not thread.is_alive()):
                self._thread = None

    def poll_once(self) -> UdpPortActivity:
        """Read one sample synchronously; useful for tests and scheduled jobs."""

        pid = self._resolve_pid()
        if pid is None:
            name = self._process_name or "процесс"
            snapshot = UdpPortSnapshot(-1, (), f"Процесс {name} не найден")
        else:
            snapshot = self._reader(pid)
        with self._lock:
            activity = self._history.observe(snapshot)
        return activity

    def _run(self) -> None:
        while not self._stop_event.is_set():
            activity = self.poll_once()
            if self._on_activity is not None:
                try:
                    self._on_activity(activity)
                except Exception:
                    # A subscriber must not stop network monitoring.
                    pass
            self._stop_event.wait(self._interval_s)

    def _resolve_pid(self) -> int | None:
        if self._pid is not None:
            return self._pid
        assert self._process_name is not None
        try:
            matches = (
                process.info
                for process in psutil.process_iter(["pid", "name"])
                if isinstance(process.info.get("name"), str)
                and process.info["name"].casefold() == self._process_name
            )
            first_match = next(matches, None)
        except (psutil.AccessDenied, psutil.Error, OSError):
            return None
        return int(first_match["pid"]) if first_match else None


class _MibUdpRowOwnerPid(ctypes.Structure):
    _fields_ = (
        ("local_address", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("owning_pid", wintypes.DWORD),
    )


def get_process_udp_ports(pid: int) -> UdpPortSnapshot:
    """Return IPv4 UDP ports currently bound by *pid* on Windows.

    The call has no side effects, performs one table read, and is suitable for
    use in a background worker. It deliberately returns a warning instead of
    raising for unsupported platforms and access failures so the GUI can stay
    responsive and informative.
    """

    if pid <= 0:
        return UdpPortSnapshot(pid, (), "Некорректный PID для UDP-мониторинга")
    if os.name != "nt":
        return _get_process_udp_ports_psutil(pid)

    try:
        rows = _read_windows_udp_rows()
    except OSError as exc:
        return UdpPortSnapshot(pid, (), f"Не удалось прочитать таблицу UDP: {exc}")

    ports = tuple(
        sorted(
            {
                _port_from_network_order(row.local_port)
                for row in rows
                if row.owning_pid == pid and _port_from_network_order(row.local_port) > 0
            }
        )
    )
    return UdpPortSnapshot(pid, ports)


def _get_process_udp_ports_psutil(pid: int) -> UdpPortSnapshot:
    """Portable fallback for systems without the Windows owner-PID UDP table."""

    try:
        connections = psutil.net_connections(kind="udp")
    except (psutil.AccessDenied, psutil.Error, OSError) as exc:
        return UdpPortSnapshot(pid, (), f"Не удалось прочитать UDP-сокеты: {exc}")

    ports = tuple(
        sorted(
            {
                port
                for connection in connections
                if getattr(connection, "pid", None) == pid
                for port in (_local_port(getattr(connection, "laddr", None)),)
                if port is not None
            }
        )
    )
    return UdpPortSnapshot(pid, ports)


def _read_windows_udp_rows() -> tuple[_MibUdpRowOwnerPid, ...]:
    iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    get_extended_udp_table = iphlpapi.GetExtendedUdpTable
    get_extended_udp_table.argtypes = (
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.BOOL,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
    )
    get_extended_udp_table.restype = wintypes.DWORD

    buffer_size = wintypes.ULONG(0)
    result = get_extended_udp_table(
        None,
        ctypes.byref(buffer_size),
        True,
        AF_INET,
        UDP_TABLE_OWNER_PID,
        0,
    )
    if result not in (0, ERROR_INSUFFICIENT_BUFFER) or buffer_size.value == 0:
        raise OSError(result, "GetExtendedUdpTable did not provide a buffer size")

    buffer = ctypes.create_string_buffer(buffer_size.value)
    result = get_extended_udp_table(
        buffer,
        ctypes.byref(buffer_size),
        True,
        AF_INET,
        UDP_TABLE_OWNER_PID,
        0,
    )
    if result != 0:
        raise OSError(result, "GetExtendedUdpTable failed")

    row_count = ctypes.c_uint32.from_buffer_copy(buffer).value
    row_size = ctypes.sizeof(_MibUdpRowOwnerPid)
    available_rows = max(0, (len(buffer) - ctypes.sizeof(ctypes.c_uint32)) // row_size)
    if row_count > available_rows:
        raise OSError("GetExtendedUdpTable returned an invalid row count")

    offset = ctypes.sizeof(ctypes.c_uint32)
    return tuple(
        _MibUdpRowOwnerPid.from_buffer_copy(buffer, offset + index * row_size)
        for index in range(row_count)
    )


def _port_from_network_order(value: int) -> int:
    return socket.ntohs(value & 0xFFFF)


def _local_port(endpoint: object) -> int | None:
    if isinstance(endpoint, tuple) and len(endpoint) >= 2 and isinstance(endpoint[1], int):
        return endpoint[1] if endpoint[1] > 0 else None
    port = getattr(endpoint, "port", None)
    return port if isinstance(port, int) and port > 0 else None
