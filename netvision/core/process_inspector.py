from __future__ import annotations

from dataclasses import dataclass
import socket

import psutil


ACTIVE_TCP_STATUSES = frozenset({"ESTABLISHED", "SYN_SENT", "SYN_RECV"})

# Background services do not provide an actionable target for end-user diagnostics.
IGNORED_PROCESS_NAMES = frozenset(
    {
        "applemobiledeviceservice.exe",
        "mdnsresponder.exe",
        "svchost.exe",
        "spoolsv.exe",
        "services.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "system",
        "system idle process",
        "taskhostw.exe",
        "searchindexer.exe",
        "runtimebroker.exe",
        "dllhost.exe",
        "fontdrvhost.exe",
        "wudfhost.exe",
    }
)


@dataclass(frozen=True, slots=True)
class ProcessConnection:
    protocol: str
    status: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int

    @property
    def remote_endpoint(self) -> str:
        if not self.remote_address or self.remote_port < 1:
            return f"локальный UDP-порт {self.local_port}"
        host = f"[{self.remote_address}]" if ":" in self.remote_address else self.remote_address
        return f"{host}:{self.remote_port}"

    @property
    def label(self) -> str:
        return f"{self.protocol} · {self.remote_endpoint} · {self.status}"


@dataclass(frozen=True, slots=True)
class ProcessNetworkInfo:
    pid: int
    name: str
    connections: tuple[ProcessConnection, ...]

    @property
    def label(self) -> str:
        count = len(self.connections)
        suffix = "соединение" if count == 1 else "соединений"
        return f"{self.name} · PID {self.pid} · {count} {suffix}"

    @property
    def friendly_name(self) -> str:
        return friendly_process_name(self.name)


@dataclass(frozen=True, slots=True)
class ProcessScanResult:
    processes: tuple[ProcessNetworkInfo, ...]
    warning: str | None = None


@dataclass(frozen=True, slots=True)
class RunningProcess:
    """A running process that can be selected for diagnostics."""

    pid: int
    name: str


@dataclass(frozen=True, slots=True)
class ProcessListResult:
    processes: tuple[RunningProcess, ...]
    warning: str | None = None


def list_running_processes() -> ProcessListResult:
    """Return all accessible running processes for the manual selector."""
    processes: list[RunningProcess] = []
    try:
        iterator = psutil.process_iter(["pid", "name"])
        for process in iterator:
            try:
                info = process.info
                pid = int(info["pid"])
                name = str(info.get("name") or "").strip()
            except (KeyError, TypeError, ValueError, psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            if pid > 0 and name:
                processes.append(RunningProcess(pid=pid, name=name))
    except (psutil.AccessDenied, OSError) as exc:
        return ProcessListResult((), str(exc))

    return ProcessListResult(
        tuple(
            sorted(
                processes,
                key=lambda item: (
                    item.name.casefold() != "huntgame.exe",
                    item.name.casefold(),
                    item.pid,
                ),
            )
        )
    )


def scan_processes() -> ProcessScanResult:
    """Collect running processes with a remote active network endpoint."""
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return ProcessScanResult(
            (),
            "Windows не разрешила получить список сокетов. Запустите NetVision с нужными правами.",
        )
    except OSError as exc:
        return ProcessScanResult((), f"Не удалось получить сетевые соединения: {exc}")

    names: dict[int, str] = {}
    grouped: dict[int, list[ProcessConnection]] = {}
    for connection in connections:
        pid = getattr(connection, "pid", None)
        local = _endpoint(getattr(connection, "laddr", None))
        if pid is None or local is None:
            continue

        protocol = _protocol(getattr(connection, "type", None))
        status = str(getattr(connection, "status", "")) or "ACTIVE"
        if protocol == "TCP" and status not in ACTIVE_TCP_STATUSES:
            continue
        remote = _endpoint(getattr(connection, "raddr", None))
        # Windows exposes many UDP sockets without a peer address. They are
        # still useful for selecting a game and observing its live local ports.
        if remote is None and protocol != "UDP":
            continue

        if pid not in names:
            names[pid] = _process_name(pid)
        if is_ignored_process(names[pid]):
            continue
        grouped.setdefault(pid, []).append(
            ProcessConnection(
                protocol=protocol,
                status=status,
                local_address=local[0],
                local_port=local[1],
                remote_address=remote[0] if remote else "",
                remote_port=remote[1] if remote else 0,
            )
        )

    processes = tuple(
        ProcessNetworkInfo(
            pid=pid,
            name=names[pid],
            connections=tuple(sorted(items, key=_connection_sort_key)),
        )
        for pid, items in sorted(grouped.items(), key=lambda item: (names[item[0]].lower(), item[0]))
    )
    return ProcessScanResult(processes)


def _process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name() or f"PID {pid}"
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return f"PID {pid}"


def friendly_process_name(name: str) -> str:
    """Return a readable process label for the simplified interface."""
    normalized = name.casefold().removesuffix(".exe")
    known_names = {
        "applemobiledeviceservice": "📱 Apple Mobile Device",
        "discord": "💬 Discord",
        "steam": "🎮 Steam",
        "cs2": "🎮 Counter-Strike 2",
        "csgo": "🎮 Counter-Strike",
        "telegram": "💬 Telegram",
        "chrome": "🌐 Google Chrome",
        "msedge": "🌐 Microsoft Edge",
        "firefox": "🌐 Firefox",
        "yandex": "🌐 Яндекс Браузер",
    }
    if normalized in known_names:
        return known_names[normalized]
    readable = name.removesuffix(".exe").replace("_", " ").replace("-", " ").strip()
    return f"🖥️ {readable or 'Системное приложение'}"


def is_ignored_process(name: str) -> bool:
    """Return whether a known background service should stay out of the default picker."""
    return name.strip().casefold() in IGNORED_PROCESS_NAMES


def _endpoint(value: object) -> tuple[str, int] | None:
    if not isinstance(value, tuple) or len(value) < 2:
        return None
    address, port = value[0], value[1]
    if not address or not isinstance(port, int) or port < 1:
        return None
    return str(address).split("%", 1)[0], port


def _protocol(connection_type: object) -> str:
    if connection_type == socket.SOCK_DGRAM:
        return "UDP"
    return "TCP"


def _connection_sort_key(connection: ProcessConnection) -> tuple[int, int, str]:
    return (
        0 if connection.protocol == "TCP" else 1,
        0 if connection.status == "ESTABLISHED" else 1,
        connection.remote_endpoint,
    )
