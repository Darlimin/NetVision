from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from collections.abc import Iterable

import psutil

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


@dataclass(frozen=True, slots=True)
class _ObservedConnection:
    """A normalized socket together with its owning process identifier."""

    pid: int | None
    connection: ProcessConnection


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
    for observed in _collect_inet_connections(connections):
        if observed.pid is None:
            continue
        pid = observed.pid

        if pid not in names:
            names[pid] = _process_name(pid)
        if is_ignored_process(names[pid]):
            continue
        grouped.setdefault(pid, []).append(observed.connection)

    processes = tuple(
        ProcessNetworkInfo(
            pid=pid,
            name=names[pid],
            connections=tuple(items),
        )
        for pid, items in sorted(
            grouped.items(), key=lambda item: (names[item[0]].lower(), item[0])
        )
    )
    return ProcessScanResult(processes)


def scan_process(pid: int) -> ProcessScanResult:
    """Collect only one process's active sockets without a global scan."""
    if pid < 1:
        return ProcessScanResult((), "Некорректный PID процесса")
    try:
        process = psutil.Process(pid)
        name = str(process.name() or f"PID {pid}").strip()
    except psutil.NoSuchProcess:
        return ProcessScanResult((), "Выбранный процесс уже завершился")
    except (psutil.AccessDenied, OSError) as exc:
        return ProcessScanResult((), f"Не удалось открыть процесс: {exc}")

    try:
        # ``inet`` explicitly includes IPv4/IPv6 TCP and UDP sockets.
        connections = process.net_connections(kind="inet")
    except psutil.NoSuchProcess:
        return ProcessScanResult((), "Выбранный процесс уже завершился")
    except psutil.AccessDenied:
        return ProcessScanResult(
            (),
            "Windows не разрешила получить сокеты выбранного процесса. Запустите NetVision с нужными правами.",
        )
    except OSError as exc:
        return ProcessScanResult((), f"Не удалось получить сокеты выбранного процесса: {exc}")

    parsed_connections = tuple(
        observed.connection for observed in _collect_inet_connections(connections)
    )
    if not parsed_connections:
        return ProcessScanResult(())
    return ProcessScanResult((ProcessNetworkInfo(pid, name, parsed_connections),))


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


def unresolved_udp_ports(connections: Iterable[ProcessConnection]) -> tuple[int, ...]:
    """Return local UDP ports whose peer address is unavailable to psutil."""
    return tuple(
        sorted(
            {
                connection.local_port
                for connection in connections
                if connection.protocol == "UDP"
                and not connection.remote_address
                and connection.local_port > 0
            }
        )
    )


def has_unresolved_udp_socket(connections: Iterable[ProcessConnection]) -> bool:
    """Return whether packet capture is useful for the selected process."""
    return bool(unresolved_udp_ports(connections))


def _to_process_connection(connection: object) -> ProcessConnection | None:
    """Normalize a psutil socket record used by global and PID-scoped scans."""
    local = _endpoint(getattr(connection, "laddr", None))
    if local is None:
        return None
    protocol = _protocol(getattr(connection, "type", None))
    status = str(getattr(connection, "status", "")) or "ACTIVE"
    remote = _endpoint(getattr(connection, "raddr", None))
    # Windows exposes many UDP sockets without a peer address. They remain
    # useful for selected-process monitoring even without a remote endpoint.
    if remote is None and protocol != "UDP":
        return None
    return ProcessConnection(
        protocol=protocol,
        status=status,
        local_address=local[0],
        local_port=local[1],
        remote_address=remote[0] if remote else "",
        remote_port=remote[1] if remote else 0,
    )


def _collect_inet_connections(connections: object) -> tuple[_ObservedConnection, ...]:
    """Filter, normalize and order psutil socket records for both scan modes."""
    observed: list[_ObservedConnection] = []
    for connection in connections:
        parsed = _normalize_inet_connection(connection)
        if parsed is not None:
            observed.append(
                _ObservedConnection(
                    pid=_connection_pid(connection),
                    connection=parsed,
                )
            )
    return tuple(sorted(observed, key=lambda item: _connection_sort_key(item.connection)))


def _normalize_inet_connection(connection: object) -> ProcessConnection | None:
    if not _is_valid_inet_connection(connection):
        return None
    return _to_process_connection(connection)


def _connection_pid(connection: object) -> int | None:
    pid = getattr(connection, "pid", None)
    return pid if isinstance(pid, int) else None


def _is_valid_inet_connection(connection: object) -> bool:
    """Keep established TCP and every UDP datagram socket from psutil."""
    connection_type = getattr(connection, "type", None)
    is_valid_tcp = (
        connection_type == socket.SOCK_STREAM
        and getattr(connection, "status", "") == psutil.CONN_ESTABLISHED
    )
    is_valid_udp = connection_type == socket.SOCK_DGRAM
    return is_valid_tcp or is_valid_udp


def _endpoint(value: object) -> tuple[str, int] | None:
    address, port = _endpoint_parts(value)
    normalized_address = _normalize_endpoint_address(address)
    normalized_port = _normalize_endpoint_port(port)
    if normalized_address is None or normalized_port is None:
        return None
    return normalized_address, normalized_port


def _endpoint_parts(value: object) -> tuple[object | None, object | None]:
    """Read psutil tuple/namedtuple endpoints and compatible object forms."""
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return value[0], value[1]
    for address_name in ("ip", "address", "host"):
        address = getattr(value, address_name, None)
        if address:
            return address, getattr(value, "port", None)
    return None, None


def _normalize_endpoint_address(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    address = value.strip().strip("[]").split("%", 1)[0]
    return address or None


def _normalize_endpoint_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if port > 0 else None


def _protocol(connection_type: object) -> str:
    if connection_type == socket.SOCK_DGRAM:
        return "UDP"
    return "TCP"


def is_loopback_address(address: object) -> bool:
    """Return whether an endpoint is a local proxy/listening address."""
    if not isinstance(address, str):
        return True
    if not address or address in {"0.0.0.0", "::"}:
        return True
    parsed = _parse_ip_address(address)
    return parsed.is_loopback if parsed is not None else False


def is_public_address(address: object) -> bool:
    """Return whether an endpoint is a globally routable IP address."""
    parsed = _parse_ip_address(address)
    return parsed.is_global if parsed is not None else False


def _parse_ip_address(address: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(address, str):
        return None
    normalized_address = _normalize_endpoint_address(address)
    if normalized_address is None:
        return None
    try:
        return ipaddress.ip_address(normalized_address)
    except (TypeError, ValueError):
        return None


def _connection_sort_key(connection: ProcessConnection) -> tuple[int, int, int, str]:
    return (
        1 if is_loopback_address(connection.remote_address) else 0,
        0 if connection.protocol == "TCP" else 1,
        0 if connection.status == "ESTABLISHED" else 1,
        connection.remote_endpoint,
    )
