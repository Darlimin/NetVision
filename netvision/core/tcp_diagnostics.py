from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import socket
from time import perf_counter

import psutil


TRACKED_TCP_STATES = frozenset({"ESTABLISHED", "TIME_WAIT", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT"})


@dataclass(frozen=True, slots=True)
class TcpSocketRecord:
    pid: int | None
    process_name: str
    local_endpoint: str
    remote_endpoint: str
    state: str


@dataclass(frozen=True, slots=True)
class TcpConnectMeasurement:
    host: str
    port: int
    connect_ms: float | None
    status: str
    error: str | None = None

    @property
    def is_open(self) -> bool:
        return self.status == "Открыт"

    @property
    def stages_are_estimated(self) -> bool:
        return self.connect_ms is not None


def scan_tcp_sockets() -> tuple[TcpSocketRecord, ...]:
    """Read selected TCP socket states visible to the current Windows session."""
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        return ()

    names: dict[int, str] = {}
    records: list[TcpSocketRecord] = []
    for connection in connections:
        state = str(getattr(connection, "status", "")).upper()
        if state not in TRACKED_TCP_STATES:
            continue
        local = _format_endpoint(getattr(connection, "laddr", None))
        remote = _format_endpoint(getattr(connection, "raddr", None))
        if not local or not remote:
            continue
        pid = getattr(connection, "pid", None)
        if not isinstance(pid, int):
            pid = None
        name = names.setdefault(pid, _process_name(pid)) if pid is not None else "Системный сокет"
        records.append(TcpSocketRecord(pid, name, local, remote, state))
    return tuple(sorted(records, key=lambda record: (record.process_name.casefold(), record.remote_endpoint, record.state)))


def probe_tcp_connect(host: str, port: int, timeout: float = 2.0) -> TcpConnectMeasurement:
    if not host.strip() or not 1 <= port <= 65535 or timeout <= 0:
        raise ValueError("Параметры TCP-проверки некорректны")
    started = perf_counter()
    try:
        with socket.create_connection((host.strip(), port), timeout=timeout):
            elapsed = round((perf_counter() - started) * 1000, 1)
    except socket.timeout:
        return TcpConnectMeasurement(host.strip(), port, None, "Фильтруется / timeout", "Время ожидания TCP истекло")
    except ConnectionRefusedError:
        return TcpConnectMeasurement(host.strip(), port, None, "Закрыт", "Удалённый узел отклонил TCP-соединение")
    except OSError as exc:
        return TcpConnectMeasurement(host.strip(), port, None, "Ошибка", str(exc))
    return TcpConnectMeasurement(host.strip(), port, elapsed, "Открыт")


def probe_common_ports(
    host: str,
    ports: tuple[int, ...] | list[int],
    *,
    timeout: float = 1.5,
) -> tuple[TcpConnectMeasurement, ...]:
    """Probe independent TCP ports in parallel, preserving the requested order."""
    normalized = tuple(dict.fromkeys(int(port) for port in ports))
    if not normalized:
        raise ValueError("Укажите хотя бы один TCP-порт")
    if any(port < 1 or port > 65535 for port in normalized):
        raise ValueError("TCP-порты должны быть в диапазоне 1–65535")
    results: dict[int, TcpConnectMeasurement] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(normalized))) as executor:
        futures = {executor.submit(probe_tcp_connect, host, port, timeout): port for port in normalized}
        for future in as_completed(futures):
            port = futures[future]
            try:
                results[port] = future.result()
            except Exception as exc:
                results[port] = TcpConnectMeasurement(host, port, None, "Ошибка", str(exc))
    return tuple(results[port] for port in normalized)


def _format_endpoint(value: object) -> str | None:
    if not isinstance(value, tuple) or len(value) < 2:
        return None
    host, port = value[0], value[1]
    if not host or not isinstance(port, int) or port < 1:
        return None
    address = str(host).split("%", 1)[0]
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name() or f"PID {pid}"
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return f"PID {pid}"
