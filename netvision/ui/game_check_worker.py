"""Background game endpoint discovery."""

from dataclasses import dataclass
from threading import Event
from PySide6.QtCore import QObject, Signal, Slot
from netvision.core.packet_capture import (
    CaptureState,
    PacketCaptureResult,
    WindowsRawUdpBackend,
    capture_udp_endpoint,
)
from netvision.core.process_inspector import (
    ProcessConnection,
    ProcessListResult,
    RunningProcess,
    list_running_processes,
    scan_process,
    is_ignored_process,
    has_unresolved_udp_socket,
    unresolved_udp_ports,
    is_public_address,
)
from netvision.core.probes import probe_ping
from netvision.core.process_utils import (
    _explain_game_connection,
    _is_background_cdn,
    _game_connection_key,
)


@dataclass(frozen=True, slots=True)
class GameAutoCheckResult:
    process: RunningProcess | None
    connections: tuple[ProcessConnection, ...]
    ping: object | None
    warning: str | None = None
    selected_connection: ProcessConnection | None = None
    selection_reason: str | None = None
    capture_state: CaptureState = CaptureState.NOT_STARTED
    capture_reason: str | None = None
    capture_started: bool = False


class GameAutoCheckWorker(QObject):
    completed = Signal(object)
    capture_started = Signal(object)

    def __init__(
        self,
        preferred_process: str | None = None,
        capture_backend: object | None = None,
        capture_timeout_s: float = 4.0,
    ) -> None:
        super().__init__()
        self._preferred_process = preferred_process
        self._capture_backend = capture_backend or WindowsRawUdpBackend()
        self._capture_timeout_s = capture_timeout_s
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        try:
            process_result = list_running_processes()
            candidates = self._candidate_processes(process_result)
            if not candidates:
                self.completed.emit(self._missing_process_result(process_result))
                return
            first_result: GameAutoCheckResult | None = None
            for process in candidates:
                if self._stop_event.is_set():
                    self.completed.emit(
                        GameAutoCheckResult(
                            None,
                            (),
                            None,
                            "Проверка остановлена",
                            None,
                            capture_state=CaptureState.STOPPED,
                        )
                    )
                    return
                result = self._inspect_process(process, process_result.warning)
                if first_result is None:
                    first_result = result
                if result.selected_connection is None:
                    continue
                self.completed.emit(result)
                return
            self.completed.emit(first_result or self._missing_process_result(process_result))
        except Exception as exc:
            self.completed.emit(GameAutoCheckResult(None, (), None, str(exc), None))

    def _candidate_processes(self, result: ProcessListResult) -> tuple[RunningProcess, ...]:
        if self._preferred_process is not None:
            preferred = self._preferred_process.casefold()
            return tuple(item for item in result.processes if item.name.casefold() == preferred)
        hunt = tuple(item for item in result.processes if item.name.casefold() == "huntgame.exe")
        fallback = tuple(
            item
            for item in result.processes
            if item.name.casefold() != "huntgame.exe" and not is_ignored_process(item.name)
        )
        return hunt + fallback

    def _missing_process_result(self, result: ProcessListResult) -> GameAutoCheckResult:
        if self._preferred_process is not None:
            warning = result.warning or f"Процесс {self._preferred_process} не найден"
        else:
            warning = (
                result.warning or "Игровой процесс и резервный процесс с внешним сокетом не найдены"
            )
        return GameAutoCheckResult(None, (), None, warning, None)

    def _inspect_process(
        self,
        process: RunningProcess,
        process_warning: str | None,
    ) -> GameAutoCheckResult:
        network_result = scan_process(process.pid)
        network_process = next(
            (item for item in network_result.processes if item.pid == process.pid),
            None,
        )
        connections = network_process.connections if network_process is not None else ()
        selected = self._select_game_connection(connections)
        capture_result = self._capture_missing_endpoint(process, connections, selected)
        if capture_result is not None and capture_result.connection is not None:
            selected = capture_result.connection
        warning = self._endpoint_warning(
            process, process_warning or network_result.warning, capture_result, selected
        )
        if selected is None:
            return GameAutoCheckResult(
                process,
                connections,
                None,
                warning,
                None,
                capture_state=capture_result.state if capture_result else CaptureState.NOT_STARTED,
                capture_reason=capture_result.reason if capture_result else None,
                capture_started=capture_result is not None,
            )
        choice = _explain_game_connection(selected, connections)
        ping = probe_ping(selected.remote_address, count=5, wait_ms=450)
        if self._preferred_process is None and process.name.casefold() != "huntgame.exe":
            fallback_warning = f"Игра не найдена; выбран резервный процесс {process.name}"
            warning = f"{fallback_warning}; {warning}" if warning else fallback_warning
        reason = choice.rule if choice is not None else None
        if capture_result is not None and capture_result.connection is not None:
            reason = "Перехват UDP-заголовков"
        return GameAutoCheckResult(
            process,
            connections,
            ping,
            warning,
            selected,
            reason,
            capture_state=capture_result.state if capture_result else CaptureState.NOT_STARTED,
            capture_reason=capture_result.reason if capture_result else None,
            capture_started=capture_result is not None,
        )

    def _capture_missing_endpoint(
        self,
        process: RunningProcess,
        connections: tuple[ProcessConnection, ...],
        selected: ProcessConnection | None,
    ) -> PacketCaptureResult | None:
        if selected is not None or not has_unresolved_udp_socket(connections):
            return None
        ports = unresolved_udp_ports(connections)
        self.capture_started.emit({"pid": process.pid, "process": process.name, "ports": ports})
        return capture_udp_endpoint(
            self._capture_backend,
            process.pid,
            ports,
            self._stop_event,
            self._capture_timeout_s,
        )

    @staticmethod
    def _endpoint_warning(
        process: RunningProcess,
        scan_warning: str | None,
        capture_result: PacketCaptureResult | None,
        selected: ProcessConnection | None,
    ) -> str | None:
        if selected is not None:
            return scan_warning
        if capture_result is not None:
            messages = {
                CaptureState.PERMISSION_DENIED: "UDP-сокет игры найден, но Windows скрывает адрес сервера. Запустите NetVision от имени Администратора для глубокого перехвата заголовков",
                CaptureState.TIMED_OUT: "Локальный UDP-сокет открыт, но активного обмена пакетами с игровым сервером сейчас нет (зайдите в матч)",
                CaptureState.BACKEND_UNAVAILABLE: "Глубокий перехват UDP недоступен на этой системе",
            }
            return messages.get(capture_result.state, scan_warning)
        return scan_warning or f"У процесса {process.name} нет внешнего UDP-сокета"

    @staticmethod
    def _select_game_connection(
        connections: tuple[ProcessConnection, ...],
    ) -> ProcessConnection | None:
        candidates = [
            item
            for item in connections
            if item.protocol == "UDP"
            and item.remote_address
            and is_public_address(item.remote_address)
        ]
        if not candidates:
            return None
        non_cdn = [item for item in candidates if not _is_background_cdn(item.remote_address)]
        if not non_cdn:
            return None
        candidates = non_cdn
        return sorted(candidates, key=_game_connection_key)[0]
