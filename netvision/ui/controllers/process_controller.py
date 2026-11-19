"""ProcessController for dashboard orchestration."""

from dataclasses import replace
from PySide6.QtCore import QObject, QThread, Slot
from PySide6.QtWidgets import QStyle
from netvision.core.session import StateStore
from netvision.core.process_inspector import (
    ProcessConnection,
    ProcessNetworkInfo,
    ProcessScanResult,
    is_loopback_address,
)
from netvision.core.process_utils import EndpointChoice, _explain_game_connection
from netvision.ui.legacy_workers import ProcessScanWorker
from netvision.ui.game_check_worker import GameAutoCheckResult
from netvision.core.packet_capture import CaptureState
from netvision.ui.presentation import GREY, socket_label, socket_priority, target_mode


from netvision.ui.workspaces.process_selector import ProcessSelector


class ProcessController(QObject):
    def __init__(self, workspace: ProcessSelector, facts: StateStore, parent: QObject) -> None:
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        workspace.process_selector.currentIndexChanged.connect(self._on_process_selected)
        workspace.process_connection_selector.currentIndexChanged.connect(
            self._on_connection_selected
        )
        workspace.process_refresh_button.clicked.connect(self.refresh_processes)

    @Slot(str)
    def _update_target_mode(self, text: str) -> None:
        connection = self.host._selected_connection
        protocol = connection.protocol if connection else "TCP"
        self.host.core_workspace.dashboard_target_mode.setText(
            self.host._tr(target_mode(text, protocol))
        )

    @Slot(object)
    def _inherited__on_process_scan_completed(self, result: object) -> None:
        self.workspace.process_selector.clear()
        if not isinstance(result, ProcessScanResult):
            result = ProcessScanResult((), "Список процессов не получен")
        if result.warning:
            self.workspace.process_status.setText(self.host._tr("Нет доступа"))
            self.workspace.process_selector.addItem(
                self.host._tr("Не удалось получить процессы"), None
            )
            self.event_bus.log_requested.emit(
                f"Ошибка инспектора процессов: {result.warning}", "INFO"
            )
        elif not result.processes:
            self.workspace.process_status.setText(self.host._tr("Активные соединения не найдены"))
            self.workspace.process_selector.addItem(
                self.host._tr("Нет процессов с активной сетью"), None
            )
            self.event_bus.log_requested.emit(
                "Инспектор процессов: активные соединения не найдены", "INFO"
            )
        else:
            self.workspace.process_status.setText(
                self.host._translator.format(
                    "Найдено процессов: {count}", count=len(result.processes)
                )
            )
            for process in result.processes:
                self.workspace.process_selector.addItem(
                    self._process_display_label(process), process
                )
            self.event_bus.log_requested.emit(
                f"Инспектор процессов: найдено {len(result.processes)} процессов", "INFO"
            )
        self.host._set_task_button_busy(self.workspace.process_refresh_button, False)
        self.workspace.process_refresh_button.setIcon(
            self.host.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload)
        )
        self.workspace.process_refresh_button.setToolTip(
            self.host._tr("Обновить список процессов и сетевых соединений")
        )

    @Slot(int)
    def _inherited__on_process_selected(self, index: int) -> None:
        value = self.workspace.process_selector.itemData(index)
        self.host._selected_process = value if isinstance(value, ProcessNetworkInfo) else None
        self.facts.set("process.selected", self.host._selected_process)
        self.host._selected_connection = None
        self.host._vpn_process_sockets = None
        self.host._vpn_process_sockets_ready = False
        self.host._connection_pick_auto = False
        self.workspace.process_connection_selector.blockSignals(True)
        self.workspace.process_connection_selector.clear()
        if self.host._selected_process is None:
            self.host._stop_udp_port_monitor()
            self.host._set_udp_ports_status(None)
            self.workspace.process_connection_selector.addItem(
                self.host._tr("Сначала выберите процесс"), None
            )
            self.workspace.process_connection_selector.blockSignals(False)
            return
        for connection in sorted(self.host._selected_process.connections, key=socket_priority):
            self.workspace.process_connection_selector.addItem(
                self._connection_display_label(connection), connection
            )
        if not self.host._selected_process.connections:
            self.workspace.process_connection_selector.addItem(
                self.host._tr("Нет активных соединений"), None
            )
        else:
            self.workspace.process_connection_selector.setCurrentIndex(-1)
        self.workspace.process_connection_selector.blockSignals(False)
        self.workspace.process_status.setText(
            f"{self.host._selected_process.name}: {len(self.host._selected_process.connections)}"
        )
        self.event_bus.log_requested.emit(
            f"Выбран процесс: {self._process_display_label(self.host._selected_process)}", "INFO"
        )
        self.event_bus.journal_event_requested.emit(
            "action.process_selected",
            {
                "subject": self.host._selected_process.name,
                "template": "Выбран процесс: {process} (PID {pid})",
                "values": {
                    "process": self.host._selected_process.name,
                    "pid": self.host._selected_process.pid,
                    "connections": len(self.host._selected_process.connections),
                },
                "refs": {"pid": self.host._selected_process.pid},
            },
        )
        self.host._start_udp_port_monitor(self.host._selected_process.pid)
        if (
            self.host._selected_process.connections
            and socket_priority(min(self.host._selected_process.connections, key=socket_priority))
            < 3
        ):
            self.host._connection_pick_auto = self.host.header_panel.lite_mode_button.isChecked()
            self.workspace.process_connection_selector.setCurrentIndex(0)

    @Slot(int)
    def _inherited__on_connection_selected(self, index: int) -> None:
        connection = self.workspace.process_connection_selector.itemData(index)
        if not isinstance(connection, ProcessConnection):
            return
        picked_automatically = self.host._connection_pick_auto
        self.host._connection_pick_auto = False
        self.host._selected_connection = connection
        if not connection.remote_address or connection.remote_port < 1:
            self.workspace.process_status.setText(
                f"{self.host._selected_process.name if self.host._selected_process else self.host._tr('Процесс')}: "
                f"{self.host._translator.format('локальный UDP-порт {port}', port=connection.local_port)}"
            )
            self.event_bus.log_requested.emit(
                f"{self.host._translator.format('локальный UDP-порт {port}', port=connection.local_port)}; "
                f"{self.host._tr('цель диагностики не изменена')}",
                "INFO",
            )
            self.host._publish_monitor_scope()
            return
        if is_loopback_address(connection.remote_address):
            self.event_bus.log_requested.emit(
                self.host._translator.format(
                    "Выбран локальный прокси-сокет {target}; адрес проверки не изменён",
                    target=connection.remote_endpoint,
                ),
                "INFO",
            )
            self.host._publish_monitor_scope()
            return
        self.host.mtr_controller.stop_mtr_monitor("target_changed")
        self.host.core_workspace.target_input.setText(connection.remote_address)
        self.host.core_workspace.port_input.setValue(connection.remote_port)
        if not self.host._ping_mtu_host_manually_edited:
            self.host.mtu_workspace.ping_mtu_host_input.setText(connection.remote_address)
        if picked_automatically:
            candidates = (
                self.host._selected_process.connections if self.host._selected_process else ()
            )
            explanation = _explain_game_connection(connection, candidates)
            choice = (
                replace(explanation, rule="Первое доступное соединение")
                if explanation is not None
                else EndpointChoice(connection, "Первое доступное соединение", 1, 0)
            )
            reason = self.host._tr(choice.rule)
            self.event_bus.log_requested.emit(
                self.host._translator.format(
                    "Цель автоматически выбрана из процесса: {target} ({protocol}); правило: {rule}",
                    target=connection.remote_endpoint,
                    protocol=connection.protocol,
                    rule=reason,
                ),
                "INFO",
            )
            self.host._record_endpoint_choice(choice)
        else:
            self.event_bus.log_requested.emit(
                f"Цель подставлена из процесса: {connection.remote_endpoint} ({connection.protocol})",
                "INFO",
            )
            self.event_bus.journal_event_requested.emit(
                "action.target_selected",
                {
                    "subject": connection.remote_endpoint,
                    "template": "Цель выбрана из процесса: {target} ({protocol})",
                    "values": {
                        "target": connection.remote_endpoint,
                        "protocol": connection.protocol,
                    },
                    "refs": {"host": connection.remote_address, "port": connection.remote_port},
                },
            )
        self.host._publish_monitor_scope()

    @Slot()
    def _clear_process_scan(self) -> None:
        if self.sender() is not self.host._process_scan_thread:
            return
        self.host._process_scan_thread = None
        self.host._process_scan_worker = None

    def _process_display_label(self, process: ProcessNetworkInfo) -> str:
        if self.host.header_panel.lite_mode_button.isChecked():
            return process.friendly_name
        count = len(process.connections)
        noun = self.host._tr("соединение") if count == 1 else self.host._tr("соединений")
        return f"{process.name} · PID {process.pid} · {count} {noun}"

    def _connection_display_label(self, connection: ProcessConnection) -> str:
        return socket_label(connection, self.host._tr)

    @Slot()
    def refresh_processes(self) -> None:
        if self.host._process_scan_thread and self.host._process_scan_thread.isRunning():
            return
        self.host._stop_udp_port_monitor()
        self.host._set_udp_ports_status(None)
        self.host._set_task_button_busy(self.workspace.process_refresh_button, True, "Сканирование")
        self.workspace.process_refresh_button.setIcon(
            self.host.style().standardIcon(QStyle.StandardPixmap.SP_BrowserStop)
        )
        self.workspace.process_status.setText(self.host._tr("Сканируем..."))
        self.workspace.process_selector.clear()
        self.workspace.process_selector.addItem(self.host._tr("Сканирование процессов..."), None)

        thread = QThread(self.host)
        worker = ProcessScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_process_scan_completed),
        )
        worker.completed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_process_scan)
        self.host._process_scan_thread = thread
        self.host._process_scan_worker = worker
        thread.start()

    def _refresh_dynamic_process_text(self) -> None:
        if not hasattr(self.workspace, "process_selector"):
            return
        for index in range(self.workspace.process_selector.count()):
            process = self.workspace.process_selector.itemData(index)
            if isinstance(process, ProcessNetworkInfo):
                self.workspace.process_selector.setItemText(
                    index, self._process_display_label(process)
                )
        if isinstance(self.host._selected_process, ProcessNetworkInfo):
            self.workspace.process_status.setText(
                f"{self.host._selected_process.name}: {len(self.host._selected_process.connections)}"
            )
            for index in range(self.workspace.process_connection_selector.count()):
                connection = self.workspace.process_connection_selector.itemData(index)
                if isinstance(connection, ProcessConnection):
                    self.workspace.process_connection_selector.setItemText(
                        index, self._connection_display_label(connection)
                    )
        self.host._set_udp_ports_status(self.host._last_udp_snapshot)

    @Slot(int)
    def _dashboard_process_selected(self, index: int) -> None:
        if self.host._dashboard_syncing:
            return
        process = self.host.core_workspace.dashboard_process_combo.itemData(index)
        for source_index in range(self.workspace.process_selector.count()):
            if self.workspace.process_selector.itemData(source_index) == process:
                self.workspace.process_selector.setCurrentIndex(source_index)
                return

    @Slot(int)
    def _dashboard_connection_selected(self, index: int) -> None:
        if self.host._dashboard_syncing:
            return
        connection = self.host.core_workspace.dashboard_connection_combo.itemData(index)
        for source_index in range(self.workspace.process_connection_selector.count()):
            if self.workspace.process_connection_selector.itemData(source_index) == connection:
                self.workspace.process_connection_selector.setCurrentIndex(source_index)
                return

    def _dashboard_sync_process_choices(self) -> None:
        if not self.host._dashboard_ready:
            return
        self.host._dashboard_syncing = True
        try:
            self.host.core_workspace.dashboard_process_combo.clear()
            for index in range(self.workspace.process_selector.count()):
                self.host.core_workspace.dashboard_process_combo.addItem(
                    self.workspace.process_selector.itemText(index),
                    self.workspace.process_selector.itemData(index),
                )
            self.host.core_workspace.dashboard_connection_combo.clear()
            for index in range(self.workspace.process_connection_selector.count()):
                self.host.core_workspace.dashboard_connection_combo.addItem(
                    self.workspace.process_connection_selector.itemText(index),
                    self.workspace.process_connection_selector.itemData(index),
                )
            self.host._dashboard_select_combo_value(
                self.host.core_workspace.dashboard_process_combo, self.host._selected_process
            )
            self.host._dashboard_select_combo_value(
                self.host.core_workspace.dashboard_connection_combo, self.host._selected_connection
            )
        finally:
            self.host._dashboard_syncing = False

    @Slot(object)
    def _on_process_scan_completed(self, result: object) -> None:
        self._inherited__on_process_scan_completed(result)
        if self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_process_combo,
            self.host.core_workspace.dashboard_connection_combo,
        ):
            self._dashboard_sync_process_choices()

    @Slot(int)
    def _on_process_selected(self, index: int) -> None:
        self.host._dashboard_game_connection = None
        self.host._dashboard_game_metrics = None
        self._inherited__on_process_selected(index)
        if not self.host._dashboard_widgets_alive(self.host.core_workspace.dashboard_process_combo):
            return
        self._dashboard_sync_process_choices()
        self.host._dashboard_render_regions()

    @Slot(int)
    def _on_connection_selected(self, index: int) -> None:
        self.host._dashboard_game_connection = None
        self.host._dashboard_game_metrics = None
        self._inherited__on_connection_selected(index)
        if not self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_connection_combo
        ):
            return
        self._dashboard_sync_process_choices()
        self.host._dashboard_sync_controls()
        if self.host._report is not None:
            self.host.overview_controller._dashboard_apply_report(self.host._report)
        else:
            udp_selected = bool(
                self.host._selected_connection
                and self.host._selected_connection.protocol.upper() == "UDP"
            )
            for key in ("tcp", "tls"):
                card = self.host.core_workspace.dashboard_metric_cards[key]
                card.set_metric(self.host._tr("Не для UDP") if udp_selected else "—", "neutral")
                card.caption.setText(self.host._tr("Не для UDP") if udp_selected else "")
                card.value.setStyleSheet(f"color: {GREY};")
        self.host._dashboard_render_regions()

    @Slot(int, str)
    def _select_manual_process(self, pid: int, name: str) -> None:
        for index in range(self.workspace.process_selector.count()):
            process = self.workspace.process_selector.itemData(index)
            if isinstance(process, ProcessNetworkInfo) and process.pid == pid:
                self.workspace.process_selector.setCurrentIndex(index)
                return

        process = ProcessNetworkInfo(pid=pid, name=name, connections=())
        self.workspace.process_selector.addItem(self._process_display_label(process), process)
        self.workspace.process_selector.setCurrentIndex(self.workspace.process_selector.count() - 1)
        self.host.statusBar().showMessage(
            self.host._translator.format(
                "Процесс назначен: {name} · PID {pid}", name=name, pid=pid
            ),
            5000,
        )

    @Slot(object)
    def _on_auto_monitor_probe_completed(self, value: object, pid: int) -> None:
        if not isinstance(value, GameAutoCheckResult):
            return
        connection = value.selected_connection
        process = value.process
        if process is None or connection is None or not connection.remote_address:
            self.event_bus.log_requested.emit("Автомониторинг: endpoint игры не найден", "INFO")
            return
        self.host._selected_process = process
        self.facts.set("process.selected", process)
        self.host._selected_connection = connection
        self.host.core_workspace.target_input.setText(connection.remote_address)
        self.host.core_workspace.port_input.setValue(connection.remote_port)
        self.host.ping_controller._start_latency_monitor(
            connection.remote_address, connection.remote_port
        )
        if connection.protocol == "UDP":
            self.host._start_udp_port_monitor(pid)
        self.host._auto_monitor_active = True
        self.event_bus.journal_event_requested.emit(
            "monitor.auto_started",
            {
                "subject": process.name,
                "template": "Автомониторинг запущен: {endpoint}",
                "values": {
                    "actor": "auto",
                    "endpoint": connection.remote_endpoint,
                    "process": process.name,
                    "pid": pid,
                },
                "refs": {"actor": "auto", "pid": pid, "protocol": connection.protocol},
            },
        )
        self.event_bus.log_requested.emit(f"Автомониторинг: {connection.remote_endpoint}", "INFO")

    @Slot(object)
    def _inherited__on_game_auto_check_completed(self, value: object) -> None:
        if not isinstance(value, GameAutoCheckResult):
            return
        if value.capture_started:
            if value.capture_state is CaptureState.ENDPOINT_FOUND and value.selected_connection:
                connection = value.selected_connection
                self.event_bus.journal_event_requested.emit(
                    "udp.endpoint_observed",
                    {
                        "subject": connection.remote_endpoint,
                        "template": "Игровой UDP endpoint обнаружен перехватом: {endpoint}",
                        "values": {
                            "endpoint": connection.remote_endpoint,
                            "pid": value.process.pid if value.process else None,
                        },
                        "refs": {
                            "pid": value.process.pid if value.process else None,
                            "host": connection.remote_address,
                            "port": connection.remote_port,
                        },
                    },
                )
            elif value.process is not None:
                self.event_bus.journal_event_requested.emit(
                    "udp.capture_failed",
                    {
                        "severity": "warning",
                        "subject": value.process.name,
                        "template": "Перехват UDP завершён: {reason}",
                        "values": {
                            "reason": value.capture_state.value,
                            "message": value.warning or value.capture_reason or "—",
                            "pid": value.process.pid,
                        },
                        "refs": {
                            "pid": value.process.pid,
                            "state": value.capture_state.value,
                        },
                    },
                )
        if value.process is None:
            message = (
                self.host._tr(value.warning) if value.warning else self.host._tr("Игра не найдена")
            )
            self.host.statusBar().showMessage(message, 6000)
            self.event_bus.log_requested.emit(f"Автопроверка игры: {message}", "INFO")
            return
        if value.selected_connection is None:
            message = (
                self.host._tr(value.warning)
                if value.warning
                else self.host._tr("У процесса {name} нет внешнего игрового сокета").format(
                    name=value.process.name
                )
            )
            self.host.statusBar().showMessage(message, 6000)
            self.event_bus.log_requested.emit(f"Автопроверка игры: {message}", "INFO")
            return

        connection = value.selected_connection
        if connection is not None:
            self.host._selected_process = ProcessNetworkInfo(
                value.process.pid,
                value.process.name,
                value.connections,
            )
            self.facts.set("process.selected", self.host._selected_process)
            self.host._selected_connection = connection
            self.host.core_workspace.target_input.setText(connection.remote_address)
            self.host.core_workspace.port_input.setValue(connection.remote_port)
            if not self.host._ping_mtu_host_manually_edited:
                self.host.mtu_workspace.ping_mtu_host_input.setText(connection.remote_address)
            self.host._publish_monitor_scope()
            message = self.host._translator.format(
                "Игровой endpoint выбран: {endpoint}",
                endpoint=connection.remote_endpoint,
            )
            self.host.statusBar().showMessage(message, 6000)
            self.event_bus.log_requested.emit(message, "INFO")

    @Slot(object)
    def _on_game_auto_check_completed(self, value: object) -> None:
        self._inherited__on_game_auto_check_completed(value)
        if not isinstance(value, GameAutoCheckResult):
            return
        if getattr(value, "process", None) is None:
            self.host._dashboard_game_connection = None
            self.host._dashboard_game_metrics = None
            self.host._dashboard_render_regions()
            return
        process = value.process
        if value.selected_connection is not None and value.selected_connection.protocol == "UDP":
            self.host._start_udp_port_monitor(process.pid)
        if value.warning:
            self.host._dashboard_append_event(value.warning)
