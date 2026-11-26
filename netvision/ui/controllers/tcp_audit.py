"""TCP audit presentation controller."""

from PySide6.QtCore import QObject, QThread, Qt, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem
from netvision.core.session import StateStore
from netvision.core.target import parse_target
from netvision.ui.legacy_workers import TcpDiagnosticsWorker
from netvision.core.tcp_diagnostics import TcpConnectMeasurement, TcpSocketRecord
from netvision.ui import constants as ui_constants
from netvision.ui.utils import _ms
from netvision.ui.workspaces.tcp_audit import TcpAuditWorkspace
from netvision.ui.components.table_context_menu import install_context_menu


class TcpAuditController(QObject):
    def __init__(self, workspace: TcpAuditWorkspace, facts: StateStore, parent: QObject) -> None:
        super().__init__(parent)
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        install_context_menu(
            parent, workspace.tcp_sockets_table, (2,), open_mtr=True, socket_matrix=True
        )
        workspace.tcp_run_button.clicked.connect(self.start_tcp_diagnostics)

    def stop(self) -> None:
        """Request cooperative cancellation through the shared registry."""
        self.host._worker_registry.stop(self.host._tcp_diagnostics_thread)

    @staticmethod
    def _parse_tcp_ports(value: str) -> tuple[int, ...]:
        raw_ports = [item.strip() for item in value.split(",") if item.strip()]
        if not raw_ports:
            raise ValueError("Укажите хотя бы один TCP-порт")
        try:
            ports = tuple(dict.fromkeys(int(item) for item in raw_ports))
        except ValueError as exc:
            raise ValueError("Порты указываются целыми числами через запятую") from exc
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("TCP-порты должны быть в диапазоне 1–65535")
        return ports

    def _render_tcp_handshake(self, measurement: TcpConnectMeasurement) -> None:
        if measurement.connect_ms is None:
            values = ui_constants.DASHBOARD_TRAY_VISIBILITY_OPTIONS
        else:
            total = measurement.connect_ms
            values = (f"{total:.1f} ms", "оценка", "оценка", "оценка")
        self.workspace.tcp_handshake_connect.setText(values[0])
        self.workspace.tcp_handshake_syn.setText(values[1])
        self.workspace.tcp_handshake_syn_ack.setText(values[2])
        self.workspace.tcp_handshake_ack.setText(values[3])
        self.workspace.tcp_handshake_status.setText(measurement.status)
        self.workspace.tcp_handshake_status.setToolTip(
            measurement.error or "Полное время TCP connect"
        )

    def _render_tcp_port_placeholders(self, status: str = "Готов к тесту") -> None:
        try:
            ports = self._parse_tcp_ports(self.workspace.tcp_ports_input.text())
        except ValueError:
            ports = ui_constants.DASHBOARD_TCP_PRESET_PORTS
        self.workspace.tcp_ports_table.setRowCount(len(ports))
        for row, port in enumerate(ports):
            for column, value in enumerate((str(port), status, "--", "--")):
                self.workspace.tcp_ports_table.setItem(row, column, QTableWidgetItem(value))

    def _render_tcp_ports(self, results: tuple[TcpConnectMeasurement, ...]) -> None:
        self.workspace.tcp_ports_table.setRowCount(len(results))
        for row, result in enumerate(results):
            values = (
                str(result.port),
                result.status,
                _ms(result.connect_ms),
                result.error or "TCP connect завершён",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(result.error or value)
                if result.is_open:
                    item.setForeground(QColor("#00E5A3"))
                elif result.status == "Фильтруется / timeout":
                    item.setForeground(QColor("#FFB800"))
                else:
                    item.setForeground(QColor("#FF6B78"))
                self.workspace.tcp_ports_table.setItem(row, column, item)

    @Slot()
    def start_tcp_diagnostics(self) -> None:
        if self.host._tcp_diagnostics_thread and self.host._tcp_diagnostics_thread.isRunning():
            return
        try:
            target = parse_target(
                self.host.tcp_workspace.tcp_target_input.text(),
                self.host.core_workspace.port_input.value(),
            )
            ports = self._parse_tcp_ports(self.host.tcp_workspace.tcp_ports_input.text())
        except ValueError as exc:
            self.host.tcp_workspace.tcp_socket_status.setText(str(exc))
            return
        self.host.tcp_workspace.tcp_target_input.setText(target.host)
        self.host._set_task_button_busy(self.host.tcp_workspace.tcp_run_button, True, "Проверка")
        self.host.tcp_workspace.tcp_socket_details_button.setEnabled(False)
        self.host.tcp_workspace.tcp_socket_status.setText(
            self.host._tr("Сканируем TCP-сокеты и проверяем порты в фоновом потоке...")
        )
        self._render_tcp_port_placeholders(self.host._tr("Проверка..."))
        thread = QThread(self.host)
        worker = TcpDiagnosticsWorker(target.host, target.port, ports)
        worker.moveToThread(thread)
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_tcp_diagnostics_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_tcp_diagnostics_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_tcp_diagnostics_worker)
        self.host._tcp_diagnostics_thread = thread
        self.host._tcp_diagnostics_worker = worker
        thread.start()

    @Slot(object, object, object)
    def _on_tcp_diagnostics_completed(
        self, sockets_value: object, primary_value: object, ports_value: object
    ) -> None:
        self.host._set_task_button_busy(self.host.tcp_workspace.tcp_run_button, False)
        if not isinstance(sockets_value, tuple) or not all(
            isinstance(item, TcpSocketRecord) for item in sockets_value
        ):
            self._on_tcp_diagnostics_failed("Сканер сокетов вернул некорректный результат")
            return
        if not isinstance(primary_value, TcpConnectMeasurement):
            self._on_tcp_diagnostics_failed("TCP connect вернул некорректный результат")
            return
        if not isinstance(ports_value, tuple) or not all(
            isinstance(item, TcpConnectMeasurement) for item in ports_value
        ):
            self._on_tcp_diagnostics_failed("Проверка портов вернула некорректный результат")
            return
        self._render_tcp_handshake(primary_value)
        self._render_tcp_ports(ports_value)
        self.host._render_tcp_sockets(sockets_value)
        self.facts.set("tcp.audit", (sockets_value, primary_value, ports_value))

    @Slot(str)
    def _on_tcp_diagnostics_failed(self, message: str) -> None:
        self.host._set_task_button_busy(self.host.tcp_workspace.tcp_run_button, False)
        self.host.tcp_workspace.tcp_socket_status.setText(message)

    @Slot()
    def _clear_tcp_diagnostics_worker(self) -> None:
        if self.sender() is not self.host._tcp_diagnostics_thread:
            return
        self.host._tcp_diagnostics_thread = None
        self.host._tcp_diagnostics_worker = None
