"""TLS audit presentation controller."""

from PySide6.QtCore import QObject, QThread, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem
from netvision.core.session import StateStore
from netvision.core.target import parse_target
from netvision.ui.legacy_workers import TlsAuditWorker
from netvision.core.tls_diagnostics import TlsAuditResult
from netvision.ui.utils import _ms
from netvision.ui.workspaces.tls_audit import TlsAuditWorkspace


class TlsAuditController(QObject):
    def __init__(self, workspace: TlsAuditWorkspace, facts: StateStore, parent: QObject) -> None:
        super().__init__(parent)
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        workspace.tls_run_button.clicked.connect(self.start_tls_audit)
        workspace.tls_check_button.clicked.connect(self.start_tls_audit)
        workspace.tls_refresh_button.clicked.connect(self.start_tls_audit)

    def stop(self) -> None:
        """Request cooperative cancellation through the shared registry."""
        self.host._worker_registry.stop(self.host._tls_audit_thread)

    def _render_tls_handshake(self, result: TlsAuditResult) -> None:
        phases = (
            ("TCP connect", _ms(result.tcp_connect_ms), "Установление сетевого соединения"),
            ("TLS handshake", _ms(result.handshake_ms), "Полный защищённый handshake"),
            (
                "Client Hello / Server Hello",
                "включено",
                "Отдельно не измеряется стандартным SSL API",
            ),
            (
                "Key exchange / проверка сертификата",
                "включено",
                "Отдельно не измеряется стандартным SSL API",
            ),
        )
        self.workspace.tls_handshake_table.setRowCount(len(phases))
        for row, values in enumerate(phases):
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                if row < 2 and result.handshake_ms is not None:
                    item.setForeground(QColor("#00E5A3"))
                self.workspace.tls_handshake_table.setItem(row, column, item)

    @Slot()
    def start_tls_audit(self) -> None:
        if not self.host._tls_audit_thread or not self.host._tls_audit_thread.isRunning():
            self.host._dashboard_tls_audit_generation = self.host._dashboard_tls_generation
        self._inherited_start_tls_audit()

    @Slot()
    def _inherited_start_tls_audit(self) -> None:
        if self.host._tls_audit_thread and self.host._tls_audit_thread.isRunning():
            return
        try:
            target = parse_target(
                self.host.tls_workspace.tls_target_input.text(),
                self.host.tls_workspace.tls_port_input.value(),
            )
        except ValueError as exc:
            self.host.tls_workspace.tls_audit_status.setText(str(exc))
            return
        self.host.tls_workspace.tls_target_input.setText(target.host)
        self.host._tls_audit_result = None
        self.host._set_tls_audit_running(True)
        self.host._render_tls_placeholders(self.host._tr("Проверка TLS-соединения..."))
        self.host.tls_workspace.tls_audit_status.setText(
            self.host._tr("Устанавливаем защищённое соединение в фоновом потоке...")
        )
        thread = QThread(self.host)
        worker = TlsAuditWorker(target.host, target.port)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_tls_audit_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_tls_audit_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_tls_audit_worker)
        self.host._tls_audit_thread = thread
        self.host._tls_audit_worker = worker
        thread.start()

    @Slot(object)
    def _on_tls_audit_completed(self, value: object) -> None:
        if self.host._dashboard_tls_audit_generation != self.host._dashboard_tls_generation:
            self.host._set_tls_audit_running(False)
            return
        self._inherited__on_tls_audit_completed(value)

    @Slot(str)
    def _on_tls_audit_failed(self, message: str) -> None:
        if self.host._dashboard_tls_audit_generation != self.host._dashboard_tls_generation:
            self.host._set_tls_audit_running(False)
            return
        self.host._tls_audit_result = None
        self.host._render_tls_placeholders()
        self._inherited__on_tls_audit_failed(message)

    @Slot(object)
    def _inherited__on_tls_audit_completed(self, value: object) -> None:
        self.host._set_tls_audit_running(False)
        if not isinstance(value, TlsAuditResult):
            self._on_tls_audit_failed("TLS-аудит вернул некорректный результат")
            return
        self.host._tls_audit_result = value
        self.facts.set("tls.audit", value)
        self.host.state_synchronizer._render_tls_audit(value)

    @Slot(str)
    def _inherited__on_tls_audit_failed(self, message: str) -> None:
        self.host._set_tls_audit_running(False)
        self.host.tls_workspace.tls_audit_status.setText(message)

    @Slot()
    def _clear_tls_audit_worker(self) -> None:
        if self.sender() is not self.host._tls_audit_thread:
            return
        self.host._tls_audit_thread = None
        self.host._tls_audit_worker = None
