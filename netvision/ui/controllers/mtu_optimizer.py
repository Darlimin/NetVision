"""MtuController for diagnostics."""

import re
from PySide6.QtCore import QObject, QThread, Qt, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem, QMessageBox, QDialog, QPushButton, QLabel
from netvision.core.session import StateStore
from netvision.core.system_actions import (
    apply_mtu_trial,
    persist_mtu,
    rollback_change,
    SystemActionResult,
    SystemChange,
)
from netvision.core.models import PendingAction
from netvision.ui.dialogs import RollbackConfirmDialog
from netvision.core.mtu_optimizer import MtuOptimizerProbe, MtuOptimizerReport
from netvision.ui.legacy_workers import MtuOptimizerWorker, MtuControlProbeWorker
from netvision.ui.monitor_workers import WorkerRegistry
from netvision.ui.utils import _ms


from netvision.ui.workspaces.mtu_optimizer import MtuWorkspace


class MtuController(QObject):
    def __init__(
        self, workspace: MtuWorkspace, facts: StateStore, registry: WorkerRegistry, parent: QObject
    ) -> None:
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        self.registry = registry
        workspace.ping_mtu_host_input.textEdited.connect(self._mark_mtu_host_manually_edited)
        workspace.ping_mtu_run_button.clicked.connect(self.start_mtu_test)
        workspace.mtu_optimizer_apply_button.clicked.connect(self._apply_optimized_mtu)

    def stop(self) -> None:
        self.registry.stop(self.host._mtu_optimizer_thread)

    @Slot(str)
    def _mark_mtu_host_manually_edited(self, _text: str) -> None:
        self.host._ping_mtu_host_manually_edited = True

    def _finish_mtu_optimizer(self) -> None:
        button = self.host._mtu_optimizer_active_button or self.workspace.mtu_optimizer_start_button
        self.host._set_task_button_busy(button, False)
        self.workspace.mtu_optimizer_progress.hide()
        self.host._mtu_optimizer_active_button = None

    @Slot()
    def _clear_mtu_optimizer_worker(self) -> None:
        if self.sender() is not self.host._mtu_optimizer_thread:
            return
        self.host._mtu_optimizer_thread = None
        self.host._mtu_optimizer_worker = None

    @Slot()
    def start_mtu_test(self) -> None:
        target = (
            self.workspace.ping_mtu_host_input.text().strip()
            or self.host.core_workspace.target_input.text().strip()
        )
        self.workspace.mtu_optimizer_target_input.setText(target)
        self.host._mtu_optimizer_active_button = self.workspace.ping_mtu_run_button
        self.start_mtu_optimizer()

    @Slot()
    def start_mtu_optimizer(self) -> None:
        if self.host._mtu_optimizer_thread and self.host._mtu_optimizer_thread.isRunning():
            return
        if self.host._mtu_optimizer_active_button is None:
            self.host._mtu_optimizer_active_button = self.workspace.mtu_optimizer_start_button
        target = self.workspace.mtu_optimizer_target_input.text().strip()
        if not target:
            self._set_mtu_optimizer_status(self.host._tr("Укажите целевой хост для MTU-проверки"))
            self.host._mtu_optimizer_active_button = None
            return

        self.host._mtu_optimizer_report = None
        self.workspace.mtu_optimizer_table.setRowCount(0)
        self.workspace.mtu_current_value.setText("--")
        self.workspace.mtu_optimal_value.setText("--")
        self.workspace.mtu_fragmentation_value.setText(self.host._tr("Проверка выполняется"))
        self.workspace.mtu_optimizer_apply_button.setEnabled(False)
        self._set_mtu_optimizer_status(self.host._tr("MTU-оптимизатор выполняется..."))
        self.workspace.mtu_optimizer_progress.show()
        self.host._set_task_button_busy(self.host._mtu_optimizer_active_button, True, "Выполняется")

        thread = QThread(self.host)
        snapshot = self.host._report.system if self.host._report is not None else None
        worker = MtuOptimizerWorker(target, snapshot, self.host._thresholds)
        worker.moveToThread(thread)
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.started.connect(worker.run)
        worker.progress.connect(
            self.host._queue_ui_slot(self._on_mtu_optimizer_progress),
        )
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_mtu_optimizer_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_mtu_optimizer_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_mtu_optimizer_worker)
        self.host._mtu_optimizer_thread = thread
        self.host._mtu_optimizer_worker = worker
        thread.start()

    @Slot(str)
    def _on_mtu_optimizer_progress(self, message: str) -> None:
        match = re.fullmatch(r"Проверяем MTU (\d+)", message)
        if match:
            self._set_mtu_optimizer_status(
                self.host._tr("Проверяем MTU {mtu}").format(mtu=match.group(1))
            )
            return
        self._set_mtu_optimizer_status(self.host._tr(message))

    @Slot(object)
    def _on_mtu_optimizer_completed(self, value: object) -> None:
        self._finish_mtu_optimizer()
        if not isinstance(value, MtuOptimizerReport):
            self._on_mtu_optimizer_failed("MTU-оптимизатор вернул некорректный результат")
            return

        self.host._mtu_optimizer_report = value
        self.facts.set("mtu.optimal", value.optimal_mtu)
        self.workspace.mtu_current_value.setText(
            str(value.current_mtu) if value.current_mtu else "--"
        )
        self.workspace.mtu_optimal_value.setText(
            str(value.optimal_mtu) if value.optimal_mtu else "--"
        )
        self.workspace.mtu_fragmentation_value.setText(
            self.host._tr("Пакет без фрагментации найден")
            if value.optimal_mtu
            else self.host._tr("Безопасный размер не найден")
        )
        self._render_mtu_optimizer_probes(value.probes)

        if value.optimal_mtu is None:
            self.event_bus.journal_event_requested.emit(
                "mtu.probe_failed",
                {
                    "severity": "warning",
                    "subject": value.target,
                    "template": "MTU-проверка не завершена: {reason}",
                    "values": {"reason": value.error_code or value.error or "unknown"},
                    "refs": {
                        "target_ip": value.target_ip,
                        "route_interface": value.route_interface,
                    },
                },
            )
        else:
            self.event_bus.journal_event_requested.emit(
                "mtu.measured",
                {
                    "subject": value.target,
                    "template": "Измерен MTU маршрута: {found}",
                    "values": {
                        "target": value.target,
                        "target_ip": value.target_ip or "",
                        "route_interface": value.route_interface or "",
                        "found": value.optimal_mtu,
                        "probes": len(value.probes),
                        "inferred_by_timeout": value.inferred_by_timeout,
                    },
                },
            )
            self.event_bus.journal_event_requested.emit(
                "mtu.recommendation",
                {
                    "subject": value.route_interface or value.target,
                    "template": "Рекомендация MTU: {decision}",
                    "values": {
                        "decision": value.decision,
                        "current": value.current_mtu,
                        "found": value.optimal_mtu,
                    },
                },
            )

        if value.optimal_mtu:
            self._set_mtu_optimizer_status(
                self.host._tr("Найден оптимальный MTU: {mtu}").format(mtu=value.optimal_mtu)
            )
            self.workspace.mtu_optimizer_apply_button.setEnabled(value.decision == "LOWER")
        else:
            self._set_mtu_optimizer_status(
                self.host._tr(value.error or "Не удалось определить оптимальный MTU")
            )
        self.event_bus.log_requested.emit(self.workspace.mtu_optimizer_status.text(), "INFO")

    @Slot(str)
    def _on_mtu_optimizer_failed(self, message: str) -> None:
        self._finish_mtu_optimizer()
        prefix = "MTU-оптимизатор завершился ошибкой: "
        status = (
            self.host._tr("MTU-оптимизатор завершился ошибкой: {error}").format(
                error=message.removeprefix(prefix),
            )
            if message.startswith(prefix)
            else self.host._tr(message)
        )
        self._set_mtu_optimizer_status(status)
        self.workspace.mtu_fragmentation_value.setText(self.host._tr("Ошибка проверки"))
        self.event_bus.log_requested.emit(f"MTU: {message}", "INFO")

    def _set_mtu_optimizer_status(self, text: str) -> None:
        self.workspace.mtu_optimizer_status.setText(text)
        if hasattr(getattr(self, "mtu_workspace", None), "ping_mtu_status"):
            self.workspace.ping_mtu_status.setText(text)

    def _render_mtu_optimizer_probes(
        self,
        probes: tuple[MtuOptimizerProbe, ...],
    ) -> None:
        """Show optimizer probes in the shared Ping/MTU quality table."""
        for table in (self.workspace.mtu_optimizer_table, self.workspace.ping_mtu_table):
            table.setRowCount(len(probes))
            for row, probe in enumerate(probes):
                values = (
                    str(probe.mtu),
                    f"{probe.payload_size} B",
                    _ms(probe.latency_ms),
                    (
                        self.host._tr("DF-пакет доставлен")
                        if probe.success
                        else self.host._tr("Фрагментация или потеря")
                    ),
                    probe.error or self.host._tr("Пакет доставлен без фрагментации"),
                )
                for column, text in enumerate(values):
                    item = QTableWidgetItem(text)
                    item.setToolTip(text)
                    item.setForeground(QColor("#00E5A3" if probe.success else "#FF6B78"))
                    table.setItem(row, column, item)

    @Slot()
    def _apply_optimized_mtu(self) -> None:
        report = self.host._mtu_optimizer_report
        if report is None or report.optimal_mtu is None:
            self.workspace.mtu_optimizer_status.setText(
                self.host._tr("Сначала найдите оптимальный MTU")
            )
            return
        if report.decision != "LOWER":
            self.workspace.mtu_optimizer_status.setText(
                self.host._tr("Найденный MTU не требует понижения")
            )
            return
        if not report.route_interface:
            self.workspace.mtu_optimizer_status.setText(
                self.host._tr("Интерфейс маршрута не определён")
            )
            return
        adapter = report.route_interface
        self._set_mtu_optimizer_status(f"Интерфейс маршрута: {adapter}")

        message = self.host._tr(
            "Применить пробный MTU {mtu} к интерфейсу маршрута «{adapter}»?\n"
            "После контрольной пробы настройку нужно подтвердить."
        ).format(mtu=report.optimal_mtu, adapter=adapter)
        answer = QMessageBox.question(
            self.host,
            self.host._tr("Применить найденный MTU"),
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.host._run_system_action(
            "Пробное применение MTU",
            lambda: apply_mtu_trial(adapter, report.optimal_mtu),
            self.workspace.mtu_optimizer_apply_button,
            self.workspace.mtu_optimizer_status,
        )

    def _handle_mtu_system_action(
        self,
        label: str,
        button: QPushButton,
        result: SystemActionResult,
        status_label: QLabel | None,
    ) -> bool:
        if label == "Пробное применение MTU" and result.success and result.change is not None:
            self._start_mtu_trial_confirmation(button, status_label, result.change)
            return True
        if label == "Сохранение MTU" and result.success:
            self._record_confirmed_mtu()
            return True
        if label != "Сохранение MTU":
            return False
        change = self.host._mtu_trial_change
        if change is not None:
            self._begin_mtu_rollback(change, button, status_label, "persist_failed")
        return True

    def _start_mtu_trial_confirmation(
        self,
        button: QPushButton,
        status_label: QLabel | None,
        change: SystemChange,
    ) -> None:
        report = self.host._mtu_optimizer_report
        if report is None or report.target_ip is None or not isinstance(change.after, int):
            self._begin_mtu_rollback(change, button, status_label, "missing_target")
            return
        self.event_bus.journal_event_requested.emit(
            "mtu.apply_trial",
            {
                "subject": change.adapter,
                "template": "Применён пробный MTU: {mtu}",
                "values": {"mtu": change.after, "target_ip": report.target_ip},
            },
        )
        self.host._mtu_trial_probe_ok = None
        self.host._mtu_trial_change = change
        pending = PendingAction(
            apply=lambda: self.host._run_system_action(
                "Сохранение MTU",
                lambda: persist_mtu(change.adapter, change.after),
                button,
                status_label,
            ),
            rollback=lambda: rollback_change(change),
            timeout_s=self.host._action_confirm_timeout_s(),
        )
        dialog = RollbackConfirmDialog(change, self.host._tr, self.host, seconds=pending.timeout_s)
        dialog.confirm_button.setEnabled(False)
        self.host._mtu_trial_dialog = dialog
        self._start_mtu_control_probe(report.target_ip, change.after)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        self.host._mtu_trial_dialog = None
        if accepted and self.host._mtu_trial_probe_ok is True:
            pending.apply()
            return
        reason = "probe_failed" if self.host._mtu_trial_probe_ok is False else "timeout"
        self._begin_mtu_rollback(change, button, status_label, reason, pending)

    def _begin_mtu_rollback(
        self,
        change: SystemChange,
        button: QPushButton,
        status_label: QLabel | None,
        reason: str,
        pending: PendingAction | None = None,
    ) -> None:
        rollback_label = "Откат MTU"
        action = pending.rollback if pending is not None else lambda: rollback_change(change)
        self.host._rollback_actions[rollback_label] = (
            change,
            pending or PendingAction(lambda: None, action, self.host._action_confirm_timeout_s()),
        )
        self.host._mtu_rollback_reasons[rollback_label] = reason
        self.host._run_system_action(rollback_label, action, button, status_label)

    def _record_confirmed_mtu(self) -> None:
        report = self.host._mtu_optimizer_report
        if report is not None:
            self.event_bus.journal_event_requested.emit(
                "mtu.confirmed",
                {
                    "subject": report.route_interface or report.target,
                    "template": "MTU подтверждён: {mtu}",
                    "values": {"mtu": report.optimal_mtu},
                    "refs": {"target_ip": report.target_ip},
                },
            )
        self.host._mtu_trial_change = None

    def _start_mtu_control_probe(self, target_ip: str, mtu: int) -> None:
        thread = QThread(self.host)
        worker = MtuControlProbeWorker(target_ip, mtu, self.host._thresholds.mtu_probe_timeout_ms)
        worker.moveToThread(thread)
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_mtu_control_probe_completed),
        )
        worker.completed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_mtu_control_probe)
        self.host._mtu_trial_probe_thread = thread
        thread.start()

    @Slot(object)
    def _on_mtu_control_probe_completed(self, value: object) -> None:
        probe_ok = isinstance(value, MtuOptimizerProbe) and value.success
        self.host._mtu_trial_probe_ok = probe_ok
        if probe_ok:
            if self.host._mtu_trial_dialog is not None:
                self.host._mtu_trial_dialog.confirm_button.setEnabled(True)
            return
        if self.host._mtu_trial_dialog is not None:
            self.host._mtu_trial_dialog.reject()

    @Slot()
    def _clear_mtu_control_probe(self) -> None:
        if self.sender() is self.host._mtu_trial_probe_thread:
            self.host._mtu_trial_probe_thread = None
