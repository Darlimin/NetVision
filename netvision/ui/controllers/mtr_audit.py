"""MtrController for diagnostics."""

from PySide6.QtCore import QObject, QThread, QTimer, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem
from shiboken6 import isValid

from netvision.core.session import StateStore
from netvision.core.traceroute import MtrSnapshot, TracerouteHop
from netvision.ui.legacy_workers import TracerouteWorker
from netvision.ui.monitor_workers import MtrMonitorWorker, WorkerRegistry
from netvision.ui.utils import _ms
from netvision.ui.presentation import VPN_MTR_HINT


from netvision.ui.workspaces.mtr_audit import MtrWorkspace


class MtrController(QObject):
    def __init__(
        self, workspace: MtrWorkspace, facts: StateStore, registry: WorkerRegistry, parent: QObject
    ) -> None:
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        self.registry = registry
        workspace.traceroute_start_button.clicked.connect(self.start_visual_traceroute)
        workspace.mtr_start_button.toggled.connect(self._toggle_mtr_monitor)
        workspace.traceroute_target_input.textEdited.connect(self._on_mtr_target_changed)

    def start_visual_traceroute(self) -> None:
        if (
            self.workspace.traceroute_target_input.text().strip()
            and self.host._traceroute_thread is None
        ):
            self.host._dashboard_reset_hop_history()
        self._inherited_start_visual_traceroute()

    def start_mtr_monitor(self) -> None:
        if self.workspace.traceroute_target_input.text().strip() and self.host._mtr_worker is None:
            self.host._dashboard_reset_hop_history()
        self._inherited_start_mtr_monitor()

    @Slot()
    def _inherited_start_visual_traceroute(self) -> None:
        if self.host._traceroute_thread and self.host._traceroute_thread.isRunning():
            return
        host = self.workspace.traceroute_target_input.text().strip()
        if not host:
            self.workspace.traceroute_status.setText(self.host._tr("Выберите целевой хост"))
            return
        self.host._set_task_button_busy(
            self.workspace.traceroute_start_button, True, "Трассировка выполняется..."
        )
        self.workspace.traceroute_progress.show()
        self.workspace.traceroute_status.setText(self.host._tr("Трассировка выполняется..."))
        self.workspace.traceroute_table.setRowCount(0)
        thread = QThread(self.host)
        worker = TracerouteWorker(host)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.hop_found.connect(
            self.host._queue_ui_slot(self._on_traceroute_hop_found),
        )
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_traceroute_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_traceroute_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_traceroute_worker)
        self.host._traceroute_thread = thread
        self.host._traceroute_worker = worker
        thread.start()

    @Slot()
    def _inherited_start_mtr_monitor(self) -> None:
        if self.host._mtr_thread is not None:
            return
        host = self.workspace.traceroute_target_input.text().strip()
        if not host:
            self.workspace.mtr_status.setText(self.host._tr("Выберите целевой хост для MTR"))
            self.workspace.mtr_start_button.blockSignals(True)
            self.workspace.mtr_start_button.setChecked(False)
            self.workspace.mtr_start_button.blockSignals(False)
            return
        self.workspace.mtr_table.setRowCount(0)
        self.workspace.mtr_status.setText(self.host._tr("MTR запускается..."))
        self.host._mtr_snapshot = None
        self.host._mtr_stop_logged = False
        worker = MtrMonitorWorker(host, th=self.host._thresholds)
        worker.snapshot.connect(
            self.host._queue_ui_slot(
                self._on_mtr_snapshot,
                owner=worker,
                active_owner=lambda: self.host._mtr_worker,
            )
        )
        worker.failed.connect(
            self.host._queue_ui_slot(
                self._on_mtr_failed,
                owner=worker,
                active_owner=lambda: self.host._mtr_worker,
            )
        )
        self.host._mtr_worker = worker
        self.host._mtr_thread = self.registry.start(worker)
        self.host._mtr_thread.finished.connect(self._clear_mtr_worker)
        if self.host._mtr_thread.isFinished():
            QTimer.singleShot(0, self._clear_mtr_worker)
        self.event_bus.journal_event_requested.emit(
            "mtr.started",
            {
                "subject": host,
                "template": "Непрерывный MTR запущен для {host}",
                "values": {"host": host},
            },
        )

    def stop_mtr_monitor(self, reason: str = "manual") -> None:
        worker = self.host._mtr_worker
        if worker is None:
            return
        self.registry.stop(self.host._mtr_thread)
        if not self.host._mtr_stop_logged:
            self.event_bus.journal_event_requested.emit(
                "mtr.stopped",
                {
                    "subject": self.workspace.traceroute_target_input.text().strip(),
                    "template": "Непрерывный MTR остановлен: {reason}",
                    "values": {"reason": reason},
                },
            )
            self.host._mtr_stop_logged = True
        self.workspace.mtr_status.setText(self.host._tr("MTR останавливается..."))
        self.host._mtr_snapshot = None
        self.workspace.mtr_start_button.blockSignals(True)
        self.workspace.mtr_start_button.setChecked(False)
        self.workspace.mtr_start_button.blockSignals(False)

    @Slot(bool)
    def _toggle_mtr_monitor(self, enabled: bool) -> None:
        if enabled:
            self.start_mtr_monitor()
        else:
            self.stop_mtr_monitor("manual")

    @Slot(str)
    def _on_mtr_target_changed(self, _text: str) -> None:
        self.stop_mtr_monitor("target_changed")

    @Slot(object)
    def _on_traceroute_hop_found(self, value: object) -> None:
        self._inherited__on_traceroute_hop_found(value)
        if not isinstance(value, TracerouteHop):
            return
        if self.host._dashboard_record_hop_sample(
            value.index,
            value.address,
            value.latency_ms,
        ):
            self.host._dashboard_auto_select_hop(value.index, self.workspace.traceroute_table)
            self.host._dashboard_refresh_hop_history()

    @Slot(object)
    def _inherited__on_traceroute_hop_found(self, value: object) -> None:
        if not isinstance(value, TracerouteHop):
            return
        row = self.workspace.traceroute_table.rowCount()
        self.workspace.traceroute_table.insertRow(row)
        values = (
            f"{value.index:02}",
            value.address or "--",
            value.hostname or "--",
            _ms(value.latency_ms),
            self.host._tr(value.status),
            (
                self.host._tr("Ответ не получен")
                if value.timed_out
                else self.host._tr("Узел обнаружен")
            ),
        )
        for column, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setToolTip(text)
            if value.timed_out:
                item.setForeground(QColor("#FFB800"))
            elif value.address:
                item.setForeground(QColor("#00E5A3"))
            self.workspace.traceroute_table.setItem(row, column, item)
        self.workspace.traceroute_status.setText(
            self.host._translator.format("Найден узел {hop}", hop=value.index)
        )

    def _render_mtr_snapshot(self, snapshot: MtrSnapshot) -> None:
        self._inherited__render_mtr_snapshot(snapshot)
        first_sampled_hop: int | None = None
        for hop in snapshot.hops:
            address = hop.addresses[0] if hop.addresses else None
            if self.host._dashboard_record_hop_sample(hop.ttl, address, hop.last_ms):
                first_sampled_hop = first_sampled_hop or hop.ttl
        if first_sampled_hop is not None:
            self.host._dashboard_auto_select_hop(first_sampled_hop, self.workspace.mtr_table)
        self.host._dashboard_refresh_hop_history()

    def _inherited__render_mtr_snapshot(self, snapshot: MtrSnapshot) -> None:
        self.workspace.mtr_table.setRowCount(len(snapshot.hops))
        for row, hop in enumerate(snapshot.hops):
            if snapshot.undetermined:
                status, color = self.host._tr("Не определено"), "#91A4C3"
            elif hop.real_loss:
                status, color = self.host._tr("Сквозная потеря"), "#FF6B78"
            elif hop.icmp_limited:
                status, color = self.host._tr("ICMP rate-limit"), "#FFB800"
            else:
                status, color = self.host._tr("Стабильно"), "#00E5A3"
            values = (
                f"{hop.ttl:02}",
                " / ".join(hop.addresses) or "???",
                "—",
                str(hop.sent),
                str(hop.recv),
                f"{hop.loss_pct:.1f}%",
                _ms(hop.last_ms),
                _ms(hop.avg_ms),
                _ms(hop.best_ms),
                _ms(hop.worst_ms),
                _ms(hop.jitter_ms),
                status,
            )
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                item.setForeground(QColor(color))
                self.workspace.mtr_table.setItem(row, column, item)

    @Slot(object)
    def _on_traceroute_completed(self, value: object) -> None:
        self.host._set_task_button_busy(self.workspace.traceroute_start_button, False)
        self.workspace.traceroute_progress.hide()
        if not isinstance(value, tuple) or not all(
            isinstance(item, TracerouteHop) for item in value
        ):
            self._on_traceroute_failed("Трассировка вернула некорректный результат")
            return
        self.facts.set("traceroute.route", value)
        report = self.host._report
        vpn = bool(
            report and report.system.default_routes and report.system.default_routes[0].is_vpn
        )
        self.workspace.vpn_hint.setText(self.host._tr(VPN_MTR_HINT))
        self.workspace.vpn_hint.setVisible(vpn and len(value) == 1)
        if not value:
            self.workspace.traceroute_status.setText(self.host._tr("Маршрут не найден"))
            return
        self.workspace.traceroute_status.setText(
            self.host._translator.format("Трассировка завершена: {count} узлов", count=len(value))
        )

    @Slot(str)
    def _on_traceroute_failed(self, message: str) -> None:
        self.host._set_task_button_busy(self.workspace.traceroute_start_button, False)
        self.workspace.traceroute_progress.hide()
        self.workspace.traceroute_status.setText(
            self.host._tr("Трассировка недоступна: {error}").format(error=message)
        )

    @Slot(object)
    def _on_mtr_snapshot(self, value: object) -> None:
        if (
            self.host._mtr_worker is None
            or self.host._mtr_worker.stopped
            or not isinstance(value, MtrSnapshot)
        ):
            return
        self.host._mtr_snapshot = value
        report = self.host._report
        vpn = bool(
            report and report.system.default_routes and report.system.default_routes[0].is_vpn
        )
        self.workspace.vpn_hint.setText(self.host._tr(VPN_MTR_HINT))
        self.workspace.vpn_hint.setVisible(vpn and len(value.hops) <= 1)
        self.facts.set("mtr.snapshot", value)
        self._render_mtr_snapshot(value)
        if value.undetermined:
            self.workspace.mtr_status.setText(
                self.host._tr("Цель не отвечает на ICMP: выводы о потерях не делаются")
            )
        elif value.real_loss_start_hop is not None:
            self.workspace.mtr_status.setText(
                self.host._translator.format(
                    "Сквозные потери с hop {hop}: {loss}%",
                    hop=value.real_loss_start_hop,
                    loss=f"{value.real_loss_pct:.1f}",
                )
            )
        else:
            self.workspace.mtr_status.setText(self.host._tr("MTR: маршрут стабилен"))
        for event in value.events:
            if event.kind == "route_changed":
                self.event_bus.journal_event_requested.emit(
                    "mtr.route_changed",
                    {
                        "subject": f"hop {event.hop}",
                        "template": "MTR: hop {hop} сменил адрес {old} -> {new}",
                        "values": {
                            "hop": event.hop,
                            "old": event.previous_address or "???",
                            "new": event.address or "???",
                        },
                    },
                )
            elif event.kind in {"loss_opened", "loss_closed"}:
                self.event_bus.journal_event_requested.emit(
                    "mtr.loss_episode",
                    {
                        "severity": "warning" if event.kind == "loss_opened" else "info",
                        "subject": f"hop {event.hop}",
                        "template": "MTR: {kind} потерь на hop {hop}, {loss}%",
                        "values": {
                            "kind": "начало" if event.kind == "loss_opened" else "конец",
                            "hop": event.hop,
                            "loss": event.loss_pct,
                            "duration": event.duration_s,
                        },
                    },
                )
        if self.host._report is not None:
            self.host.overview_controller._update_root_cause_analysis(self.host._report)

    @Slot(str)
    def _on_mtr_failed(self, message: str) -> None:
        self.workspace.mtr_status.setText(self.host._tr(message))
        self.workspace.mtr_start_button.blockSignals(True)
        self.workspace.mtr_start_button.setChecked(False)
        self.workspace.mtr_start_button.blockSignals(False)
        self.event_bus.journal_event_requested.emit(
            "mtr.probe_failed",
            {
                "severity": "warning",
                "subject": self.workspace.traceroute_target_input.text().strip(),
                "template": "MTR недоступен: {error}",
                "values": {"error": message},
            },
        )

    @Slot()
    def _clear_traceroute_worker(self) -> None:
        if self.sender() is not self.host._traceroute_thread:
            return
        self.host._traceroute_thread = None
        self.host._traceroute_worker = None

    @Slot()
    def _clear_mtr_worker(self) -> None:
        if self.sender() is not None and self.sender() is not self.host._mtr_thread:
            return
        thread = self.host._mtr_thread
        if thread is not None and isValid(thread) and not thread.wait(0):
            QTimer.singleShot(10, self._clear_mtr_worker)
            return
        self.host._mtr_thread = None
        self.host._mtr_worker = None
        self.workspace.mtr_start_button.blockSignals(True)
        self.workspace.mtr_start_button.setChecked(False)
        self.workspace.mtr_start_button.blockSignals(False)
