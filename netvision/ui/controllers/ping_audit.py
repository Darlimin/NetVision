"""PingController for diagnostics."""

from datetime import datetime
from PySide6.QtCore import QObject, QThread, Qt, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem
from netvision.core.session import StateStore
from netvision.core.target import parse_target
from netvision.core.ping_benchmark import (
    LatencyStatistics,
    MtuProbeResult,
    RegionalPingResult,
    RegionalPingTarget,
    REGIONAL_GAMING_TARGETS,
    latency_statistics,
)
from netvision.ui.legacy_workers import PingBenchmarkWorker
from netvision.ui.monitor_workers import LatencyMonitorWorker, WorkerRegistry
from netvision.ui.utils import _ms


from netvision.ui.workspaces.ping_audit import PingWorkspace


class PingController(QObject):
    def __init__(
        self, workspace: PingWorkspace, facts: StateStore, registry: WorkerRegistry, parent: QObject
    ) -> None:
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        self.registry = registry
        workspace.ping_run_button.clicked.connect(self.start_ping_benchmark)
        workspace.ping_matrix_table.cellClicked.connect(self._select_ping_region)

    def _inherited__render_ping_matrix(self, results: tuple[RegionalPingResult, ...]) -> None:
        self.host._ping_matrix_results = results
        self.workspace.ping_matrix_table.setRowCount(len(results))
        successful = [result for result in results if result.success]
        fastest = (
            min(successful, key=lambda result: result.latency_ms or float("inf"))
            if successful
            else None
        )
        for row, result in enumerate(results):
            latency = _ms(result.latency_ms)
            is_preferred = result.target == self.host._preferred_ping_target
            status = (
                self.host._tr("Основной")
                if is_preferred
                else (
                    self.host._tr("Лучший")
                    if result is fastest
                    else (
                        self.host._tr("Доступен") if result.success else self.host._tr("Нет ответа")
                    )
                )
            )
            values = [
                result.target.region,
                result.target.host,
                latency,
                f"{result.ping.loss_percent:.0f}%",
                status,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(result.ping.error or result.target.note if column == 4 else value)
                item.setData(Qt.ItemDataRole.UserRole, result.target)
                if is_preferred:
                    item.setBackground(QColor("#124F43"))
                    item.setForeground(QColor("#00E5A3"))
                elif result is fastest and column in {2, 4}:
                    item.setForeground(QColor("#00E5A3"))
                elif not result.success:
                    item.setForeground(QColor("#FF6B78"))
                self.workspace.ping_matrix_table.setItem(row, column, item)
        self._update_ping_matrix_selection_status()

    @Slot(object, bool)
    def _inherited__on_latency_sample(self, latency_ms: object, success: bool) -> None:
        value = float(latency_ms) if isinstance(latency_ms, (int, float)) else None
        self.host.jitter_controller._record_jitter_sample(value, success)
        self.host._latency_window.append(value if success else None)
        if len(self.host._latency_window) > 60:
            del self.host._latency_window[:-60]
        step, episode = self.host._rtt_episode_tracker.update(
            value if success else None,
            datetime.now().astimezone(),
        )
        self.host._sync_rtt_episode_log(step, episode)
        if step == "opened":
            if episode is not None:
                self.event_bus.journal_event_requested.emit(
                    "jitter.episode",
                    {
                        "severity": "warning",
                        "subject": self.host._jitter_endpoint(),
                        "template": "Высокий ping: {latency:.1f} мс",
                        "values": {"latency": episode.peak},
                        "refs": {"kind": "spike", "started_at": episode.started_at.isoformat()},
                        "at": episode.started_at,
                    },
                )
            self.host._record_wifi_correlation("rtt")
        self.host.node_details.latency_chart.add_sample(value, success)
        loss_snapshot, loss_event = self.host._loss_analyzer.observe(success, value)
        self.host._set_loss_snapshot(loss_snapshot)
        if loss_event is not None:
            self.event_bus.journal_event_requested.emit(
                "loss.episode",
                {
                    "severity": "error" if loss_event.kind in {"burst", "burst_end"} else "warning",
                    "subject": self.host.core_workspace.target_input.text().strip(),
                    "template": "Потери: {message}",
                    "values": {"message": loss_event.message, "lost": loss_event.lost},
                    "refs": {
                        "kind": loss_event.kind,
                        "started_at": (
                            loss_event.started_at.isoformat() if loss_event.started_at else ""
                        ),
                    },
                    "at": loss_event.observed_at,
                },
            )
            self.host.loss_workspace.loss_events_log.setPlainText(
                "\n".join(
                    f"[{event.observed_at:%H:%M:%S}] {event.message}"
                    for event in self.host._loss_analyzer.events
                )
            )
            self.host.loss_workspace.loss_detector_status.setText(
                f"{loss_event.snapshot.status} · событий: {len(self.host._loss_analyzer.events)}"
            )
            if loss_event.kind == "drop":
                self.host._record_wifi_correlation("loss")
        elif loss_snapshot.sent:
            self.host.loss_workspace.loss_detector_status.setText(loss_snapshot.status)
        self._set_ping_statistics(
            latency_statistics(
                [sample for sample in self.host._latency_window if sample is not None],
                sent=len(self.host._latency_window),
                th=self.host._thresholds,
            )
        )
        if self.host._ping_spike_events:
            self.workspace.ping_spike_log.setPlainText("\n".join(self.host._ping_spike_events))
            self.workspace.ping_spike_status.setText(
                f"Зафиксировано событий: {len(self.host._ping_spike_events)}"
            )
        self.host.state_synchronizer._update_live_header_anomaly(value, success, loss_snapshot)

    @Slot()
    def _clear_ping_benchmark_worker(self) -> None:
        if self.sender() is not self.host._ping_benchmark_thread:
            return
        self.host._ping_benchmark_thread = None
        self.host._ping_benchmark_worker = None

    def _update_ping_matrix_selection_status(self) -> None:
        if self.host._preferred_ping_target is None:
            self.workspace.ping_matrix_selection_status.setText(
                self.host._tr("Региональный узел не выбран")
            )
            return
        self.workspace.ping_matrix_selection_status.setText(
            self.host._translator.format(
                "Основной узел: {region} ({host})",
                region=self.host._preferred_ping_target.region,
                host=self.host._preferred_ping_target.host,
            )
        )

    def _set_ping_statistics(self, statistics: LatencyStatistics) -> None:
        self.workspace.ping_stat_min.setText(_ms(statistics.minimum_ms))
        self.workspace.ping_stat_max.setText(_ms(statistics.maximum_ms))
        self.workspace.ping_stat_average.setText(_ms(statistics.average_ms))
        self.workspace.ping_stat_jitter.setText(_ms(statistics.jitter_ms))
        self.workspace.ping_stat_loss.setText(f"{statistics.loss_percent:.0f}%")
        self.workspace.ping_stat_stability.setText(statistics.stability)

    def _render_ping_matrix_placeholders(self) -> None:
        self.host._ping_matrix_results = ()
        self.workspace.ping_matrix_table.setRowCount(len(REGIONAL_GAMING_TARGETS))
        for row, target in enumerate(REGIONAL_GAMING_TARGETS):
            is_preferred = target == self.host._preferred_ping_target
            status = self.host._tr("Основной") if is_preferred else self.host._tr("Готов к тесту")
            values = [target.region, target.host, "--", "--", status]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(target.note if column in {0, 1} else value)
                item.setData(Qt.ItemDataRole.UserRole, target)
                if is_preferred:
                    item.setBackground(QColor("#124F43"))
                    item.setForeground(QColor("#00E5A3"))
                self.workspace.ping_matrix_table.setItem(row, column, item)
        self._update_ping_matrix_selection_status()

    def _start_latency_monitor(
        self,
        host: str,
        port: int,
        *,
        protocol: str = "TCP",
    ) -> None:
        if self.host._closing:
            return
        self.host._publish_monitor_scope()
        self._stop_latency_monitor()
        worker = LatencyMonitorWorker(host, port, protocol=protocol)
        worker.sample.connect(
            self.host._queue_ui_slot(
                self._on_latency_sample,
                owner=worker,
                active_owner=lambda: self.host._latency_worker,
            )
        )
        thread = self.registry.start(worker)
        thread.finished.connect(self._clear_latency_monitor)
        self.host._latency_thread = thread
        self.host._latency_worker = worker

        route = (
            self.host._report.system.default_routes[0]
            if self.host._report is not None and self.host._report.system.default_routes
            else None
        )
        self.host._start_wifi_monitor(route)

    def _stop_latency_monitor(self) -> None:
        self.host._stop_wifi_monitor()
        thread = self.host._latency_thread
        self.registry.stop(thread)
        if thread is self.host._latency_thread:
            self.host._latency_thread = None
            self.host._latency_worker = None

    @Slot()
    def _clear_latency_monitor(self) -> None:
        thread = self.sender()
        if thread is not self.host._latency_thread:
            return
        self.host._latency_thread = None
        self.host._latency_worker = None

    @Slot(int, int)
    def _select_ping_region(self, row: int, _column: int) -> None:
        item = self.workspace.ping_matrix_table.item(row, 0)
        target = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(target, RegionalPingTarget):
            return
        self.host._preferred_ping_target = target
        self._update_ping_matrix_selection_status()
        if self.host._ping_matrix_results:
            self._render_ping_matrix(self.host._ping_matrix_results)
        else:
            self._render_ping_matrix_placeholders()
        for current_row in range(self.workspace.ping_matrix_table.rowCount()):
            current = self.workspace.ping_matrix_table.item(current_row, 0)
            if current is not None and current.data(Qt.ItemDataRole.UserRole) == target:
                self.workspace.ping_matrix_table.selectRow(current_row)
                break
        self.event_bus.log_requested.emit(
            f"Зафиксирован основной региональный узел: {target.region} ({target.host})", "INFO"
        )

    @Slot()
    def start_ping_benchmark(self) -> None:
        self._start_ping_analysis(include_matrix=True, include_mtu=False)

    def _start_ping_analysis(self, *, include_matrix: bool, include_mtu: bool) -> None:
        if self.host._ping_benchmark_thread and self.host._ping_benchmark_thread.isRunning():
            return
        mtu_host = self.host.core_workspace.target_input.text().strip()
        try:
            parsed_target = parse_target(mtu_host, self.host.core_workspace.port_input.value())
        except ValueError as exc:
            self.workspace.ping_spike_status.setText(f"MTU-проверка: {exc}")
            return

        self.host._set_task_button_busy(self.workspace.ping_run_button, True, "Проверка")
        self.workspace.ping_run_button.setDisabled(True)
        if include_matrix:
            self._render_ping_matrix_placeholders()
        running_parts = []
        if include_matrix:
            running_parts.append("региональные ориентиры")
        if include_mtu:
            running_parts.append(f"MTU для {parsed_target.host}")
        self.workspace.ping_spike_status.setText(f"Проверяем: {', '.join(running_parts)}...")

        thread = QThread(self.host)
        regional_targets = None
        if include_matrix and self.host._preferred_ping_target is not None:
            regional_targets = (
                self.host._preferred_ping_target,
                *(
                    target
                    for target in REGIONAL_GAMING_TARGETS
                    if target != self.host._preferred_ping_target
                ),
            )
        worker = PingBenchmarkWorker(
            parsed_target.host,
            include_matrix=include_matrix,
            include_mtu=include_mtu,
            regional_targets=regional_targets,
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_ping_benchmark_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_ping_benchmark_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_ping_benchmark_worker)
        self.host._ping_benchmark_thread = thread
        self.host._ping_benchmark_worker = worker
        thread.start()

    def _refresh_ping_statistics(self) -> None:
        values = [value for value in self.host._latency_window if value is not None]
        self._set_ping_statistics(
            latency_statistics(
                values, sent=len(self.host._latency_window), th=self.host._thresholds
            )
        )
        if self.host._ping_spike_events:
            self.workspace.ping_spike_log.setPlainText("\n".join(self.host._ping_spike_events))

    @Slot(object, object)
    def _on_ping_benchmark_completed(self, regional_value: object, mtu_value: object) -> None:
        self.host._set_task_button_busy(self.workspace.ping_run_button, False)
        self.workspace.ping_run_button.setEnabled(True)
        if not isinstance(regional_value, tuple) or not all(
            isinstance(item, RegionalPingResult) for item in regional_value
        ):
            self._on_ping_benchmark_failed("Матрица регионов вернула некорректный результат")
            return
        if not isinstance(mtu_value, tuple) or not all(
            isinstance(item, MtuProbeResult) for item in mtu_value
        ):
            self._on_ping_benchmark_failed("MTU-проверка вернула некорректный результат")
            return
        self.facts.set("ping.benchmark", (regional_value, mtu_value))
        if regional_value:
            self._render_ping_matrix(regional_value)
        self._render_ping_mtu_probe_results(mtu_value)
        tested = []
        if regional_value:
            tested.append(f"регионов: {len(regional_value)}")
        if mtu_value:
            tested.append(f"MTU: {len(mtu_value)} размера")
        self.workspace.ping_spike_status.setText(f"Анализ завершён ({', '.join(tested)}).")

    @Slot(str)
    def _on_ping_benchmark_failed(self, message: str) -> None:
        self.host._set_task_button_busy(self.workspace.ping_run_button, False)
        self.workspace.ping_run_button.setEnabled(True)
        self.workspace.ping_spike_status.setText(message)

    def _render_ping_mtu_probe_results(self, results: tuple[MtuProbeResult, ...]) -> None:
        """Render the DF probes returned with the regional ping benchmark."""
        self.host.mtu_workspace.ping_mtu_table.setRowCount(len(results))
        for row, probe in enumerate(results):
            status = (
                self.host._tr("DF-пакет доставлен")
                if probe.success
                else probe.error or self.host._tr("Фрагментация или потеря")
            )
            details = (
                f"{probe.received}/{probe.sent} · {self.host._tr('Потери')}: {probe.loss_percent:.0f}%"
                if probe.sent
                else self.host._tr("Проба не выполнена")
            )
            values = (
                str(probe.payload_size + 28),
                f"{probe.payload_size} B",
                _ms(probe.average_ms),
                status,
                details,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(probe.error or value)
                item.setForeground(QColor("#00E5A3" if probe.success else "#FF6B78"))
                self.host.mtu_workspace.ping_mtu_table.setItem(row, column, item)

    @Slot(object, bool)
    def _on_latency_sample(self, latency_ms: object, success: bool) -> None:
        self._inherited__on_latency_sample(latency_ms, success)
        self.facts.set("ping.sample", (latency_ms, success))
        if not self.host._dashboard_ready or not self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_latency_chart,
            self.host.core_workspace.dashboard_metric_cards["ping"],
        ):
            return
        value = float(latency_ms) if isinstance(latency_ms, (int, float)) else None
        self.host._dashboard_add_sample("ping", value if success else None)
        if len(self.host._dashboard_histories["ping"]) > 1:
            samples = self.host._dashboard_histories["ping"]
            self.host._dashboard_add_sample("jitter", abs(samples[-1] - samples[-2]))
        snapshot = self.host._loss_analyzer_snapshot()
        self.host._dashboard_add_sample("loss", snapshot.loss_percent)
        self.host.overview_controller._set_dashboard_metric(
            "ping",
            self.host._format_ms(value) if success else "нет ответа",
            self.host._latency_state(value) if success else "error",
        )
        jitter = (
            self.host._dashboard_histories["jitter"][-1]
            if self.host._dashboard_histories["jitter"]
            else None
        )
        loss_state, jitter_state = self.host._dashboard_quality_states(
            snapshot.loss_percent,
            jitter,
            self.host._thresholds,
        )
        self.host.overview_controller._set_dashboard_metric(
            "loss",
            f"{snapshot.loss_percent:.0f}%",
            loss_state,
        )
        self.host.overview_controller._set_dashboard_metric(
            "jitter",
            self.host._format_ms(jitter),
            jitter_state,
        )
        self.host.core_workspace.dashboard_latency_chart.set_samples(
            self.host._dashboard_histories["latency"]
        )
        if self.host._dashboard_game_connection is not None:
            snapshot = self.host._loss_analyzer_snapshot()
            self.host._dashboard_game_metrics = (
                value if success else None,
                snapshot.loss_percent,
                success,
            )
            self.host._dashboard_render_regions(self.host._report)

    def _render_ping_matrix(self, results: tuple[object, ...]) -> None:
        self._inherited__render_ping_matrix(results)  # type: ignore[arg-type]
        if self.host._dashboard_ready and self.host._dashboard_widgets_alive(
            self.host.region_card.dashboard_region_table
        ):
            self.host._dashboard_render_regions(self.host._report)
