"""Dashboard DiagnosticsCoordinator operations."""

from __future__ import annotations
from PySide6.QtCore import QObject, Slot
from netvision.ui import constants as ui_constants

from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import QMessageBox, QTableWidgetItem
from netvision.core.process_inspector import ProcessScanResult, is_public_address
from netvision.core.process_utils import EndpointChoice
from netvision.core.ping_benchmark import latency_statistics
from netvision.core.bufferbloat import BufferbloatReport, resolve_target_ipv4
from netvision.core.root_cause import vpn_bypass_connections
from netvision.core.target import parse_target
from netvision.core.session import Scope
from netvision.core import judgement
from netvision.core.internet_quality import InternetQualityReport, build_smart_report
from netvision.core.nat_diagnostics import NatReport
from netvision.models import DiagnosticReport, NetworkInterface, ProbeStatus, SystemSnapshot, Target
from netvision.ui.legacy_workers import DiagnosticWorker
from netvision.ui.legacy_workers import BufferbloatWorker, InternetQualityWorker, NatProbeWorker
from netvision.ui.lite_mode import LiteStatus
from netvision.ui.utils import _format_diagnostic_failure, _ms
from netvision.ui.utils import _bufferbloat_speed, _speed, _latency
from netvision.ui.presentation import nat_description

from datetime import datetime
import re
from pathlib import Path
from PySide6.QtWidgets import QFileDialog
from netvision.reporting import serialize_support_bundle

from PySide6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout
from netvision.core.network_boost import BackgroundTrafficCandidate
from netvision.ui.legacy_workers import NetworkBoostTerminateWorker


class DiagnosticsCoordinator(QObject):
    def __init__(self, parent, facts, event_bus):
        super().__init__(parent)
        self.host = parent
        self.facts = facts
        self.event_bus = event_bus

    @Slot(str, str)
    def _on_progress(self, stage: str, message: str) -> None:
        self.host.node_details.stage_label.setText(self.host._tr(message))
        self.host.core_workspace.topology.set_active_stage(stage)
        self.host._append_log(message)

    @Slot(str)
    def _on_quality_progress(self, message: str) -> None:
        self.host.quality_workspace.quality_status.setText(
            self.host._translate_quality_progress(message)
        )
        self.host._append_log(message)

    @Slot(str)
    def _on_bufferbloat_progress(self, message: str) -> None:
        self.host.bufferbloat_workspace.bufferbloat_status.setText(self.host._tr(message))
        if message.startswith("Фаза 1/3"):
            self.host.diagnostics_coordinator._update_bufferbloat_phase(0)
        elif message.startswith("Фаза 2/3"):
            self.host.diagnostics_coordinator._update_bufferbloat_phase(1)
        elif message.startswith("Фаза 3/3"):
            self.host.diagnostics_coordinator._update_bufferbloat_phase(2)
        self.host._append_log(message)

    def _update_bufferbloat_phase(self, active_index: int) -> None:
        sources = ui_constants.DASHBOARD_BUFFERBLOAT_SOURCES
        for index, label in enumerate(self.host.bufferbloat_workspace.bufferbloat_phase_labels):
            marker = "✓" if index < active_index else "●" if index == active_index else "○"
            label.setText(f"{marker} {self.host._tr(sources[index])}")

    def _inherited__on_endpoint_chosen(self, value: object) -> None:
        if isinstance(value, EndpointChoice):
            connection = value.connection
            if (
                connection.remote_address
                and connection.remote_port > 0
                and is_public_address(connection.remote_address)
            ):
                self.host.core_workspace.target_input.setText(connection.remote_address)
                self.host.core_workspace.port_input.setValue(connection.remote_port)
                if not self.host._ping_mtu_host_manually_edited:
                    self.host.mtu_workspace.ping_mtu_host_input.setText(connection.remote_address)
                self.host._publish_monitor_scope()
            self.host._record_endpoint_choice(value)

    def _inherited__on_completed(self, report: object) -> None:
        if not isinstance(report, DiagnosticReport):
            self.host._on_failed("Диагностический модуль вернул неизвестный результат")
            return
        self.host._report = report
        self.host._vpn_process_sockets = None
        self.host._vpn_process_sockets_ready = False
        self.host.core_workspace.topology.set_report(report)
        self.host.overview_controller._fill_metrics(report)
        self.host.ping_controller._set_ping_statistics(
            latency_statistics(
                tuple(report.ping.samples_ms), sent=report.ping.sent, th=self.host._thresholds
            )
        )
        self.host.loss_controller._render_loss_hops_placeholders(
            report.hops, self.host._tr("Нажмите «Запустить анализ потерь»")
        )
        self.host.loss_workspace.loss_hops_status.setText(
            self.host._tr(
                "Трассировка получена. Запустите анализ, чтобы проверить ICMP-потери по каждому hop."
            )
        )
        self.host._fill_interfaces(report.system.interfaces)
        self.host._start_wifi_monitor(
            report.system.default_routes[0] if report.system.default_routes else None
        )
        self.host._fill_route_analysis(report)
        self.host._show_system_details(report)
        self.host.state_synchronizer._update_lite_summary(report)
        self.host.overview_controller._update_root_cause_analysis(report)
        if (
            self.host._selected_process is not None
            and report.system.default_routes
            and report.system.default_routes[0].is_vpn
        ):
            self.host._start_process_sockets_scan(report, self.host._selected_process.pid)
        self.host.header_panel.export_button.setEnabled(True)
        self.host.header_panel.support_bundle_button.setEnabled(True)
        self.host._set_running(False)
        state = "CONNECTED" if report.tcp.status == ProbeStatus.SUCCESS else "ISSUES FOUND"
        self.host._set_status(
            state, "success" if report.tcp.status == ProbeStatus.SUCCESS else "warning"
        )
        anomaly_state, anomaly_source, anomaly_values = judgement.header_anomaly(
            report, self.host._thresholds
        )
        self.host.overview_controller._set_header_anomaly(
            anomaly_state, anomaly_source, **anomaly_values
        )
        self.host.node_details.stage_label.setText(
            self.host._translator.format(
                "Готово за {seconds:.1f} с", seconds=report.total_ms / 1000
            )
        )
        for error in report.errors:
            self.host._append_log(f"Предупреждение: {error}")
        if report.tls and judgement.tls_domain_required(report.target.host, report.tls.error):
            self.event_bus.log_requested.emit(
                self.host._tr("Проверка сертификата ограничена: для IP требуется домен"), "INFO"
            )
        self.host._append_log("Диагностика завершена")

    def _inherited__on_failed(self, failure: object) -> None:
        message = _format_diagnostic_failure(failure)
        self.host._diagnostic_failure_text = message
        self.host._set_running(False)
        self.host._set_status("ERROR", "error")
        self.host.overview_controller._set_header_anomaly("error", "Ошибка диагностики")
        self.host.node_details.stage_label.setText(
            self.host._tr("Диагностика остановлена из-за ошибки")
        )
        self.host._append_log(f"Ошибка: {message}")
        self.host.header_panel.support_bundle_button.setEnabled(True)
        QMessageBox.critical(self.host, self.host._tr("Ошибка диагностики"), message)

    def _inherited__reset_results(self, target: Target) -> None:
        self.host.node_details.latency_chart.reset()
        self.host.jitter_workspace.jitter_chart.reset()
        self.host._latency_window.clear()
        self.host._ping_spike_events.clear()
        self.host._jitter_events.clear()
        self.host._jitter_deviations.clear()
        self.host._jitter_previous_rtt = None
        self.host._jitter_episode_tracker = self.host._new_jitter_episode_tracker()
        self.host._jitter_episode_row_index = None
        self.host._jitter_timeout_row_index = None
        self.host._rtt_episode_tracker = self.host._new_rtt_episode_tracker()
        self.host._rtt_episode_log_index = None
        self.host._jitter_target_host = target.host
        self.host._loss_analyzer.reset()
        self.host.ping_workspace.ping_spike_log.clear()
        self.host.ping_workspace.ping_spike_status.setText(
            self.host._translator.format(
                "Пики выше {threshold:.0f} мс и потери появятся здесь во время мониторинга",
                threshold=self.host._thresholds.rtt_high_ms,
            )
        )
        self.host.ping_controller._set_ping_statistics(
            latency_statistics((), th=self.host._thresholds)
        )
        self.host.ping_controller._render_ping_matrix_placeholders()
        self.host.loss_workspace.loss_events_log.clear()
        self.host.loss_workspace.loss_detector_status.setText(
            self.host._tr("Ожидание данных live-монитора")
        )
        self.host._set_loss_snapshot(self.host._loss_analyzer_snapshot())
        self.host.loss_workspace.loss_hops_table.setRowCount(0)
        self.host.loss_workspace.loss_hops_status.setText(
            self.host._tr("Диагностика выполняется: трассировка будет доступна после завершения.")
        )
        self.host.loss_controller._render_loss_stress_placeholders()
        self.host.core_workspace.topology.reset(target.display_name)
        self.host._clear_detail_grid()
        self.host.node_details.detail_title.setText(self.host._tr("Диагностика выполняется"))
        self.host.interfaces_panel.interfaces_table.setRowCount(0)
        self.host._set_wifi_status("Wi-Fi: ожидание активного маршрута")
        self.host.path_workspace.routes_table.setRowCount(0)
        self.host.path_workspace.geo_table.setRowCount(0)
        self.host.path_workspace.geo_status.setText(self.host._tr("GeoIP ещё не получен"))
        self.host.lite_panel.lite_title.setText(self.host._tr("Проверка выполняется"))
        self.host.lite_panel.lite_message.setText(
            self.host._translator.format(
                "Проверяем соединение с {target}.", target=target.display_name
            )
        )
        self.host.lite_panel.lite_cause.setText(
            self.host._tr("Анализ причины появится после завершения проверки.")
        )
        self.host.analysis_panel.analysis_title.setText(self.host._tr("Анализ выполняется"))
        self.host.analysis_panel.analysis_output.clear()
        self.host._clear_lite_details()
        self.host._set_lite_status_style(LiteStatus.WARNING)
        self.host.header_panel.export_button.setEnabled(False)
        self.host.header_panel.support_bundle_button.setEnabled(False)
        for tile in self.host.expert_view.metrics.values():
            tile.set_waiting(self.host._tr("Проверка выполняется"))

    def _on_process_sockets_completed(self, result: object) -> None:
        report = self.host._process_sockets_report
        selected_process = self.host._selected_process
        if (
            report is None
            or self.host._report is not report
            or selected_process is None
            or (selected_process.pid != self.host._process_sockets_pid)
        ):
            return
        if not isinstance(result, ProcessScanResult):
            result = ProcessScanResult((), "Сокеты выбранного процесса не получены")
        process = next(
            (item for item in result.processes if item.pid == selected_process.pid), None
        )
        socket_count = len(process.connections) if process is not None else 0
        measurement = self.host._record_journal_event(
            "process.sockets",
            severity="warning" if result.warning else "info",
            subject=selected_process.name,
            template="Сокеты процесса: {count}",
            values={"count": socket_count, "warning": result.warning or ""},
            refs={"pid": selected_process.pid},
        )
        if result.warning:
            self.host._append_log(f"Проверка сокетов процесса: {result.warning}")
        self.host._vpn_process_sockets = process
        self.host._vpn_process_sockets_ready = True
        finding = vpn_bypass_connections(report, process)
        if finding is not None:
            self.host._record_journal_event(
                "vpn.bypass_suspected",
                severity="warning",
                subject=selected_process.name,
                template="Возможный обход VPN: {evidence}",
                values={"evidence": finding.evidence},
                refs={"measurement_event_id": measurement.id, "pid": selected_process.pid},
            )
        self.host.overview_controller._update_root_cause_analysis(report)

    def start_diagnostic(self) -> None:
        if self.host._thread and self.host._thread.isRunning():
            return
        try:
            target = parse_target(
                self.host.core_workspace.target_input.text(),
                self.host.core_workspace.port_input.value(),
            )
        except ValueError as exc:
            QMessageBox.warning(self.host, "Некорректный адрес", str(exc))
            self.host.core_workspace.target_input.setFocus()
            return
        self.host._run_scope = Scope.of(target.host, target.port)
        self.host._report = None
        self.host._diagnostic_failure_text = None
        self.host._start_diagnostic_session()
        self.host._reset_results(target)
        monitor_protocol = (
            self.host._selected_connection.protocol
            if self.host._selected_connection is not None
            and self.host._selected_connection.remote_address == target.host
            and (self.host._selected_connection.remote_port == target.port)
            else "TCP"
        )
        self.host.ping_controller._start_latency_monitor(
            target.host, target.port, protocol=monitor_protocol
        )
        self.host._set_running(True)
        self.host._append_log(f"Запуск диагностики {target.display_name}")
        thread = QThread(self.host)
        worker = DiagnosticWorker(target)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(
            self.host._queue_ui_slot(self.host.diagnostics_coordinator._on_progress)
        )
        worker.completed.connect(self.host._queue_ui_slot(self.host._on_completed))
        worker.failed.connect(
            self.host._queue_ui_slot(
                self.host._on_failed, owner=worker, active_owner=lambda: self.host._worker
            )
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self.host._clear_worker)
        self.host._thread = thread
        self.host._worker = worker
        thread.start()

    def _fill_route_analysis(self, report: DiagnosticReport) -> None:
        routes = report.system.default_routes
        self.host.path_workspace.routes_table.setRowCount(len(routes))
        for row, route in enumerate(routes):
            values = [
                (
                    "VPN · активен"
                    if row == 0 and route.is_vpn
                    else "Обычный · активен"
                    if row == 0
                    else "VPN"
                    if route.is_vpn
                    else "Обычный"
                ),
                route.interface or "не определён",
                f"{route.gateway} · напрямую" if route.on_link else route.gateway,
                str(route.metric),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if row == 0:
                    item.setForeground(Qt.GlobalColor.cyan)
                self.host.path_workspace.routes_table.setItem(row, column, item)
        if not routes:
            self.host.path_workspace.routes_table.setRowCount(1)
            self.host.path_workspace.routes_table.setItem(
                0, 0, QTableWidgetItem("Default routes не найдены")
            )
        self.host.path_workspace.geo_table.setRowCount(len(report.geolocation))
        successful_geo = 0
        for row, result in enumerate(report.geolocation):
            if result.status == ProbeStatus.SUCCESS:
                successful_geo += 1
            values = [
                result.address,
                ", ".join((part for part in (result.country, result.region, result.city) if part))
                or "--",
                result.asn or "--",
                result.isp or "--",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.host.path_workspace.geo_table.setItem(row, column, item)
        self.host.path_workspace.geo_status.setText(
            f"{successful_geo}/{len(report.geolocation)} узлов · источник ipwho.is"
            if report.geolocation
            else "Публичные IP узлов маршрута не найдены"
        )

    def _fill_interfaces(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self.host.interfaces_panel.interfaces_table.setRowCount(len(interfaces))
        for row, interface in enumerate(interfaces):
            values = [
                interface.name,
                self.host._tr(interface.kind),
                ", ".join(interface.ipv4) or "--",
                "UP" if interface.is_up else "DOWN",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 3:
                    item.setForeground(
                        Qt.GlobalColor.green if interface.is_up else Qt.GlobalColor.gray
                    )
                self.host.interfaces_panel.interfaces_table.setItem(row, column, item)

    def start_bufferbloat_test(self) -> None:
        if self.host._bufferbloat_thread and self.host._bufferbloat_thread.isRunning():
            return
        self.host._bufferbloat_report = None
        self.host._set_task_button_busy(
            self.host.bufferbloat_workspace.bufferbloat_start_button, True, "Проверка"
        )
        self.host.bufferbloat_workspace.bufferbloat_progress.show()
        self.host.bufferbloat_workspace.bufferbloat_status.setText(
            self.host._tr("Фаза 1/3: базовая задержка")
        )
        self.host.diagnostics_coordinator._update_bufferbloat_phase(0)
        self.host.bufferbloat_recommendation_sources = ()
        self.host._render_bufferbloat_recommendations()
        for label in self.host.bufferbloat_workspace.bufferbloat_values.values():
            label.setText("--")
        self.host.bufferbloat_workspace.bufferbloat_grade.setText("--")
        self.host.bufferbloat_workspace.bufferbloat_verdict.setText(
            self.host._tr("Недостаточно данных для оценки bufferbloat")
        )
        self.host.bufferbloat_workspace.bufferbloat_delta.setText(
            self.host._tr("Δ download: {download} · Δ upload: {upload}").format(
                download="--", upload="--"
            )
        )
        self.host.bufferbloat_workspace.bufferbloat_network_boost_button.hide()
        target_ip = resolve_target_ipv4(self.host.core_workspace.target_input.text().strip())
        gateway = None
        if self.host._report and self.host._report.system.gateway:
            gateway = self.host._report.system.gateway.address
        elif self.host._report and self.host._report.system.default_routes:
            gateway = self.host._report.system.default_routes[0].gateway
        thread = QThread(self.host)
        worker = BufferbloatWorker(target_ip, gateway, self.host._thresholds)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(
            self.host._queue_ui_slot(self.host.diagnostics_coordinator._on_bufferbloat_progress)
        )
        worker.completed.connect(self.host._queue_ui_slot(self.host._on_bufferbloat_completed))
        worker.failed.connect(self.host._queue_ui_slot(self.host._on_bufferbloat_failed))
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self.host._clear_bufferbloat_worker)
        self.host._bufferbloat_thread = thread
        self.host._bufferbloat_worker = worker
        thread.start()

    def start_quality_check(self) -> None:
        if self.host._quality_thread and self.host._quality_thread.isRunning():
            return
        self.host._quality_report = None
        self.host._set_task_button_busy(
            self.host.quality_workspace.quality_test_button, True, "Проверка"
        )
        self.host.quality_workspace.quality_progress.show()
        self.host.quality_workspace.quality_status.setText(
            self.host._tr("Подготавливаем проверку качества...")
        )
        self.host.quality_workspace.quality_report_output.clear()
        for tile in self.host.quality_workspace.quality_metrics.values():
            tile.set_metric("--", self.host._tr("выполняется"))
        for label in self.host.quality_workspace.quality_details.values():
            label.setText("--")
        self.host._append_log("Запуск проверки качества интернета")
        snapshot = self.host._report.system if self.host._report else None
        thread = QThread(self.host)
        worker = InternetQualityWorker(snapshot)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(
            self.host._queue_ui_slot(self.host.diagnostics_coordinator._on_quality_progress)
        )
        worker.completed.connect(self.host._queue_ui_slot(self.host._on_quality_completed))
        worker.failed.connect(self.host._queue_ui_slot(self.host._on_quality_failed))
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self.host._clear_quality_worker)
        self.host._quality_thread = thread
        self.host._quality_worker = worker
        thread.start()

    def start_nat_probe(self) -> None:
        if self.host._nat_thread and self.host._nat_thread.isRunning():
            return
        self.host._nat_report = None
        self.host._set_task_button_busy(self.host.quality_workspace.nat_probe_button, True, "STUN")
        self.host.quality_workspace.nat_probe_status.setText("Проверяем UDP NAT через STUN...")
        snapshot = self.host._report.system if self.host._report else None
        thread = QThread(self.host)
        worker = NatProbeWorker(
            snapshot.external_ip if snapshot else None,
            self.host._report.hops if self.host._report else (),
            self.host._thresholds,
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self.host._queue_ui_slot(self.host._on_nat_probe_completed))
        worker.failed.connect(self.host._queue_ui_slot(self.host._on_nat_probe_failed))
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self.host._clear_nat_worker)
        self.host._nat_thread = thread
        self.host._nat_worker = worker
        thread.start()

    def _on_bufferbloat_completed(self, value: object) -> None:
        self.host._finish_bufferbloat_test()
        if not isinstance(value, BufferbloatReport):
            self.host._on_bufferbloat_failed("Модуль bufferbloat вернул неизвестный результат")
            return
        self.host._bufferbloat_report = value
        self.host.event_bus.history_update_requested.emit(
            "Bufferbloat",
            {
                "download_mbps": value.download_active.speed_mbps,
                "upload_mbps": value.upload_active.speed_mbps,
                "ping_ms": value.unloaded.latency_ms,
                "bufferbloat_grade": value.grade,
            },
        )
        self.host.diagnostics_coordinator._update_bufferbloat_phase(3)
        self.host.bufferbloat_recommendation_sources = value.recommendations
        self.host._render_bufferbloat_recommendations()
        self.host.bufferbloat_workspace.bufferbloat_values["unloaded"].setText(
            _ms(value.unloaded.latency_ms)
        )
        self.host.bufferbloat_workspace.bufferbloat_values["download"].setText(
            f"{_ms(value.download_active.latency_ms)} · {_bufferbloat_speed(value.download_active.speed_mbps)}"
        )
        self.host.bufferbloat_workspace.bufferbloat_values["upload"].setText(
            f"{_ms(value.upload_active.latency_ms)} · {_bufferbloat_speed(value.upload_active.speed_mbps)}"
        )
        self.host.bufferbloat_workspace.bufferbloat_phase_details["unloaded"].setText(
            self.host._tr("Базовый ping")
        )
        self.host.bufferbloat_workspace.bufferbloat_phase_details["download"].setText(
            self.host._tr("Дельта (p95 − p50): {delta} · скорость: {speed}").format(
                delta=_ms(value.download_active.delta_ms),
                speed=_bufferbloat_speed(value.download_active.speed_mbps),
            )
        )
        self.host.bufferbloat_workspace.bufferbloat_phase_details["upload"].setText(
            self.host._tr("Дельта (p95 − p50): {delta} · скорость: {speed}").format(
                delta=_ms(value.upload_active.delta_ms),
                speed=_bufferbloat_speed(value.upload_active.speed_mbps),
            )
        )
        self.host.bufferbloat_workspace.bufferbloat_grade.setText(value.grade)
        self.host.bufferbloat_workspace.bufferbloat_verdict.setText(self.host._tr(value.verdict))
        attribution = self.host._bufferbloat_attribution(value)
        self.host.bufferbloat_workspace.bufferbloat_delta.setText(
            self.host._tr(
                "Δ (p95 − p50) download: {download} · upload: {upload} · {attribution}"
            ).format(
                download=_ms(value.download_active.delta_ms),
                upload=_ms(value.upload_active.delta_ms),
                attribution=attribution,
            )
        )
        self.host.bufferbloat_workspace.bufferbloat_network_boost_button.setVisible(
            value.grade in {"C", "D", "F"}
        )
        self.host._record_bufferbloat_journal(value, attribution)
        self.host.bufferbloat_workspace.bufferbloat_status.setText(
            self.host._tr("Тест завершён частично")
            if value.error
            else self.host._tr("Тест завершён")
        )
        self.host._set_status("BUFFERBLOAT READY", "warning" if value.error else "success")

    def _on_bufferbloat_failed(self, message: str) -> None:
        self.host._finish_bufferbloat_test()
        prefix = "Тест bufferbloat завершился ошибкой: "
        status = (
            self.host._tr("Тест bufferbloat завершился ошибкой: {error}").format(
                error=message.removeprefix(prefix)
            )
            if message.startswith(prefix)
            else self.host._tr(message)
        )
        self.host.bufferbloat_workspace.bufferbloat_status.setText(status)
        self.host._set_status("BUFFERBLOAT ERROR", "error")
        self.host._append_log(f"Bufferbloat: {message}")

    def _on_quality_completed(self, value: object) -> None:
        self.host._finish_quality_check()
        if not isinstance(value, InternetQualityReport):
            self.host._on_quality_failed("Модуль качества вернул неизвестный результат")
            return
        self.host._quality_report = value
        speed = value.speedtest
        network = value.network
        local = value.local
        self.host.event_bus.history_update_requested.emit(
            "Качество интернета",
            {
                "download_mbps": speed.download_mbps,
                "upload_mbps": speed.upload_mbps,
                "ping_ms": speed.ping_ms,
            },
        )
        self.host.quality_workspace.quality_metrics["download"].set_metric(
            _speed(speed.download_mbps),
            self.host._tr("HTTP CDN, 10 МБ"),
            "good" if speed.download_mbps is not None else "neutral",
        )
        upload_value = (
            _speed(speed.upload_mbps)
            if speed.upload_mbps is not None
            else self.host._tr("Не измерена")
        )
        self.host.quality_workspace.quality_metrics["upload"].set_metric(
            upload_value,
            self.host._tr("HTTP POST, 5 МБ"),
            "good" if speed.upload_mbps is not None else "neutral",
        )
        self.host.quality_workspace.quality_metrics["ping"].set_metric(
            _latency(speed.ping_ms),
            speed.server_name or self.host._tr("TCP DNS"),
            "good" if speed.ping_ms is not None else "neutral",
        )
        loaded_ping_value = (
            _latency(speed.loaded_ping_ms)
            if speed.loaded_ping_ms is not None
            else self.host._tr("Не измерен")
        )
        self.host.quality_workspace.quality_metrics["loaded_ping"].set_metric(
            loaded_ping_value,
            self.host._tr("TCP DNS во время отдачи"),
            "good" if speed.loaded_ping_ms is not None else "neutral",
        )
        self.host.quality_workspace.quality_details["ipv4"].setText(network.ipv4 or "не определён")
        self.host.quality_workspace.quality_details["ipv6"].setText(network.ipv6 or "не определён")
        self.host.quality_workspace.quality_details["local_ip"].setText(
            ", ".join(local.local_ipv4 + local.local_ipv6) or "не определён"
        )
        self.host.quality_workspace.quality_details["local_ip"].setToolTip(
            local.local_ip_tooltip or ""
        )
        self.host.quality_workspace.quality_details["isp"].setText(network.isp or "не определён")
        self.host.quality_workspace.quality_details["location"].setText(
            ", ".join((value for value in (network.city, network.region) if value))
            or "не определён"
        )
        if (
            local.vpn_detected
            or local.proxy_detected
            or network.vpn_detected is True
            or (network.proxy_detected is True)
        ):
            vpn_proxy = "обнаружен"
        elif network.vpn_detected is False and network.proxy_detected is False:
            vpn_proxy = "не обнаружен"
        else:
            vpn_proxy = "не определён"
        self.host.quality_workspace.quality_details["vpn_proxy"].setText(vpn_proxy)
        adapter_speed = (
            f"{local.adapter_speed_mbps} Мбит/с"
            if local.adapter_speed_mbps is not None
            else "скорость не определена"
        )
        self.host.quality_workspace.quality_details["adapter"].setText(
            f"{local.adapter_name or 'не определён'} · {adapter_speed}"
        )
        self.host.quality_workspace.quality_report_output.setPlainText(
            build_smart_report(value, self.host._tr)
        )
        if value.errors:
            self.host.quality_workspace.quality_status.setText(
                self.host._tr(speed.error)
                if speed.error
                else self.host._tr("Проверка завершена частично: часть источников недоступна")
            )
            self.host._set_status("PARTIAL", "warning")
            for error in value.errors:
                self.host._append_log(f"Качество: {error}")
        else:
            self.host.quality_workspace.quality_status.setText(
                self.host._tr("Проверка качества завершена · Geo API: {source}").format(
                    source=network.source
                )
            )
            self.host._set_status("QUALITY READY", "success")
        self.host._append_log("Проверка качества интернета завершена")

    def _on_quality_failed(self, message: str) -> None:
        self.host._finish_quality_check()
        self.host.quality_workspace.quality_status.setText(self.host._tr(message))
        self.host._set_status("QUALITY ERROR", "error")
        self.host._append_log(f"Ошибка качества: {message}")

    def _on_nat_probe_completed(self, value: object) -> None:
        if not isinstance(value, NatReport):
            self.host._on_nat_probe_failed("STUN-проверка вернула неизвестный результат")
            return
        self.host._nat_report = value
        endpoints = [endpoint.display for endpoint in value.mapped_endpoints]
        if value.status in {"udp_blocked", "no_servers"}:
            self.host.quality_workspace.nat_probe_status.setText(
                "UDP не получил ответа от STUN-серверов"
                if value.status == "udp_blocked"
                else "STUN-серверы недоступны"
            )
            self.host._record_journal_event(
                "nat.probe_failed",
                severity="warning",
                subject="NAT/STUN",
                template="NAT/STUN: {reason}",
                values={"reason": value.status},
            )
        else:
            flags = []
            if value.cgnat_likely:
                flags.append("возможен CGNAT")
            if value.double_nat_likely:
                flags.append("возможен Double NAT")
            if value.udp_egress_differs:
                flags.append("UDP egress отличается от внешнего IP")
            suffix = f" · {', '.join(flags)}" if flags else ""
            self.host.quality_workspace.nat_probe_status.setText(
                f"NAT: {value.nat_type or self.host._tr('Не определён')} ({self.host._tr(nat_description(value.nat_type))}) · filtering: {value.filtering}\n{'; '.join(endpoints)}{suffix}"
            )
            self.host._record_journal_event(
                "nat.measured",
                subject="NAT/STUN",
                template="NAT/STUN endpoints: {endpoints}",
                values={"endpoints": "; ".join(endpoints) or "—"},
            )
            self.host._record_journal_event(
                "nat.inferred",
                severity="warning" if value.nat_type == "apdm" else "info",
                subject="NAT/STUN",
                template="NAT: {nat_type}",
                values={
                    "nat_type": value.nat_type,
                    "filtering": value.filtering,
                    "cgnat_likely": value.cgnat_likely,
                    "double_nat_likely": value.double_nat_likely,
                    "udp_egress_differs": value.udp_egress_differs,
                },
            )
        if self.host._report is not None:
            self.host.overview_controller._update_root_cause_analysis(self.host._report)
        self.host._append_log(f"NAT/STUN: {value.status}")

    def _on_nat_probe_failed(self, message: str) -> None:
        self.host._nat_report = None
        self.host.quality_workspace.nat_probe_status.setText(message)
        self.host._record_journal_event(
            "nat.probe_failed",
            severity="warning",
            subject="NAT/STUN",
            template="NAT/STUN: {reason}",
            values={"reason": message},
        )
        self.host._append_log(message)
        if self.host._report is not None:
            self.host.overview_controller._update_root_cause_analysis(self.host._report)

    def _on_dashboard_local_snapshot(self, value: object) -> None:
        if not self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_topology_label
        ):
            return
        if not isinstance(value, SystemSnapshot):
            self.host.core_workspace.dashboard_topology_label.setText(
                self.host._tr("Локальные сетевые данные пока недоступны")
            )
            self.host._dashboard_append_event(
                self.host._tr("Не удалось получить локальные данные интерфейса")
            )
            return
        local_ip = self.host._first_local_ip(value)
        gateway = value.gateway.address if value.gateway is not None else "шлюз не определён"
        dns = ", ".join(value.dns_servers) or "DNS не определены"
        self.host.core_workspace.dashboard_topology_label.setText(
            self.host._tr("[Ваш ПК: {local_ip}]  →  [Шлюз: {gateway}]  →  [Цель: ожидание]").format(
                local_ip=local_ip, gateway=gateway
            )
        )
        self.host.core_workspace.dashboard_topology_label.setToolTip(
            self.host._tr("Системные DNS: {dns}").format(dns=dns)
        )
        self.host._dashboard_append_event(
            self.host._tr("Локальный интерфейс: {local_ip}; DNS: {dns}").format(
                local_ip=local_ip, dns=dns
            )
        )

    def _on_endpoint_chosen(self, value: object) -> None:
        if isinstance(value, EndpointChoice):
            connection = value.connection
            if (
                connection.remote_address
                and connection.remote_port > 0
                and is_public_address(connection.remote_address)
            ):
                self.host.core_workspace.target_input.setText(connection.remote_address)
                self.host.core_workspace.port_input.setValue(connection.remote_port)
                if not self.host._ping_mtu_host_manually_edited:
                    self.host.mtu_workspace.ping_mtu_host_input.setText(connection.remote_address)
                self.host._publish_monitor_scope()
            self.host._record_endpoint_choice(value)
        if not isinstance(value, EndpointChoice) or not self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_target_input,
            self.host.core_workspace.dashboard_port_input,
        ):
            return
        connection = value.connection
        self.host._dashboard_game_connection = connection
        self.host._dashboard_game_metrics = None
        self.host.core_workspace.target_input.setText(connection.remote_address)
        self.host.core_workspace.port_input.setValue(connection.remote_port)
        self.host._selected_connection = connection
        self.host.ping_controller._start_latency_monitor(
            connection.remote_address, connection.remote_port, protocol=connection.protocol
        )
        self.host._dashboard_sync_controls()
        self.host._dashboard_render_regions()
        self.host._dashboard_append_event(
            f"Автопроверка игры: выбран {connection.remote_endpoint} ({value.rule})"
        )

    def _on_completed(self, report: object) -> None:
        if isinstance(report, DiagnosticReport):
            current_scope = Scope.of(
                self.host.core_workspace.target_input.text(),
                self.host.core_workspace.port_input.value(),
            )
            if judgement.is_stale(report, self.host._run_scope, current_scope):
                self.host._set_running(False)
                self.host._set_status("READY", "idle")
                self.host.overview_controller._set_header_anomaly(
                    "warning", "Результат устарел: цель изменена"
                )
                self.host._append_log(
                    "Результат диагностики отброшен: цель изменена во время проверки"
                )
                return
        self.host._inherited__on_completed(report)
        if isinstance(report, DiagnosticReport) and self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_status_pill,
            self.host.region_card.dashboard_region_table,
        ):
            self.host.overview_controller._dashboard_apply_report(report)
            self.host.core_workspace.dashboard_export_button.setEnabled(True)
            self.host.core_workspace.dashboard_support_button.setEnabled(True)
            self.host._dashboard_probe_regions_once()

    def _reset_results(self, target: object) -> None:
        self.host._inherited__reset_results(target)
        if self.host._dashboard_ready:
            self.host.core_workspace.dashboard_export_button.setEnabled(False)
            self.host.core_workspace.dashboard_support_button.setEnabled(False)

    def _on_failed(self, failure: object) -> None:
        self.host._inherited__on_failed(failure)
        if self.host._dashboard_ready and self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_status_pill
        ):
            self.host.overview_controller._dashboard_apply_health("error", "Ошибка диагностики")
            self.host.core_workspace.dashboard_support_button.setEnabled(True)

    def _export_support_bundle(self) -> None:
        options = self.host._support_bundle_options()
        if options is None:
            return
        redact, sections = options
        target_host = (
            self.host._report.target.host
            if self.host._report is not None
            else self.host.core_workspace.target_input.text()
        )
        target_slug = re.sub("[^A-Za-z0-9._-]", "_", target_host) or "diagnostic_failure"
        suggested_name = f"NetVision_Support_{target_slug}_{datetime.now():%Y%m%d_%H%M%S}.json"
        path, _filter = QFileDialog.getSaveFileName(
            self.host,
            "Экспорт пакета для техподдержки",
            str(Path.home() / suggested_name),
            "JSON (*.json)",
        )
        if not path:
            return
        if not path.lower().endswith(".json"):
            path += ".json"
        payload = serialize_support_bundle(
            self.host._report,
            journal=self.host._journal,
            thresholds=self.host._thresholds,
            measurements=self.host._support_bundle_measurements(),
            process=self.host._selected_process,
            endpoints=(self.host._selected_connection,) if self.host._selected_connection else (),
            history=self.host._test_history_store.load(),
            sections=sections,
            redact=redact,
            max_events=self.host._thresholds.export_max_events,
        ).encode("utf-8")
        if self.host._write_export_payload(path, payload):
            self.host._record_journal_event(
                "export.created",
                subject="support_bundle",
                template="Создан пакет техподдержки: {filename}",
                values={
                    "filename": Path(path).name,
                    "redacted": redact,
                    "sections": sorted(sections),
                    "size_bytes": len(payload),
                },
            )
            self.host._append_log(f"Пакет для техподдержки сохранён: {Path(path).name}")

    def _support_bundle_options(self) -> tuple[bool, tuple[str, ...]] | None:
        dialog = QDialog(self.host)
        dialog.setWindowTitle("Пакет для техподдержки")
        dialog.setModal(True)
        dialog.setMinimumWidth(360)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        description = QLabel(
            "Будут включены выбранные диагностические данные. Сырой трафик и командные строки процессов не экспортируются."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        section_labels = ui_constants.DASHBOARD_EXPORT_SECTION_LABELS
        section_checks: list[tuple[str, QCheckBox]] = []
        for name, label in section_labels:
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            layout.addWidget(checkbox)
            section_checks.append((name, checkbox))
        redact_checkbox = QCheckBox("Скрыть личные данные (IP, MAC, Hostname, SSID)")
        redact_checkbox.setChecked(True)
        layout.addWidget(redact_checkbox)
        actions = QHBoxLayout()
        actions.addStretch(1)
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(dialog.reject)
        create = QPushButton("Создать пакет")
        create.setObjectName("PrimaryButton")
        create.clicked.connect(dialog.accept)
        actions.addWidget(cancel)
        actions.addWidget(create)
        layout.addLayout(actions)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        sections = tuple((name for name, checkbox in section_checks if checkbox.isChecked()))
        return (redact_checkbox.isChecked(), sections)

    def _start_network_boost_termination(self, value: object) -> None:
        if (
            self.host._network_boost_terminate_thread
            and self.host._network_boost_terminate_thread.isRunning()
        ):
            return
        if not isinstance(value, tuple) or not all(
            (isinstance(item, BackgroundTrafficCandidate) for item in value)
        ):
            self.host._set_network_boost_status(
                "Network Boost: не удалось проверить выбранные процессы"
            )
            return
        self.host._record_journal_event(
            "action.network_boost",
            subject="network-boost",
            template="Network Boost: выбрано процессов: {count}",
            values={"count": len(value)},
            refs={"pids": [item.pid for item in value]},
        )
        dialog = self.host._network_boost_dialog
        if dialog is not None:
            dialog.set_busy(True)
        self.host._set_network_boost_controls(True)
        self.host._set_network_boost_status(
            self.host._tr("Завершаем выбранные процессы в фоновом потоке...")
        )
        thread = QThread(self.host)
        worker = NetworkBoostTerminateWorker(value)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self.host._queue_ui_slot(self.host._on_network_boost_terminated))
        worker.completed.connect(thread.quit)
        self.host._worker_registry.retain(thread, worker)
        thread.finished.connect(self.host._clear_network_boost_terminate_worker)
        self.host._network_boost_terminate_thread = thread
        self.host._network_boost_terminate_worker = worker
        thread.start()
