"""LossController for diagnostics."""

from PySide6.QtCore import QObject, QThread, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem

from netvision.core.session import StateStore
from netvision.core.target import parse_target
from netvision.core.packet_loss import HopLossResult, StressTestResult
from netvision.core.udp_stress import UdpStressReport
from netvision.models import HopResult
from netvision.ui.legacy_workers import PacketLossTestWorker, UdpStressWorker
from netvision.ui.monitor_workers import WorkerRegistry
from netvision.ui.utils import _ms


from netvision.ui.workspaces.loss_audit import LossWorkspace


class LossController(QObject):
    def __init__(
        self, workspace: LossWorkspace, facts: StateStore, registry: WorkerRegistry, parent: QObject
    ) -> None:
        super().__init__(parent)
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        self.registry = registry
        workspace.loss_run_button.clicked.connect(self.start_packet_loss_analysis)
        workspace.udp_stress_button.clicked.connect(self.start_udp_packet_loss_stress)

    @Slot()
    def start_packet_loss_analysis(self) -> None:
        if self.host._loss_test_thread and self.host._loss_test_thread.isRunning():
            return
        try:
            target = parse_target(
                self.workspace.loss_target_input.text(), self.workspace.loss_port_input.value()
            )
        except ValueError as exc:
            self.workspace.loss_detector_status.setText(str(exc))
            return
        hops = self.host._report.hops if self.host._report is not None else ()
        self.host._set_task_button_busy(self.workspace.loss_run_button, True, "Проверка")
        self._render_loss_stress_placeholders("Выполняется тест...")
        if hops:
            self._render_loss_hops_placeholders(hops, "Проверяем ICMP каждого hop...")
        else:
            self.workspace.loss_hops_table.setRowCount(0)
            self.workspace.loss_hops_status.setText(
                "Трассировка ещё не получена: выполнен только стресс-тест цели."
            )
        self.workspace.loss_detector_status.setText(
            self.host._tr("Выполняются ICMP/UDP стресс-тесты в фоновом потоке...")
        )
        thread = QThread(self.host)
        worker = PacketLossTestWorker(hops, target.host, target.port)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_packet_loss_analysis_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_packet_loss_analysis_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_packet_loss_worker)
        self.host._loss_test_thread = thread
        self.host._loss_test_worker = worker
        thread.start()

    @Slot()
    def start_udp_packet_loss_stress(self) -> None:
        if self.host._udp_stress_thread and self.host._udp_stress_thread.isRunning():
            return
        host = self.workspace.udp_stress_target_input.text().strip()
        port = self.workspace.udp_stress_port_input.value()
        if not host:
            self.workspace.udp_stress_status.setText(self.host._tr("UDP: выберите адрес DNS"))
            return
        self.host._set_task_button_busy(
            self.workspace.udp_stress_button, True, "UDP стресс выполняется..."
        )
        self.workspace.udp_stress_progress.setVisible(True)
        self.workspace.udp_stress_status.setText(self.host._tr("UDP стресс выполняется..."))
        self.workspace.udp_stress_sent_value.setText("--")
        self.workspace.udp_stress_received_value.setText("--")
        self.workspace.udp_stress_loss_value.setText("--")
        thread = QThread(self.host)
        worker = UdpStressWorker(host, port)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_udp_packet_loss_stress_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_udp_packet_loss_stress_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_udp_packet_loss_worker)
        self.host._udp_stress_thread = thread
        self.host._udp_stress_worker = worker
        thread.start()

    @Slot(object, object, object)
    def _on_packet_loss_analysis_completed(
        self,
        hop_value: object,
        icmp_value: object,
        udp_value: object,
    ) -> None:
        self.host._set_task_button_busy(self.workspace.loss_run_button, False)
        if not isinstance(hop_value, tuple) or not all(
            isinstance(item, HopLossResult) for item in hop_value
        ):
            self._on_packet_loss_analysis_failed("Hop-анализ вернул некорректный результат")
            return
        if not isinstance(icmp_value, StressTestResult) or not isinstance(
            udp_value, StressTestResult
        ):
            self._on_packet_loss_analysis_failed("Стресс-тест вернул некорректный результат")
            return
        self.facts.set("loss.analysis", (hop_value, icmp_value, udp_value))
        if hop_value:
            self._render_loss_hop_results(hop_value)
        self._render_loss_stress_results((icmp_value, udp_value))
        self.workspace.loss_detector_status.setText(
            self.host._tr(
                "Фоновый анализ потерь завершён. Live-монитор продолжает сбор burst-событий."
            )
        )

    @Slot(str)
    def _on_packet_loss_analysis_failed(self, message: str) -> None:
        self.host._set_task_button_busy(self.workspace.loss_run_button, False)
        self.workspace.loss_detector_status.setText(message)

    @Slot(object)
    def _on_udp_packet_loss_stress_completed(self, value: object) -> None:
        self.host._set_task_button_busy(self.workspace.udp_stress_button, False)
        self.workspace.udp_stress_progress.setVisible(False)
        if not isinstance(value, UdpStressReport):
            self._on_udp_packet_loss_stress_failed("UDP-тест вернул некорректный результат")
            return
        self.facts.set("loss.udp_stress", value)
        self.workspace.udp_stress_sent_value.setText(str(value.sent))
        self.workspace.udp_stress_received_value.setText(str(value.received))
        self.workspace.udp_stress_loss_value.setText(f"{value.loss_percent:.1f}%")
        status = self.host._tr(value.status)
        if value.average_ms is not None:
            status = f"{status} · RTT {value.average_ms:.1f} ms"
        self.workspace.udp_stress_status.setText(status)
        self.workspace.udp_stress_status.setToolTip(value.error or value.target)
        self._render_udp_stress_result(value)

    @Slot(str)
    def _on_udp_packet_loss_stress_failed(self, message: str) -> None:
        self.host._set_task_button_busy(self.workspace.udp_stress_button, False)
        self.workspace.udp_stress_progress.setVisible(False)
        self.workspace.udp_stress_status.setText(
            self.host._tr("UDP-тест недоступен: {error}").format(error=message)
        )

    @Slot()
    def _clear_packet_loss_worker(self) -> None:
        if self.sender() is not self.host._loss_test_thread:
            return
        self.host._loss_test_thread = None
        self.host._loss_test_worker = None

    @Slot()
    def _clear_udp_packet_loss_worker(self) -> None:
        if self.sender() is not self.host._udp_stress_thread:
            return
        self.host._udp_stress_thread = None
        self.host._udp_stress_worker = None

    def _render_loss_stress_placeholders(self, status: str = "Готов к тесту") -> None:
        self.workspace.loss_stress_table.setRowCount(2)
        for row, protocol in enumerate(("ICMP", "UDP")):
            for column, value in enumerate((protocol, "10", "--", "--", status)):
                self.workspace.loss_stress_table.setItem(row, column, QTableWidgetItem(value))

    def _render_loss_hops_placeholders(self, hops: tuple[HopResult, ...], status: str) -> None:
        self.workspace.loss_hops_table.setRowCount(len(hops))
        for row, hop in enumerate(hops):
            values = [
                f"{hop.index:02}",
                hop.address or "--",
                "--",
                "--",
                _ms(hop.latency_ms),
                status,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if hop.timed_out:
                    item.setForeground(QColor("#FFB800"))
                self.workspace.loss_hops_table.setItem(row, column, item)

    def _render_loss_hop_results(self, results: tuple[HopLossResult, ...]) -> None:
        self.workspace.loss_hops_table.setRowCount(len(results))
        first_loss_hop = next(
            (result for result in results if (result.loss_percent or 0) > 0), None
        )
        for row, result in enumerate(results):
            loss = "--" if result.loss_percent is None else f"{result.loss_percent:.0f}%"
            values = [
                f"{result.hop:02}",
                result.address or "Адрес не определён",
                f"{result.received}/{result.sent}" if result.sent else "--",
                loss,
                _ms(result.average_ms),
                result.status,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(result.error or value)
                if result.loss_percent is not None and result.sent > 0 and result.received == 0:
                    item.setForeground(QColor("#FF6B78"))
                elif result.loss_percent and result.loss_percent > 0:
                    item.setForeground(QColor("#FFB800"))
                elif result.loss_percent == 0:
                    item.setForeground(QColor("#00E5A3"))
                self.workspace.loss_hops_table.setItem(row, column, item)
        if first_loss_hop is None:
            self.workspace.loss_hops_status.setText(
                self.host._tr("Потерь ICMP в ответах hop не обнаружено.")
            )
        else:
            self.workspace.loss_hops_status.setText(
                f"Первый hop с потерями: {first_loss_hop.hop:02} · {first_loss_hop.address or 'адрес не определён'} · "
                f"{first_loss_hop.loss_percent:.0f}%"
            )

    def _render_loss_stress_results(self, results: tuple[StressTestResult, ...]) -> None:
        self.workspace.loss_stress_table.setRowCount(len(results))
        for row, result in enumerate(results):
            loss = (
                "не подтверждается"
                if result.loss_percent is None
                else f"{result.loss_percent:.0f}%"
            )
            status = result.status if not result.note else f"{result.status} · см. подсказку"
            values = [
                result.protocol,
                str(result.sent),
                str(result.received),
                loss,
                status,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(result.error or result.note or value)
                if result.protocol == "ICMP" and result.loss_percent == 0:
                    item.setForeground(QColor("#00E5A3"))
                elif result.protocol == "ICMP" and (result.loss_percent or 0) > 0:
                    item.setForeground(QColor("#FFB800" if result.received else "#FF6B78"))
                self.workspace.loss_stress_table.setItem(row, column, item)

    def _render_udp_stress_result(self, result: UdpStressReport) -> None:
        row = next(
            (
                index
                for index in range(self.workspace.loss_stress_table.rowCount())
                if self.workspace.loss_stress_table.item(index, 0)
                and self.workspace.loss_stress_table.item(index, 0).text() == "UDP"
            ),
            None,
        )
        if row is None:
            row = self.workspace.loss_stress_table.rowCount()
            self.workspace.loss_stress_table.insertRow(row)
        values = (
            "UDP",
            str(result.sent),
            str(result.received),
            f"{result.loss_percent:.1f}%",
            self.host._tr(result.status),
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(result.error or result.target)
            if result.loss_percent == 0:
                item.setForeground(QColor("#00E5A3"))
            elif result.loss_percent >= 3:
                item.setForeground(QColor("#FF6B78"))
            else:
                item.setForeground(QColor("#FFB800"))
            self.workspace.loss_stress_table.setItem(row, column, item)
