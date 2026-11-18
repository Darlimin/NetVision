"""Dashboard history orchestration."""

from __future__ import annotations
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import QObject, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFileDialog, QMessageBox, QTableWidgetItem
from netvision.core.bufferbloat import BufferbloatReport
from netvision.core.session_journal import JournalEvent
from netvision.core.session_journal import Layer
from netvision.reporting import (
    serialize_journal_csv,
    serialize_journal_json,
    serialize_udp_events_csv,
    serialize_udp_events_json,
)
from netvision.ui.utils import _udp_event_color, _journal_event_color

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSizePolicy, QSplitter, QVBoxLayout, QWidget
from netvision.ui import constants as ui_constants


class HistoryController(QObject):
    def __init__(self, workspace, facts, parent):
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts

    @Slot(str, str)
    def handle_log_requested(self, message: str, _level: str) -> None:
        self.host._append_log(message)

    @Slot(str, dict)
    def handle_journal_requested(self, kind: str, values: dict) -> None:
        self._record_journal_event(kind, **values)

    @Slot(str, dict)
    def handle_history_requested(self, test_type: str, values: dict) -> None:
        self._record_test_history(test_type, **values)

    def _render_journal(self) -> None:

        if not hasattr(self.host.journal_workspace, "journal_table"):

            return

        events = self.host._journal_events_for_view()

        self.host.journal_workspace.journal_table.setHorizontalHeaderLabels(
            [self.host._tr(text) for text in ("Время", "Слой", "Тип", "Объект", "Подробности")]
        )

        self.host.journal_workspace.journal_table.setRowCount(len(events))

        for row_index, event in enumerate(reversed(events)):

            try:

                details = self.host._translator.format(event.template, **event.values)

            except (KeyError, ValueError):

                details = event.template

            values = (
                event.at.astimezone().strftime("%H:%M:%S"),
                self.host._journal_layer_label(event.layer),
                event.kind,
                event.subject or "--",
                details,
            )

            color = _journal_event_color(event.severity)

            for column, value in enumerate(values):

                item = QTableWidgetItem(value)

                item.setToolTip(value)

                item.setForeground(color)

                self.host.journal_workspace.journal_table.setItem(row_index, column, item)

        count = len(events)

        self.host.journal_workspace.journal_status.setText(
            self.host._translator.format("Событий в журнале: {count}", count=count)
            if count
            else self.host._tr("Журнал текущей сессии пока пуст")
        )

        self.host.journal_workspace.export_journal_json_button.setEnabled(bool(events))

        self.host.journal_workspace.export_journal_csv_button.setEnabled(bool(events))

    def _retranslate_journal_filter(self) -> None:

        selected = self.host.journal_workspace.journal_layer_filter.currentData()

        self.host.journal_workspace.journal_layer_filter.blockSignals(True)

        self.host.journal_workspace.journal_layer_filter.clear()

        self.host.journal_workspace.journal_layer_filter.addItem(self.host._tr("Все слои"), None)

        for layer in Layer:

            self.host.journal_workspace.journal_layer_filter.addItem(
                self.host._journal_layer_label(layer), layer.value
            )

        index = self.host.journal_workspace.journal_layer_filter.findData(selected)

        self.host.journal_workspace.journal_layer_filter.setCurrentIndex(index if index >= 0 else 0)

        self.host.journal_workspace.journal_layer_filter.blockSignals(False)

    def _journal_layer_label(self, layer: Layer) -> str:

        sources = {
            Layer.MEASUREMENT: "Измерение",
            Layer.INFERENCE: "Вывод",
            Layer.ACTION: "Действие",
        }

        return self.host._tr(sources[layer])

    def _journal_events_for_view(self) -> list[JournalEvent]:

        include_past = self.host.journal_workspace.journal_include_past_sessions.isChecked()

        events = self.host._journal.events(include_past_sessions=include_past)

        selected_layer = self.host.journal_workspace.journal_layer_filter.currentData()

        if isinstance(selected_layer, str):

            events = [event for event in events if event.layer.value == selected_layer]

        return events

    def _clear_journal(self) -> None:

        self.host._journal_store.clear(session=self.host._journal.session)

        self.host._render_journal()

    def _export_journal(self, file_format: str) -> None:

        events = self.host._journal_events_for_view()

        if not events:

            return

        if file_format not in {"json", "csv"}:

            raise ValueError(f"Unsupported journal export format: {file_format}")

        suggested_name = f"NetVision_Journal_{datetime.now():%Y%m%d_%H%M%S}.{file_format}"

        filter_text = "JSON (*.json)" if file_format == "json" else "CSV (*.csv)"

        path, _filter = QFileDialog.getSaveFileName(
            self.host,
            self.host._tr("Экспорт журнала"),
            str(Path.home() / suggested_name),
            filter_text,
        )

        if not path:

            return

        suffix = f".{file_format}"

        if not path.lower().endswith(suffix):

            path += suffix

        payload = (
            serialize_journal_json(events)
            if file_format == "json"
            else serialize_journal_csv(events)
        ).encode("utf-8")

        if self.host._write_export_payload(path, payload):

            self.event_bus.log_requested.emit(
                self.host._translator.format(
                    "Журнал сохранён в {format}: {path}", format=file_format.upper(), path=path
                ),
                "INFO",
            )

    def _clear_udp_event_table(self) -> None:

        self.host._udp_event_rows.clear()

        if hasattr(self.host.udp_history_workspace, "udp_events_table"):

            self.host.udp_history_workspace.udp_events_table.setRowCount(0)

            self.host.udp_history_workspace.udp_event_status.setText(
                self.host._tr("UDP-события появятся после изменения портов")
            )

            self.host.udp_history_workspace.export_udp_json_button.setEnabled(False)

            self.host.udp_history_workspace.export_udp_csv_button.setEnabled(False)

    def _record_journal_event(
        self,
        kind: str,
        *,
        severity: str = "info",
        subject: str = "",
        template: str = "",
        values: dict[str, object] | None = None,
        refs: dict[str, object] | None = None,
        at: datetime | None = None,
    ) -> JournalEvent:

        event = self.host._journal.record(
            kind,
            severity=severity,
            subject=subject,
            template=template,
            values=values,
            refs=refs,
            at=at,
        )

        if hasattr(self.host.journal_workspace, "journal_table"):

            self.host._render_journal()

        self.event_bus.anomaly_detected.emit(event)

        return event

    def _refresh_udp_event_table(self) -> None:

        anomalies_only = self.host.udp_history_workspace.udp_anomaly_filter.isChecked()

        visible_rows = [
            row for row in self.host._udp_event_rows if not anomalies_only or row.is_anomaly
        ]

        self.host.udp_history_workspace.udp_events_table.setRowCount(len(visible_rows))

        for row_index, event in enumerate(visible_rows):

            timestamp = event.observed_at.astimezone().strftime("%H:%M:%S")

            values = (
                timestamp,
                event.event_type,
                str(event.port) if event.port else "--",
                event.details,
            )

            color = _udp_event_color(event)

            for column, value in enumerate(values):

                item = QTableWidgetItem(value)

                item.setToolTip(value)

                item.setForeground(color)

                self.host.udp_history_workspace.udp_events_table.setItem(row_index, column, item)

        total = len(self.host._udp_event_rows)

        if total == 0:

            self.host.udp_history_workspace.udp_event_status.setText(
                self.host._tr("UDP-события появятся после изменения портов")
            )

        elif anomalies_only:

            self.host.udp_history_workspace.udp_event_status.setText(
                self.host._translator.format(
                    "Показано аномалий: {visible} из {total} событий",
                    visible=len(visible_rows),
                    total=total,
                )
            )

        else:

            self.host.udp_history_workspace.udp_event_status.setText(
                self.host._translator.format("Событий UDP: {total}", total=total)
            )

    def _refresh_history_view(self) -> None:

        self.host._test_history_records = self.host._test_history_store.load()

        self.host.history_workspace.history_table.setRowCount(len(self.host._test_history_records))

        for row, record in enumerate(reversed(self.host._test_history_records)):

            test_type = str(record.get("test_type") or "Неизвестный тест")

            values = (
                str(record.get("timestamp") or "--").replace("T", " "),
                self.host._tr(test_type),
                self.host._format_history_metric(record.get("download_mbps"), "Мбит/с"),
                self.host._format_history_metric(record.get("upload_mbps"), "Мбит/с"),
                self.host._format_history_metric(record.get("ping_ms"), "мс"),
                str(record.get("bufferbloat_grade") or "--"),
            )

            for column, value in enumerate(values):

                item = QTableWidgetItem(value)

                item.setToolTip(value)

                if column == 5 and value in {"A+", "A"}:

                    item.setForeground(QColor("#00E5A3"))

                self.host.history_workspace.history_table.setItem(row, column, item)

        count = len(self.host._test_history_records)

        self.host.history_workspace.history_summary.setText(
            self.host._translator.format("Сохранено тестов: {count}", count=count)
            if count
            else self.host._tr("История тестов пока пуста")
        )

        quality_records = [
            record
            for record in self.host._test_history_records
            if record.get("test_type") == "Качество интернета"
        ]

        if len(quality_records) < 2:

            self.host.history_workspace.history_trend.setText(
                self.host._tr("Для тренда нужны минимум два теста качества.")
            )

            return

        latest, previous = (quality_records[-1], quality_records[-2])

        self.host.history_workspace.history_trend.setText(
            self.host._translator.format(
                "Динамика качества: ping {ping_delta} · download {download_delta}",
                ping_delta=self.host._history_delta(
                    latest.get("ping_ms"), previous.get("ping_ms"), "мс"
                ),
                download_delta=self.host._history_delta(
                    latest.get("download_mbps"), previous.get("download_mbps"), "Мбит/с"
                ),
            )
        )

    def _clear_test_history(self) -> None:

        answer = QMessageBox.question(
            self.host,
            self.host._tr("Очистить историю"),
            self.host._tr("Удалить все сохранённые результаты тестов?"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:

            return

        try:

            self.host._test_history_store.clear()

        except OSError as exc:

            QMessageBox.critical(
                self.host,
                self.host._tr("История тестов"),
                self.host._translator.format("Не удалось очистить историю: {error}", error=exc),
            )

            return

        self.host._test_history_records = []

        self.host._refresh_history_view()

    def _export_udp_events_json(self) -> None:

        self.host._export_udp_events("json")

    def _export_udp_events_csv(self) -> None:

        self.host._export_udp_events("csv")

    def _export_udp_events(self, file_format: str) -> None:

        if not self.host._udp_event_rows:

            return

        if file_format not in {"json", "csv"}:

            raise ValueError(f"Unsupported UDP export format: {file_format}")

        suggested_name = f"NetVision_UDP_{datetime.now():%Y%m%d_%H%M%S}.{file_format}"

        filter_text = "JSON (*.json)" if file_format == "json" else "CSV (*.csv)"

        path, _filter = QFileDialog.getSaveFileName(
            self.host, "Экспорт UDP-событий", str(Path.home() / suggested_name), filter_text
        )

        if not path:

            return

        suffix = f".{file_format}"

        if not path.lower().endswith(suffix):

            path += suffix

        payload = (
            serialize_udp_events_json(self.host._udp_event_rows)
            if file_format == "json"
            else serialize_udp_events_csv(self.host._udp_event_rows)
        ).encode("utf-8")

        if self.host._write_export_payload(path, payload):

            self.event_bus.log_requested.emit(
                f"UDP-события сохранены в {file_format.upper()}: {path}", "INFO"
            )

    def _record_bufferbloat_journal(self, report: BufferbloatReport, attribution: str) -> None:

        phases = (
            ("unloaded", report.unloaded),
            ("download", report.download_active),
            ("upload", report.upload_active),
        )

        for phase_name, phase in phases:

            for series in phase.series:

                self.event_bus.journal_event_requested.emit(
                    "bufferbloat.measured",
                    {
                        "subject": series.name,
                        "template": "Bufferbloat {phase}/{series}: p50 {p50} мс, p95 {p95} мс",
                        "values": {
                            "phase": phase_name,
                            "series": series.name,
                            "p50": series.p50_ms,
                            "p95": series.p95_ms,
                            "max": series.max_ms,
                            "samples": series.samples,
                            "mbps": phase.speed_mbps,
                        },
                    },
                )

        self.event_bus.journal_event_requested.emit(
            "bufferbloat.verdict",
            {
                "severity": "warning" if report.grade in {"C", "D", "F"} else "info",
                "subject": report.target_ip or "1.1.1.1",
                "template": "Bufferbloat: {grade}; {attribution}",
                "values": {
                    "grade": report.grade,
                    "attribution": attribution,
                    "download_delta": report.download_active.delta_ms,
                    "upload_delta": report.upload_active.delta_ms,
                    "target_delta": report.target_delta_ms,
                    "gateway_delta": report.gateway_delta_ms,
                },
            },
        )

    def _record_test_history(
        self,
        test_type: str,
        *,
        download_mbps: float | None = None,
        upload_mbps: float | None = None,
        ping_ms: float | None = None,
        bufferbloat_grade: str | None = None,
    ) -> None:

        try:

            self.host._test_history_store.append(
                test_type,
                download_mbps=download_mbps,
                upload_mbps=upload_mbps,
                ping_ms=ping_ms,
                bufferbloat_grade=bufferbloat_grade,
            )

        except (OSError, TypeError, ValueError) as exc:

            self.event_bus.log_requested.emit(f"История тестов не сохранена: {exc}", "INFO")

            return

        self.host._test_history_records = self.host._test_history_store.load()

        if hasattr(self.host.history_workspace, "history_table"):

            self.host._refresh_history_view()

    def _restore_route_map(self) -> None:
        """Place the existing animated topology map beside the route tables."""
        path_tab = self.host.workspace_tabs.widget(ui_constants.WORKSPACE_TABS["routes"])
        topology_scroll = getattr(
            getattr(self.host, "core_workspace", None), "topology_scroll", None
        )
        if path_tab is None or topology_scroll is None or path_tab.layout() is None:
            return
        path_layout = path_tab.layout()
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        while path_layout.count():
            item = path_layout.takeAt(0)
            widget = item.widget()
            nested_layout = item.layout()
            if widget is not None:
                stretch = 2 if widget is getattr(self.host.path_workspace, "geo_table", None) else 1
                right_layout.addWidget(widget, stretch)
            elif nested_layout is not None:
                right_layout.addLayout(nested_layout)
        topology_scroll.setParent(None)
        left_panel = QWidget()
        left_panel.setMinimumWidth(260)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(topology_scroll, 1)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("RouteWorkspaceSplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 45)
        splitter.setStretchFactor(1, 55)
        splitter.setSizes([450, 670])
        path_layout.addWidget(splitter, 1)
        self.host.dashboard_route_splitter = splitter
        left_panel.show()
        right_panel.show()
        topology_scroll.show()
