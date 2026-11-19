"""NetVision dashboard and its Qt state, controls, and worker bindings."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import datetime
import math
import re
from pathlib import Path
from typing import Iterable

from PySide6.QtCore import (
    QByteArray,
    QIODevice,
    QSaveFile,
    QObject,
    QSettings,
    QThread,
    Qt,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import QColor, QCloseEvent, QPixmap
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSystemTrayIcon,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo
from netvision.core.process_utils import EndpointChoice
from netvision.core.packet_loss import PacketLossSnapshot, summarize_loss
from netvision.core.bufferbloat import BufferbloatReport
from netvision.core.system_actions import (
    SystemActionResult,
    rollback_change,
    SystemChange,
)
from netvision.core.episodes import Episode, EpisodeTracker
from netvision.core.session_journal import JournalEvent
from netvision.core.session_journal import Layer
from netvision.core import judgement
from netvision.core.tcp_diagnostics import TcpSocketRecord
from netvision.core.tls_diagnostics import CertificateRecord
from netvision.core.udp_monitor import UdpPortActivity, UdpPortHistory, UdpPortSnapshot
from netvision.core.mtu_optimizer import detect_active_adapter
from netvision.core.network_boost import NetworkBoostScanResult, ProcessTerminationResult
from netvision.core.models import PendingAction
from netvision.core.thresholds import Thresholds
from netvision.models import (
    DefaultRoute,
    DiagnosticReport,
    MonitorScope,
    NetworkInterface,
    ProbeStatus,
    SystemSnapshot,
    Target,
)
from netvision.ui.dialogs import (
    ConnectionCaptureDialog,
    GeoHideDialog,
    PresetEditorDialog,
    RollbackConfirmDialog,
)
from netvision.ui.game_check_worker import GameAutoCheckResult, GameAutoCheckWorker
from netvision.ui.legacy_workers import ProcessSocketsWorker
from netvision.ui.legacy_dialogs import GameAutoCheckDialog, NetworkBoostDialog
from netvision.ui.legacy_workers import GameLaunchMonitorWorker, NetworkBoostScanWorker
from netvision.ui.lite_mode import LiteStatus
from netvision.ui.monitor_workers import UdpPortMonitorWorker, WifiMonitorWorker
from netvision.ui.ui_models import HeaderAnomalyEvent
from netvision.ui.theme import APP_STYLE, LIGHT_STYLE
from netvision.ui.widgets import TopologyNode
from netvision.ui.workspaces.overview_workspace import RegionCard, EventsCard
from netvision.ui.components.manual_process_dialog import ManualProcessDialog
from netvision.ui.components.sparkline_widget import SparklineWidget
from netvision.ui.app_bootstrapper import AppBootstrapper
from netvision.ui.workers.local_snapshot import LocalNetworkSnapshotWorker
from netvision.ui import constants as ui_constants
from netvision.reporting import (
    serialize_report,
)
from netvision.ui.utils import _ms
from netvision.ui.utils import (
    _tls_datetime,
    _tls_state_color,
    _wifi_correlation_evidence,
    _tls_certificate_state,
)
from netvision.version import display_version
from netvision.ui.presentation import BUFFERBLOAT_HELP, MTR_HELP, MTU_HELP, NAT_HELP, target_mode


class MetricCard(QFrame):
    """A metric label with a bounded graph; it never invents a value."""

    def __init__(self, title: str, color: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("MiniCard")
        self.setProperty("metricState", "neutral")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(5)
        self.title = QLabel(title)
        self.title.setObjectName("MetricTitle")
        self.value = QLabel("—")
        self.value.setObjectName("MetricValue")
        self.caption = QLabel("")
        self.caption.setObjectName("SubLabel")
        self.sparkline = SparklineWidget(color, 26)
        layout.addWidget(self.title)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)
        layout.addWidget(self.sparkline)

    def set_metric(self, value: str, state: str, samples: Iterable[float] = ()) -> None:
        self.value.setText(value)
        self.setProperty("metricState", state)
        self.style().unpolish(self)
        self.style().polish(self)
        self.sparkline.set_samples(samples)

    def add_action_chip(self, text: str, callback: object) -> QPushButton:
        """Add an optional, compact action without changing metric rendering."""
        chip = QPushButton(text, self)
        chip.setObjectName("MtuHintChip")
        chip.setVisible(False)
        chip.clicked.connect(callback)  # type: ignore[arg-type]
        self.layout().insertWidget(2, chip)
        return chip


class _UiCallDispatcher(QObject):
    requested = Signal(object, object, object, object)

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        self.requested.connect(self._invoke, Qt.ConnectionType.QueuedConnection)

    @Slot(object, object, object, object)
    def _invoke(
        self,
        callback: object,
        args: object,
        owner: object,
        active_owner: object,
    ) -> None:
        if not callable(callback) or not isinstance(args, tuple):
            return
        if owner is not None and callable(active_owner):
            try:
                if active_owner() is not owner:
                    return
            except RuntimeError:
                return
        try:
            callback(*args)
        except RuntimeError:
            # The target widget may already be destroyed during shutdown.
            return


class NetVisionDashboardV2(QMainWindow):
    """Main dashboard window for NetVision."""

    _ui_log_requested = Signal(str)

    def _mount_dns_workspace(self) -> None:
        pass

    def _mount_mtu_section(self, splitter: QSplitter, panel: QFrame) -> None:
        pass

    def __init__(self, *, bootstrap: bool = True) -> None:
        super().__init__()
        AppBootstrapper().bootstrap(self, bootstrap, MetricCard, SparklineWidget, _UiCallDispatcher)

    @staticmethod
    def _format_session_elapsed(seconds: int) -> str:
        hours, remainder = divmod(max(0, seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"

    def _start_diagnostic_session(self) -> None:
        self._session_elapsed_seconds = 0
        self._session_timer.start()
        self.overview_controller._set_header_anomaly("info", "Диагностика выполняется")

    @Slot()
    def _advance_session_timer(self) -> None:
        self._session_elapsed_seconds += 1
        self._refresh_session_capsule()

    @Slot()
    def _toggle_session_timer(self) -> None:
        if self._session_timer.isActive():
            self._session_timer.stop()
        else:
            self._session_timer.start()
        self._refresh_session_capsule()

    @Slot()
    def _reset_session_timer(self) -> None:
        self._session_elapsed_seconds = 0
        self._session_timer.stop()
        self._refresh_session_capsule()

    @Slot(int)
    def _on_language_changed(self, index: int) -> None:
        language = self.header_panel.language_combo.itemData(index)
        self._translator.set_language(str(language))

    def _tr(self, text: str) -> str:
        return self._translator.translate(text)

    def _set_translatable_tooltip(self, widget: QWidget, *parts: str) -> None:
        """Set a multi-part tooltip whose source phrases survive language changes."""
        widget._i18n_tooltip_parts = parts  # type: ignore[attr-defined]
        widget.setToolTip("\n".join(self._tr(part) for part in parts))

    def _refresh_preset_buttons(self) -> None:
        return self.state_synchronizer._refresh_preset_buttons()

    def _monitor_scope(self) -> MonitorScope:
        process = self._selected_process
        host = (
            self.core_workspace.target_input.text().strip()
            if hasattr(getattr(self, "core_workspace", None), "target_input")
            else ""
        )
        port = (
            self.core_workspace.port_input.value()
            if hasattr(getattr(self, "core_workspace", None), "port_input")
            else 0
        )
        return MonitorScope(
            pid=process.pid if process is not None else None,
            process_name=process.name if process is not None else None,
            host=host,
            port=port,
        )

    @Slot(int)
    def _clear_geohide_dialog(self, _result: int) -> None:
        self._geohide_dialog = None

    def _render_tcp_sockets(self, sockets: tuple[TcpSocketRecord, ...]) -> None:
        self.tcp_workspace.tcp_sockets_table.setRowCount(len(sockets))
        self._tcp_socket_records = sockets
        for row, record in enumerate(sockets):
            identity = f"{record.pid if record.pid is not None else '--'} · {record.process_name}"
            values = (
                identity,
                record.local_endpoint,
                record.remote_endpoint,
                record.state,
                "Выберите строку",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if record.state == "ESTABLISHED":
                    item.setForeground(QColor("#00E5A3"))
                elif record.state in {"SYN_SENT", "SYN_RECV"}:
                    item.setForeground(QColor("#FFB800"))
                elif record.state in {"CLOSE_WAIT", "TIME_WAIT"}:
                    item.setForeground(QColor("#8A99AD"))
                self.tcp_workspace.tcp_sockets_table.setItem(row, column, item)
        self.tcp_workspace.tcp_socket_status.setText(
            f"Отображено TCP-сокетов: {len(sockets)}"
            if sockets
            else "Доступных TCP-сокетов не найдено или доступ ограничен Windows."
        )

    @Slot()
    def _update_tcp_socket_selection(self) -> None:
        return self.state_synchronizer._update_tcp_socket_selection()

    def _set_tls_audit_running(self, running: bool) -> None:
        for button in (
            self.tls_workspace.tls_run_button,
            self.tls_workspace.tls_check_button,
            self.tls_workspace.tls_refresh_button,
        ):
            self._set_task_button_busy(button, running, "Проверка")
        self.tls_workspace.tls_run_button.setDisabled(running)
        self.tls_workspace.tls_check_button.setDisabled(running)
        self.tls_workspace.tls_refresh_button.setDisabled(running)
        if running:
            self.tls_workspace.tls_copy_fingerprint_button.setDisabled(True)

    def _set_tls_overview_value(self, label: QLabel, text: str, state: str) -> None:
        label.setText(text)
        label.setToolTip(text)
        label.setProperty("state", state)
        label.style().unpolish(label)
        label.style().polish(label)

    def _inherited__refresh_session_capsule(self) -> None:
        return self.state_synchronizer._inherited__refresh_session_capsule()

    @Slot()
    def _inherited__toggle_theme(self) -> None:
        self._theme = "light" if self._theme == "dark" else "dark"
        application = QApplication.instance()
        if application is not None:
            application.setStyleSheet(LIGHT_STYLE if self._theme == "light" else APP_STYLE)
        if self._theme == "light":
            self.header_panel.theme_button.setText("☀")
            self.header_panel.theme_button.setToolTip(self._tr("Переключить на тёмную тему"))
        else:
            self.header_panel.theme_button.setText("☾")
            self.header_panel.theme_button.setToolTip(self._tr("Переключить на светлую тему"))

    @Slot(str)
    def _inherited__retranslate_ui(self, language: str) -> None:
        """Apply the selected language to every already-created UI element.

        Qt only emits ``LanguageChange`` automatically for resource-based
        ``QTranslator`` catalogs. NetVision creates dashboards and dialogs in
        Python, so the runtime service deliberately updates all text-bearing
        widgets, tabs and table headers here instead.
        """
        self._language = language
        self._retranslate_window_chrome()
        self._retranslate_widget_tree(self)
        self._retranslate_content_views()
        self._retranslate_open_dialogs()
        self._retranslate_live_statuses()
        self._retranslate_theme_tooltip()
        self._finish_retranslation(language)

    @Slot(object)
    def _inherited__on_endpoint_chosen(self, value: object) -> None:
        return self.diagnostics_coordinator._inherited__on_endpoint_chosen(value)

    def _inherited__open_tls_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.tls_view:
            self._previous_workspace = (
                "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
            )
        self._close_combo_popups()
        host = self.core_workspace.target_input.text().strip()
        port = self.core_workspace.port_input.value()
        self.tls_workspace.tls_target_input.setText(host)
        self.tls_workspace.tls_port_input.setValue(port)
        if self._tls_audit_result is None or (
            self._tls_audit_result.host != host or self._tls_audit_result.port != port
        ):
            self._render_tls_placeholders()
            if (
                self._report
                and self._report.tls
                and self._report.target.host == host
                and self._report.target.port == port
            ):
                self._render_tls_report_summary(self._report.tls)
        self.mode_stack.setCurrentWidget(self.tls_view)
        self.tls_workspace.tls_back_button.setFocus()

    @Slot(object)
    def _inherited__on_completed(self, report: object) -> None:
        return self.diagnostics_coordinator._inherited__on_completed(report)

    @Slot(object)
    def _inherited__on_failed(self, failure: object) -> None:
        return self.diagnostics_coordinator._inherited__on_failed(failure)

    def _inherited__reset_results(self, target: Target) -> None:
        return self.diagnostics_coordinator._inherited__reset_results(target)

    def _inherited__set_running(self, running: bool) -> None:
        self._set_task_button_busy(self.core_workspace.start_button, running, "Диагностика")
        self.core_workspace.start_button.setDisabled(running)
        self.core_workspace.target_input.setDisabled(running)
        self.core_workspace.port_input.setDisabled(running)
        for button in self.preset_buttons.values():
            button.setDisabled(running)
        if running:
            self._set_status("ANALYZING", "running")

    def _inherited__set_status(self, text: str, state: str) -> None:
        self._status_state = state
        colors = ui_constants.DASHBOARD_STATUS_COLORS
        health_labels = ui_constants.DASHBOARD_STATUS_HEALTH_LABELS
        foreground, background, border = colors[state]
        self.header_panel.status_badge.setStyleSheet(
            f"color: {foreground}; background: {background}; border: 1px solid {border}; "
            "border-radius: 10px; padding: 6px 12px; font-size: 9pt; font-weight: 700;"
        )
        health_text = self._tr(health_labels[state])
        self.header_panel.status_badge.setProperty("fullText", health_text)
        self.header_panel.status_badge.setToolTip(health_text)
        self.header_panel.status_badge.setText(health_text)
        required_width = (
            self.header_panel.status_badge.fontMetrics().horizontalAdvance(health_text) + 34
        )
        compact_width = max(250, required_width)
        self.header_panel.status_badge.setFixedWidth(compact_width)

    @Slot(str)
    def _inherited__append_log(self, message: str) -> None:
        try:
            if QThread.currentThread() != self.thread():
                self._ui_log_requested.emit(message)
                return
        except RuntimeError:
            return

    @Slot()
    def _clear_network_boost_scan_worker(self) -> None:
        if self.sender() is not self._network_boost_scan_thread:
            return
        self._network_boost_scan_thread = None
        self._network_boost_scan_worker = None

    @Slot()
    def _clear_network_boost_terminate_worker(self) -> None:
        if self.sender() is not self._network_boost_terminate_thread:
            return
        self._network_boost_terminate_thread = None
        self._network_boost_terminate_worker = None

    @Slot()
    def _clear_network_boost_dialog(self) -> None:
        self._network_boost_dialog = None

    def _new_jitter_episode_tracker(self) -> EpisodeTracker:
        return EpisodeTracker(
            self._thresholds.jitter_spike_ms,
            self._thresholds.jitter_clear_ms,
            self._thresholds.episode_quiet_samples,
        )

    def _new_rtt_episode_tracker(self) -> EpisodeTracker:
        return EpisodeTracker(
            self._thresholds.rtt_high_ms,
            self._thresholds.rtt_normal_ms,
            self._thresholds.episode_quiet_samples,
            break_on_none=True,
        )

    def _jitter_endpoint(self) -> str:
        return (
            self._jitter_target_host
            or self.core_workspace.target_input.text().strip()
            or "не определён"
        )

    @staticmethod
    def _format_history_metric(value: object, unit: str) -> str:
        if isinstance(value, (int, float)):
            return f"{float(value):.1f} {unit}"
        return "--"

    @staticmethod
    def _history_delta(latest: object, previous: object, unit: str) -> str:
        if not isinstance(latest, (int, float)) or not isinstance(previous, (int, float)):
            return "--"
        return f"{latest - previous:+.1f} {unit}"

    def _set_task_button_busy(
        self,
        button: QAbstractButton,
        busy: bool,
        busy_text: str = "Выполняется",
    ) -> None:
        if busy:
            if button not in self._task_button_states:
                self._task_button_states[button] = (button.toolTip(), button.styleSheet())
                button.setToolTip(self._tr(busy_text))
            button.setEnabled(False)
            button.setProperty("taskBusy", True)
            button.setProperty("taskBusyPhase", str(self._task_button_phase))
            self._apply_task_button_busy_style(button)
            button.style().unpolish(button)
            button.style().polish(button)
            if not self._task_button_timer.isActive():
                self._task_button_timer.start()
            self._animate_task_buttons()
            return
        state = self._task_button_states.pop(button, None)
        if state is None:
            return
        button.setToolTip(state[0])
        button.setEnabled(True)
        button.setProperty("taskBusy", False)
        button.setProperty("taskBusyPhase", "0")
        button.setStyleSheet(state[1])
        button.style().unpolish(button)
        button.style().polish(button)
        button.update()
        if not self._task_button_states:
            self._task_button_timer.stop()

    @Slot()
    def _animate_task_buttons(self) -> None:
        self._task_button_phase = (self._task_button_phase + 1) % 3
        for button in self._task_button_states:
            button.setProperty("taskBusyPhase", str(self._task_button_phase))
            self._apply_task_button_busy_style(button)
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

    def _apply_task_button_busy_style(self, button: QAbstractButton) -> None:
        state = self._task_button_states.get(button)
        if state is None:
            return
        border, background = (
            ("#00E5A3", "#182C32"),
            ("#75F8D7", "#1B343B"),
            ("#129D7A", "#172A31"),
        )[self._task_button_phase]
        button.setStyleSheet(
            f"{state[1]}\n"
            "QPushButton, QToolButton { color: #E1E7EF; "
            f"background-color: {background}; border: 1px solid {border}; }}"
        )

    def _finish_retranslation(self, language: str) -> None:
        self._set_status("READY", getattr(self, "_status_state", "idle"))
        self._refresh_session_capsule()
        if self._header_anomaly_menu is not None:
            self._header_anomaly_menu.hide()
        self._schedule_responsive_layout_update()
        self._append_log(
            "Interface language: English" if language == "en" else "Язык интерфейса: русский"
        )

    def _update_preset_button(self, profile_id: str) -> None:
        return self.state_synchronizer._update_preset_button(profile_id)

    def _set_udp_ports_status(self, snapshot: UdpPortSnapshot | None) -> None:
        self._last_udp_snapshot = snapshot
        if snapshot is None:
            text = self._tr("UDP: выберите процесс для мониторинга")
        elif snapshot.warning:
            text = f"UDP: {self._tr(snapshot.warning)}"
        elif not snapshot.ports:
            text = self._tr("UDP: локальные порты не обнаружены")
        else:
            visible_ports = ", ".join(str(port) for port in snapshot.ports[:8])
            extra = len(snapshot.ports) - 8
            suffix = self._translator.format(" и ещё {count}", count=extra) if extra > 0 else ""
            text = self._translator.format(
                "UDP-порты PID {pid}: {ports}{suffix}",
                pid=snapshot.pid,
                ports=visible_ports,
                suffix=suffix,
            )
        self._set_elided_text(self.process_selector_panel.udp_ports_status, text)

    @Slot()
    def _show_selected_tcp_socket_details(self) -> None:
        row = self.tcp_workspace.tcp_sockets_table.currentRow()
        records = getattr(self, "_tcp_socket_records", ())
        if not 0 <= row < len(records):
            return
        record = records[row]
        QMessageBox.information(
            self,
            "Детали TCP-сокета",
            "\n".join(
                (
                    f"Процесс: {record.process_name}",
                    f"PID: {record.pid if record.pid is not None else 'не определён'}",
                    f"Локально: {record.local_endpoint}",
                    f"Удалённо: {record.remote_endpoint}",
                    f"Состояние: {record.state}",
                    "Закрытие отдельного чужого TCP-сокета Windows штатно не поддерживает.",
                )
            ),
        )

    @Slot()
    def _request_tcp_stack_reset(self) -> None:
        self.event_bus.quick_fix_requested.emit(
            "stack", self.tcp_workspace.tcp_reset_stack_button, self.quick_fix_status["tcp"]
        )

    def _set_loss_snapshot(self, snapshot: PacketLossSnapshot) -> None:
        self.loss_workspace.loss_stat_window.setText(str(snapshot.sent))
        self.loss_workspace.loss_stat_received.setText(
            f"{snapshot.received}/{snapshot.sent}" if snapshot.sent else "--"
        )
        self.loss_workspace.loss_stat_percent.setText(f"{snapshot.loss_percent:.0f}%")
        self.loss_workspace.loss_stat_current_burst.setText(str(snapshot.current_burst))
        self.loss_workspace.loss_stat_longest_burst.setText(str(snapshot.longest_burst))
        self.loss_workspace.loss_stat_jitter_drops.setText(str(snapshot.jitter_drops))

    def _clear_detail_grid(self) -> None:
        while self.node_details.detail_grid.count():
            item = self.node_details.detail_grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _close_combo_popups(self) -> None:
        for combo in self.findChildren(QComboBox):
            combo.hidePopup()
        if hasattr(getattr(self, "process_selector_panel", None), "embedded_dropdown"):
            self.process_selector_panel.embedded_dropdown.hide()
            self.process_selector_panel.embedded_dropdown_list.clear()
            self._active_embedded_combo = None

    @Slot(object)
    def _show_embedded_dropdown(self, combo: object) -> None:
        if not isinstance(combo, QComboBox):
            return
        if (
            self._active_embedded_combo is combo
            and self.process_selector_panel.embedded_dropdown.isVisible()
        ):
            self._close_combo_popups()
            return

        self._close_combo_popups()
        self._active_embedded_combo = combo
        for index in range(combo.count()):
            item = QListWidgetItem(combo.itemText(index))
            item.setData(Qt.ItemDataRole.UserRole, index)
            item.setToolTip(combo.itemText(index))
            self.process_selector_panel.embedded_dropdown_list.addItem(item)
        self.process_selector_panel.embedded_dropdown_list.setCurrentRow(combo.currentIndex())
        self.process_selector_panel.embedded_dropdown.show()
        self.process_selector_panel.embedded_dropdown.raise_()

    @Slot(QListWidgetItem)
    def _select_embedded_dropdown_item(self, item: QListWidgetItem) -> None:
        combo = self._active_embedded_combo
        if combo is not None:
            index = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(index, int):
                combo.setCurrentIndex(index)
        self._close_combo_popups()

    def _clear_lite_details(self) -> None:
        while self.lite_panel.lite_details.count():
            item = self.lite_panel.lite_details.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.lite_panel.lite_detail_labels.clear()

    def _set_wifi_status(self, text: str) -> None:
        if not hasattr(getattr(self, "interfaces_panel", None), "wifi_status_label"):
            return
        self.interfaces_panel.wifi_status_label.setText(text)
        self.interfaces_panel.wifi_status_label.setToolTip(
            f"{text}\nВ Windows 11 для данных Wi-Fi может потребоваться разрешение «Расположение»."
        )

    @Slot(bool)
    def _sync_tray_game_monitor(self, enabled: bool) -> None:
        return self.state_synchronizer._sync_tray_game_monitor(enabled)

    def _start_process_sockets_scan(self, report: DiagnosticReport, pid: int) -> None:
        if self._process_sockets_thread and self._process_sockets_thread.isRunning():
            return
        thread = QThread(self)
        worker = ProcessSocketsWorker(pid)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self._queue_ui_slot(
                self._on_process_sockets_completed,
                owner=worker,
                active_owner=lambda: self._process_sockets_worker,
            ),
        )
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_process_sockets_scan)
        self._process_sockets_thread = thread
        self._process_sockets_worker = worker
        self._process_sockets_pid = pid
        self._process_sockets_report = report
        thread.start()

    def _start_udp_port_monitor(self, pid: int) -> None:
        self._publish_monitor_scope()
        if (
            self._udp_monitor_pid == pid
            and self._udp_monitor_thread
            and self._udp_monitor_thread.isRunning()
        ):
            return
        self._stop_udp_port_monitor()
        self._udp_monitor_pid = pid
        self._udp_monitor_warning = None
        self._udp_activity_history.clear()
        self._clear_udp_event_table()
        self._set_udp_ports_status(None)

        worker = UdpPortMonitorWorker(pid)
        worker.activity.connect(
            self._queue_ui_slot(
                self._on_udp_port_activity,
                owner=worker,
                active_owner=lambda: self._udp_monitor_worker,
            )
        )
        thread = self._worker_registry.start(worker)
        thread.finished.connect(self._clear_udp_port_monitor)
        self._udp_monitor_thread = thread
        self._udp_monitor_worker = worker

    def _stop_udp_port_monitor(self) -> None:
        thread = self._udp_monitor_thread
        self._worker_registry.stop(thread)
        if thread is self._udp_monitor_thread:
            self._udp_monitor_thread = None
            self._udp_monitor_worker = None
            self._udp_monitor_pid = None
            self._udp_monitor_warning = None

    def _render_tls_placeholders(
        self, status: str = "Нажмите «Проверить сертификат», чтобы начать аудит"
    ) -> None:
        for value in self.tls_workspace.tls_overview_values.values():
            self._set_tls_overview_value(value, "--", "neutral")
        self.tls_workspace.tls_handshake_table.setRowCount(4)
        phases = (
            ("TCP connect", "--", status),
            ("TLS handshake", "--", status),
            ("Client Hello / Server Hello", "--", "Входит в полный TLS handshake"),
            ("Key exchange / проверка сертификата", "--", "Входит в полный TLS handshake"),
        )
        for row, values in enumerate(phases):
            for column, text in enumerate(values):
                self.tls_workspace.tls_handshake_table.setItem(row, column, QTableWidgetItem(text))
        self.tls_workspace.tls_certificate_table.setRowCount(1)
        self.tls_workspace.tls_certificate_table.setItem(0, 0, QTableWidgetItem("--"))
        self.tls_workspace.tls_certificate_table.setItem(0, 1, QTableWidgetItem(status))
        for column in range(2, self.tls_workspace.tls_certificate_table.columnCount()):
            self.tls_workspace.tls_certificate_table.setItem(0, column, QTableWidgetItem("--"))
        self.tls_workspace.tls_chain_note.setText(
            self._tr("Python SSL покажет доступный leaf-сертификат после аудита.")
        )
        self.tls_workspace.tls_copy_fingerprint_button.setEnabled(False)

    def _render_tls_report_summary(self, result: object) -> None:
        if not hasattr(result, "version"):
            return
        tls_ok = getattr(result, "status", None) == ProbeStatus.SUCCESS
        state = "good" if tls_ok else "bad"
        self._set_tls_overview_value(
            self.tls_workspace.tls_overview_values["handshake"],
            _ms(getattr(result, "latency_ms", None)),
            state,
        )
        self._set_tls_overview_value(
            self.tls_workspace.tls_overview_values["protocol"],
            getattr(result, "version", None) or "--",
            state,
        )
        self._set_tls_overview_value(
            self.tls_workspace.tls_overview_values["cipher"],
            getattr(result, "cipher", None) or "--",
            state,
        )
        self._set_tls_overview_value(
            self.tls_workspace.tls_overview_values["certificate"],
            "Подтверждён" if tls_ok else "Нужна проверка",
            state,
        )
        expires = getattr(result, "expires_at", None)
        self._set_tls_overview_value(
            self.tls_workspace.tls_overview_values["expiry"],
            expires.strftime("%Y-%m-%d") if expires else "--",
            state,
        )
        self.tls_workspace.tls_audit_status.setText(
            self._tr(
                "Показана сводка основной диагностики. Запустите аудит для сертификата и отпечатка."
            )
        )

    def _render_journal(self) -> None:
        return self.history_controller._render_journal()

    def _start_wifi_monitor(self, route: DefaultRoute | None) -> None:
        self._stop_wifi_monitor()
        self._wifi_snapshot = None
        self._wifi_signal_low = False
        self._wifi_signal_tracker.reset()
        self._wifi_probe_state = None
        if route is None or not route.interface:
            self._set_wifi_status("Wi-Fi: активный маршрут ещё не определён")
            return
        worker = WifiMonitorWorker(
            route.interface,
            route.gateway,
            route_is_vpn=route.is_vpn,
            th=self._thresholds,
        )
        worker.snapshot.connect(
            self._queue_ui_slot(
                self._on_wifi_snapshot,
                owner=worker,
                active_owner=lambda: self._wifi_worker,
            )
        )
        thread = self._worker_registry.start(worker)
        thread.finished.connect(self._clear_wifi_monitor)
        self._wifi_thread = thread
        self._wifi_worker = worker

    def _stop_game_launch_monitor(self) -> None:
        worker = self._game_monitor_worker
        if worker is not None:
            worker.stop()

    def _schedule_responsive_layout_update(self) -> None:
        """Queue one resize pass without retaining a deleted window wrapper."""
        self._responsive_layout_timer.start(0)

    @staticmethod
    def _set_elided_text(label: QLabel, text: str, width: int | None = None) -> None:
        """Keep compact labels inside their layout while retaining the full tooltip."""
        label.setProperty("fullText", text)
        label.setToolTip(text)
        available_width = width if width is not None else label.contentsRect().width()
        if not label.isVisible() or available_width < 40:
            label.setText(text)
            return
        label.setText(
            label.fontMetrics().elidedText(
                text,
                Qt.TextElideMode.ElideRight,
                max(available_width, 40),
            )
        )

    def _retranslate_window_chrome(self) -> None:
        self.setWindowTitle(
            self._translator.format(
                "NetVision {version} — визуальная диагностика сети",
                version=display_version(),
            )
        )
        if hasattr(getattr(self, "header_panel", None), "brand_caption"):
            self.header_panel.brand_caption.setText(
                self._translator.format(
                    "NETWORK DIAGNOSTICS / WINDOWS · {version}",
                    version=display_version(),
                )
            )

    def _retranslate_content_views(self) -> None:
        self.mtr_workspace.setToolTip(self._tr(MTR_HELP))
        self.bufferbloat_workspace.setToolTip(self._tr(BUFFERBLOAT_HELP))
        self.mtu_workspace.mtu_section_title.setToolTip(self._tr(MTU_HELP))
        self.quality_workspace.nat_probe_status.setToolTip(self._tr(NAT_HELP))
        self._refresh_preset_buttons()
        if hasattr(self.bufferbloat_workspace, "bufferbloat_recommendations"):
            self._render_bufferbloat_recommendations()
        for widget in (
            getattr(getattr(self, "node_details", None), "latency_chart", None),
            getattr(self.jitter_workspace, "jitter_chart", None),
            getattr(getattr(self, "core_workspace", None), "topology", None),
        ):
            if widget is not None and hasattr(widget, "set_translator"):
                widget.set_translator(self._tr)
        self.process_controller._refresh_dynamic_process_text()
        if hasattr(getattr(self, "dns_workspace", None), "dns_info_grid"):
            self.dns_controller._render_dns_info()

    def _retranslate_open_dialogs(self) -> None:
        if self._network_boost_dialog is not None:
            self._network_boost_dialog.retranslate(self._tr)
        if self._geohide_dialog is not None:
            self._geohide_dialog.retranslate(self._tr)

    def _retranslate_live_statuses(self) -> None:
        if hasattr(self.jitter_workspace, "jitter_event_status"):
            self.jitter_workspace.jitter_event_status.setText(
                self._translator.format(
                    "Критический порог: Δ RTT > {threshold:.0f} мс · событий: {count}",
                    threshold=self._thresholds.jitter_spike_ms,
                    count=len(self._jitter_events),
                )
            )
        if (
            hasattr(getattr(self, "ping_workspace", None), "ping_spike_status")
            and not self._ping_spike_events
        ):
            self.ping_workspace.ping_spike_status.setText(
                self._translator.format(
                    "Пики выше {threshold:.0f} мс и потери появятся здесь во время мониторинга",
                    threshold=self._thresholds.rtt_high_ms,
                )
            )
        if hasattr(self.journal_workspace, "journal_layer_filter"):
            self._retranslate_journal_filter()
            self._render_journal()
        if hasattr(getattr(self, "process_selector_panel", None), "monitor_scope_label"):
            self.state_synchronizer._update_monitor_scope_label(self._monitor_scope())

    def _retranslate_theme_tooltip(self) -> None:
        # Theme tooltips are stateful, so derive them from the current theme.
        if self._theme == "light":
            self.header_panel.theme_button.setToolTip(self._tr("Переключить на тёмную тему"))
        else:
            self.header_panel.theme_button.setToolTip(self._tr("Переключить на светлую тему"))

    def _retranslate_widget_tree(self, root: QWidget) -> None:
        """Translate static text, tooltips, placeholders and table tabs in-place."""
        self._retranslate_labels(root)
        self._retranslate_buttons(root)
        self._retranslate_inputs(root)
        self._retranslate_combos(root)
        self._retranslate_tabs(root)
        self._retranslate_tables(root)

    def _active_adapter_name(self) -> str | None:
        adapter_combo = getattr(getattr(self, "dns_workspace", None), "dns_adapter_combo", None)
        if isinstance(adapter_combo, QComboBox):
            value = adapter_combo.currentData()
            if isinstance(value, str) and value.strip():
                return value
        if self._report is not None:
            for interface in self._report.system.interfaces:
                if interface.is_up and interface.name.strip():
                    return interface.name
        return detect_active_adapter()

    def _retranslate_journal_filter(self) -> None:
        return self.history_controller._retranslate_journal_filter()

    def _journal_layer_label(self, layer: Layer) -> str:
        return self.history_controller._journal_layer_label(layer)

    def _journal_events_for_view(self) -> list[JournalEvent]:
        return self.history_controller._journal_events_for_view()

    @Slot()
    def _clear_journal(self) -> None:
        return self.history_controller._clear_journal()

    def _export_journal(self, file_format: str) -> None:
        return self.history_controller._export_journal(file_format)

    def _set_lite_status_style(self, status: LiteStatus) -> None:
        styles = {
            LiteStatus.SUCCESS: ("#00E5A3", "#102A26", "#00F5B4"),
            LiteStatus.WARNING: ("#FFB800", "#2A2110", "#806000"),
            LiteStatus.ERROR: ("#FF4757", "#2A1218", "#8F2633"),
        }
        foreground, background, border = styles[status]
        self.lite_panel.lite_status_indicator.setStyleSheet(
            f"color: {foreground}; background: {background}; border: 1px solid {border}; "
            "border-radius: 32px; font-size: 22pt; font-weight: 700;"
        )
        icons = {
            LiteStatus.SUCCESS: "🟢",
            LiteStatus.WARNING: "⚠️",
            LiteStatus.ERROR: "🔴",
        }
        self.lite_panel.lite_status_indicator.setText(icons[status])
        self.lite_panel.lite_title.setStyleSheet(
            "color: #E1E7EF; font-size: 19pt; font-weight: 700;"
        )

    def _save_network_alarm_settings(self, _value: object = True) -> None:
        return self.alarms_controller._save_network_alarm_settings(_value)

    @Slot(bool)
    def _toggle_game_launch_monitor(self, enabled: bool) -> None:
        self._background_auto_monitor = enabled
        self._alarm_settings.setValue("background/auto_monitor", enabled)
        if not enabled:
            self._stop_auto_monitors("выключено пользователем")
            self._stop_game_launch_monitor()
            self.process_selector_panel.game_monitor_status.setText(
                self._tr("Мониторинг игры выключен")
            )
            return
        if self._game_monitor_thread and self._game_monitor_thread.isRunning():
            return
        scope = self._publish_monitor_scope()
        process_names = (scope.process_name,) if scope.process_name else ("HuntGame.exe",)
        self.process_selector_panel.game_monitor_status.setText(
            self._tr("Ожидание запуска игры")
            if scope.process_name is None
            else self._translator.format("Ожидание запуска {process}", process=scope.process_name)
        )
        worker = GameLaunchMonitorWorker(process_names, (scope.host, scope.port))
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.event.connect(self._queue_ui_slot(self._on_game_monitor_event))
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_game_launch_monitor)
        self._game_monitor_worker = worker
        self._game_monitor_thread = thread
        thread.start()
        self._append_log("Мониторинг запуска игры включён")

    def _retranslate_labels(self, root: QWidget) -> None:
        labels = root.findChildren(QLabel)
        detached = getattr(getattr(self, "process_selector_panel", None), "process_status", None)
        if isinstance(detached, QLabel) and detached not in labels:
            labels.append(detached)
        for label in labels:
            label.setText(self._tr(label.text()))
            self._retranslate_tooltip(label)
            label.setAccessibleName(self._tr(label.accessibleName()))

    def _retranslate_buttons(self, root: QWidget) -> None:
        for button_type in (QPushButton, QToolButton, QRadioButton, QCheckBox):
            for button in root.findChildren(button_type):
                button.setText(self._tr(button.text()))
                self._retranslate_tooltip(button)
                button.setAccessibleName(self._tr(button.accessibleName()))

    def _retranslate_inputs(self, root: QWidget) -> None:
        for line_edit in root.findChildren(QLineEdit):
            line_edit.setPlaceholderText(self._tr(line_edit.placeholderText()))
            self._retranslate_tooltip(line_edit)
        for spin_box in root.findChildren(QSpinBox):
            self._retranslate_tooltip(spin_box)
        for text_edit in root.findChildren(QPlainTextEdit):
            text_edit.setPlaceholderText(self._tr(text_edit.placeholderText()))
            self._retranslate_tooltip(text_edit)

    def _retranslate_combos(self, root: QWidget) -> None:
        for combo in root.findChildren(QComboBox):
            self._retranslate_tooltip(combo)
            combo.setAccessibleName(self._tr(combo.accessibleName()))
            for index in range(combo.count()):
                combo.setItemText(index, self._tr(combo.itemText(index)))

    def _retranslate_tabs(self, root: QWidget) -> None:
        for tabs in root.findChildren(QTabWidget):
            for index in range(tabs.count()):
                tabs.setTabText(index, self._tr(tabs.tabText(index)))

    def _retranslate_tables(self, root: QWidget) -> None:
        for table in root.findChildren(QTableWidget):
            self._retranslate_table_headers(table)
            self._retranslate_table_items(table)

    @Slot()
    def _clear_process_sockets_scan(self) -> None:
        if self.sender() is not self._process_sockets_thread:
            return
        self._process_sockets_thread = None
        self._process_sockets_worker = None
        self._process_sockets_pid = None
        self._process_sockets_report = None

    def _clear_udp_event_table(self) -> None:
        return self.history_controller._clear_udp_event_table()

    @Slot()
    def _clear_udp_port_monitor(self) -> None:
        thread = self.sender()
        if thread is not self._udp_monitor_thread:
            return
        self._udp_monitor_thread = None
        self._udp_monitor_worker = None
        self._udp_monitor_pid = None
        self._udp_monitor_warning = None

    def _close_dns_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _close_loss_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _close_tcp_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _stop_wifi_monitor(self) -> None:
        thread = self._wifi_thread
        self._worker_registry.stop(thread)
        if thread is self._wifi_thread:
            self._wifi_thread = None
            self._wifi_worker = None

    @Slot()
    def _clear_wifi_monitor(self) -> None:
        if self.sender() is not self._wifi_thread:
            return
        self._wifi_thread = None
        self._wifi_worker = None

    def _stop_auto_monitors(self, reason: str) -> None:
        if not self._auto_monitor_active:
            return
        self.ping_controller._stop_latency_monitor()
        self._stop_udp_port_monitor()
        self._auto_monitor_active = False
        self._append_log(f"Автомониторинг остановлен: {reason}")

    @Slot()
    def _clear_game_launch_monitor(self) -> None:
        if self.sender() is not self._game_monitor_thread:
            return
        self._game_monitor_thread = None
        self._game_monitor_worker = None

    def _retranslate_table_headers(self, table: QTableWidget) -> None:
        for index in range(table.columnCount()):
            header = table.horizontalHeaderItem(index)
            if header is not None:
                header.setText(self._tr(header.text()))

    def _retranslate_table_items(self, table: QTableWidget) -> None:
        for row in range(table.rowCount()):
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None:
                    item.setText(self._tr(item.text()))
                    item.setToolTip(self._tr(item.toolTip()))

    def _retranslate_tooltip(self, widget: QWidget) -> None:
        parts = getattr(widget, "_i18n_tooltip_parts", None)
        if parts:
            widget.setToolTip("\n".join(self._tr(part) for part in parts))
            return
        widget.setToolTip(self._tr(widget.toolTip()))

    @Slot(object)
    def _on_process_sockets_completed(self, result: object) -> None:
        return self.diagnostics_coordinator._on_process_sockets_completed(result)

    @Slot(object)
    def _on_udp_port_activity(self, activity: object) -> None:
        snapshot = self._current_udp_activity_snapshot(activity)
        if snapshot is None:
            return
        assert isinstance(activity, UdpPortActivity)
        self._udp_activity_history.append(activity)
        if len(self._udp_activity_history) > 120:
            del self._udp_activity_history[:-120]
        self._set_udp_ports_status(snapshot)
        warning_changed = self._handle_udp_monitor_warning(snapshot)
        self._record_udp_activity(activity, include_warning=warning_changed)
        self._log_udp_port_changes(activity, snapshot)
        self._handle_udp_connection_health(activity, snapshot)

    @Slot()
    def start_diagnostic(self) -> None:
        return self.diagnostics_coordinator.start_diagnostic()

    @Slot()
    def _export_report(self) -> None:
        if self._report is None:
            return
        target_slug = re.sub(r"[^A-Za-z0-9._-]", "_", self._report.target.host)
        suggested_name = f"NetVision_{target_slug}_{datetime.now():%Y%m%d_%H%M%S}.json"
        path, _filter = QFileDialog.getSaveFileName(
            self,
            "Экспорт диагностического отчёта",
            str(Path.home() / suggested_name),
            "JSON (*.json)",
        )
        if not path:
            return
        if not path.lower().endswith(".json"):
            path += ".json"
        payload = serialize_report(self._report, self._udp_event_rows).encode("utf-8")
        if self._write_export_payload(path, payload):
            self._append_log(f"Полный отчёт с UDP-историей сохранён: {path}")

    def _write_export_payload(self, path: str, payload: bytes) -> bool:
        output = QSaveFile(path)
        if not output.open(QIODevice.OpenModeFlag.WriteOnly):
            QMessageBox.critical(self, "Экспорт не выполнен", output.errorString())
            return False
        if output.write(payload) != len(payload) or not output.commit():
            QMessageBox.critical(self, "Экспорт не выполнен", output.errorString())
            return False
        return True

    @Slot(object, str)
    def _on_wifi_snapshot(self, value: object, state: str) -> None:
        return self.wifi_controller._on_wifi_snapshot(value, state)

    @Slot(object)
    def _on_game_monitor_event(self, value: object) -> None:
        return self.game_monitor_controller._on_game_monitor_event(value)

    def _queue_ui_slot(
        self,
        callback: Callable[..., object],
        *,
        owner: object | None = None,
        active_owner: Callable[[], object | None] | None = None,
    ) -> Callable[..., None]:
        def dispatch(*args: object) -> None:
            self._ui_dispatcher.requested.emit(callback, args, owner, active_owner)

        return dispatch

    def _make_network_boost_button(self) -> QPushButton:
        button = QPushButton("Оптимизировать сеть")
        button.setObjectName("NetworkBoostButton")
        button.setToolTip(
            "Найти известные фоновые приложения с активными сетевыми сокетами и предложить закрыть выбранные"
        )
        button.setAccessibleName("Оптимизировать фоновый сетевой трафик")
        button.clicked.connect(self.start_network_boost_scan)
        self._network_boost_buttons.append(button)
        return button

    def _render_bufferbloat_recommendations(self) -> None:
        if not self.bufferbloat_recommendation_sources:
            self.bufferbloat_workspace.bufferbloat_recommendations.setText(
                self._tr("После теста здесь появятся рекомендации по настройке сети.")
            )
            return
        self.bufferbloat_workspace.bufferbloat_recommendations.setText(
            "\n".join(f"• {self._tr(source)}" for source in self.bufferbloat_recommendation_sources)
        )

    def _fill_route_analysis(self, report: DiagnosticReport) -> None:
        return self.diagnostics_coordinator._fill_route_analysis(report)

    def _fill_interfaces(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        return self.diagnostics_coordinator._fill_interfaces(interfaces)

    def _show_system_details(self, report: DiagnosticReport) -> None:
        self.node_details.detail_title.setText(report.system.hostname)
        self._clear_detail_grid()
        gateway = report.system.gateway
        details = {
            "Целевой узел": report.target.display_name,
            "Шлюз": gateway.address if gateway else "не определён",
            "Внешний IP": report.system.external_ip or "не определён",
            "Ping / jitter": f"{_ms(report.ping.average_ms)} / {_ms(report.ping.jitter_ms)}",
            "Потери пакетов": f"{report.ping.loss_percent:.0f}% ({report.ping.received}/{report.ping.sent})",
            "DNS": ", ".join(report.system.dns_servers) or "не определены",
            "Маршруты по умолчанию": str(len(report.system.default_routes)),
            "Прокси": ", ".join(key for key, _ in report.system.proxies) or "не обнаружен",
            "TCP": "доступен" if report.tcp.status == ProbeStatus.SUCCESS else "недоступен",
        }
        for row, (key, value) in enumerate(details.items()):
            key_label = QLabel(self._tr(key).upper())
            key_label.setObjectName("FieldLabel")
            value_label = QLabel(self._tr(value))
            if key in {"Целевой узел", "Шлюз", "Внешний IP", "Ping / jitter", "Потери пакетов"}:
                value_label.setObjectName("MonospaceValue")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.node_details.detail_grid.addWidget(key_label, row, 0, Qt.AlignmentFlag.AlignTop)
            self.node_details.detail_grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)

    @staticmethod
    def _quick_fix_tooltip(action_key: str) -> str:
        return {
            "dns": "Очистить локальный DNS-кэш без открытия окна консоли",
            "mtu": "Рассчитать безопасный MTU бинарным поиском и применить его к активному адаптеру",
            "stack": "Сбросить TCP/IP и Winsock; после этого потребуется перезагрузка Windows",
            "adapter": "Временно отключить и снова включить активный сетевой адаптер",
        }[action_key]

    @Slot(str)
    def _apply_preset(self, profile_id: str) -> None:
        label, host, port = self._preset_profiles[profile_id]
        display_label = self._tr(label)
        self._active_preset = profile_id
        self.core_workspace.target_input.setText(host)
        self.core_workspace.port_input.setValue(port)
        self.core_workspace.target_input.setFocus()
        self.statusBar().showMessage(
            self._translator.format(
                "Профиль «{name}» готов к проверке: {host}:{port}",
                name=display_label,
                host=host,
                port=port,
            ),
            4000,
        )
        self._append_log(
            self._translator.format(
                "Выбран профиль «{name}»: {host}:{port}", name=display_label, host=host, port=port
            )
        )

    @Slot(str)
    def _edit_preset(self, profile_id: str) -> None:
        dialog = PresetEditorDialog(
            *self._preset_profiles[profile_id],
            defaults=self._preset_defaults[profile_id],
            translate=self._tr,
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        label, host, port = dialog.values()
        self._save_preset_profile(profile_id, label, host, port)

    @Slot(str, int, str)
    def _save_captured_connection(self, host: str, port: int, profile_id: str) -> None:
        profile = self._preset_profiles.get(profile_id)
        if profile is None:
            return
        label, _previous_host, _previous_port = profile
        self._save_preset_profile(profile_id, label, host, port)
        self._active_preset = profile_id
        self.preset_buttons[profile_id].setChecked(True)
        self.core_workspace.target_input.setText(host)
        self.core_workspace.port_input.setValue(port)
        self.statusBar().showMessage(
            self._translator.format(
                "Подключение сохранено в профиль «{name}»: {host}:{port}",
                name=self._tr(label),
                host=host,
                port=port,
            ),
            5000,
        )

    def _record_endpoint_choice(self, choice: EndpointChoice) -> None:
        connection = choice.connection
        state = (
            connection.protocol,
            connection.local_port,
            connection.remote_address,
            connection.remote_port,
            choice.rule,
        )
        if state == self._endpoint_choice_state:
            return
        self._endpoint_choice_state = state
        self._record_journal_event(
            "endpoint.choice",
            subject=connection.remote_endpoint,
            template="Автоматически выбран endpoint: {endpoint} ({rule})",
            values={
                "endpoint": connection.remote_endpoint,
                "rule": self._tr(choice.rule),
                "candidates": choice.candidates,
                "excluded_cdn": choice.excluded_cdn,
            },
            refs={
                "protocol": connection.protocol,
                "host": connection.remote_address,
                "port": connection.remote_port,
            },
        )

    def _publish_monitor_scope(self) -> MonitorScope:
        scope = self._monitor_scope()
        self.state_synchronizer._update_monitor_scope_label(scope)
        if scope == self._published_monitor_scope:
            return scope
        self._published_monitor_scope = scope
        template = (
            "Наблюдение: {process} · PID {pid} → {host}:{port}"
            if scope.pid is not None and scope.process_name
            else "Наблюдение: только цель {host}:{port}"
        )
        values: dict[str, object] = {"host": scope.host, "port": scope.port}
        if scope.pid is not None and scope.process_name:
            values.update({"process": scope.process_name, "pid": scope.pid})
        self._record_journal_event(
            "action.monitor_scope",
            subject=f"{scope.host}:{scope.port}",
            template=template,
            values=values,
            refs={"pid": scope.pid, "process_name": scope.process_name},
        )
        return scope

    @Slot()
    def start_network_boost_scan(self) -> None:
        if self._network_boost_scan_thread and self._network_boost_scan_thread.isRunning():
            return
        self._set_network_boost_controls(True)
        self._set_network_boost_status(
            "Network Boost: ищем известные фоновые приложения с активными сокетами..."
        )
        thread = QThread(self)
        worker = NetworkBoostScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self._queue_ui_slot(self._on_network_boost_scan_completed),
        )
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_network_boost_scan_worker)
        self._network_boost_scan_thread = thread
        self._network_boost_scan_worker = worker
        thread.start()

    def _current_udp_activity_snapshot(self, activity: object) -> UdpPortSnapshot | None:
        if not isinstance(activity, UdpPortActivity):
            return None
        snapshot = activity.snapshot
        if not isinstance(snapshot, UdpPortSnapshot) or snapshot.pid != self._udp_monitor_pid:
            return None
        return snapshot

    def _handle_udp_monitor_warning(self, snapshot: UdpPortSnapshot) -> bool:
        warning_changed = bool(snapshot.warning and snapshot.warning != self._udp_monitor_warning)
        if warning_changed:
            self._udp_monitor_warning = snapshot.warning
            self._append_log(f"UDP-монитор: {snapshot.warning}")
        return warning_changed

    def _log_udp_port_changes(self, activity: UdpPortActivity, snapshot: UdpPortSnapshot) -> None:
        changes = self._udp_port_change_labels(activity)
        if changes:
            self._append_log(f"UDP-порты PID {snapshot.pid}: {'; '.join(changes)}")

    def _handle_udp_connection_health(
        self,
        activity: UdpPortActivity,
        snapshot: UdpPortSnapshot,
    ) -> None:
        if activity.potential_disconnect:
            message = self._udp_disconnect_message(activity)
            self._append_log(message)
            self.statusBar().showMessage(message, 6000)
            self.overview_controller._set_header_anomaly("error", "Возможный обрыв UDP-соединения")
        elif snapshot.warning:
            self.overview_controller._set_header_anomaly("warning", "Проблема UDP-монитора")

    def _record_udp_activity(self, activity: UdpPortActivity, include_warning: bool) -> None:
        return self.udp_controller._record_udp_activity(activity, include_warning)

    @Slot()
    def _open_game_auto_check(self) -> None:
        preferred_process = (
            "HuntGame.exe"
            if isinstance(self._selected_process, ProcessNetworkInfo)
            and self._selected_process.name.casefold() == "huntgame.exe"
            else None
        )
        dialog = GameAutoCheckDialog(self._tr, preferred_process, self, self._thresholds)
        dialog.endpoint_chosen.connect(self._on_endpoint_chosen)
        dialog.capture_started.connect(self._on_game_capture_started)
        dialog.check_completed.connect(self.process_controller._on_game_auto_check_completed)
        launched = False

        def start_once(result: object) -> None:
            nonlocal launched
            if (
                not launched
                and isinstance(result, GameAutoCheckResult)
                and result.selected_connection is not None
                and result.selected_connection.protocol.upper() == "UDP"
            ):
                launched = True
                self.start_diagnostic()

        dialog.check_completed.connect(start_once)
        dialog.exec()

    def _render_tls_chain(self, records: tuple[CertificateRecord, ...]) -> None:
        self.tls_workspace.tls_certificate_table.setRowCount(len(records))
        if not records:
            self.tls_workspace.tls_chain_note.setText(
                self._tr("Сертификат не получен. Проверьте адрес, порт и настройки TLS на сервере.")
            )
            return
        self.tls_workspace.tls_chain_note.setText(
            "Доступен leaf-сертификат. Полная цепочка зависит от версии Python/OpenSSL и политики сервера."
        )
        for row, record in enumerate(records):
            values = (
                str(record.position + 1),
                record.subject,
                record.issuer,
                record.serial_number,
                _tls_datetime(record.valid_from),
                _tls_datetime(record.valid_to),
                "--" if record.days_remaining is None else f"{record.days_remaining} дн.",
                record.fingerprint_sha256 or "--",
            )
            state = _tls_certificate_state(record.status, record.status == "Действителен")
            color = _tls_state_color(state)
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(f"{record.status}\n{text}" if text != "--" else record.status)
                item.setForeground(color)
                self.tls_workspace.tls_certificate_table.setItem(row, column, item)

    def _loss_analyzer_snapshot(self) -> PacketLossSnapshot:
        return summarize_loss(self._loss_analyzer.samples, th=self._thresholds)

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
        return self.history_controller._record_journal_event(
            kind,
            severity=severity,
            subject=subject,
            template=template,
            values=values,
            refs=refs,
            at=at,
        )

    def _run_system_action(
        self,
        label: str,
        action: Callable[[], SystemActionResult],
        button: QPushButton,
        status_label: QLabel | None = None,
    ) -> None:
        return self.alarms_controller._run_system_action(label, action, button, status_label)

    def _support_bundle_options(self) -> tuple[bool, tuple[str, ...]] | None:
        return self.diagnostics_coordinator._support_bundle_options()

    def _support_bundle_measurements(self) -> dict[str, object]:
        return {
            "mtu": self._mtu_optimizer_report,
            "bufferbloat": self._bufferbloat_report,
            "mtr": self._mtr_snapshot,
            "nat": self._nat_report,
            "wifi": self._wifi_snapshot,
            "loss": self._loss_analyzer_snapshot(),
            "jitter": {
                "latency_window_ms": tuple(self._latency_window),
                "events": tuple(self._jitter_events),
            },
            "diagnostic_failure": self._diagnostic_failure_text,
        }

    @Slot()
    def _clear_worker(self) -> None:
        if self.sender() is not self._thread:
            return
        self._thread = None
        self._worker = None

    def _record_wifi_correlation(self, trigger: str) -> None:
        recent = self._journal.recent(
            "wifi.",
            since_s=self._thresholds.correlation_window_s,
        )
        snapshot = self._wifi_snapshot
        confirmed, evidence = _wifi_correlation_evidence(
            snapshot,
            self._wifi_signal_low,
            {event.kind for event in recent},
            self._thresholds,
        )
        self._record_journal_event(
            "wifi.suspected_cause",
            severity="warning" if confirmed else "info",
            subject=self.core_workspace.target_input.text().strip(),
            template="Wi-Fi {status} для {trigger}",
            values={
                "status": "подтверждён" if confirmed else "не подтверждён",
                "trigger": trigger,
                "evidence": evidence,
            },
        )

    def _sync_rtt_episode_log(self, step: str | None, episode: Episode | None) -> None:
        return self.state_synchronizer._sync_rtt_episode_log(step, episode)

    def _start_auto_monitor_probe(self, process_name: str, pid: int) -> None:
        if self._auto_monitor_thread and self._auto_monitor_thread.isRunning():
            return
        thread = QThread(self)
        worker = GameAutoCheckWorker(process_name)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self._queue_ui_slot(
                lambda result, pid=pid: self.process_controller._on_auto_monitor_probe_completed(
                    result, pid
                )
            )
        )
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_auto_monitor_probe)
        self._auto_monitor_thread = thread
        self._auto_monitor_worker = worker
        thread.start()

    def _save_preset_profile(self, profile_id: str, label: str, host: str, port: int) -> None:
        self._preset_profiles[profile_id] = (label, host, port)
        key = f"quick_profiles/{profile_id}"
        self._preset_settings.setValue(f"{key}/label", label)
        self._preset_settings.setValue(f"{key}/host", host)
        self._preset_settings.setValue(f"{key}/port", port)
        self._preset_settings.sync()
        self._update_preset_button(profile_id)

    @Slot(object)
    def _on_network_boost_scan_completed(self, value: object) -> None:
        self._set_network_boost_controls(False)
        if not isinstance(value, NetworkBoostScanResult):
            self._set_network_boost_status("Network Boost: сканер вернул некорректный результат")
            return
        if value.warning:
            self._set_network_boost_status(value.warning)
            QMessageBox.warning(self, "Network Boost", value.warning)
            return
        count = len(value.candidates)
        self._set_network_boost_status(
            "Network Boost: подходящих приложений не найдено"
            if not count
            else f"Network Boost: найдено приложений с активными сокетами: {count}"
        )
        dialog = NetworkBoostDialog(value.candidates, self, self._tr)
        dialog.terminate_requested.connect(self._start_network_boost_termination)
        dialog.finished.connect(self._clear_network_boost_dialog)
        self._network_boost_dialog = dialog
        dialog.open()

    def _set_network_boost_controls(self, running: bool) -> None:
        for button in self._network_boost_buttons:
            self._set_task_button_busy(button, running, "Сканирование")

    def _set_network_boost_status(self, message: str) -> None:
        if hasattr(self.loss_workspace, "loss_detector_status"):
            self.loss_workspace.loss_detector_status.setText(message)
        if hasattr(self.jitter_workspace, "jitter_graph_status"):
            self.jitter_workspace.jitter_graph_status.setText(message)
        self.statusBar().showMessage(message, 6000)

    @staticmethod
    def _udp_port_change_labels(activity: UdpPortActivity) -> list[str]:
        labels: list[str] = []
        if activity.opened_ports:
            labels.append("+" + ", +".join(str(port) for port in activity.opened_ports))
        if activity.closed_ports:
            labels.append("-" + ", -".join(str(port) for port in activity.closed_ports))
        return labels

    @staticmethod
    def _udp_disconnect_message(activity: UdpPortActivity) -> str:
        closed = ", ".join(str(port) for port in activity.closed_ports)
        opened = ", ".join(str(port) for port in activity.opened_ports)
        if activity.anomaly.value == "all_ports_lost":
            return f"UDP: возможный обрыв, исчезли порты {closed}"
        return f"UDP: резкая смена портов {closed} -> {opened}"

    @Slot()
    def _refresh_udp_event_table(self) -> None:
        return self.state_synchronizer._refresh_udp_event_table()

    @Slot(object)
    def _on_game_capture_started(self, value: object) -> None:
        if not isinstance(value, dict):
            return
        pid = value.get("pid")
        process = value.get("process")
        ports = value.get("ports")
        if not isinstance(pid, int) or not isinstance(process, str):
            return
        if not isinstance(ports, tuple):
            ports = tuple(ports) if isinstance(ports, (list, set, frozenset)) else ()
        ports_text = ", ".join(str(port) for port in ports) or "—"
        self._record_journal_event(
            "udp.capture_started",
            subject=process,
            template="Перехват UDP-заголовков запущен для PID {pid} по портам {ports}",
            values={"pid": pid, "process": process, "ports": ports_text},
            refs={"pid": pid, "ports": ports},
        )

    @Slot(str, object, object)
    def _on_system_action_completed(
        self,
        label: str,
        button: QPushButton,
        result: object,
    ) -> None:
        return self.alarms_controller._on_system_action_completed(label, button, result)

    @Slot()
    def _release_system_action(self) -> None:
        return self.alarms_controller._release_system_action()

    @Slot()
    def _clear_auto_monitor_probe(self) -> None:
        if self.sender() is not self._auto_monitor_thread:
            return
        self._auto_monitor_thread = None
        self._auto_monitor_worker = None

    @Slot(object)
    def _start_network_boost_termination(self, value: object) -> None:
        return self.diagnostics_coordinator._start_network_boost_termination(value)

    def _finish_system_action_button(self, button: QPushButton) -> QLabel | None:
        self._set_task_button_busy(button, False)
        button.setEnabled(True)
        return self._system_action_status.pop(button, None)

    def _handle_unknown_system_action(
        self,
        label: str,
        status_label: QLabel | None,
    ) -> None:
        message = f"{label}: получен неизвестный результат"
        self._append_log(f"Ошибка: {message}")
        self.statusBar().showMessage(message, 6000)
        if status_label is not None:
            status_label.setText(message)
        self._record_journal_event(
            "action.system_finished",
            severity="error",
            subject=label,
            template="Системное действие завершилось с ошибкой: {action}",
            values={"action": label},
        )

    def _publish_system_action_result(
        self,
        label: str,
        result: SystemActionResult,
        status_label: QLabel | None,
    ) -> None:
        message = f"{label}: {result.message}"
        self._append_log(("" if result.success else "Ошибка: ") + message)
        self.statusBar().showMessage(message, 6000)
        if status_label is not None:
            prefix = "Успешно" if result.success else "Ошибка"
            status_label.setText(f"{prefix}: {result.message}")
        self._record_journal_event(
            "action.system_finished",
            severity="info" if result.success else "error",
            subject=label,
            template="Системное действие {action}: {message}",
            values={"action": label, "message": result.message},
            refs={"success": result.success},
        )

    def _handle_rollback_system_action(
        self,
        label: str,
        result: SystemActionResult,
    ) -> bool:
        rollback = self._rollback_actions.pop(label, None)
        if rollback is None:
            return False
        change, _pending = rollback
        self._record_rollback_result(label, change, result)
        self._mtu_trial_change = None
        return True

    def _confirm_system_change(
        self,
        label: str,
        button: QPushButton,
        status_label: QLabel | None,
        change: SystemChange,
    ) -> None:
        pending = PendingAction(
            apply=lambda: self._record_journal_event(
                "action.system_confirmed",
                subject=change.adapter,
                template="Изменение подтверждено: {action}",
                values={"action": change.kind.upper()},
                refs={"adapter": change.adapter, "kind": change.kind},
            ),
            rollback=lambda change=change: rollback_change(change),
            timeout_s=self._action_confirm_timeout_s(),
        )
        dialog = RollbackConfirmDialog(change, self._tr, self, seconds=pending.timeout_s)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        if accepted:
            pending.apply()
            return
        rollback_label = f"Откат: {label}"
        self._rollback_actions[rollback_label] = (change, pending)
        self._run_system_action(
            rollback_label,
            pending.rollback,
            button,
            status_label,
        )

    @Slot(object)
    def _on_network_boost_terminated(self, value: object) -> None:
        self._set_network_boost_controls(False)
        if not isinstance(value, tuple) or not all(
            isinstance(item, ProcessTerminationResult) for item in value
        ):
            self._set_network_boost_status("Network Boost: результат завершения не распознан")
            return
        dialog = self._network_boost_dialog
        if dialog is not None:
            dialog.set_busy(False)
            dialog.apply_termination_results(value)
        completed = tuple(result for result in value if result.success)
        if not completed:
            details = "; ".join(result.message for result in value) or "нет выбранных процессов"
            self._set_network_boost_status(f"Network Boost: процессы не завершены: {details}")
            return
        names = ", ".join(result.name for result in completed)
        self._set_network_boost_status(f"Network Boost: завершено процессов: {len(completed)}")
        self._append_log(f"Network Boost: завершено {names}")
        self._offer_network_boost_retest(len(completed))

    def _record_rollback_result(
        self,
        label: str,
        change: SystemChange,
        result: SystemActionResult,
    ) -> None:
        severity = "info" if result.success else "error"
        self._record_journal_event(
            "action.system_rolled_back",
            severity=severity,
            subject=change.adapter,
            template="Откат изменения {action}: {message}",
            values={"action": change.kind.upper(), "message": result.message},
            refs={"success": result.success, "adapter": change.adapter},
        )
        reason = self._mtu_rollback_reasons.pop(label, None)
        if reason is not None:
            self._record_journal_event(
                "mtu.rolled_back",
                severity=severity,
                subject=change.adapter,
                template="Пробный MTU отменён: {reason}",
                values={"reason": reason, "mtu": change.after},
                refs={"success": result.success},
            )

    def _action_confirm_timeout_s(self) -> float:
        """Read the confirmation window from settings without changing its default."""
        configured = QSettings().value(
            "system_actions/confirm_timeout_s",
            self._thresholds.action_confirm_timeout_s,
        )
        try:
            return max(0.05, float(configured))
        except (TypeError, ValueError):
            return self._thresholds.action_confirm_timeout_s

    def _offer_network_boost_retest(self, completed_count: int) -> None:
        answer = QMessageBox.question(
            self,
            self._tr("Network Boost завершён"),
            self._translator.format(
                "Завершено фоновых процессов: {count}. Повторить проверку стабильности сейчас?",
                count=completed_count,
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        if self.mode_stack.currentWidget() is self.loss_view:
            self.loss_controller.start_packet_loss_analysis()
            return
        self.start_diagnostic()

    def _setup_network_health_tray(self) -> None:
        return self.teardown_coordinator._setup_network_health_tray()

    def _make_quick_action_button(
        self,
        label: str,
        action: Callable[[], SystemActionResult],
        primary: bool = False,
    ) -> QPushButton:
        button = QPushButton(label)
        button.setObjectName("QuickActionPrimary" if primary else "QuickActionButton")
        button.setToolTip(label)
        button.setAccessibleName(label)
        button.clicked.connect(
            lambda _checked=False, label=label, action=action, button=button: self._run_system_action(
                label,
                action,
                button,
            )
        )
        return button

    @Slot(QSystemTrayIcon.ActivationReason)
    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in {
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        }:
            self._show_from_tray()

    @Slot()
    def _show_from_tray(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    @Slot(bool)
    def _set_background_enabled(self, enabled: bool) -> None:
        self._background_enabled = enabled
        self._alarm_settings.setValue("background/enabled", enabled)

    @Slot(bool)
    def _set_game_monitor_from_tray(self, enabled: bool) -> None:
        if self.process_selector_panel.game_monitor_checkbox.isChecked() != enabled:
            self.process_selector_panel.game_monitor_checkbox.setChecked(enabled)

    @Slot(bool)
    def _set_notification_pause(self, paused: bool) -> None:
        return self.alarms_controller._set_notification_pause(paused)

    @Slot()
    def _exit_from_tray(self) -> None:
        self._quit_requested = True
        self.close()

    @Slot()
    def _toggle_header_anomaly_menu(self) -> None:
        """Show the recent anomaly history directly below the capsule status."""
        menu = self._header_anomaly_menu
        if menu is None:
            return
        if menu.isVisible():
            menu.hide()
            return
        anchor = self.header_panel.session_log_button.mapToGlobal(
            self.header_panel.session_log_button.rect().bottomLeft()
        )
        menu.popup(anchor)

    @Slot()
    def _open_manual_process_dialog(self) -> None:
        dialog = ManualProcessDialog(self._tr, self)
        dialog.process_selected.connect(self.process_controller._select_manual_process)
        dialog.exec()

    def _open_dns_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.dns_view:
            self._previous_workspace = (
                "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
            )
        self._close_combo_popups()
        self.mode_stack.setCurrentWidget(self.dns_view)
        self.dns_workspace.dns_back_button.setFocus()
        self.dns_controller._check_network_identity()
        self.dns_controller._load_dns_configuration()

    def _render_quality_mtu_placeholders(self) -> None:
        self.mtu_workspace.ping_mtu_table.setRowCount(0)
        self.mtu_workspace.ping_mtu_status.setText(self._tr("Готов к тесту"))

    def _open_ping_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.ping_view:
            self._previous_workspace = (
                "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
            )
        self._close_combo_popups()
        self.ping_controller._refresh_ping_statistics()
        self.mode_stack.setCurrentWidget(self.ping_view)
        self.ping_workspace.ping_back_button.setFocus()

    def _close_ping_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _open_jitter_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.jitter_view:
            self._previous_workspace = (
                "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
            )
        self._close_combo_popups()
        self._jitter_target_host = self.core_workspace.target_input.text().strip()
        self.jitter_controller._refresh_jitter_workspace()
        self.mode_stack.setCurrentWidget(self.jitter_view)
        self.jitter_workspace.jitter_back_button.setFocus()

    def _close_jitter_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _open_loss_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.loss_view:
            self._previous_workspace = (
                "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
            )
        self._close_combo_popups()
        self.loss_workspace.loss_target_input.setText(
            self.core_workspace.target_input.text().strip()
        )
        self.loss_workspace.loss_port_input.setValue(self.core_workspace.port_input.value())
        self._refresh_loss_workspace()
        self.mode_stack.setCurrentWidget(self.loss_view)
        self.loss_workspace.loss_back_button.setFocus()

    def _open_tcp_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.tcp_view:
            self._previous_workspace = (
                "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
            )
        self._close_combo_popups()
        self.tcp_workspace.tcp_target_input.setText(self.core_workspace.target_input.text().strip())
        self.tcp_workspace.tcp_ports_input.setText(self._default_tcp_port_text())
        self.mode_stack.setCurrentWidget(self.tcp_view)
        self.tcp_workspace.tcp_back_button.setFocus()

    def _close_tls_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    @Slot()
    def _copy_tls_fingerprint(self) -> None:
        fingerprint = self._tls_audit_result.fingerprint_sha256 if self._tls_audit_result else None
        if not fingerprint:
            self.tls_workspace.tls_audit_status.setText(
                "Сначала выполните аудит, чтобы получить SHA-256 отпечаток."
            )
            return
        QApplication.clipboard().setText(fingerprint)
        self.tls_workspace.tls_audit_status.setText("SHA-256 отпечаток скопирован в буфер обмена.")

    @Slot()
    def start_bufferbloat_test(self) -> None:
        return self.diagnostics_coordinator.start_bufferbloat_test()

    @Slot()
    def _refresh_history_view(self) -> None:
        return self.state_synchronizer._refresh_history_view()

    @Slot()
    def _clear_test_history(self) -> None:
        return self.history_controller._clear_test_history()

    @Slot()
    def start_quality_check(self) -> None:
        return self.diagnostics_coordinator.start_quality_check()

    @Slot()
    def start_nat_probe(self) -> None:
        return self.diagnostics_coordinator.start_nat_probe()

    @Slot(object)
    def _show_node_details(self, value: object) -> None:
        if not isinstance(value, TopologyNode):
            return
        self.node_details.detail_title.setText(value.primary)
        self._clear_detail_grid()
        details = value.details or {
            "Тип": value.label,
            "Описание": value.secondary,
            "Задержка": "--" if value.latency_ms is None else f"{value.latency_ms:.1f} ms",
        }
        for row, (key, text) in enumerate(details.items()):
            key_label = QLabel(self._tr(key).upper())
            key_label.setObjectName("FieldLabel")
            value_label = QLabel(self._tr(text))
            if key in {"IP", "Адрес", "Порт", "IP соединения"} or "IP" in key:
                value_label.setObjectName("MonospaceValue")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.node_details.detail_grid.addWidget(key_label, row, 0, Qt.AlignmentFlag.AlignTop)
            self.node_details.detail_grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)

    def _set_interface_mode(self, mode: str) -> None:
        self._close_combo_popups()
        self.mode_stack.setCurrentWidget(self.lite_view if mode == "lite" else self.expert_view)
        self.state_synchronizer._update_process_display(mode == "lite")
        self._schedule_responsive_layout_update()
        self._append_log("Включён простой режим" if mode == "lite" else "Включён экспертный режим")

    @Slot()
    def _export_udp_events_json(self) -> None:
        return self.history_controller._export_udp_events_json()

    @Slot()
    def _export_udp_events_csv(self) -> None:
        return self.history_controller._export_udp_events_csv()

    @Slot(QWidget, str)
    def _export_widget_png(self, widget: QWidget, section: str) -> None:
        if widget.width() <= 0 or widget.height() <= 0:
            QMessageBox.warning(
                self,
                self._tr("Экспорт сводки"),
                self._tr("Сводка пока недоступна для сохранения."),
            )
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_section = re.sub(r"[^A-Za-z0-9_-]", "_", section)
        suggested_name = str(Path.home() / f"NetVision_{safe_section}_{timestamp}.png")
        path, _filter = QFileDialog.getSaveFileName(
            self,
            self._tr("Экспорт сводки"),
            suggested_name,
            self._tr("PNG-изображение (*.png)"),
        )
        if not path:
            return
        if not path.lower().endswith(".png"):
            path += ".png"
        pixmap = QPixmap(widget.size())
        pixmap.fill(widget.palette().color(widget.backgroundRole()))
        widget.render(pixmap)
        if not pixmap.save(path, "PNG"):
            QMessageBox.critical(
                self,
                self._tr("Экспорт не выполнен"),
                self._tr("Не удалось сохранить изображение PNG."),
            )
            return
        self.statusBar().showMessage(
            self._translator.format("Сводка сохранена: {path}", path=path),
            6000,
        )
        self._append_log(f"PNG summary saved: {path}")

    def _header_anomaly_text(self, event: HeaderAnomalyEvent) -> str:
        return self._translator.format(event.source, **dict(event.values))

    @Slot()
    def _open_full_log_from_anomaly_menu(self) -> None:
        if self._header_anomaly_menu is not None:
            self._header_anomaly_menu.hide()
        self._open_log_from_header()

    def _default_tcp_port_text(self) -> str:
        primary = self.core_workspace.port_input.value()
        ports = tuple(dict.fromkeys((80, 443, 3389, primary)))
        return ", ".join(str(port) for port in ports)

    def _refresh_loss_workspace(self) -> None:
        return self.state_synchronizer._refresh_loss_workspace()

    @Slot(object)
    def _on_bufferbloat_completed(self, value: object) -> None:
        return self.diagnostics_coordinator._on_bufferbloat_completed(value)

    @Slot(str)
    def _on_bufferbloat_failed(self, message: str) -> None:
        return self.diagnostics_coordinator._on_bufferbloat_failed(message)

    @Slot()
    def _clear_bufferbloat_worker(self) -> None:
        if self.sender() is not self._bufferbloat_thread:
            return
        self._bufferbloat_thread = None
        self._bufferbloat_worker = None

    @Slot(object)
    def _on_quality_completed(self, value: object) -> None:
        return self.diagnostics_coordinator._on_quality_completed(value)

    @Slot(str)
    def _on_quality_failed(self, message: str) -> None:
        return self.diagnostics_coordinator._on_quality_failed(message)

    @Slot()
    def _clear_quality_worker(self) -> None:
        if self.sender() is not self._quality_thread:
            return
        self._quality_thread = None
        self._quality_worker = None

    @Slot(object)
    def _on_nat_probe_completed(self, value: object) -> None:
        return self.diagnostics_coordinator._on_nat_probe_completed(value)

    @Slot(str)
    def _on_nat_probe_failed(self, message: str) -> None:
        return self.diagnostics_coordinator._on_nat_probe_failed(message)

    @Slot()
    def _clear_nat_worker(self) -> None:
        if self.sender() is not self._nat_thread:
            return
        self._set_task_button_busy(self.quality_workspace.nat_probe_button, False)
        self.quality_workspace.nat_probe_button.setEnabled(True)
        self._nat_thread = None
        self._nat_worker = None

    def _export_udp_events(self, file_format: str) -> None:
        return self.history_controller._export_udp_events(file_format)

    @Slot()
    def _open_log_from_header(self) -> None:
        """Open the event log from any dashboard or deep-dive workspace."""
        if self._header_anomaly_menu is not None:
            self._header_anomaly_menu.hide()
        self._close_combo_popups()
        if not self.header_panel.expert_mode_button.isChecked():
            self.header_panel.expert_mode_button.setChecked(True)
        else:
            self.mode_stack.setCurrentWidget(self.expert_view)
            self.state_synchronizer._update_process_display(False)
        self.workspace_tabs.setCurrentWidget(self.log_tab)
        self.journal_tabs.setCurrentIndex(0)
        self.journal_workspace.journal_table.setFocus()

    def _finish_bufferbloat_test(self) -> None:
        self._set_task_button_busy(self.bufferbloat_workspace.bufferbloat_start_button, False)
        self.bufferbloat_workspace.bufferbloat_progress.hide()

    def _bufferbloat_attribution(self, report: BufferbloatReport) -> str:
        if (
            report.gateway_delta_ms is not None
            and report.gateway_delta_ms >= self._thresholds.bufferbloat_local_delta_ms
        ):
            return self._tr("Очередь LAN/Wi-Fi")
        if report.grade in {"C", "D", "F"}:
            return self._tr("Очередь WAN: SQM/QoS на роутере")
        return self._tr("Существенная очередь не обнаружена")

    def _record_bufferbloat_journal(
        self,
        report: BufferbloatReport,
        attribution: str,
    ) -> None:
        return self.history_controller._record_bufferbloat_journal(report, attribution)

    def _translate_quality_progress(self, message: str) -> str:
        for prefix, template in (
            ("Тест отдачи: ", "Тест отдачи: {host}"),
            ("Пинг под нагрузкой: ", "Пинг под нагрузкой: {target}"),
        ):
            if message.startswith(prefix):
                value = message.removeprefix(prefix)
                field = "host" if "{host}" in template else "target"
                return self._tr(template).format(**{field: value})
        return self._tr(message)

    def _finish_quality_check(self) -> None:
        self._set_task_button_busy(self.quality_workspace.quality_test_button, False)
        self.quality_workspace.quality_test_button.setEnabled(True)
        self.quality_workspace.quality_progress.hide()

    @Slot()
    def _finish_monitor_shutdown(self) -> None:
        if self._closing:
            QTimer.singleShot(0, self.close)

    def _load_preset_profiles(self) -> dict[str, tuple[str, str, int]]:
        profiles: dict[str, tuple[str, str, int]] = {}
        for profile_id, defaults in self._preset_defaults.items():
            default_label, default_host, default_port = defaults
            key = f"quick_profiles/{profile_id}"
            label = (
                str(self._preset_settings.value(f"{key}/label", default_label)).strip()
                or default_label
            )
            host = (
                str(self._preset_settings.value(f"{key}/host", default_host)).strip()
                or default_host
            )
            try:
                port = int(self._preset_settings.value(f"{key}/port", default_port))
            except (TypeError, ValueError):
                port = default_port
            profiles[profile_id] = (label, host, port if 1 <= port <= 65535 else default_port)
        return profiles

    def _update_responsive_layout(self) -> None:
        return self.state_synchronizer._update_responsive_layout()

    def _on_udp_port_snapshot(self, snapshot: object) -> None:
        """Compatibility seam for direct UI tests and external callers."""
        if isinstance(snapshot, UdpPortSnapshot):
            self._on_udp_port_activity(UdpPortHistory(max_entries=1).observe(snapshot))

    def _install_dashboard_shell(self) -> None:
        self.setWindowTitle(f"NetVision {display_version()} — Network Diagnostics & Insight")
        self.setMinimumSize(1120, 720)
        self.resize(1280, 820)

        theme_path = Path(__file__).with_name("cyber_theme.qss")
        try:
            self._dashboard_dark_style = theme_path.read_text(encoding="utf-8")
        except OSError:
            self._dashboard_dark_style = ""
        self._apply_dashboard_theme()

        self._build_native_shell()
        self.workspace_tabs.tabBar().hide()
        self.state_synchronizer._extract_quality_tabs()
        self.history_controller._restore_route_map()
        self._move_quick_actions_to_interfaces()
        self._move_mtu_section_to_interfaces()
        self._install_traceroute_history_chart()

        shell_layout = self.centralWidget().layout()
        shell_layout.addWidget(self.core_workspace._build_sidebar())

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(18, 18, 18, 18)
        body_layout.setSpacing(12)
        self.dashboard_stack = QStackedWidget()
        self.region_card = RegionCard(self._tr)
        self.events_card = EventsCard(self._tr)
        self.dashboard_overview = self.core_workspace._build_overview_page()
        self.dashboard_details = self.core_workspace._build_details_page()
        self.dashboard_stack.addWidget(self.dashboard_overview)
        self.dashboard_stack.addWidget(self.dashboard_details)
        body_layout.addWidget(self.dashboard_stack, 1)
        shell_layout.addWidget(body, 1)

    def _build_native_shell(self) -> None:
        """Create dashboard-owned containers while retaining existing pages."""
        self._legacy_central = self.takeCentralWidget()
        if self._legacy_central is not None:
            self._legacy_central.setParent(self)
            self._legacy_central.hide()

        old_tabs = self.workspace_tabs
        self._legacy_workspace_tabs = old_tabs
        self.workspace_tabs = QTabWidget()
        while old_tabs.count():
            page = old_tabs.widget(0)
            title = old_tabs.tabText(0)
            icon = old_tabs.tabIcon(0)
            old_tabs.removeTab(0)
            self.workspace_tabs.addTab(page, icon, title)

        old_stack = self.mode_stack
        self._legacy_mode_stack = old_stack
        self._legacy_mode_scroll = self.mode_scroll
        self.mode_stack = QStackedWidget()
        while old_stack.count():
            page = old_stack.widget(0)
            old_stack.removeWidget(page)
            self.mode_stack.addWidget(page)
        self.mode_scroll = QScrollArea(self._legacy_central)
        self.mode_scroll.setWidgetResizable(True)
        self.mode_scroll.setWidget(self.mode_stack)
        self.mode_scroll.hide()

        shell = QWidget()
        shell.setObjectName("MainBg")
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        self.setCentralWidget(shell)

    @Slot(int)
    def _dashboard_quality_tab_changed(self, index: int) -> None:
        if self.dashboard_quality_tabs.widget(index) is self.dns_view:
            self.dns_controller._check_network_identity()
            self.dns_controller._load_dns_configuration()

    def _open_tls_workspace(self) -> None:
        if self._dashboard_ready:
            self._show_dashboard_section("tls")
            self.tls_workspace.tls_target_input.setFocus()
        else:
            self._inherited__open_tls_workspace()

    @Slot()
    def _open_connection_capture_dialog(self) -> None:
        dialog = ConnectionCaptureDialog(
            self._preset_profiles,
            self._active_preset,
            self._tr,
            self,
        )
        dialog.connection_selected.connect(self._save_captured_connection)
        dialog.exec()

    @Slot()
    def _open_geohide_dialog(self) -> None:
        if self._geohide_dialog is None:
            self._geohide_dialog = GeoHideDialog(
                self,
                self._tr,
                self.dns_controller._use_geohide_dns,
                self._worker_registry,
            )
            self._geohide_dialog.finished.connect(self._clear_geohide_dialog)
            QTimer.singleShot(0, self._geohide_dialog._refresh)
        self._geohide_dialog.show()
        self._geohide_dialog.raise_()
        self._geohide_dialog.activateWindow()

    @Slot()
    def _dashboard_reset_tls(self) -> None:
        self._dashboard_tls_generation += 1
        self._tls_audit_result = None
        self._render_tls_placeholders()
        self.tls_workspace.tls_audit_status.setText(
            self._tr("Укажите цель и запустите проверку сертификата")
        )

    def _install_traceroute_history_chart(self) -> None:
        """Add one bounded RTT history view below both traceroute data tables."""
        route_tabs = getattr(self.mtr_workspace, "traceroute_mode_tabs", None)
        if not self._qt_object_is_alive(route_tabs):
            return
        container = route_tabs.parentWidget()
        layout = container.layout() if container is not None else None
        if layout is None:
            return
        tab_index = layout.indexOf(route_tabs)
        if tab_index < 0:
            return

        self._remove_trailing_spacer(layout)
        layout.removeWidget(route_tabs)
        history_card = self.core_workspace._build_hop_history_card()
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setObjectName("TracerouteHistorySplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setMinimumHeight(430)
        splitter.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        splitter.addWidget(route_tabs)
        splitter.addWidget(history_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([360, 170])
        layout.insertWidget(tab_index, splitter, 1)
        self.dashboard_traceroute_history_splitter = splitter
        self.mtr_workspace.traceroute_table.itemSelectionChanged.connect(
            self._dashboard_select_traceroute_hop
        )
        self.mtr_workspace.mtr_table.itemSelectionChanged.connect(self._dashboard_select_mtr_hop)

    @staticmethod
    def _remove_trailing_spacer(layout: QLayout) -> None:
        item = layout.itemAt(layout.count() - 1)
        if item is not None and item.spacerItem() is not None:
            layout.takeAt(layout.count() - 1)

    def _move_quick_actions_to_interfaces(self) -> None:
        """Place Windows system actions in the interface workspace only."""
        interface_tab = self.workspace_tabs.widget(ui_constants.WORKSPACE_TABS["interfaces"])
        if interface_tab is None or not hasattr(
            getattr(self, "core_workspace", None), "quick_actions_panel"
        ):
            return
        actions_host = interface_tab.findChild(QFrame, "InterfaceActionsHost")
        if actions_host is not None and actions_host.layout() is not None:
            if self.core_workspace.quick_actions_panel.parentWidget() is not actions_host:
                self.core_workspace.quick_actions_panel.setParent(None)
            actions_host.layout().addWidget(self.core_workspace.quick_actions_panel)
            interface_tab.show()
            actions_host.show()
            self.core_workspace.quick_actions_panel.show()

    def _move_mtu_section_to_interfaces(self) -> None:
        """Expose the existing MTU workflow beside the active interface details."""
        interface_tab = self.workspace_tabs.widget(ui_constants.WORKSPACE_TABS["interfaces"])
        mtu_panel = getattr(getattr(self, "mtu_workspace", None), "mtu_optimizer_panel", None)
        if (
            interface_tab is None
            or interface_tab.layout() is None
            or not self._qt_object_is_alive(mtu_panel)
        ):
            return
        mtu_panel.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        self.mtu_workspace.mtu_section_title.setText(self._tr("MTU"))
        self.mtu_workspace.ping_mtu_host_input.setReadOnly(True)
        self.mtu_workspace.ping_mtu_host_input.setClearButtonEnabled(False)
        self.mtu_workspace.ping_mtu_table.setMinimumHeight(190)
        mtu_panel.setMaximumHeight(16777215)
        mtu_panel.layout().setSpacing(10)
        interface_tab.layout().addWidget(mtu_panel)
        self.dashboard_mtu_section = mtu_panel
        mtu_panel.show()
        interface_tab.show()

    @Slot(str)
    def _dashboard_sync_mtu_target(self, target: str) -> None:
        if not self._qt_object_is_alive(
            getattr(getattr(self, "mtu_workspace", None), "ping_mtu_host_input", None)
        ):
            return
        self.mtu_workspace.ping_mtu_host_input.setText(target.strip())

    @Slot()
    def _show_dashboard_mtu_section(self) -> None:
        self._show_dashboard_section("interfaces")
        if self._dashboard_widgets_alive(getattr(self, "dashboard_mtu_section", None)):
            self.dashboard_mtu_section.setFocus()

    @staticmethod
    def _qt_object_is_alive(value: object | None) -> bool:
        try:
            return value is not None and isValid(value)
        except RuntimeError:
            return False

    def _dashboard_widgets_alive(self, *widgets: object) -> bool:
        return (
            not self._dashboard_closing
            and self._qt_object_is_alive(self)
            and all(self._qt_object_is_alive(widget) for widget in widgets)
        )

    def _restore_dashboard_splitter_state(
        self,
        splitter: QSplitter,
        settings_key: str,
        default_sizes: tuple[int, ...],
    ) -> None:
        state = self._dashboard_settings.value(
            settings_key,
            QByteArray(),
            type=QByteArray,
        )
        if not state or not splitter.restoreState(state):
            splitter.setSizes(list(default_sizes))

    def _save_dashboard_splitter_state(
        self,
        splitter: QSplitter,
        settings_key: str,
    ) -> None:
        if not self._qt_object_is_alive(splitter):
            return
        self._dashboard_settings.setValue(
            settings_key,
            splitter.saveState(),
        )
        self._dashboard_settings.sync()

    def _dashboard_set_waiting_state(self) -> None:
        self.core_workspace.dashboard_status_pill.setText(self._tr("ОЖИДАНИЕ ПРОВЕРКИ"))
        self.core_workspace.dashboard_status_pill.setProperty("healthState", "neutral")
        self.core_workspace.dashboard_status_subtitle.setText(
            f"00:00 • {self._tr('Ожидание проверки')}"
        )
        self.core_workspace.dashboard_topology_label.setText(
            self._tr("Локальный интерфейс и шлюз определяются…")
        )
        neutral_metrics = ui_constants.DASHBOARD_NEUTRAL_METRICS
        for key, card in self.core_workspace.dashboard_metric_cards.items():
            card.set_metric(neutral_metrics[key], "neutral")
        self.region_card.dashboard_region_table.setRowCount(0)
        self.events_card.dashboard_action_status.setText(self._tr("Воркеры свободны"))
        self._dashboard_append_event(self._tr("Готов к запуску диагностики. Все воркеры свободны."))

    def _load_local_network_snapshot(self) -> None:
        if self._dashboard_closing or not self._dashboard_widgets_alive():
            return
        worker = LocalNetworkSnapshotWorker()
        worker.completed.connect(
            self._on_dashboard_local_snapshot,
            Qt.ConnectionType.QueuedConnection,
        )
        self._dashboard_local_thread = self._worker_registry.start(worker)
        self._dashboard_local_thread.finished.connect(
            self._clear_dashboard_local_snapshot,
            Qt.ConnectionType.QueuedConnection,
        )

    @Slot()
    def _clear_dashboard_local_snapshot(self) -> None:
        if (
            not self._dashboard_closing
            and self._dashboard_local_thread is not None
            and self.sender() is self._dashboard_local_thread
        ):
            self._dashboard_local_thread = None

    @Slot(object)
    def _on_dashboard_local_snapshot(self, value: object) -> None:
        return self.diagnostics_coordinator._on_dashboard_local_snapshot(value)

    def _show_dashboard_section(self, section: str) -> None:
        self._set_dashboard_navigation(section)
        if section == "overview":
            self._show_dashboard_overview()
            return
        if not self._dashboard_widgets_alive(
            self.dashboard_stack, self.core_workspace.dashboard_details_stack
        ):
            return
        self.dashboard_stack.setCurrentWidget(self.dashboard_details)
        self._show_dashboard_detail_section(section)

    def _set_dashboard_navigation(self, section: str) -> None:
        for key, button in self.core_workspace.dashboard_nav_buttons.items():
            button.blockSignals(True)
            button.setChecked(key == section or (section == "diagnosis" and key == "overview"))
            button.blockSignals(False)

    def _show_dashboard_overview(self) -> None:
        if not self._dashboard_widgets_alive(self.dashboard_stack):
            return
        self.dashboard_stack.setCurrentWidget(self.dashboard_overview)

    def _show_dashboard_detail_section(self, section: str) -> None:
        if section in ui_constants.QUALITY_TABS:
            self.core_workspace.dashboard_details_stack.setCurrentWidget(
                self.dashboard_quality_tabs
            )
            self.dashboard_quality_tabs.setCurrentIndex(ui_constants.QUALITY_TABS[section])
            self._ensure_quality_visibility()
            return
        if not self._dashboard_widgets_alive(self.workspace_tabs):
            return
        self.core_workspace.dashboard_details_stack.setCurrentWidget(self.workspace_tabs)
        index = ui_constants.WORKSPACE_TABS.get(section, ui_constants.WORKSPACE_TABS["diagnosis"])
        self.workspace_tabs.setCurrentIndex(index)
        self._ensure_workspace_visibility(index)
        if section == "journal":
            self.journal_tabs.setCurrentIndex(0)
        elif section == "udp":
            self.journal_tabs.setCurrentIndex(1)
        if section in {"journal", "udp"}:
            self._ensure_workspace_visibility(index)

    def _ensure_workspace_visibility(self, index: int) -> None:
        """Restore the visible chain after a workspace widget was reparented."""
        if not self._dashboard_widgets_alive(
            self.dashboard_stack,
            self.core_workspace.dashboard_details_stack,
            self.workspace_tabs,
        ):
            return
        self.dashboard_details.show()
        self.dashboard_details.setVisible(True)
        self.core_workspace.dashboard_details_stack.setCurrentWidget(self.workspace_tabs)
        self.core_workspace.dashboard_details_stack.show()
        self.core_workspace.dashboard_details_stack.setVisible(True)
        self.workspace_tabs.show()
        self.workspace_tabs.setVisible(True)
        page = self.workspace_tabs.widget(index)
        if page is not None and self._qt_object_is_alive(page):
            page.show()
            page.setVisible(True)
        if index == ui_constants.WORKSPACE_TABS["traceroute"]:
            nested = getattr(self.mtr_workspace, "traceroute_mode_tabs", None)
        elif index == ui_constants.WORKSPACE_TABS["journal"]:
            nested = getattr(self, "journal_tabs", None)
        else:
            nested = None
        if nested is not None and self._qt_object_is_alive(nested):
            nested.show()
            nested.setVisible(True)
            current = nested.currentWidget()
            if current is not None:
                current.show()
                current.setVisible(True)

    def _ensure_quality_visibility(self) -> None:
        if not self._dashboard_widgets_alive(
            self.dashboard_stack,
            self.core_workspace.dashboard_details_stack,
            self.dashboard_quality_tabs,
        ):
            return
        self.dashboard_details.show()
        self.dashboard_details.setVisible(True)
        self.core_workspace.dashboard_details_stack.setCurrentWidget(self.dashboard_quality_tabs)
        self.core_workspace.dashboard_details_stack.show()
        self.core_workspace.dashboard_details_stack.setVisible(True)
        self.dashboard_quality_tabs.show()
        self.dashboard_quality_tabs.setVisible(True)
        current = self.dashboard_quality_tabs.currentWidget()
        if current is not None:
            current.show()
            current.setVisible(True)

    def _dashboard_record_hop_sample(
        self,
        hop: int,
        address: str | None,
        rtt_ms: float | None,
    ) -> bool:
        if rtt_ms is None or not math.isfinite(rtt_ms):
            return False
        history = self._dashboard_hop_histories.setdefault(
            hop,
            deque(maxlen=ui_constants.DASHBOARD_HOP_HISTORY_SAMPLES),
        )
        history.append(rtt_ms)
        if address:
            self._dashboard_hop_addresses[hop] = address
        return True

    def _dashboard_select_traceroute_hop(self) -> None:
        self._dashboard_select_hop_from_table(self.mtr_workspace.traceroute_table)

    def _dashboard_select_mtr_hop(self) -> None:
        self._dashboard_select_hop_from_table(self.mtr_workspace.mtr_table)

    def _dashboard_select_hop_from_table(self, table: QTableWidget) -> None:
        row = table.currentRow()
        hop_item = table.item(row, 0) if row >= 0 else None
        if hop_item is None:
            return
        try:
            hop = int(hop_item.text())
        except ValueError:
            return
        address_item = table.item(row, 1)
        address = address_item.text() if address_item is not None else None
        self._dashboard_select_hop(hop, address)

    def _dashboard_auto_select_hop(self, hop: int, table: QTableWidget) -> None:
        if self._dashboard_selected_hop is not None:
            return
        self._dashboard_select_hop(hop, self._dashboard_hop_addresses.get(hop))
        self._dashboard_select_table_row(table, hop)

    @staticmethod
    def _dashboard_select_table_row(table: QTableWidget, hop: int) -> None:
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is not None and item.text() == f"{hop:02}":
                table.selectRow(row)
                return

    def _dashboard_select_hop(self, hop: int, address: str | None) -> None:
        self._dashboard_selected_hop = hop
        if address and address not in {"--", "???"}:
            self._dashboard_hop_addresses[hop] = address
        self._dashboard_refresh_hop_history()

    def _dashboard_reset_hop_history(self) -> None:
        self._dashboard_hop_histories.clear()
        self._dashboard_hop_addresses.clear()
        self._dashboard_selected_hop = None
        self.mtr_workspace.traceroute_table.clearSelection()
        self.mtr_workspace.mtr_table.clearSelection()
        self._dashboard_refresh_hop_history()

    def _dashboard_refresh_hop_history(self) -> None:
        if not self._dashboard_widgets_alive(
            self.core_workspace.dashboard_hop_history_chart,
            self.core_workspace.dashboard_hop_history_title,
        ):
            return
        hop = self._dashboard_selected_hop
        if hop is None:
            self.core_workspace.dashboard_hop_history_title.setText(
                self._tr("Выберите узел в таблице для просмотра графика")
            )
            self.core_workspace.dashboard_hop_history_chart.set_samples(())
            return
        address = self._dashboard_hop_addresses.get(hop, "???")
        self.core_workspace.dashboard_hop_history_title.setText(
            self._translator.format(
                "История задержки узла: #{hop:02} — {address}",
                hop=hop,
                address=address,
            )
        )
        self.core_workspace.dashboard_hop_history_chart.set_samples(
            self._dashboard_hop_histories.get(hop, ())
        )

    @Slot(str)
    def _retranslate_ui(self, language: str) -> None:
        self._inherited__retranslate_ui(language)
        for label, caption in getattr(self, "_dashboard_udp_labels", ()):
            label.setText(self._tr(caption))
        if hasattr(self, "dashboard_quality_tabs"):
            self.dashboard_quality_tabs.setTabText(3, self._tr("Порт и TLS"))
        if not hasattr(getattr(self, "core_workspace", None), "dashboard_hop_history_title"):
            return
        self.core_workspace.dashboard_hop_history_chart.setToolTip(
            self._tr("Последние измерения RTT выбранного узла; тайм-ауты не отображаются")
        )
        self._dashboard_refresh_hop_history()

    @Slot()
    def _toggle_theme(self) -> None:
        self._inherited__toggle_theme()
        self._apply_dashboard_theme()

    def _apply_dashboard_theme(self) -> None:
        style = self._dashboard_dark_style
        if self._theme == "light":
            style += ui_constants.CYBER_LIGHT_OVERRIDES
        self.setStyleSheet(style)

    @Slot()
    def _dashboard_start_diagnostics(self) -> None:
        self._dashboard_apply_target()
        self._dashboard_apply_port()
        self.start_diagnostic()

    @Slot()
    def _dashboard_apply_target(self) -> None:
        if self._dashboard_syncing:
            return
        value = self.core_workspace.dashboard_target_input.text().strip()
        if value and value != self.core_workspace.target_input.text():
            self.core_workspace.target_input.setText(value)

    @Slot(int)
    def _dashboard_sync_tcp_ports(self, port: int) -> None:
        self.tcp_workspace.tcp_ports_input.setText(str(port))

    @Slot(int)
    def _dashboard_apply_port(self, value: int | None = None) -> None:
        if self._dashboard_syncing:
            return
        port = int(value if value is not None else self.core_workspace.dashboard_port_input.value())
        if port != self.core_workspace.port_input.value():
            self.core_workspace.port_input.setValue(port)

    def _dashboard_sync_controls(self) -> None:
        if not self._dashboard_ready:
            return
        self._dashboard_syncing = True
        try:
            self.core_workspace.dashboard_target_input.setText(
                self.core_workspace.target_input.text()
            )
            self._dashboard_sync_mtu_target(self.core_workspace.target_input.text())
            self.core_workspace.dashboard_port_input.setValue(
                self.core_workspace.port_input.value()
            )
            self.tls_workspace.tls_target_input.setText(
                self.core_workspace.dashboard_target_input.text()
            )
            self.tls_workspace.tls_port_input.setValue(
                self.core_workspace.dashboard_port_input.value()
            )
            self.tcp_workspace.tcp_target_input.setText(
                self.core_workspace.dashboard_target_input.text()
            )
            self._dashboard_sync_tcp_ports(self.core_workspace.dashboard_port_input.value())
            mode = target_mode(
                self.core_workspace.target_input.text(),
                self._selected_connection.protocol if self._selected_connection else "TCP",
            )
            self.core_workspace.dashboard_target_mode.setText(self._tr(mode))
            self.core_workspace.dashboard_port_input.setToolTip(
                self._tr(
                    "Порт (UDP)"
                    if self._selected_connection
                    and self._selected_connection.protocol.upper() == "UDP"
                    else "Порт (TCP)"
                )
            )
            self.core_workspace.dashboard_port_input.setPrefix(
                self._tr(
                    "Порт (UDP)"
                    if self._selected_connection
                    and self._selected_connection.protocol.upper() == "UDP"
                    else "Порт (TCP)"
                )
                + " "
            )
        finally:
            self._dashboard_syncing = False

    @staticmethod
    def _dashboard_select_combo_value(combo: QComboBox, value: object) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return
        combo.setCurrentIndex(-1)

    def _dashboard_render_topology(self, report: DiagnosticReport) -> None:
        local_ip = self._first_local_ip(report.system)
        gateway = (
            report.system.gateway.address
            if report.system.gateway is not None
            else "шлюз не определён"
        )
        endpoint = report.tcp.peer_address or report.target.host
        geo = next((item for item in report.geolocation if item.address == endpoint), None)
        target_name = report.target.host or report.target.display_name
        provider = (geo.organization or geo.isp or geo.asn) if geo is not None else None
        endpoint_label = f"{target_name} • {provider}" if provider else target_name
        self.core_workspace.dashboard_topology_label.setText(
            f"[Ваш ПК: {local_ip}]  →  [Шлюз: {gateway}]  →  [{endpoint_label}]"
        )

    def _dashboard_render_regions(self, report: DiagnosticReport | None = None) -> None:
        rows, row_states = self._dashboard_region_data(report)
        self.region_card.dashboard_region_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self._dashboard_set_region_row(row_index, row, row_states)

    def _dashboard_region_data(
        self, report: DiagnosticReport | None
    ) -> tuple[list[tuple[str, str, str, str, str]], list[str]]:
        rows, row_states = self._dashboard_matrix_rows()
        if not rows and report is not None:
            row, state = self._dashboard_report_row(report)
            rows.append(row)
            row_states.append(state)
        connection = self._dashboard_game_connection or self._selected_connection
        if self._dashboard_game_connection is not None:
            row, state = self._dashboard_game_row(connection)
            rows.append(row)
            row_states.append(state)
        elif not rows and connection is not None:
            row, state = self._dashboard_selected_connection_row(connection)
            rows.append(row)
            row_states.append(state)
        return rows, row_states

    def _dashboard_matrix_rows(
        self,
    ) -> tuple[list[tuple[str, str, str, str, str]], list[str]]:
        rows: list[tuple[str, str, str, str, str]] = []
        row_states: list[str] = []
        for result in self._ping_matrix_results:
            state = "good" if result.success and result.ping.loss_percent == 0 else "error"
            rows.append(
                (
                    result.target.region,
                    result.target.host,
                    self._format_ms(result.latency_ms),
                    f"{result.ping.loss_percent:.0f}%",
                    "Доступен" if result.success else "Нет ответа",
                )
            )
            row_states.append(state)
        return rows, row_states

    def _dashboard_report_row(
        self, report: DiagnosticReport
    ) -> tuple[tuple[str, str, str, str, str], str]:
        state = "good" if report.ping.loss_percent == 0 else "warning"
        return (
            (
                "Целевой узел",
                report.target.display_name,
                self._format_ms(report.ping.average_ms),
                f"{report.ping.loss_percent:.0f}%",
                "Стабильно" if report.ping.loss_percent == 0 else "Предупреждение",
            ),
            state,
        )

    def _dashboard_game_row(
        self, connection: ProcessConnection
    ) -> tuple[tuple[str, str, str, str, str], str]:
        rtt, loss, success = self._dashboard_game_metrics or (None, 0.0, False)
        status, state = self._dashboard_game_status(rtt, loss, success)
        return (
            (
                self._tr("Игровой процесс"),
                connection.remote_endpoint,
                self._format_ms(rtt) if success else "— ms",
                f"{loss:.0f}%" if self._dashboard_game_metrics is not None else "—",
                status,
            ),
            state,
        )

    def _dashboard_selected_connection_row(
        self, connection: ProcessConnection
    ) -> tuple[tuple[str, str, str, str, str], str]:
        process_name = self._selected_process.name if self._selected_process else "Процесс"
        return (
            (
                (
                    self._tr("Игровой процесс")
                    if connection is self._dashboard_game_connection
                    else process_name
                ),
                connection.remote_endpoint,
                "—",
                "—",
                (
                    "Выбран автопроверкой"
                    if connection is self._dashboard_game_connection
                    else "Ожидание проверки"
                ),
            ),
            "neutral",
        )

    def _dashboard_game_status(
        self, rtt: float | None, loss: float, success: bool
    ) -> tuple[str, str]:
        if self._dashboard_game_metrics is None:
            return "Проверка…", "neutral"
        if not success:
            return "Внимание", "error"
        if rtt is not None and rtt < self._thresholds.game_good_rtt_ms and loss == 0.0:
            return "Отлично", "good"
        if (rtt is not None and rtt > self._thresholds.rtt_high_ms) or loss > 0.0:
            state = (
                "error"
                if loss >= self._thresholds.loss_warn_pct
                or (rtt or 0.0) >= self._thresholds.rtt_peak_ms
                else "warning"
            )
            return "Внимание", state
        return "Стабильно", "good"

    def _dashboard_set_region_row(
        self,
        row_index: int,
        row: tuple[str, str, str, str, str],
        row_states: list[str],
    ) -> None:
        state = row_states[row_index] if row_index < len(row_states) else "neutral"
        for column, value in enumerate(row):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            if column == 4:
                item.setForeground(
                    QColor(
                        {
                            "good": "#34D399",
                            "warning": "#FBBF24",
                            "error": "#FB7185",
                        }.get(state, "#94A3B8")
                    )
                )
            self.region_card.dashboard_region_table.setItem(row_index, column, item)

    @staticmethod
    def _dashboard_quality_states(
        loss: float,
        jitter: float | None,
        thresholds: Thresholds,
    ) -> tuple[str, str]:
        return judgement.metric_states(loss, jitter, thresholds)

    def _dashboard_add_sample(self, key: str, value: float | None) -> None:
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            self._dashboard_histories[key].append(float(value))
            if key == "ping":
                self._dashboard_histories["latency"].append(float(value))

    @staticmethod
    def _first_local_ip(snapshot: SystemSnapshot) -> str:
        for route in sorted(snapshot.default_routes, key=lambda route: route.metric):
            if route.local_address and not route.local_address.startswith("127."):
                return route.local_address
        for interface in snapshot.interfaces:
            if interface.is_up:
                for address in interface.ipv4:
                    if not address.startswith("127."):
                        return address
        return "локальный IP не определён"

    @staticmethod
    def _format_ms(value: float | None) -> str:
        return "— ms" if value is None else f"{value:.1f} ms"

    def _latency_state(self, value: float | None, threshold: float | None = None) -> str:
        if value is None:
            return "neutral"
        limit = threshold if threshold is not None else self._thresholds.rtt_high_ms
        if value >= self._thresholds.rtt_peak_ms:
            return "error"
        return "warning" if value > limit else "good"

    def _dashboard_append_event(self, message: str) -> None:
        if not hasattr(
            getattr(self, "events_card", None), "dashboard_event_output"
        ) or not self._dashboard_widgets_alive(self.events_card.dashboard_event_output):
            return
        if "UDP-порты PID" in message and not self.events_card.show_udp_events.isChecked():
            return
        self._dashboard_events.append(
            f"[{self._format_session_elapsed(self._session_elapsed_seconds)}] {message}"
        )
        self.events_card.dashboard_event_output.setPlainText("\n".join(self._dashboard_events))
        self.events_card.dashboard_event_output.verticalScrollBar().setValue(
            self.events_card.dashboard_event_output.verticalScrollBar().maximum()
        )

    # Dashboard hooks update the shared state and visible controls together.
    def showEvent(self, event: object) -> None:
        """Show the shell without starting target monitoring before a user test.

        The legacy window starts a latency monitor from ``showEvent``. The
        dashboard keeps its metrics neutral until the user starts diagnostics;
        it only restores the established background-mode journal behaviour.
        """

        QMainWindow.showEvent(self, event)  # type: ignore[arg-type]
        if self._dashboard_closing:
            return
        if self._background_hidden:
            self._background_hidden = False
            self._record_journal_event(
                "app.background_left",
                subject="application",
                template="Приложение возвращено из фонового режима",
            )

    @Slot(str)
    def _append_log(self, message: str) -> None:
        try:
            if QThread.currentThread() != self.thread():
                self._ui_log_requested.emit(message)
                return
        except RuntimeError:
            return
        self._inherited__append_log(message)
        if self._dashboard_ready and self._dashboard_widgets_alive(
            self.events_card.dashboard_event_output
        ):
            self._dashboard_append_event(message)

    def _set_status(self, text: str, state: str) -> None:
        return self.state_synchronizer._set_status(text, state)

    def _set_running(self, running: bool) -> None:
        self._inherited__set_running(running)
        if self._dashboard_ready and self._dashboard_widgets_alive(
            self.core_workspace.dashboard_start_button
        ):
            self.core_workspace.dashboard_start_button.setEnabled(not running)
            self.core_workspace.dashboard_start_button.setText(
                "Проверка выполняется…" if running else "Начать диагностику"
            )
            if running:
                self.overview_controller._dashboard_apply_health(
                    "running", self._tr("Запуск диагностики")
                )

    def _refresh_session_capsule(self) -> None:
        return self.state_synchronizer._refresh_session_capsule()

    @Slot(object)
    def _on_endpoint_chosen(self, value: object) -> None:
        return self.diagnostics_coordinator._on_endpoint_chosen(value)

    @Slot()
    def _dashboard_probe_regions_once(self) -> None:
        if not self._dashboard_autoprobe or self._dashboard_regions_probed:
            return
        self._dashboard_regions_probed = True
        self.ping_controller.start_ping_benchmark()

    @Slot(object)
    def _on_completed(self, report: object) -> None:
        return self.diagnostics_coordinator._on_completed(report)

    def _reset_results(self, target: object) -> None:
        return self.diagnostics_coordinator._reset_results(target)

    def _dashboard_update_mtu_hint(self) -> None:
        analysis = getattr(self, "_root_cause_analysis", None)
        visible = any(
            getattr(finding, "title", "") == "Проверить MTU"
            for finding in getattr(analysis, "findings", ())
        )
        if visible and not self._dashboard_mtu_hint_chips:
            self._dashboard_mtu_hint_chips = tuple(
                self.core_workspace.dashboard_metric_cards[key].add_action_chip(
                    self._tr("Проверить MTU"),
                    self._show_dashboard_mtu_section,
                )
                for key in ("tcp", "tls")
            )
        for chip in self._dashboard_mtu_hint_chips:
            if self._qt_object_is_alive(chip):
                chip.setVisible(visible)

    @Slot(object)
    def _on_failed(self, failure: object) -> None:
        return self.diagnostics_coordinator._on_failed(failure)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.teardown_coordinator.execute_teardown(event)
