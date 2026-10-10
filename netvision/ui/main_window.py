from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import csv
import json
from pathlib import Path
import re

from PySide6.QtCore import QEvent, QIODevice, QObject, QSaveFile, QSettings, QThread, QTimer, QUrl, Qt, Signal, Slot
from PySide6.QtGui import QColor, QCloseEvent, QCursor, QShowEvent, QWheelEvent
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractScrollArea,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QSpinBox,
    QSplitter,
    QStyle,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QToolTip,
    QVBoxLayout,
    QWidget,
    QWidgetAction,
)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
except Exception:  # QtWebEngine is an optional dependency for portable builds.
    QWebEngineView = None

from netvision.core.diagnostics import DiagnosticService
from netvision.core.dns_benchmark import (
    DnsBenchmarkResult,
    DnsResolverProfile,
    PUBLIC_DNS_PROFILES,
    benchmark_resolvers,
    custom_dns_profile,
)
from netvision.core.geohide import GeoHideResult, fetch_geohide_dns
from netvision.core.internet_quality import (
    InternetQualityReport,
    PublicIpAddresses,
    build_smart_report,
    fetch_public_ip_addresses,
    run_internet_quality_check,
)
from netvision.core.network_boost import (
    BackgroundTrafficCandidate,
    NetworkBoostScanResult,
    ProcessTerminationResult,
    scan_background_traffic_candidates,
    terminate_background_candidates,
)
from netvision.core.packet_loss import (
    HopLossResult,
    PacketLossAnalyzer,
    PacketLossSnapshot,
    StressTestResult,
    run_hop_loss_breakdown,
    run_icmp_stress_test,
    run_udp_stress_test,
    summarize_loss,
)
from netvision.core.tcp_diagnostics import (
    TcpConnectMeasurement,
    TcpSocketRecord,
    probe_common_ports,
    probe_tcp_connect,
    scan_tcp_sockets,
)
from netvision.core.tls_diagnostics import CertificateRecord, TlsAuditResult, audit_tls_endpoint
from netvision.core.ping_benchmark import (
    LatencyStatistics,
    MtuProbeResult,
    RegionalPingTarget,
    RegionalPingResult,
    REGIONAL_GAMING_TARGETS,
    benchmark_regional_targets,
    latency_statistics,
    run_mtu_stress_test,
)
from netvision.core.process_inspector import (
    ProcessConnection,
    ProcessListResult,
    ProcessNetworkInfo,
    ProcessScanResult,
    RunningProcess,
    list_running_processes,
    scan_processes,
)
from netvision.core.probes import probe_ping
from netvision.core.udp_monitor import UdpPortActivity, UdpPortHistory, UdpPortSnapshot, get_process_udp_ports
from netvision.core.root_cause import analyze_report
from netvision.core.system_actions import (
    SystemActionResult,
    apply_dns_servers,
    flush_dns_cache,
    optimize_mtu,
    open_network_adapters,
    open_network_proxy_settings,
    open_windows_firewall,
    reset_tcpip_stack,
    restart_network_adapter,
)
from netvision.core.system import DnsConfiguration, collect_dns_configuration
from netvision.core.target import parse_target
from netvision.models import DiagnosticReport, HopResult, NetworkInterface, ProbeStatus, SystemSnapshot, Target
from netvision.reporting import serialize_report, serialize_udp_events_csv, serialize_udp_events_json
from netvision.ui.theme import APP_STYLE, LIGHT_STYLE
from netvision.ui.i18n import UiTranslator
from netvision.ui.monitor_workers import LatencyMonitorWorker, WorkerRegistry, UdpPortMonitorWorker
from netvision.ui.widgets import (
    EmbeddedComboBox,
    LatencyChart,
    JitterChart,
    MetricTile,
    ResponsiveMetricGrid,
    TopologyNode,
    TopologyWidget,
    apply_accent_glow,
    apply_panel_shadow,
)
from netvision.ui.lite_mode import LiteStatus, summarize_report


METRIC_TOOLTIPS = {
    "dns": "Перевод имени в адрес. Показывает, насколько быстро компьютер находит IP-адрес сайта.",
    "ping": "Скорость отклика. Время в миллисекундах, за которое сигнал долетает до сервера и возвращается обратно.",
    "loss": "Пропавшие данные. Процент запросов без ответа. 100% потерь часто означают, что сайт просто скрывает пинг (ICMP).",
    "jitter": "Стабильность связи. Разброс времени отклика. Высокий Jitter вызывает зависания в играх и звонках.",
    "tcp": "Проверка порта. Показывает, открыт ли конкретный вход на сервере (например, 443 для HTTPS).",
    "tls": "Защищенность. Проверка шифрования и действительности защитного сертификата сайта.",
}

QUICK_PRESETS = (
    ("Google", "google.com", 443),
    ("Telegram", "t.me", 443),
    ("Яндекс", "yandex.ru", 443),
    ("Игровой сервер", "steamcommunity.com", 443),
)


@dataclass(frozen=True, slots=True)
class UdpEventRow:
    observed_at: datetime
    event_type: str
    port: int | None
    details: str
    is_anomaly: bool = False
    pid: int | None = None


@dataclass(frozen=True, slots=True)
class JitterEventRow:
    observed_at: datetime
    deviation_ms: float
    endpoint: str
    details: str


@dataclass(frozen=True, slots=True)
class HeaderAnomalyEvent:
    """A compact history row rendered from the header session capsule."""

    observed_at: datetime
    state: str
    source: str
    values: tuple[tuple[str, object], ...]


class _NestedScrollWheelFilter(QObject):
    """Keep wheel scrolling inside a table or list embedded in a scroll area."""

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() != QEvent.Type.Wheel or not isinstance(event, QWheelEvent):
            return super().eventFilter(watched, event)

        scroll_area = watched.parent()
        if not isinstance(scroll_area, QAbstractScrollArea):
            return super().eventFilter(watched, event)

        delta = event.angleDelta().y()
        scrollbar = scroll_area.verticalScrollBar()
        if delta and scrollbar.maximum() > scrollbar.minimum():
            step = scrollbar.singleStep() or 1
            scrollbar.setValue(scrollbar.value() - (step if delta > 0 else -step) * 3)
        event.accept()
        return True


_NESTED_SCROLL_WHEEL_FILTER = _NestedScrollWheelFilter()


def _keep_wheel_scroll_local(scroll_area: QAbstractScrollArea) -> None:
    """Prevent a parent QScrollArea from consuming the wheel event first."""
    scroll_area.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
    scroll_area.viewport().installEventFilter(_NESTED_SCROLL_WHEEL_FILTER)


class PresetEditorDialog(QDialog):
    """Edit one user-configurable quick diagnostic profile."""

    def __init__(
        self,
        label: str,
        host: str,
        port: int,
        defaults: tuple[str, str, int],
        translate: Callable[[str], str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._defaults = defaults
        self._translate = translate
        self.setWindowTitle(self._translate("Редактирование профиля"))
        self.setModal(True)
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        fields = QGridLayout()
        fields.setHorizontalSpacing(10)
        fields.setVerticalSpacing(8)

        self.label_input = QLineEdit(label)
        self.host_input = QLineEdit(host)
        self.host_input.setPlaceholderText("example.com")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(port)
        for row, (field_label, field) in enumerate(
            (
                (self._translate("Название"), self.label_input),
                (self._translate("Адрес"), self.host_input),
                (self._translate("Порт"), self.port_input),
            )
        ):
            fields.addWidget(QLabel(field_label), row, 0)
            fields.addWidget(field, row, 1)
        layout.addLayout(fields)

        actions = QHBoxLayout()
        self.reset_button = QPushButton(self._translate("Сбросить по умолчанию"))
        self.cancel_button = QPushButton(self._translate("Отмена"))
        self.save_button = QPushButton(self._translate("Сохранить"))
        self.reset_button.clicked.connect(self._restore_defaults)
        self.cancel_button.clicked.connect(self.reject)
        self.save_button.clicked.connect(self._accept_if_valid)
        actions.addWidget(self.reset_button)
        actions.addStretch(1)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.save_button)
        layout.addLayout(actions)

    def values(self) -> tuple[str, str, int]:
        return (
            self.label_input.text().strip() or self._defaults[0],
            self.host_input.text().strip(),
            self.port_input.value(),
        )

    @Slot()
    def _restore_defaults(self) -> None:
        label, host, port = self._defaults
        self.label_input.setText(label)
        self.host_input.setText(host)
        self.port_input.setValue(port)

    @Slot()
    def _accept_if_valid(self) -> None:
        if not self.host_input.text().strip():
            self.host_input.setFocus()
            return
        self.accept()


class DiagnosticWorker(QObject):
    progress = Signal(str, str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, target: Target) -> None:
        super().__init__()
        self._target = target

    @Slot()
    def run(self) -> None:
        try:
            report = DiagnosticService().run(self._target, self.progress.emit)
        except Exception as exc:  # Last-resort boundary for the worker thread.
            self.failed.emit(str(exc))
            return
        self.completed.emit(report)


class SystemActionWorker(QObject):
    completed = Signal(str, object, object)

    def __init__(
        self,
        label: str,
        button: QPushButton,
        action: Callable[[], SystemActionResult],
    ) -> None:
        super().__init__()
        self._label = label
        self._button = button
        self._action = action

    @Slot()
    def run(self) -> None:
        try:
            result = self._action()
        except Exception as exc:  # Keep system actions from crossing into the GUI thread.
            result = SystemActionResult(False, f"Системное действие завершилось ошибкой: {exc}")
        self.completed.emit(self._label, self._button, result)


class ProcessScanWorker(QObject):
    completed = Signal(object)

    @Slot()
    def run(self) -> None:
        try:
            result = scan_processes()
        except Exception as exc:  # Keep process enumeration failures inside the worker.
            result = ProcessScanResult((), f"Не удалось просканировать процессы: {exc}")
        self.completed.emit(result)


class RunningProcessListWorker(QObject):
    completed = Signal(object)

    @Slot()
    def run(self) -> None:
        try:
            result = list_running_processes()
        except Exception as exc:  # Keep process enumeration failures inside the worker.
            result = ProcessListResult((), str(exc))
        self.completed.emit(result)


class ManualProcessDialog(QDialog):
    """Choose any currently running process for the active diagnostic session."""

    process_selected = Signal(int, str)

    def __init__(self, translate: Callable[[str], str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._translate = translate
        self._processes: tuple[RunningProcess, ...] = ()
        self._thread: QThread | None = None
        self._worker: RunningProcessListWorker | None = None
        self.setWindowTitle(self._translate("Выбор процесса"))
        self.setModal(True)
        self.resize(540, 430)
        self.setMinimumSize(440, 320)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            self._translate("Введите имя процесса, например HuntGame.exe")
        )
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._render_processes)
        self.refresh_button = QPushButton(self._translate("Обновить процессы"))
        self.refresh_button.clicked.connect(self._refresh_processes)
        top_row.addWidget(self.search_input, 1)
        top_row.addWidget(self.refresh_button)
        layout.addLayout(top_row)

        self.process_list = QListWidget()
        self.process_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.process_list.itemSelectionChanged.connect(self._update_selection_state)
        self.process_list.itemDoubleClicked.connect(lambda _item: self._select_current_process())
        _keep_wheel_scroll_local(self.process_list)
        layout.addWidget(self.process_list, 1)

        self.status_label = QLabel(self._translate("Сканирование процессов..."))
        self.status_label.setObjectName("Muted")
        layout.addWidget(self.status_label)

        actions = QHBoxLayout()
        self.cancel_button = QPushButton(self._translate("Отмена"))
        self.cancel_button.clicked.connect(self.reject)
        self.select_button = QPushButton(self._translate("Выбрать процесс"))
        self.select_button.setEnabled(False)
        self.select_button.clicked.connect(self._select_current_process)
        actions.addStretch(1)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.select_button)
        layout.addLayout(actions)

        QTimer.singleShot(0, self._refresh_processes)

    @Slot()
    def _refresh_processes(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self.process_list.clear()
        self.select_button.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.status_label.setText(self._translate("Сканирование процессов..."))
        thread = QThread(self)
        worker = RunningProcessListWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_processes_loaded)
        worker.completed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        thread.finished.connect(self._clear_process_worker)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _on_processes_loaded(self, value: object) -> None:
        if not isinstance(value, ProcessListResult) or value.warning:
            self.status_label.setText(self._translate("Не удалось получить список процессов"))
            return
        self._processes = value.processes
        self._render_processes()
        self.status_label.setText(
            self._translate("Запущено процессов: {count}").format(count=len(self._processes))
        )

    @Slot()
    def _render_processes(self) -> None:
        selected = self._selected_process()
        selected_pid = selected.pid if selected is not None else None
        filter_text = self.search_input.text().strip().casefold()
        self.process_list.clear()
        for process in self._processes:
            searchable = f"{process.name} {process.pid}".casefold()
            if filter_text and filter_text not in searchable:
                continue
            item = QListWidgetItem(f"{process.name} · PID {process.pid}")
            item.setData(Qt.ItemDataRole.UserRole, process)
            self.process_list.addItem(item)
            if process.pid == selected_pid:
                self.process_list.setCurrentItem(item)
        if self.process_list.count() == 0 and self._processes:
            self.status_label.setText(self._translate("Процессы не найдены"))
        self._update_selection_state()

    def _selected_process(self) -> RunningProcess | None:
        item = self.process_list.currentItem()
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return value if isinstance(value, RunningProcess) else None

    @Slot()
    def _update_selection_state(self) -> None:
        self.select_button.setEnabled(self._selected_process() is not None)

    @Slot()
    def _select_current_process(self) -> None:
        process = self._selected_process()
        if process is None:
            return
        self.process_selected.emit(process.pid, process.name)
        self.accept()

    @Slot()
    def _clear_process_worker(self) -> None:
        self.refresh_button.setEnabled(True)
        self._thread = None
        self._worker = None

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(1500)
        super().closeEvent(event)


class ConnectionCaptureDialog(QDialog):
    """Select an active remote endpoint and assign it to a quick profile."""

    connection_selected = Signal(str, int, str)

    def __init__(
        self,
        profiles: dict[str, tuple[str, str, int]],
        active_profile: str | None,
        translate: Callable[[str], str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._translate = translate
        self._profiles = profiles
        self._rows: list[tuple[str, int, ProcessConnection]] = []
        self._visible_rows: list[tuple[str, int, ProcessConnection]] = []
        self._sort_mode = 0
        self._thread: QThread | None = None
        self._worker: ProcessScanWorker | None = None
        self.setWindowTitle(self._translate("Диагностика и выбор соединений"))
        self.setModal(True)
        self.resize(760, 460)
        self.setMinimumSize(620, 360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        self.refresh_button = QPushButton(self._translate("Обновить соединения"))
        self.refresh_button.clicked.connect(self._refresh_connections)
        self.sort_button = QPushButton()
        self.sort_button.setObjectName("ConnectionSortButton")
        self.sort_button.clicked.connect(self._cycle_sort_mode)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(120)
        self.progress.setVisible(False)
        self.status_label = QLabel(self._translate("Сканирование соединений..."))
        self.status_label.setObjectName("Muted")
        top_row.addWidget(self.refresh_button)
        top_row.addWidget(self.sort_button)
        top_row.addWidget(self.progress)
        top_row.addWidget(self.status_label, 1)
        layout.addLayout(top_row)
        self._update_sort_button()

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            [
                self._translate("Процесс / PID"),
                self._translate("Удаленный IP / хост"),
                self._translate("Порт"),
                self._translate("Статус"),
            ]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._update_save_state)
        _keep_wheel_scroll_local(self.table)
        header = self.table.horizontalHeader()
        for column in range(self.table.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        bottom_row = QHBoxLayout()
        bottom_row.addWidget(QLabel(self._translate("Целевой профиль")))
        self.profile_combo = QComboBox()
        self.profile_combo.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        _keep_wheel_scroll_local(self.profile_combo.view())
        for profile_id, (label, _host, _port) in profiles.items():
            self.profile_combo.addItem(self._translate(label), profile_id)
        if active_profile is not None:
            index = self.profile_combo.findData(active_profile)
            if index >= 0:
                self.profile_combo.setCurrentIndex(index)
        self.save_button = QPushButton(self._translate("Сохранить в профиль"))
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._save_selection)
        self.cancel_button = QPushButton(self._translate("Отмена"))
        self.cancel_button.clicked.connect(self.reject)
        bottom_row.addWidget(self.profile_combo, 1)
        bottom_row.addWidget(self.cancel_button)
        bottom_row.addWidget(self.save_button)
        layout.addLayout(bottom_row)

        QTimer.singleShot(0, self._refresh_connections)

    @Slot()
    def _refresh_connections(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self.table.setRowCount(0)
        self._rows.clear()
        self.save_button.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.progress.setVisible(True)
        self.status_label.setText(self._translate("Сканирование соединений..."))
        thread = QThread(self)
        worker = ProcessScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_scan_completed)
        worker.completed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        thread.finished.connect(self._clear_scan_worker)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _on_scan_completed(self, value: object) -> None:
        if not isinstance(value, ProcessScanResult):
            self.status_label.setText(self._translate("Не удалось получить соединения"))
            return
        if value.warning:
            self.status_label.setText(
                self._translator_message("Не удалось получить соединения: {error}", error=value.warning)
            )
            return
        for process in sorted(
            value.processes,
            key=lambda item: (item.name.casefold() != "huntgame.exe", item.name.casefold(), item.pid),
        ):
            for connection in process.connections:
                self._rows.append((process.name, process.pid, connection))
        self._render_connection_rows()
        self.status_label.setText(
            self._translator_message("Найдено соединений: {count}", count=len(self._rows))
            if self._rows
            else self._translate("Соединения не найдены")
        )

    @Slot()
    def _cycle_sort_mode(self) -> None:
        self._sort_mode = (self._sort_mode + 1) % 3
        self._update_sort_button()
        self._render_connection_rows()

    def _update_sort_button(self) -> None:
        labels = (
            "Все соединения",
            "Лучшие соединения",
            "Проблемные соединения",
        )
        self.sort_button.setText(self._translate(labels[self._sort_mode]))
        self.sort_button.setToolTip(self._translate("Переключить сортировку соединений"))
        self.sort_button.setProperty("sortMode", self._sort_mode)
        self.sort_button.style().unpolish(self.sort_button)
        self.sort_button.style().polish(self.sort_button)

    def _render_connection_rows(self) -> None:
        self.table.setRowCount(0)
        if self._sort_mode == 1:
            rows = sorted(self._rows, key=self._best_connection_key)
        elif self._sort_mode == 2:
            rows = sorted(self._rows, key=self._problem_connection_key)
        else:
            rows = self._rows
        self._visible_rows = list(rows)

        for process_name, pid, connection in self._visible_rows:
            remote = connection.remote_address or "—"
            remote_port = connection.remote_port if connection.remote_address else 0
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f"{process_name} · PID {pid}"))
            self.table.setItem(row, 1, QTableWidgetItem(remote))
            self.table.setItem(row, 2, QTableWidgetItem(str(remote_port) if remote_port else "—"))
            self.table.setItem(row, 3, QTableWidgetItem(f"{connection.protocol} · {connection.status}"))

    @staticmethod
    def _best_connection_key(row: tuple[str, int, ProcessConnection]) -> tuple[int, int, str]:
        process_name, _pid, connection = row
        return (
            0 if connection.status == "ESTABLISHED" else 1,
            0 if connection.protocol == "TCP" else 1,
            process_name.casefold(),
        )

    @staticmethod
    def _problem_connection_key(row: tuple[str, int, ProcessConnection]) -> tuple[int, int, str]:
        process_name, _pid, connection = row
        return (
            0 if connection.status in {"SYN_SENT", "SYN_RECV"} else 1,
            0 if connection.protocol == "UDP" and not connection.remote_address else 1,
            process_name.casefold(),
        )

    def _translator_message(self, source: str, **values: object) -> str:
        return self._translate(source).format(**values)

    @Slot()
    def _clear_scan_worker(self) -> None:
        self.refresh_button.setEnabled(True)
        self.progress.setVisible(False)
        self._thread = None
        self._worker = None

    def _selected_connection(self) -> ProcessConnection | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._visible_rows):
            return None
        return self._visible_rows[row][2]

    @Slot()
    def _update_save_state(self) -> None:
        connection = self._selected_connection()
        self.save_button.setEnabled(
            connection is not None and bool(connection.remote_address) and connection.remote_port > 0
        )

    @Slot()
    def _save_selection(self) -> None:
        connection = self._selected_connection()
        if connection is None or not connection.remote_address or connection.remote_port < 1:
            self.status_label.setText(self._translate("Выберите соединение с удаленным IP-адресом"))
            return
        profile_id = str(self.profile_combo.currentData())
        self.connection_selected.emit(connection.remote_address, connection.remote_port, profile_id)
        self.accept()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None and self._thread.isRunning():
            event.ignore()
            self.status_label.setText(self._translate("Дождитесь завершения сканирования соединений"))
            return
        super().closeEvent(event)


class NetworkBoostScanWorker(QObject):
    """Find safe, recognised background network consumers outside the GUI thread."""

    completed = Signal(object)

    @Slot()
    def run(self) -> None:
        try:
            result = scan_background_traffic_candidates()
        except Exception as exc:  # Keep a scanner failure out of the GUI thread.
            result = NetworkBoostScanResult((), f"Не удалось выполнить Network Boost: {exc}")
        self.completed.emit(result)


class NetworkBoostTerminateWorker(QObject):
    """Gracefully terminate only the candidates explicitly chosen in the dialog."""

    completed = Signal(object)

    def __init__(self, candidates: tuple[BackgroundTrafficCandidate, ...]) -> None:
        super().__init__()
        self._candidates = candidates

    @Slot()
    def run(self) -> None:
        try:
            results = terminate_background_candidates(self._candidates)
        except Exception as exc:  # Last-resort boundary for psutil operations.
            results = tuple(
                ProcessTerminationResult(candidate.pid, candidate.name, False, f"Ошибка завершения: {exc}")
                for candidate in self._candidates
            )
        self.completed.emit(results)


class InternetQualityWorker(QObject):
    progress = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, system_snapshot: SystemSnapshot | None = None) -> None:
        super().__init__()
        self._system_snapshot = system_snapshot

    @Slot()
    def run(self) -> None:
        try:
            report = run_internet_quality_check(
                self._system_snapshot,
                self.progress.emit,
            )
        except Exception as exc:  # Keep external services from crossing into the GUI thread.
            self.failed.emit(f"Проверка качества завершилась ошибкой: {exc}")
            return
        self.completed.emit(report)


class DnsBenchmarkWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, profiles: tuple[DnsResolverProfile, ...]) -> None:
        super().__init__()
        self._profiles = profiles

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(benchmark_resolvers(self._profiles))
        except Exception as exc:
            self.failed.emit(f"DNS-бенчмарк завершился ошибкой: {exc}")


class DnsConfigurationWorker(QObject):
    completed = Signal(object, object)
    failed = Signal(str)

    @Slot()
    def run(self) -> None:
        try:
            configuration = collect_dns_configuration()
            public_addresses = fetch_public_ip_addresses()
            self.completed.emit(configuration, public_addresses)
        except Exception as exc:
            self.failed.emit(f"Не удалось получить системные DNS: {exc}")


class GeoHideWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(fetch_geohide_dns())
        except Exception as exc:
            self.failed.emit(str(exc))


class PingBenchmarkWorker(QObject):
    """Run regional latency and MTU checks outside the Qt GUI thread."""

    completed = Signal(object, object)
    failed = Signal(str)

    def __init__(
        self,
        mtu_host: str,
        *,
        include_matrix: bool,
        include_mtu: bool,
        regional_targets: tuple[RegionalPingTarget, ...] | None = None,
    ) -> None:
        super().__init__()
        self._mtu_host = mtu_host
        self._include_matrix = include_matrix
        self._include_mtu = include_mtu
        self._regional_targets = regional_targets

    @Slot()
    def run(self) -> None:
        try:
            regional_results = (
                benchmark_regional_targets(self._regional_targets)
                if self._include_matrix and self._regional_targets
                else benchmark_regional_targets() if self._include_matrix else ()
            )
            mtu_results = run_mtu_stress_test(self._mtu_host) if self._include_mtu else ()
        except Exception as exc:
            self.failed.emit(f"Анализ задержки завершился ошибкой: {exc}")
            return
        self.completed.emit(regional_results, mtu_results)


class PacketLossTestWorker(QObject):
    """Keep hop and controlled packet-burst checks off the Qt GUI thread."""

    completed = Signal(object, object, object)
    failed = Signal(str)

    def __init__(self, hops: tuple[HopResult, ...], host: str, port: int) -> None:
        super().__init__()
        self._hops = hops
        self._host = host
        self._port = port

    @Slot()
    def run(self) -> None:
        try:
            hop_results = run_hop_loss_breakdown(self._hops) if self._hops else ()
            icmp_result = run_icmp_stress_test(self._host)
            udp_result = run_udp_stress_test(self._host, self._port)
        except Exception as exc:
            self.failed.emit(f"Анализ потерь завершился ошибкой: {exc}")
            return
        self.completed.emit(hop_results, icmp_result, udp_result)


@dataclass(frozen=True, slots=True)
class GameAutoCheckResult:
    process: RunningProcess | None
    connections: tuple[ProcessConnection, ...]
    ping: object | None
    warning: str | None = None


class GameAutoCheckWorker(QObject):
    completed = Signal(object)

    def __init__(self, preferred_process: str | None = None) -> None:
        super().__init__()
        self._preferred_process = preferred_process

    @Slot()
    def run(self) -> None:
        try:
            process_result = list_running_processes()
            preferred = (self._preferred_process or "HuntGame.exe").casefold()
            process = next(
                (item for item in process_result.processes if item.name.casefold() == preferred),
                None,
            )
            if process is None and preferred != "huntgame.exe":
                process = next(
                    (item for item in process_result.processes if item.name.casefold() == "huntgame.exe"),
                    None,
                )

            network_result = scan_processes()
            connections: tuple[ProcessConnection, ...] = ()
            if process is not None:
                network_process = next(
                    (item for item in network_result.processes if item.pid == process.pid),
                    None,
                )
                if network_process is not None:
                    connections = network_process.connections

            selected_connection = self._select_game_connection(connections)
            remote_host = selected_connection.remote_address if selected_connection else None
            ping = probe_ping(remote_host, count=5, wait_ms=450) if remote_host else None
            warning = process_result.warning or network_result.warning
            self.completed.emit(GameAutoCheckResult(process, connections, ping, warning))
        except Exception as exc:
            self.completed.emit(GameAutoCheckResult(None, (), None, str(exc)))

    @staticmethod
    def _select_game_connection(
        connections: tuple[ProcessConnection, ...],
    ) -> ProcessConnection | None:
        candidates = [item for item in connections if item.remote_address]
        if not candidates:
            return None
        non_cdn = [item for item in candidates if not _is_background_cdn(item.remote_address)]
        candidates = non_cdn or candidates
        return sorted(candidates, key=_game_connection_key)[0]


class GameAutoCheckDialog(QDialog):
    """Compact background process and packet-stability check for a game."""

    def __init__(
        self,
        translate: Callable[[str], str],
        preferred_process: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._translate = translate
        self._preferred_process = preferred_process
        self._thread: QThread | None = None
        self._worker: GameAutoCheckWorker | None = None
        self._monitor_timer = QTimer(self)
        self._monitor_timer.setInterval(8000)
        self._monitor_timer.timeout.connect(self._start_check)
        self._history: list[dict[str, object]] = []
        self._last_result: GameAutoCheckResult | None = None
        self.setObjectName("GameAutoCheckDialog")
        self.setWindowTitle(self._translate("Автопроверка игры"))
        self.setModal(True)
        self.resize(600, 480)
        self.setMinimumSize(500, 380)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel(self._translate("Автоматическая проверка процесса"))
        title.setObjectName("GameAutoCheckTitle")
        subtitle = QLabel(self._translate("Поиск HuntGame.exe, сокетов и быстрый тест стабильности соединения"))
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        cards = QGridLayout()
        cards.setHorizontalSpacing(8)
        cards.setVerticalSpacing(8)
        self.process_value = self._add_status_card(cards, 0, 0, "Процесс", "Проверка...")
        self.socket_value = self._add_status_card(cards, 0, 1, "Активные сокеты", "Проверка...")
        self.loss_value = self._add_status_card(cards, 1, 0, "Уровень потерь", "Проверка...")
        self.stability_value = self._add_status_card(cards, 1, 1, "Стабильность соединения", "Проверка...")
        layout.addLayout(cards)

        self.endpoint_label = QLabel(self._translate("Удалённая цель: проверка..."))
        self.endpoint_label.setObjectName("Muted")
        layout.addWidget(self.endpoint_label)
        self.socket_list = QListWidget()
        self.socket_list.setObjectName("GameAutoCheckSocketList")
        self.socket_list.setMinimumHeight(100)
        self.socket_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        _keep_wheel_scroll_local(self.socket_list)
        layout.addWidget(self.socket_list, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        self.status_label = QLabel(self._translate("Проверка выполняется..."))
        self.status_label.setObjectName("GameAutoCheckStatus")
        layout.addWidget(self.status_label)

        history_title = QLabel(self._translate("История критических всплесков"))
        history_title.setObjectName("FieldLabel")
        layout.addWidget(history_title)
        self.history_table = QTableWidget(0, 3)
        self.history_table.setObjectName("GameAutoCheckHistoryTable")
        self.history_table.setHorizontalHeaderLabels(
            [
                self._translate("Время"),
                self._translate("Потери"),
                self._translate("Статус"),
            ]
        )
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setMinimumHeight(92)
        self.history_table.setMaximumHeight(170)
        self.history_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        history_header = self.history_table.horizontalHeader()
        for column in range(self.history_table.columnCount()):
            history_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        history_header.setStretchLastSection(True)
        _keep_wheel_scroll_local(self.history_table)
        layout.addWidget(self.history_table)

        actions = QHBoxLayout()
        self.monitor_checkbox = QCheckBox(self._translate("Непрерывный мониторинг в бою"))
        self.monitor_checkbox.setToolTip(
            self._translate("Проверять процесс и соединение автоматически каждые 8 секунд")
        )
        self.monitor_checkbox.toggled.connect(self._toggle_monitoring)
        self.export_button = QPushButton(self._translate("Экспорт отчёта"))
        self.export_button.clicked.connect(self._export_report)
        self.refresh_button = QPushButton(self._translate("Проверить снова"))
        self.refresh_button.clicked.connect(self._start_check)
        close_button = QPushButton(self._translate("Закрыть"))
        close_button.clicked.connect(self.reject)
        actions.addWidget(self.monitor_checkbox)
        actions.addStretch(1)
        actions.addWidget(self.export_button)
        actions.addWidget(close_button)
        actions.addWidget(self.refresh_button)
        layout.addLayout(actions)
        QTimer.singleShot(0, self._start_check)

    def _add_status_card(
        self,
        layout: QGridLayout,
        row: int,
        column: int,
        title: str,
        value: str,
    ) -> QLabel:
        card = QFrame()
        card.setObjectName("GameAutoCheckCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(10, 8, 10, 8)
        card_layout.setSpacing(2)
        title_label = QLabel(self._translate(title).upper())
        title_label.setObjectName("FieldLabel")
        value_label = QLabel(self._translate(value))
        value_label.setObjectName("GameAutoCheckValue")
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)
        layout.addWidget(card, row, column)
        layout.setColumnStretch(column, 1)
        return value_label

    @Slot()
    def _start_check(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self.refresh_button.setEnabled(False)
        self.progress.show()
        self.status_label.setText(self._translate("Проверка выполняется..."))
        self.status_label.setProperty("alertState", "info")
        self._polish_alert_status()
        self.process_value.setText(self._translate("Проверка..."))
        self.socket_value.setText(self._translate("Проверка..."))
        self.loss_value.setText(self._translate("Проверка..."))
        self.stability_value.setText(self._translate("Проверка..."))
        self.socket_list.clear()
        thread = QThread(self)
        worker = GameAutoCheckWorker(self._preferred_process)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_check_completed)
        worker.completed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        thread.finished.connect(self._clear_check_worker)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _on_check_completed(self, value: object) -> None:
        self.refresh_button.setEnabled(True)
        self.progress.hide()
        if not isinstance(value, GameAutoCheckResult):
            self.status_label.setText(self._translate("Не удалось завершить проверку"))
            self._set_alert_state("error")
            return
        self._last_result = value
        if value.process is None:
            self.process_value.setText(self._translate("Процесс не найден"))
            self.socket_value.setText("--")
            self.loss_value.setText("--")
            self.stability_value.setText(self._translate("Нет данных"))
            self.status_label.setText(self._translate("Запустите игру и повторите проверку"))
            self._set_alert_state("warning")
            return

        self.process_value.setText(f"{value.process.name} · PID {value.process.pid}")
        self.socket_value.setText(str(len(value.connections)))
        self.socket_list.clear()
        for connection in value.connections:
            self.socket_list.addItem(
                f"{connection.protocol} · {connection.local_port} → "
                f"{connection.remote_endpoint} · {connection.status}"
            )
        if not value.connections:
            self.socket_list.addItem(self._translate("Активные соединения не найдены"))

        ping = value.ping
        if ping is None:
            self.endpoint_label.setText(self._translate("Удалённая цель: не определена"))
            self.loss_value.setText("--")
            self.stability_value.setText(self._translate("Нет удалённой цели"))
            self._set_alert_state("warning")
        else:
            self.endpoint_label.setText(
                self._translate("Удалённая цель: {host}").format(host=ping.host)
            )
            self.loss_value.setText(f"{ping.loss_percent:.1f}%")
            jitter = "--" if ping.jitter_ms is None else f"{ping.jitter_ms:.1f} ms"
            self.stability_value.setText(
                self._translate("RTT {rtt} · jitter {jitter}").format(
                    rtt="--" if ping.average_ms is None else f"{ping.average_ms:.1f} ms",
                    jitter=jitter,
                )
            )
            self._record_critical_event(ping)
            self._set_alert_state("error" if self._is_critical_ping(ping) else "good")
        self.status_label.setText(value.warning or self._translate("Проверка завершена"))

    @staticmethod
    def _is_critical_ping(ping: object) -> bool:
        return bool(
            getattr(ping, "loss_percent", 0.0) >= 5.0
            or (getattr(ping, "jitter_ms", None) or 0.0) >= 25.0
            or (getattr(ping, "average_ms", None) or 0.0) >= 100.0
        )

    def _record_critical_event(self, ping: object) -> None:
        if not self._is_critical_ping(ping):
            return
        loss = float(getattr(ping, "loss_percent", 0.0) or 0.0)
        rtt = getattr(ping, "average_ms", None)
        jitter = getattr(ping, "jitter_ms", None)
        reasons: list[str] = []
        if loss >= 5.0:
            reasons.append(self._translate("потери выше 5%"))
        if (jitter or 0.0) >= 25.0:
            reasons.append(self._translate("резкий jitter"))
        if (rtt or 0.0) >= 100.0:
            reasons.append(self._translate("высокий RTT"))
        row = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "loss_percent": round(loss, 1),
            "rtt_ms": round(float(rtt), 1) if rtt is not None else None,
            "jitter_ms": round(float(jitter), 1) if jitter is not None else None,
            "status": ", ".join(reasons),
            "endpoint": str(getattr(ping, "host", "")),
        }
        self._history.append(row)
        del self._history[:-100]
        table_row = self.history_table.rowCount()
        self.history_table.insertRow(table_row)
        values = (
            datetime.fromisoformat(str(row["timestamp"])).strftime("%H:%M:%S"),
            f"{loss:.1f}%",
            str(row["status"]),
        )
        for column, text in enumerate(values):
            self.history_table.setItem(table_row, column, QTableWidgetItem(text))
        self.history_table.scrollToBottom()

    @Slot(bool)
    def _toggle_monitoring(self, enabled: bool) -> None:
        if enabled:
            self._monitor_timer.start()
            self.status_label.setText(self._translate("Мониторинг включён"))
        else:
            self._monitor_timer.stop()
            self.status_label.setText(self._translate("Мониторинг выключен"))

    def _set_alert_state(self, state: str) -> None:
        self.status_label.setProperty("alertState", state)
        self._polish_alert_status()

    def _polish_alert_status(self) -> None:
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    @Slot()
    def _export_report(self) -> None:
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            self._translate("Экспорт отчёта"),
            "netvision-game-session",
            "JSON (*.json);;CSV (*.csv)",
        )
        if not path:
            return
        report = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "process": (
                {"name": self._last_result.process.name, "pid": self._last_result.process.pid}
                if self._last_result and self._last_result.process
                else None
            ),
            "connections": [
                {
                    "protocol": item.protocol,
                    "local_port": item.local_port,
                    "remote_address": item.remote_address,
                    "remote_port": item.remote_port,
                    "status": item.status,
                }
                for item in (self._last_result.connections if self._last_result else ())
            ],
            "last_ping": (
                {
                    "host": self._last_result.ping.host,
                    "loss_percent": self._last_result.ping.loss_percent,
                    "average_ms": self._last_result.ping.average_ms,
                    "jitter_ms": self._last_result.ping.jitter_ms,
                }
                if self._last_result and self._last_result.ping is not None
                else None
            ),
            "history": self._history,
        }
        try:
            if "CSV" in selected_filter or path.casefold().endswith(".csv"):
                process_name = report["process"]["name"] if report["process"] else ""
                process_pid = report["process"]["pid"] if report["process"] else ""
                socket_count = len(report["connections"])
                csv_rows = [
                    {
                        **row,
                        "process_name": process_name,
                        "process_pid": process_pid,
                        "socket_count": socket_count,
                    }
                    for row in self._history
                ]
                with open(path, "w", newline="", encoding="utf-8-sig") as output:
                    writer = csv.DictWriter(
                        output,
                        fieldnames=(
                            "timestamp",
                            "process_name",
                            "process_pid",
                            "socket_count",
                            "endpoint",
                            "loss_percent",
                            "rtt_ms",
                            "jitter_ms",
                            "status",
                        ),
                    )
                    writer.writeheader()
                    writer.writerows(csv_rows)
            else:
                if not path.casefold().endswith(".json"):
                    path += ".json"
                with open(path, "w", encoding="utf-8") as output:
                    json.dump(report, output, ensure_ascii=False, indent=2)
            self.status_label.setText(self._translate("Отчёт сохранён"))
        except OSError as exc:
            self.status_label.setText(
                self._translate("Не удалось сохранить отчёт: {error}").format(error=exc)
            )

    @Slot()
    def _clear_check_worker(self) -> None:
        self._thread = None
        self._worker = None

    def closeEvent(self, event: QCloseEvent) -> None:
        self._monitor_timer.stop()
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(1500)
        super().closeEvent(event)


class TcpDiagnosticsWorker(QObject):
    """Collect socket state and TCP connect checks outside the GUI thread."""

    completed = Signal(object, object, object)
    failed = Signal(str)

    def __init__(self, host: str, port: int, ports: tuple[int, ...]) -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._ports = ports

    @Slot()
    def run(self) -> None:
        try:
            sockets = scan_tcp_sockets()
            primary = probe_tcp_connect(self._host, self._port)
            ports = probe_common_ports(self._host, self._ports)
        except Exception as exc:
            self.failed.emit(f"TCP-анализ завершился ошибкой: {exc}")
            return
        self.completed.emit(sockets, primary, ports)


class TlsAuditWorker(QObject):
    """Run a TLS audit outside the Qt GUI thread."""

    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self._host = host
        self._port = port

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(audit_tls_endpoint(self._host, self._port))
        except Exception as exc:
            self.failed.emit(f"TLS-аудит завершился ошибкой: {exc}")


class NetworkBoostDialog(QDialog):
    """Explicit selection is required before a Network Boost process is closed."""

    terminate_requested = Signal(object)

    def __init__(
        self,
        candidates: tuple[BackgroundTrafficCandidate, ...],
        parent: QWidget | None = None,
        translate: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("NetworkBoostDialog")
        self.setModal(True)
        self.setMinimumWidth(540)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._translate = translate or (lambda text: text)
        self._candidates = candidates
        self._candidate_checkboxes: dict[BackgroundTrafficCandidate, QCheckBox] = {}
        self._empty_label: QLabel | None = None
        self._termination_results: tuple[ProcessTerminationResult, ...] | None = None
        self._busy = False
        self._status_source = "Ничего не выбрано. NetVision не завершает процессы автоматически."

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(12, 12, 12, 12)
        panel = QFrame()
        panel.setObjectName("NetworkBoostDialogPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        self.title_label = QLabel("NETWORK BOOST")
        self.title_label.setObjectName("NetworkBoostDialogTitle")
        self.description_label = QLabel(
            "Найдены только известные фоновые приложения с активными сетевыми сокетами. "
            "Системные процессы и NetVision исключены. Выберите приложения, которые можно закрыть."
        )
        self.description_label.setObjectName("Muted")
        self.description_label.setWordWrap(True)
        layout.addWidget(self.title_label)
        layout.addWidget(self.description_label)

        self.candidate_scroll = QScrollArea()
        self.candidate_scroll.setWidgetResizable(True)
        self.candidate_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.candidate_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.candidate_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        _keep_wheel_scroll_local(self.candidate_scroll)
        candidate_container = QWidget()
        candidate_layout = QVBoxLayout(candidate_container)
        candidate_layout.setContentsMargins(0, 0, 0, 0)
        candidate_layout.setSpacing(5)
        if candidates:
            for candidate in candidates:
                checkbox = QCheckBox(self._candidate_text(candidate))
                checkbox.setObjectName("NetworkBoostCandidate")
                checkbox.setToolTip(self._candidate_tooltip(candidate))
                checkbox.stateChanged.connect(self._update_terminate_state)
                candidate_layout.addWidget(checkbox)
                self._candidate_checkboxes[candidate] = checkbox
        else:
            self._empty_label = QLabel("Подходящих фоновых приложений с активными сетевыми сокетами не найдено.")
            self._empty_label.setObjectName("Muted")
            self._empty_label.setWordWrap(True)
            candidate_layout.addWidget(self._empty_label)
        candidate_layout.addStretch(1)
        self.candidate_scroll.setWidget(candidate_container)
        self.candidate_scroll.setMinimumHeight(120)
        layout.addWidget(self.candidate_scroll)

        self.status_label = QLabel(self._status_source)
        self.status_label.setObjectName("NetworkBoostDialogStatus")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self._busy_phase = 0
        self._busy_timer = QTimer(self)
        self._busy_timer.setInterval(420)
        self._busy_timer.timeout.connect(self._animate_terminate_button)

        actions = QHBoxLayout()
        actions.addStretch(1)
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.setObjectName("NetworkBoostCancelButton")
        self.cancel_button.clicked.connect(self.reject)
        self.terminate_button = QPushButton("Завершить выбранные")
        self.terminate_button.setObjectName("NetworkBoostTerminateButton")
        self._terminate_button_style = self.terminate_button.styleSheet()
        self.terminate_button.clicked.connect(self._emit_termination_request)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.terminate_button)
        layout.addLayout(actions)

        outer_layout.addWidget(panel)
        self._update_terminate_state()
        self.retranslate(self._translate)

    def retranslate(self, translate: Callable[[str], str]) -> None:
        """Refresh the dialog even while it is open."""
        self._translate = translate
        self.setWindowTitle(self._translate("Оптимизация фоновых процессов"))
        self.title_label.setText(self._translate("NETWORK BOOST"))
        self.description_label.setText(
            self._translate(
                "Найдены только известные фоновые приложения с активными сетевыми сокетами. "
                "Системные процессы и NetVision исключены. Выберите приложения, которые можно закрыть."
            )
        )
        if self._empty_label is not None:
            self._empty_label.setText(
                self._translate("Подходящих фоновых приложений с активными сетевыми сокетами не найдено.")
            )
        self.cancel_button.setText(self._translate("Отмена"))
        self.terminate_button.setText(self._translate("Завершить выбранные"))
        for candidate, checkbox in self._candidate_checkboxes.items():
            if checkbox.isEnabled():
                checkbox.setText(self._candidate_text(candidate))
            checkbox.setToolTip(self._candidate_tooltip(candidate))
        if self._termination_results is not None:
            self.apply_termination_results(self._termination_results)
        else:
            self.status_label.setText(self._translate(self._status_source))

    def _candidate_text(self, candidate: BackgroundTrafficCandidate) -> str:
        socket_label = "активный сокет" if candidate.active_connection_count == 1 else "активных сокетов"
        return (
            f"{candidate.display_name} · {self._translate(candidate.category)} · PID {candidate.pid} · "
            f"{candidate.active_connection_count} {self._translate(socket_label)}"
        )

    def _candidate_tooltip(self, candidate: BackgroundTrafficCandidate) -> str:
        return (
            f"{candidate.display_name}\n{self._translate('Категория')}: {self._translate(candidate.category)}\n"
            f"PID: {candidate.pid}\n{self._translate('Активных сокетов')}: {candidate.active_connection_count}"
        )

    def selected_candidates(self) -> tuple[BackgroundTrafficCandidate, ...]:
        return tuple(candidate for candidate, checkbox in self._candidate_checkboxes.items() if checkbox.isChecked())

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        for checkbox in self._candidate_checkboxes.values():
            checkbox.setDisabled(busy)
        self.cancel_button.setDisabled(busy)
        self.terminate_button.setDisabled(busy or not self.selected_candidates())
        self._set_terminate_button_busy(busy)
        if busy:
            self._status_source = "Завершаем выбранные процессы в фоновом потоке..."
            self.status_label.setText(self._translate(self._status_source))

    def _set_terminate_button_busy(self, busy: bool) -> None:
        self.terminate_button.setProperty("taskBusy", busy)
        self.terminate_button.setProperty("taskBusyPhase", str(self._busy_phase if busy else 0))
        if busy:
            self._animate_terminate_button()
            self._busy_timer.start()
        else:
            self._busy_timer.stop()
        self._apply_terminate_button_style()
        self.terminate_button.style().unpolish(self.terminate_button)
        self.terminate_button.style().polish(self.terminate_button)
        self.terminate_button.update()

    @Slot()
    def _animate_terminate_button(self) -> None:
        self._busy_phase = (self._busy_phase + 1) % 3
        self.terminate_button.setProperty("taskBusyPhase", str(self._busy_phase))
        self._apply_terminate_button_style()
        self.terminate_button.style().unpolish(self.terminate_button)
        self.terminate_button.style().polish(self.terminate_button)
        self.terminate_button.update()

    def _apply_terminate_button_style(self) -> None:
        if not self.terminate_button.property("taskBusy"):
            self.terminate_button.setStyleSheet(self._terminate_button_style)
            return
        border, background = (
            ("#00E5A3", "#182C32"),
            ("#75F8D7", "#1B343B"),
            ("#129D7A", "#172A31"),
        )[self._busy_phase]
        self.terminate_button.setStyleSheet(
            f"{self._terminate_button_style}\n"
            "QPushButton { color: #E1E7EF; "
            f"background-color: {background}; border: 1px solid {border}; }}"
        )

    def apply_termination_results(self, results: tuple[ProcessTerminationResult, ...]) -> None:
        self._termination_results = results
        results_by_pid = {result.pid: result for result in results}
        success_count = 0
        failures: list[str] = []
        for candidate, checkbox in self._candidate_checkboxes.items():
            result = results_by_pid.get(candidate.pid)
            if result is None:
                continue
            if result.success:
                success_count += 1
                checkbox.setChecked(False)
                checkbox.setDisabled(True)
                checkbox.setText(f"{self._candidate_text(candidate)} · {self._translate('завершён')}")
            else:
                failures.append(f"{candidate.display_name}: {result.message}")
        if success_count:
            message = self._translate("Завершено процессов: {count}.").format(count=success_count)
            if failures:
                message += " " + self._translate("Не удалось") + ": " + "; ".join(failures)
        else:
            message = self._translate("Процессы не завершены.") + " " + "; ".join(
                failures or [self._translate("Неизвестная ошибка")]
            )
        self.status_label.setText(message)
        self._update_terminate_state()

    @Slot()
    def _emit_termination_request(self) -> None:
        selected = self.selected_candidates()
        if selected and not self._busy:
            names = "\n".join(f"• {item.display_name} (PID {item.pid})" for item in selected)
            answer = QMessageBox.question(
                self,
                self._translate("Завершить выбранные приложения?"),
                self._translate(
                    "В Windows завершение процесса принудительное. Несохранённые данные могут быть потеряны. Продолжить?"
                ) + "\n\n" + names,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.terminate_requested.emit(selected)

    @Slot()
    def _update_terminate_state(self) -> None:
        self.terminate_button.setEnabled(not self._busy and bool(self.selected_candidates()))

    def reject(self) -> None:
        if not self._busy:
            super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._busy:
            event.ignore()
        else:
            super().closeEvent(event)


class GeoHideDialog(QDialog):
    """Show the current DNS-over-UDP data published by GeoHide."""

    STATUS_URL = "https://hetrixtools.com/r/f1e2a8d87f855e5a611040c56ca5d5b0/"

    def __init__(
        self,
        parent: QWidget | None = None,
        translate: Callable[[str], str] | None = None,
        apply_dns: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("GeoHideDialog")
        self.setModal(False)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.resize(760, 580)
        self.setMinimumSize(680, 480)
        self._is_expanded = False
        self._translate = translate or (lambda text: text)
        self._apply_dns = apply_dns
        self._thread: QThread | None = None
        self._worker: GeoHideWorker | None = None
        self._result: GeoHideResult | None = None
        self._status_source = "Нажмите «Обновить», чтобы получить данные GeoHide"
        self._status_values: dict[str, object] = {}
        self._refresh_phase = 0
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(420)
        self._refresh_timer.timeout.connect(self._animate_refresh_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title_bar = QFrame()
        title_bar.setObjectName("GeoHideTitleBar")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 6, 6, 6)
        title_layout.setSpacing(4)
        self.title_label = QLabel("GEOHIDE DNS")
        self.title_label.setObjectName("DnsWorkspaceTitle")
        title_layout.addWidget(self.title_label, 1)
        self.expand_button = QPushButton("□")
        self.expand_button.setObjectName("GeoHideExpandButton")
        self.expand_button.setFixedSize(30, 26)
        self.expand_button.setToolTip(self._translate("Развернуть окно"))
        self.expand_button.clicked.connect(self._toggle_expanded)
        title_layout.addWidget(self.expand_button)
        self.close_button = QPushButton("×")
        self.close_button.setObjectName("GeoHideCloseButton")
        self.close_button.setFixedSize(30, 26)
        self.close_button.setToolTip(self._translate("Закрыть окно"))
        self.close_button.clicked.connect(self.close)
        title_layout.addWidget(self.close_button)
        layout.addWidget(title_bar)

        panel = QFrame()
        panel.setObjectName("GeoHideDialogPanel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 14, 0, 14)
        panel_layout.setSpacing(9)

        actions = QHBoxLayout()
        self.refresh_button = QPushButton("Обновить")
        self.refresh_button.setObjectName("GeoHideRefreshButton")
        self._refresh_button_style = self.refresh_button.styleSheet()
        self.refresh_button.clicked.connect(self._refresh)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(150)
        self.progress.setVisible(False)
        self.apply_button = QPushButton("Подставить выбранный DNS")
        self.apply_button.setObjectName("GeoHideApplyButton")
        self.apply_button.setEnabled(False)
        self.apply_button.clicked.connect(self._apply_selected_address)
        actions.addWidget(self.refresh_button)
        actions.addWidget(self.progress)
        actions.addWidget(self.apply_button)
        actions.addStretch(1)
        panel_layout.addLayout(actions)

        self.data_table = QTableWidget(0, 3)
        self.data_table.setObjectName("GeoHideDataTable")
        self.data_table.setHorizontalHeaderLabels(["Тип", "Регион", "Адрес"])
        self.data_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.data_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.data_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.data_table.customContextMenuRequested.connect(self._show_table_context_menu)
        self.data_table.cellDoubleClicked.connect(self._copy_address_from_row)
        self.data_table.itemSelectionChanged.connect(self._update_selection_actions)
        _keep_wheel_scroll_local(self.data_table)
        header = self.data_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        panel_layout.addWidget(self.data_table, 1)

        self.status_view_title = QLabel("Статус серверов GeoHide (HetrixTools)")
        self.status_view_title.setObjectName("FieldLabel")
        panel_layout.addWidget(self.status_view_title)
        if QWebEngineView is not None:
            self.status_web_view = QWebEngineView()
            self.status_web_view.setObjectName("GeoHideStatusView")
            self.status_web_view.setContentsMargins(0, 0, 0, 0)
            self.status_web_view.setMinimumHeight(180)
            self.status_web_view.setMinimumWidth(0)
            self.status_web_view.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Expanding,
            )
            self.status_web_view.setZoomFactor(0.82)
            self.status_web_view.setUrl(QUrl(self.STATUS_URL))
            panel_layout.addWidget(self.status_web_view, 1)
            self.status_web_fallback = None
        else:
            self.status_web_view = None
            self.status_web_fallback = QLabel(self._fallback_status_text())
            self.status_web_fallback.setObjectName("Muted")
            self.status_web_fallback.setOpenExternalLinks(True)
            self.status_web_fallback.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextBrowserInteraction
            )
            self.status_web_fallback.setWordWrap(True)
            panel_layout.addWidget(self.status_web_fallback)

        self.status_label = QLabel(self._status_source)
        self.status_label.setObjectName("Muted")
        self.status_label.setWordWrap(True)
        panel_layout.addWidget(self.status_label)
        layout.addWidget(panel)
        self.retranslate(self._translate)

    def retranslate(self, translate: Callable[[str], str]) -> None:
        self._translate = translate
        self.setWindowTitle(self._translate("GeoHide DNS"))
        self.title_label.setText(self._translate("GEOHIDE DNS"))
        self.refresh_button.setText(self._translate("Обновить"))
        self.apply_button.setText(self._translate("Подставить выбранный DNS"))
        self.expand_button.setToolTip(
            self._translate("Восстановить окно" if self._is_expanded else "Развернуть окно")
        )
        self.close_button.setToolTip(self._translate("Закрыть окно"))
        self.data_table.setHorizontalHeaderLabels(
            [self._translate("Тип"), self._translate("Регион"), self._translate("Адрес")]
        )
        self.status_view_title.setText(self._translate("Статус серверов GeoHide (HetrixTools)"))
        if self.status_web_fallback is not None:
            self.status_web_fallback.setText(self._fallback_status_text())
        self._render_result()
        self._set_status(self._status_source, **self._status_values)

    def _set_status(self, source: str, **values: object) -> None:
        self._status_source = source
        self._status_values = values
        self.status_label.setText(self._translate(source).format(**values))

    def _fallback_status_text(self) -> str:
        return (
            f"{self._translate('QtWebEngine недоступен')}. "
            f'<a href="{self.STATUS_URL}">{self._translate("Открыть статус GeoHide в браузере")}</a>'
        )

    def _selected_address(self, row: int | None = None) -> str | None:
        selected_row = self.data_table.currentRow() if row is None else row
        if selected_row < 0:
            return None
        item = self.data_table.item(selected_row, 2)
        if item is None:
            return None
        value = item.data(Qt.ItemDataRole.UserRole)
        return str(value).strip() if value else None

    @Slot()
    def _update_selection_actions(self) -> None:
        self.apply_button.setEnabled(self._selected_address() is not None)

    @Slot(int, int)
    def _copy_address_from_row(self, row: int, _column: int) -> None:
        address = self._selected_address(row)
        if address is None:
            return
        QApplication.clipboard().setText(address)
        QToolTip.showText(
            QCursor.pos(),
            self._translate("Скопировано"),
            self.data_table,
        )

    @Slot()
    def _copy_selected_address(self) -> None:
        self._copy_address_from_row(self.data_table.currentRow(), 2)

    @Slot()
    def _apply_selected_address(self) -> None:
        address = self._selected_address()
        if address is None:
            return
        if self._apply_dns is not None:
            self._apply_dns(address)
        self._set_status("Адрес GeoHide подставлен: {address}", address=address)

    @Slot(object)
    def _show_table_context_menu(self, position: object) -> None:
        if not hasattr(position, "x") or not hasattr(position, "y"):
            return
        point = position
        index = self.data_table.indexAt(point)
        address = self._selected_address(index.row()) if index.isValid() else None
        if address is None:
            return
        self.data_table.selectRow(index.row())
        menu = QMenu(self.data_table)
        copy_action = menu.addAction(self._translate("Скопировать IP"))
        apply_action = menu.addAction(self._translate("Подставить выбранный DNS"))
        copy_action.triggered.connect(self._copy_selected_address)
        apply_action.triggered.connect(self._apply_selected_address)
        menu.exec(self.data_table.viewport().mapToGlobal(point))

    @Slot()
    def _toggle_expanded(self) -> None:
        if self.isMaximized():
            self.showNormal()
            self._is_expanded = False
            self.expand_button.setText("□")
            self.expand_button.setToolTip(self._translate("Развернуть окно"))
        else:
            self.showMaximized()
            self._is_expanded = True
            self.expand_button.setText("❐")
            self.expand_button.setToolTip(self._translate("Восстановить окно"))

    def _set_refresh_button_busy(self, busy: bool) -> None:
        self.refresh_button.setEnabled(not busy)
        self.refresh_button.setProperty("taskBusy", busy)
        self.refresh_button.setProperty("taskBusyPhase", str(self._refresh_phase if busy else 0))
        self._apply_refresh_button_style()
        self.refresh_button.style().unpolish(self.refresh_button)
        self.refresh_button.style().polish(self.refresh_button)
        if busy:
            self._animate_refresh_button()
            self._refresh_timer.start()
        else:
            self._refresh_timer.stop()
        self.refresh_button.update()

    @Slot()
    def _animate_refresh_button(self) -> None:
        self._refresh_phase = (self._refresh_phase + 1) % 3
        self.refresh_button.setProperty("taskBusyPhase", str(self._refresh_phase))
        self._apply_refresh_button_style()
        self.refresh_button.style().unpolish(self.refresh_button)
        self.refresh_button.style().polish(self.refresh_button)
        self.refresh_button.update()

    def _apply_refresh_button_style(self) -> None:
        if not self.refresh_button.property("taskBusy"):
            self.refresh_button.setStyleSheet(self._refresh_button_style)
            return
        border, background = (
            ("#00E5A3", "#182C32"),
            ("#75F8D7", "#1B343B"),
            ("#129D7A", "#172A31"),
        )[self._refresh_phase]
        self.refresh_button.setStyleSheet(
            f"{self._refresh_button_style}\n"
            "QPushButton { color: #E1E7EF; "
            f"background-color: {background}; border: 1px solid {border}; }}"
        )

    def _refresh(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self._set_refresh_button_busy(True)
        self.progress.setVisible(True)
        self._set_status("Загрузка данных GeoHide...")
        thread = QThread(self)
        worker = GeoHideWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_loaded)
        worker.failed.connect(self._on_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(self._clear_thread)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _on_loaded(self, value: object) -> None:
        if not isinstance(value, GeoHideResult):
            self._on_failed("Некорректный ответ GeoHide")
            return
        self._result = value
        self._render_result()
        status = (
            "GeoHide недоступен, показан резервный список: {count} адресов"
            if value.used_fallback
            else "Данные GeoHide обновлены: {count} адресов"
        )
        self._set_status(status, count=len(value.servers))

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._set_status("GeoHide недоступен: {error}", error=message)

    def _render_result(self) -> None:
        self.data_table.setRowCount(0)
        if self._result is None:
            return
        rows = [
            (server.server_type, server.region, server.address)
            for server in self._result.servers
        ]
        rows.extend(("Параметр", "Global", parameter) for parameter in self._result.parameters)
        self.data_table.setRowCount(len(rows))
        for row, (kind, region, value) in enumerate(rows):
            self.data_table.setItem(row, 0, QTableWidgetItem(self._translate(kind)))
            self.data_table.setItem(row, 1, QTableWidgetItem(self._translate(region)))
            address_item = QTableWidgetItem(value)
            if row < len(self._result.servers):
                address_item.setData(Qt.ItemDataRole.UserRole, value)
            self.data_table.setItem(row, 2, address_item)
        self._update_selection_actions()

    @Slot()
    def _clear_thread(self) -> None:
        self._set_refresh_button_busy(False)
        self.progress.setVisible(False)
        self._thread = None
        self._worker = None

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None and self._thread.isRunning():
            event.ignore()
            self._set_status("Дождитесь завершения загрузки GeoHide")
            return
        self._refresh_timer.stop()
        if self.status_web_view is not None:
            self.status_web_view.stop()
            self.status_web_view.setUrl(QUrl("about:blank"))
            self.status_web_view.deleteLater()
            self.status_web_view = None
        super().closeEvent(event)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetVision — визуальная диагностика сети")
        self.resize(1280, 820)
        self.setMinimumSize(960, 680)

        self._thread: QThread | None = None
        self._worker: DiagnosticWorker | None = None
        self._report: DiagnosticReport | None = None
        self._selected_process: ProcessNetworkInfo | None = None
        self._selected_connection: ProcessConnection | None = None
        self._system_action_threads: set[QThread] = set()
        self._system_action_workers: dict[QThread, SystemActionWorker] = {}
        self._system_action_status: dict[QPushButton, QLabel] = {}
        self.quick_fix_status: dict[str, QLabel] = {}
        self.quick_fix_buttons: dict[str, list[QPushButton]] = {}
        self._process_scan_thread: QThread | None = None
        self._process_scan_worker: ProcessScanWorker | None = None
        self._network_boost_scan_thread: QThread | None = None
        self._network_boost_scan_worker: NetworkBoostScanWorker | None = None
        self._network_boost_terminate_thread: QThread | None = None
        self._network_boost_terminate_worker: NetworkBoostTerminateWorker | None = None
        self._network_boost_dialog: NetworkBoostDialog | None = None
        self._network_boost_buttons: list[QPushButton] = []
        self._udp_monitor_thread: QThread | None = None
        self._udp_monitor_worker: UdpPortMonitorWorker | None = None
        self._udp_monitor_pid: int | None = None
        self._udp_monitor_warning: str | None = None
        self._last_udp_snapshot: UdpPortSnapshot | None = None
        self._udp_activity_history: list[UdpPortActivity] = []
        self._udp_event_rows: list[UdpEventRow] = []
        self._quality_thread: QThread | None = None
        self._quality_worker: InternetQualityWorker | None = None
        self._quality_report: InternetQualityReport | None = None
        self._latency_thread: QThread | None = None
        self._latency_worker: LatencyMonitorWorker | None = None
        self._worker_registry = WorkerRegistry(self)
        self._worker_registry.idle.connect(self._finish_monitor_shutdown)
        self._closing = False
        self._task_button_states: dict[QAbstractButton, tuple[str, str]] = {}
        self._task_button_timer = QTimer(self)
        self._task_button_timer.setInterval(420)
        self._task_button_timer.timeout.connect(self._animate_task_buttons)
        self._task_button_phase = 0
        self._dns_benchmark_thread: QThread | None = None
        self._dns_benchmark_worker: DnsBenchmarkWorker | None = None
        self._dns_config_thread: QThread | None = None
        self._dns_config_worker: DnsConfigurationWorker | None = None
        self._dns_configuration: DnsConfiguration | None = None
        self._dns_public_addresses: PublicIpAddresses | None = None
        self._geohide_dialog: GeoHideDialog | None = None
        self._ping_benchmark_thread: QThread | None = None
        self._ping_benchmark_worker: PingBenchmarkWorker | None = None
        self._preferred_ping_target: RegionalPingTarget | None = None
        self._ping_matrix_results: tuple[RegionalPingResult, ...] = ()
        self._loss_test_thread: QThread | None = None
        self._loss_test_worker: PacketLossTestWorker | None = None
        self._tcp_diagnostics_thread: QThread | None = None
        self._tcp_diagnostics_worker: TcpDiagnosticsWorker | None = None
        self._tls_audit_thread: QThread | None = None
        self._tls_audit_worker: TlsAuditWorker | None = None
        self._tls_audit_result: TlsAuditResult | None = None
        self._dns_profiles: list[DnsResolverProfile] = list(PUBLIC_DNS_PROFILES)
        self._latency_window: list[float | None] = []
        self._ping_spike_events: list[str] = []
        self._jitter_events: list[JitterEventRow] = []
        self._jitter_deviations: list[float] = []
        self._jitter_previous_rtt: float | None = None
        self._jitter_target_host = self.target_input.text().strip() if hasattr(self, "target_input") else ""
        self._loss_analyzer = PacketLossAnalyzer()
        self._previous_workspace = "expert"
        self._active_preset: str | None = None
        self._theme = "dark"
        self._translator = UiTranslator("ru", self)
        self._language = self._translator.language
        self._translator.language_changed.connect(self._retranslate_ui)
        self._session_elapsed_seconds = 0
        self._session_timer = QTimer(self)
        self._session_timer.setInterval(1000)
        self._session_timer.timeout.connect(self._advance_session_timer)
        self._header_anomaly_state = "good"
        self._header_anomaly_source = "Связь стабильна"
        self._header_anomaly_values: dict[str, object] = {}
        self._header_anomaly_history: deque[HeaderAnomalyEvent] = deque(maxlen=5)
        self._last_header_anomaly_signature: tuple[str, str] | None = None
        self._header_anomaly_menu: QMenu | None = None
        self._preset_defaults = {
            name: (name, host, port) for name, host, port in QUICK_PRESETS
        }
        self._preset_settings = QSettings()
        self._preset_profiles = self._load_preset_profiles()
        self.preset_buttons: dict[str, QPushButton] = {}

        self._build_ui()
        self._refresh_session_capsule()
        self._set_status("READY", "idle")
        self._append_log("NetVision готов к диагностике")
        self._retranslate_ui(self._language)

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("AppSurface")
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)
        self.setCentralWidget(central)

        root.addWidget(self._build_header())
        root.addWidget(self._build_controls())
        root.addWidget(self._build_process_selector())

        self.mode_stack = QStackedWidget()
        self.expert_view = self._build_expert_view()
        self.lite_view = self._build_lite_view()
        self.dns_view = self._build_dns_workspace()
        self.ping_view = self._build_ping_workspace()
        self.loss_view = self._build_loss_workspace()
        self.tcp_view = self._build_tcp_workspace()
        self.tls_view = self._build_tls_workspace()
        self.jitter_view = self._build_jitter_workspace()
        self.mode_stack.addWidget(self.expert_view)
        self.mode_stack.addWidget(self.lite_view)
        self.mode_stack.addWidget(self.dns_view)
        self.mode_stack.addWidget(self.ping_view)
        self.mode_stack.addWidget(self.loss_view)
        self.mode_stack.addWidget(self.tcp_view)
        self.mode_stack.addWidget(self.tls_view)
        self.mode_stack.addWidget(self.jitter_view)
        self.mode_scroll = self._make_scroll_area(self.mode_stack)
        self.mode_scroll.setObjectName("ModeScrollArea")
        root.addWidget(self.mode_scroll, 1)
        QTimer.singleShot(0, self._update_responsive_layout)

    def _build_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("Header")
        apply_panel_shadow(header)
        layout = QHBoxLayout(header)
        # Keep the identity block flush with the header's left content edge.
        layout.setContentsMargins(0, 12, 18, 12)
        layout.setSpacing(6)

        self.header_brand = QWidget()
        self.header_brand.setObjectName("HeaderBrand")
        self.header_brand.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.header_brand.setMinimumWidth(190)
        brand_box = QVBoxLayout(self.header_brand)
        brand_box.setContentsMargins(0, 0, 0, 0)
        brand_box.setSpacing(0)
        brand = QLabel("NETVISION")
        brand.setObjectName("Brand")
        self.brand_caption = QLabel("NETWORK DIAGNOSTICS / WINDOWS")
        self.brand_caption.setObjectName("BrandCaption")
        brand.setMargin(0)
        self.brand_caption.setMargin(0)
        brand_box.addWidget(brand)
        brand_box.addWidget(self.brand_caption)

        self.status_badge = QLabel()
        self.status_badge.setObjectName("HealthIndicator")
        self.status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # The exact width is updated from the active health text. Keep the
        # badge compact instead of allowing it to absorb header free space.
        self.status_badge.setMinimumWidth(250)
        self.status_badge.setMaximumWidth(340)
        self.status_badge.setMinimumHeight(38)
        self.status_badge.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Fixed,
        )
        self.status_badge.setAccessibleName("Индикатор здоровья сети")

        self.header_identity = QWidget()
        self.header_identity.setObjectName("HeaderIdentity")
        self.header_identity.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        identity_layout = QHBoxLayout(self.header_identity)
        identity_layout.setContentsMargins(0, 0, 0, 0)
        identity_layout.setSpacing(14)
        identity_layout.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        identity_layout.addWidget(self.header_brand)
        identity_layout.addWidget(self.status_badge)

        self.session_capsule = QFrame()
        self.session_capsule.setObjectName("SessionCapsule")
        self.session_capsule.setMinimumWidth(182)
        self.session_capsule.setMaximumWidth(520)
        self.session_capsule.setMinimumHeight(38)
        self.session_capsule.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        session_layout = QHBoxLayout(self.session_capsule)
        session_layout.setContentsMargins(5, 3, 5, 3)
        session_layout.setSpacing(2)

        self.session_timer_button = QToolButton()
        self.session_timer_button.setObjectName("SessionTimerButton")
        self.session_timer_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.session_timer_button.clicked.connect(self._toggle_session_timer)

        self.session_reset_button = QToolButton()
        self.session_reset_button.setObjectName("SessionResetButton")
        self.session_reset_button.setText("↺")
        self.session_reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.session_reset_button.clicked.connect(self._reset_session_timer)

        self.session_log_button = QToolButton()
        self.session_log_button.setObjectName("SessionLogButton")
        self.session_log_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.session_log_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.session_log_button.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        self.session_log_button.clicked.connect(self._toggle_header_anomaly_menu)
        self._header_anomaly_menu = QMenu(self)
        self._header_anomaly_menu.setObjectName("SessionAnomalyMenu")
        self._header_anomaly_menu.setSeparatorsCollapsible(False)
        self._header_anomaly_menu.aboutToShow.connect(self._populate_header_anomaly_menu)

        session_layout.addWidget(self.session_timer_button)
        session_layout.addWidget(self.session_reset_button)
        session_layout.addWidget(self.session_log_button, 1)

        self.mode_label = QLabel("РЕЖИМ")
        self.mode_label.setObjectName("ModeLabel")
        self.expert_mode_button = QRadioButton("Эксперт")
        self.expert_mode_button.setObjectName("ModeToggle")
        self.lite_mode_button = QRadioButton("Простой режим")
        self.lite_mode_button.setObjectName("ModeToggle")
        self.mode_button_group = QButtonGroup(self)
        self.mode_button_group.setExclusive(True)
        self.mode_button_group.addButton(self.expert_mode_button)
        self.mode_button_group.addButton(self.lite_mode_button)
        self.expert_mode_button.setChecked(True)
        self.expert_mode_button.toggled.connect(
            lambda checked: checked and self._set_interface_mode("expert")
        )
        self.lite_mode_button.toggled.connect(
            lambda checked: checked and self._set_interface_mode("lite")
        )

        self.export_button = QToolButton()
        self.export_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        self.export_button.setToolTip("Экспортировать диагностический отчёт в JSON")
        self.export_button.setAccessibleName("Экспортировать отчёт")
        self.export_button.setFixedSize(36, 36)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_report)

        self.connection_capture_button = QPushButton("⌕  Выбрать соединение")
        self.connection_capture_button.setObjectName("ProcessCaptureButton")
        self.connection_capture_button.setToolTip(self._tr("Выбрать соединение"))
        self.connection_capture_button.setAccessibleName(self._tr("Выбрать соединение"))
        self.connection_capture_button.setMinimumWidth(158)
        self.connection_capture_button.clicked.connect(self._open_connection_capture_dialog)

        self.manual_process_button = QPushButton("Сменить процесс")
        self.manual_process_button.setObjectName("ManualProcessButton")
        self.manual_process_button.setToolTip(self._tr("Выбрать процесс вручную"))
        self.manual_process_button.setAccessibleName(self._tr("Выбрать процесс вручную"))
        self.manual_process_button.setMinimumWidth(144)
        self.manual_process_button.clicked.connect(self._open_manual_process_dialog)

        self.header_settings = QWidget()
        self.header_settings.setObjectName("HeaderSettings")
        self.header_settings.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        settings_layout = QHBoxLayout(self.header_settings)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(5)

        self.language_label = QLabel("ЯЗЫК")
        self.language_label.setObjectName("ModeLabel")
        self.language_combo = QComboBox()
        self.language_combo.setObjectName("LanguageSelector")
        self.language_combo.setToolTip("Выбрать язык интерфейса / Choose interface language")
        self.language_combo.addItem("RU", "ru")
        self.language_combo.addItem("EN", "en")
        self.language_combo.setCurrentIndex(0)
        self.language_combo.setMinimumWidth(58)
        self.language_combo.setMaximumWidth(66)
        self.language_combo.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.language_combo.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        _keep_wheel_scroll_local(self.language_combo.view())
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)

        self.theme_button = QToolButton()
        self.theme_button.setObjectName("ThemeToggle")
        self.theme_button.setText("☾")
        self.theme_button.setToolTip("Переключить на светлую тему")
        self.theme_button.setAccessibleName("Переключатель тёмной и светлой темы")
        self.theme_button.setFixedSize(36, 36)
        self.theme_button.clicked.connect(self._toggle_theme)

        # Keep the edge controls anchored on wide screens. The two stretches
        # reserve the free width around the central session capsule instead of
        # spreading it between every header control.
        layout.addWidget(
            self.header_identity,
            0,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        )
        layout.addStretch(1)
        layout.addWidget(self.session_capsule, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addStretch(1)
        settings_layout.addWidget(self.language_label)
        settings_layout.addWidget(self.language_combo)
        settings_layout.addWidget(self.theme_button)

        self.header_mode_controls = QWidget()
        self.header_mode_controls.setObjectName("HeaderModeControls")
        self.header_mode_controls.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        mode_layout = QHBoxLayout(self.header_mode_controls)
        mode_layout.setContentsMargins(0, 0, 0, 0)
        mode_layout.setSpacing(5)
        mode_layout.addWidget(self.mode_label)
        mode_layout.addWidget(self.expert_mode_button)
        mode_layout.addWidget(self.lite_mode_button)

        layout.addWidget(self.header_mode_controls, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.export_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(
            self.header_settings,
            0,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )
        return header

    def resizeEvent(self, event: object) -> None:
        super().resizeEvent(event)
        QTimer.singleShot(0, self._update_responsive_layout)

    def _update_responsive_layout(self) -> None:
        """Compact dense control rows before they can overflow the window."""
        compact = self.width() < 1120
        narrow = self.width() < 1040
        if hasattr(self, "brand_caption"):
            self.brand_caption.setVisible(not compact)
            self.header_mode_controls.setVisible(not compact)
            self.mode_label.setVisible(not compact)
            self.language_label.setVisible(not narrow)
        if hasattr(self, "status_badge"):
            self.status_badge.setVisible(not narrow)
        if hasattr(self, "session_capsule"):
            show_anomaly_text = self.width() >= 1180
            self.session_log_button.setVisible(show_anomaly_text)
            self.session_capsule.setMaximumWidth(520 if show_anomaly_text else 182)
            header = self.session_capsule.parentWidget()
            layout = header.layout()
            margins = layout.contentsMargins()
            available = header.width() - margins.left() - margins.right()

            def required_width() -> int:
                controls = [layout.itemAt(index).widget() for index in range(layout.count())]
                visible = [widget for widget in controls if widget is not None and not widget.isHidden()]
                return sum(
                    182 if widget is self.session_capsule else max(widget.minimumWidth(), widget.sizeHint().width())
                    for widget in visible
                ) + max(0, len(visible) - 1) * layout.spacing()

            for secondary in (self.brand_caption, self.mode_label, self.language_label,
                              self.status_badge, self.header_mode_controls):
                if required_width() <= available:
                    break
                secondary.hide()
        if hasattr(self, "control_layout"):
            self._reflow_control_bar(compact)
        self._refresh_elided_labels()

    def _refresh_elided_labels(self) -> None:
        for name in ("udp_ports_status",):
            label = getattr(self, name, None)
            if not isinstance(label, QLabel):
                continue
            text = label.property("fullText")
            if isinstance(text, str):
                self._set_elided_text(label, text)

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

    @staticmethod
    def _format_session_elapsed(seconds: int) -> str:
        hours, remainder = divmod(max(0, seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"

    def _refresh_session_capsule(self) -> None:
        """Render the compact session timer and its current anomaly summary."""
        if not hasattr(self, "session_timer_button"):
            return
        elapsed = self._format_session_elapsed(self._session_elapsed_seconds)
        running = self._session_timer.isActive()
        self.session_timer_button.setText(f"⏱  {elapsed}")
        self.session_timer_button.setProperty("paused", not running)
        self.session_timer_button.setToolTip(
            self._tr(
                "Поставить таймер сессии на паузу"
                if running
                else "Продолжить таймер сессии"
            )
        )
        self.session_timer_button.setAccessibleName(
            self._translator.format("Таймер сессии диагностики: {time}", time=elapsed)
        )
        self.session_reset_button.setToolTip(self._tr("Сбросить таймер сессии"))
        self.session_reset_button.setAccessibleName(self._tr("Сбросить таймер сессии"))

        icons = {"good": "●", "info": "ℹ", "warning": "⚠", "error": "⛔"}
        state = self._header_anomaly_state
        message = self._translator.format(
            self._header_anomaly_source,
            **self._header_anomaly_values,
        )
        self.session_log_button.setText(f"{icons.get(state, 'ℹ')}  {message}")
        self.session_log_button.setProperty("anomalyState", state)
        self.session_log_button.setProperty("fullText", message)
        self.session_log_button.setToolTip(self._tr("Открыть недавние аномалии"))
        self.session_log_button.setAccessibleName(
            self._translator.format(
                "Статус сети: {message}. Открыть недавние аномалии",
                message=message,
            )
        )
        for button in (self.session_timer_button, self.session_log_button):
            button.style().unpolish(button)
            button.style().polish(button)

    def _start_diagnostic_session(self) -> None:
        self._session_elapsed_seconds = 0
        self._session_timer.start()
        self._set_header_anomaly("info", "Диагностика выполняется")

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

    def _set_header_anomaly(self, state: str, source: str, **values: object) -> None:
        normalized_state = state if state in {"good", "info", "warning", "error"} else "info"
        if normalized_state in {"warning", "error"}:
            signature = (normalized_state, source)
            if signature != self._last_header_anomaly_signature:
                self._header_anomaly_history.append(
                    HeaderAnomalyEvent(
                        observed_at=datetime.now(),
                        state=normalized_state,
                        source=source,
                        values=tuple(values.items()),
                    )
                )
            self._last_header_anomaly_signature = signature
        else:
            self._last_header_anomaly_signature = None
        self._header_anomaly_state = normalized_state
        self._header_anomaly_source = source
        self._header_anomaly_values = values
        self._refresh_session_capsule()

    def _header_anomaly_text(self, event: HeaderAnomalyEvent) -> str:
        return self._translator.format(event.source, **dict(event.values))

    def _populate_header_anomaly_menu(self) -> None:
        """Rebuild the compact, translated popup before it is displayed."""
        menu = self._header_anomaly_menu
        if menu is None:
            return
        menu.clear()

        content = QFrame(menu)
        content.setObjectName("SessionAnomalyMenuContent")
        content.setFixedWidth(322)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(6)

        title = QLabel(self._tr("ПОСЛЕДНИЕ АНОМАЛИИ"))
        title.setObjectName("SessionAnomalyMenuTitle")
        content_layout.addWidget(title)

        if self._header_anomaly_history:
            for event in reversed(self._header_anomaly_history):
                item = QLabel(
                    f"{event.observed_at:%H:%M:%S}  -  {self._header_anomaly_text(event)}"
                )
                item.setObjectName("SessionAnomalyItem")
                item.setProperty("anomalyState", event.state)
                item.setWordWrap(True)
                item.setToolTip(item.text())
                content_layout.addWidget(item)
        else:
            empty_state = QLabel(self._tr("Нет недавних аномалий"))
            empty_state.setObjectName("SessionAnomalyEmptyState")
            empty_state.setWordWrap(True)
            content_layout.addWidget(empty_state)

        content_layout.addSpacing(2)
        open_log_button = QPushButton(self._tr("Открыть полный журнал"))
        open_log_button.setObjectName("SessionAnomalyOpenLogButton")
        open_log_button.clicked.connect(self._open_full_log_from_anomaly_menu)
        content_layout.addWidget(open_log_button)

        action = QWidgetAction(menu)
        action.setDefaultWidget(content)
        menu.addAction(action)

    @Slot()
    def _toggle_header_anomaly_menu(self) -> None:
        """Show the recent anomaly history directly below the capsule status."""
        menu = self._header_anomaly_menu
        if menu is None:
            return
        if menu.isVisible():
            menu.hide()
            return
        anchor = self.session_log_button.mapToGlobal(self.session_log_button.rect().bottomLeft())
        menu.popup(anchor)

    @Slot()
    def _open_full_log_from_anomaly_menu(self) -> None:
        if self._header_anomaly_menu is not None:
            self._header_anomaly_menu.hide()
        self._open_log_from_header()

    @Slot()
    def _open_log_from_header(self) -> None:
        """Open the event log from any dashboard or deep-dive workspace."""
        if self._header_anomaly_menu is not None:
            self._header_anomaly_menu.hide()
        self._close_combo_popups()
        if not self.expert_mode_button.isChecked():
            self.expert_mode_button.setChecked(True)
        else:
            self.mode_stack.setCurrentWidget(self.expert_view)
            self._update_process_display(False)
        self.workspace_tabs.setCurrentWidget(self.log_tab)
        self.log_output.setFocus()

    @Slot()
    def _toggle_theme(self) -> None:
        self._theme = "light" if self._theme == "dark" else "dark"
        application = QApplication.instance()
        if application is not None:
            application.setStyleSheet(LIGHT_STYLE if self._theme == "light" else APP_STYLE)
        if self._theme == "light":
            self.theme_button.setText("☀")
            self.theme_button.setToolTip(self._tr("Переключить на тёмную тему"))
        else:
            self.theme_button.setText("☾")
            self.theme_button.setToolTip(self._tr("Переключить на светлую тему"))

    @Slot(int)
    def _on_language_changed(self, index: int) -> None:
        language = self.language_combo.itemData(index)
        self._translator.set_language(str(language))

    def _tr(self, text: str) -> str:
        return self._translator.translate(text)

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

    @Slot(str)
    def _retranslate_ui(self, language: str) -> None:
        """Apply the selected language to every already-created UI element.

        Qt only emits ``LanguageChange`` automatically for resource-based
        ``QTranslator`` catalogs. NetVision creates dashboards and dialogs in
        Python, so the runtime service deliberately updates all text-bearing
        widgets, tabs and table headers here instead.
        """
        self._language = language
        self.setWindowTitle(self._tr("NetVision — визуальная диагностика сети"))
        self._retranslate_widget_tree(self)
        self._refresh_preset_buttons()

        for widget in (getattr(self, "latency_chart", None), getattr(self, "jitter_chart", None), getattr(self, "topology", None)):
            if widget is not None and hasattr(widget, "set_translator"):
                widget.set_translator(self._tr)

        self._refresh_dynamic_process_text()
        if hasattr(self, "dns_info_grid"):
            self._render_dns_info()

        if self._network_boost_dialog is not None:
            self._network_boost_dialog.retranslate(self._tr)
        if self._geohide_dialog is not None:
            self._geohide_dialog.retranslate(self._tr)

        if hasattr(self, "jitter_event_status"):
            self.jitter_event_status.setText(
                self._translator.format(
                    "Критический порог: Δ RTT > 15 мс · событий: {count}",
                    count=len(self._jitter_events),
                )
            )

        # Theme tooltips are stateful, so set them from the current theme
        # rather than translating a stale tooltip from the prior language.
        if self._theme == "light":
            self.theme_button.setToolTip(self._tr("Переключить на тёмную тему"))
        else:
            self.theme_button.setToolTip(self._tr("Переключить на светлую тему"))
        self._set_status("READY", getattr(self, "_status_state", "idle"))
        self._refresh_session_capsule()
        if self._header_anomaly_menu is not None:
            self._header_anomaly_menu.hide()
        QTimer.singleShot(0, self._update_responsive_layout)
        self._append_log(
            "Interface language: English" if language == "en" else "Язык интерфейса: русский"
        )

    def _retranslate_widget_tree(self, root: QWidget) -> None:
        """Translate static text, tooltips, placeholders and table tabs in-place."""
        labels = root.findChildren(QLabel)
        # ``process_status`` is not parented by the compact selector layout.
        # Include it in the same update path as the visible child labels.
        detached_process_status = getattr(self, "process_status", None)
        if isinstance(detached_process_status, QLabel) and detached_process_status not in labels:
            labels.append(detached_process_status)
        for label in labels:
            label.setText(self._tr(label.text()))
            self._retranslate_tooltip(label)
            label.setAccessibleName(self._tr(label.accessibleName()))

        for button_type in (QPushButton, QToolButton, QRadioButton, QCheckBox):
            for button in root.findChildren(button_type):
                button.setText(self._tr(button.text()))
                self._retranslate_tooltip(button)
                button.setAccessibleName(self._tr(button.accessibleName()))

        for line_edit in root.findChildren(QLineEdit):
            line_edit.setPlaceholderText(self._tr(line_edit.placeholderText()))
            self._retranslate_tooltip(line_edit)

        for spin_box in root.findChildren(QSpinBox):
            self._retranslate_tooltip(spin_box)

        for text_edit in root.findChildren(QPlainTextEdit):
            text_edit.setPlaceholderText(self._tr(text_edit.placeholderText()))
            self._retranslate_tooltip(text_edit)

        for combo in root.findChildren(QComboBox):
            self._retranslate_tooltip(combo)
            combo.setAccessibleName(self._tr(combo.accessibleName()))
            for index in range(combo.count()):
                combo.setItemText(index, self._tr(combo.itemText(index)))

        for tabs in root.findChildren(QTabWidget):
            for index in range(tabs.count()):
                tabs.setTabText(index, self._tr(tabs.tabText(index)))

        for table in root.findChildren(QTableWidget):
            for index in range(table.columnCount()):
                header = table.horizontalHeaderItem(index)
                if header is not None:
                    header.setText(self._tr(header.text()))
            for row in range(table.rowCount()):
                for column in range(table.columnCount()):
                    item = table.item(row, column)
                    if item is not None:
                        item.setText(self._tr(item.text()))
                        item.setToolTip(self._tr(item.toolTip()))

    def _set_translatable_tooltip(self, widget: QWidget, *parts: str) -> None:
        """Set a multi-part tooltip whose source phrases survive language changes."""
        widget._i18n_tooltip_parts = parts  # type: ignore[attr-defined]
        widget.setToolTip("\n".join(self._tr(part) for part in parts))

    def _retranslate_tooltip(self, widget: QWidget) -> None:
        parts = getattr(widget, "_i18n_tooltip_parts", None)
        if parts:
            widget.setToolTip("\n".join(self._tr(part) for part in parts))
            return
        widget.setToolTip(self._tr(widget.toolTip()))

    def _build_expert_view(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._build_metrics())

        self.workspace_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.workspace_splitter.setChildrenCollapsible(False)
        self.workspace_splitter.addWidget(self._build_topology_panel())
        self.workspace_splitter.addWidget(self._build_tabs())
        self.workspace_splitter.setSizes([580, 740])
        self.workspace_splitter.setStretchFactor(0, 4)
        self.workspace_splitter.setStretchFactor(1, 5)
        layout.addWidget(self.workspace_splitter, 1)
        layout.addWidget(self._build_quick_actions())
        return view

    def _build_lite_view(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("LiteSummaryPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        self.lite_hero = QFrame()
        self.lite_hero.setObjectName("LiteHeroCard")
        apply_panel_shadow(self.lite_hero)
        hero_layout = QHBoxLayout(self.lite_hero)
        hero_layout.setContentsMargins(22, 18, 22, 18)
        hero_layout.setSpacing(18)

        self.lite_status_indicator = QLabel("⚠️")
        self.lite_status_indicator.setObjectName("LiteStatusIndicator")
        self.lite_status_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lite_status_indicator.setFixedSize(64, 64)

        hero_text = QVBoxLayout()
        hero_text.setSpacing(6)
        self.lite_title = QLabel("Ожидание проверки")
        self.lite_title.setObjectName("LiteTitle")
        self.lite_title.setWordWrap(True)
        self.lite_message = QLabel("Запустите диагностику, чтобы увидеть понятный итог.")
        self.lite_message.setObjectName("LiteMessage")
        self.lite_message.setWordWrap(True)
        self.lite_cause = QLabel("Диагноз появится после проверки.")
        self.lite_cause.setObjectName("LiteCause")
        self.lite_cause.setWordWrap(True)
        hero_text.addWidget(self.lite_title)
        hero_text.addWidget(self.lite_message)
        hero_text.addWidget(self.lite_cause)
        hero_layout.addWidget(self.lite_status_indicator)
        hero_layout.addLayout(hero_text, 1)

        self.lite_details = QGridLayout()
        self.lite_details.setHorizontalSpacing(10)
        self.lite_details.setVerticalSpacing(10)
        self.lite_detail_labels: list[QLabel] = []
        self._set_lite_status_style(LiteStatus.WARNING)

        summary_header = QLabel("КОРОТКАЯ СВОДКА")
        summary_header.setObjectName("FieldLabel")
        layout.addWidget(self.lite_hero)
        layout.addWidget(summary_header)
        layout.addLayout(self.lite_details)
        layout.addStretch(1)
        return panel

    def _build_quick_actions(self) -> QFrame:
        panel = QFrame()
        self.quick_actions_panel = panel
        panel.setObjectName("QuickActions")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)

        title = QLabel("ДЕЙСТВИЯ")
        title.setObjectName("QuickActionsTitle")
        layout.addWidget(title)

        self.flush_dns_button = self._make_quick_action_button(
            "🔄  Сброс DNS",
            flush_dns_cache,
            primary=True,
        )
        apply_accent_glow(self.flush_dns_button)
        self.adapters_button = self._make_quick_action_button(
            "🖥️  Сетевые адаптеры",
            open_network_adapters,
        )
        self.proxy_settings_button = self._make_quick_action_button(
            "⚙️  Параметры прокси",
            open_network_proxy_settings,
        )
        self.firewall_button = self._make_quick_action_button(
            "🛡️  Брандмауэр",
            open_windows_firewall,
        )
        layout.addWidget(self.flush_dns_button, 1)
        layout.addWidget(self.adapters_button, 1)
        layout.addWidget(self.proxy_settings_button, 1)
        layout.addWidget(self.firewall_button, 1)
        return panel

    def _build_process_selector(self) -> QFrame:
        panel = QFrame()
        self.process_panel = panel
        panel.setObjectName("ProcessInspectorBar")
        apply_panel_shadow(panel)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(12, 5, 12, 5)
        panel_layout.setSpacing(6)
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        self.process_title = QLabel("ПРОЦЕСС")
        title = self.process_title
        title.setObjectName("ProcessSelectorLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        title.setMinimumHeight(36)
        title.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.process_selector = EmbeddedComboBox()
        self.process_selector.setMinimumWidth(140)
        self.process_selector.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        self.process_selector.setToolTip("Выберите приложение с активными сетевыми соединениями")
        self.process_selector.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        _keep_wheel_scroll_local(self.process_selector.view())
        self.process_selector.addItem("Список процессов не обновлён", None)
        self.process_selector.currentIndexChanged.connect(self._on_process_selected)
        self.process_selector.popup_requested.connect(self._show_embedded_dropdown)

        self.connection_title = QLabel("СОЕДИНЕНИЕ")
        connection_title = self.connection_title
        connection_title.setObjectName("ProcessSelectorLabel")
        connection_title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        connection_title.setMinimumHeight(36)
        connection_title.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.process_connection_selector = EmbeddedComboBox()
        self.process_connection_selector.setMinimumWidth(180)
        self.process_connection_selector.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        self.process_connection_selector.setToolTip("Выберите IP-адрес и порт процесса")
        self.process_connection_selector.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        _keep_wheel_scroll_local(self.process_connection_selector.view())
        self.process_connection_selector.addItem("Сначала выберите процесс", None)
        self.process_connection_selector.currentIndexChanged.connect(self._on_connection_selected)
        self.process_connection_selector.popup_requested.connect(self._show_embedded_dropdown)

        self.process_refresh_button = QToolButton()
        self.process_refresh_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.process_refresh_button.setToolTip(
            self._tr("Обновить список процессов и сетевых соединений")
        )
        self.process_refresh_button.setAccessibleName("Обновить список процессов")
        self.process_refresh_button.setFixedSize(36, 36)
        self.process_refresh_button.clicked.connect(self.refresh_processes)

        self.process_status = QLabel()
        self.process_status.setObjectName("Muted")
        self.process_status.setVisible(False)

        self.udp_ports_status = QLabel("UDP: выберите процесс для мониторинга")
        self.udp_ports_status.setObjectName("UdpPortStatus")
        self.udp_ports_status.setToolTip(
            "В реальном времени показывает локальные UDP-порты, занятые выбранным процессом."
        )

        layout.addWidget(title, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.process_selector, 1)
        layout.addWidget(self.manual_process_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.connection_capture_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(connection_title, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.process_connection_selector, 1)
        layout.addWidget(self.process_refresh_button)
        panel_layout.addLayout(layout)
        panel_layout.addWidget(self.udp_ports_status)

        self.embedded_dropdown = QFrame(panel)
        self.embedded_dropdown.setObjectName("EmbeddedDropdown")
        dropdown_layout = QVBoxLayout(self.embedded_dropdown)
        dropdown_layout.setContentsMargins(6, 6, 6, 6)
        dropdown_layout.setSpacing(0)
        self.embedded_dropdown_list = QListWidget(self.embedded_dropdown)
        _keep_wheel_scroll_local(self.embedded_dropdown_list)
        self.embedded_dropdown_list.setObjectName("EmbeddedDropdownList")
        self.embedded_dropdown_list.setMaximumHeight(180)
        self.embedded_dropdown_list.itemActivated.connect(self._select_embedded_dropdown_item)
        self.embedded_dropdown_list.itemClicked.connect(self._select_embedded_dropdown_item)
        dropdown_layout.addWidget(self.embedded_dropdown_list)
        self.embedded_dropdown.hide()
        self._active_embedded_combo: QComboBox | None = None
        panel_layout.addWidget(self.embedded_dropdown)
        return panel

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

    def _build_quick_fix_panel(self, context: str) -> QFrame:
        panel = QFrame()
        panel.setObjectName("QuickFixPanel")
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        heading = QHBoxLayout()
        title = QLabel("БЫСТРЫЕ РЕШЕНИЯ / QUICK FIXES")
        title.setObjectName("QuickFixTitle")
        status = QLabel("Готово к применению")
        status.setObjectName("QuickFixStatus")
        status.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        heading.addWidget(title)
        heading.addStretch(1)
        heading.addWidget(status)
        layout.addLayout(heading)

        actions = QGridLayout()
        actions.setHorizontalSpacing(8)
        actions.setVerticalSpacing(8)
        definitions = (
            ("dns", "🔄  Сбросить кэш DNS", True),
            ("mtu", "📐  Оптимизировать MTU", False),
            ("stack", "🧰  Сбросить TCP/IP", False),
            ("adapter", "🔌  Перезапустить адаптер", False),
        )
        buttons: list[QPushButton] = []
        for index, (action_key, label, primary) in enumerate(definitions):
            button = QPushButton(label)
            button.setObjectName("QuickFixPrimary" if primary else "QuickFixButton")
            button.setAccessibleName(label)
            button.setToolTip(self._quick_fix_tooltip(action_key))
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(
                lambda _checked=False, action_key=action_key, button=button, status=status:
                self._trigger_quick_fix(action_key, button, status)
            )
            row, column = divmod(index, 2)
            actions.addWidget(button, row, column)
            actions.setColumnStretch(column, 1)
            buttons.append(button)
        layout.addLayout(actions)
        self.quick_fix_status[context] = status
        self.quick_fix_buttons[context] = buttons
        return panel

    @staticmethod
    def _quick_fix_tooltip(action_key: str) -> str:
        return {
            "dns": "Очистить локальный DNS-кэш без открытия окна консоли",
            "mtu": "Применить консервативный MTU 1500 к активному адаптеру",
            "stack": "Сбросить TCP/IP и Winsock; после этого потребуется перезагрузка Windows",
            "adapter": "Временно отключить и снова включить активный сетевой адаптер",
        }[action_key]

    def _active_adapter_name(self) -> str | None:
        adapter_combo = getattr(self, "dns_adapter_combo", None)
        if isinstance(adapter_combo, QComboBox):
            value = adapter_combo.currentData()
            if isinstance(value, str) and value.strip():
                return value
        if self._report is not None:
            for interface in self._report.system.interfaces:
                if interface.is_up and interface.name.strip():
                    return interface.name
        return None

    def _trigger_quick_fix(self, action_key: str, button: QPushButton, status: QLabel) -> None:
        if action_key == "dns":
            self._run_system_action("Сброс кэша DNS", flush_dns_cache, button, status)
            return
        adapter = self._active_adapter_name()
        if not adapter:
            status.setText(self._tr("Активный адаптер не определён"))
            return
        confirmations = {
            "mtu": (
                "Оптимизация MTU",
                f"Применить MTU 1500 к адаптеру «{adapter}»?\nТекущая сеть может кратковременно прерваться.",
            ),
            "stack": (
                "Сброс TCP/IP",
                "Сбросить TCP/IP и Winsock? Потребуется перезагрузка Windows, а текущие соединения будут закрыты.",
            ),
            "adapter": (
                "Перезапуск адаптера",
                f"Отключить и снова включить адаптер «{adapter}»? Текущее соединение будет временно потеряно.",
            ),
        }
        title, message = confirmations[action_key]
        answer = QMessageBox.question(
            self,
            self._tr(title),
            self._tr(message),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            status.setText(self._tr("Действие отменено"))
            return
        actions: dict[str, tuple[str, Callable[[], SystemActionResult]]] = {
            "mtu": ("Оптимизация MTU", lambda adapter=adapter: optimize_mtu(adapter)),
            "stack": ("Сброс TCP/IP и Winsock", reset_tcpip_stack),
            "adapter": ("Перезапуск адаптера", lambda adapter=adapter: restart_network_adapter(adapter)),
        }
        label, action = actions[action_key]
        self._run_system_action(label, action, button, status)

    def _build_controls(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("ControlBar")
        apply_panel_shadow(panel)
        layout = QGridLayout(panel)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setHorizontalSpacing(7)
        layout.setVerticalSpacing(6)
        self.control_layout = layout

        host_label = QLabel("АДРЕС")
        host_label.setObjectName("FieldLabel")
        self.target_input = QLineEdit("example.com")
        self.target_input.setPlaceholderText("example.com или https://example.com")
        self.target_input.setClearButtonEnabled(True)
        self.target_input.returnPressed.connect(self.start_diagnostic)

        preset_label = QLabel("ПРОФИЛЬ")
        preset_label.setObjectName("FieldLabel")
        preset_group = QButtonGroup(self)
        preset_group.setExclusive(True)
        for profile_id in self._preset_defaults:
            button = QPushButton()
            button.setObjectName("PresetButton")
            button.setCheckable(True)
            button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            button.clicked.connect(lambda _checked=False, profile_id=profile_id: self._apply_preset(profile_id))
            button.customContextMenuRequested.connect(
                lambda _position, profile_id=profile_id: self._edit_preset(profile_id)
            )
            preset_group.addButton(button)
            self.preset_buttons[profile_id] = button
            self._update_preset_button(profile_id)

        self.port_label = QLabel("ПОРТ")
        port_label = self.port_label
        port_label.setObjectName("FieldLabel")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)
        self._set_translatable_tooltip(
            self.port_input,
            "Сетевой порт целевого узла.",
            "• 443 — для защищенных HTTPS-соединений и большинства веб-серверов",
            "• 80 — для обычных HTTP-соединений",
            "Оставьте стандартное значение, если не уверены.",
        )
        self.port_input.setFixedWidth(108)

        self.start_button = QPushButton("Запустить диагностику")
        self.start_button.clicked.connect(self.start_diagnostic)

        self._control_host_label = host_label
        self._control_preset_label = preset_label
        self._reflow_control_bar(compact=False)
        return panel

    def _reflow_control_bar(self, compact: bool) -> None:
        if getattr(self, "_controls_compact", None) == compact:
            return
        self._controls_compact = compact
        while self.control_layout.count():
            self.control_layout.takeAt(0)

        presets = list(self.preset_buttons.values())
        if compact:
            self.control_layout.addWidget(self._control_host_label, 0, 0)
            self.control_layout.addWidget(self.target_input, 0, 1)
            self.control_layout.addWidget(self.start_button, 0, 2)
            self.control_layout.addWidget(self._control_preset_label, 1, 0)
            for column, button in enumerate(presets, start=1):
                self.control_layout.addWidget(button, 1, column)
            port_column = len(presets) + 1
            self.control_layout.addWidget(self.port_label, 1, port_column)
            self.control_layout.addWidget(self.port_input, 1, port_column + 1)
            self.control_layout.setColumnStretch(1, 1)
        else:
            column = 0
            self.control_layout.addWidget(self._control_host_label, 0, column)
            column += 1
            self.control_layout.addWidget(self.target_input, 0, column)
            self.control_layout.setColumnStretch(column, 1)
            column += 1
            self.control_layout.addWidget(self._control_preset_label, 0, column)
            column += 1
            for button in presets:
                self.control_layout.addWidget(button, 0, column)
                column += 1
            self.control_layout.addWidget(self.port_label, 0, column)
            column += 1
            self.control_layout.addWidget(self.port_input, 0, column)
            column += 1
            self.control_layout.addWidget(self.start_button, 0, column)
        self.control_layout.invalidate()

    def _load_preset_profiles(self) -> dict[str, tuple[str, str, int]]:
        profiles: dict[str, tuple[str, str, int]] = {}
        for profile_id, defaults in self._preset_defaults.items():
            default_label, default_host, default_port = defaults
            key = f"quick_profiles/{profile_id}"
            label = str(self._preset_settings.value(f"{key}/label", default_label)).strip() or default_label
            host = str(self._preset_settings.value(f"{key}/host", default_host)).strip() or default_host
            try:
                port = int(self._preset_settings.value(f"{key}/port", default_port))
            except (TypeError, ValueError):
                port = default_port
            profiles[profile_id] = (label, host, port if 1 <= port <= 65535 else default_port)
        return profiles

    def _update_preset_button(self, profile_id: str) -> None:
        button = self.preset_buttons[profile_id]
        label, host, port = self._preset_profiles[profile_id]
        display_label = self._tr(label)
        button.setText(display_label)
        button.setToolTip(
            self._translator.format("Проверить профиль: {host}:{port}", host=host, port=port)
        )
        button.setAccessibleName(self._translator.format("Профиль: {name}", name=display_label))

    def _refresh_preset_buttons(self) -> None:
        for profile_id in self.preset_buttons:
            self._update_preset_button(profile_id)

    @Slot(str)
    def _apply_preset(self, profile_id: str) -> None:
        label, host, port = self._preset_profiles[profile_id]
        display_label = self._tr(label)
        self._active_preset = profile_id
        self.target_input.setText(host)
        self.port_input.setValue(port)
        self.target_input.setFocus()
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
            self._translator.format("Выбран профиль «{name}»: {host}:{port}", name=display_label, host=host, port=port)
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

    def _save_preset_profile(self, profile_id: str, label: str, host: str, port: int) -> None:
        self._preset_profiles[profile_id] = (label, host, port)
        key = f"quick_profiles/{profile_id}"
        self._preset_settings.setValue(f"{key}/label", label)
        self._preset_settings.setValue(f"{key}/host", host)
        self._preset_settings.setValue(f"{key}/port", port)
        self._preset_settings.sync()
        self._update_preset_button(profile_id)

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
    def _open_manual_process_dialog(self) -> None:
        dialog = ManualProcessDialog(self._tr, self)
        dialog.process_selected.connect(self._select_manual_process)
        dialog.exec()

    @Slot(int, str)
    def _select_manual_process(self, pid: int, name: str) -> None:
        for index in range(self.process_selector.count()):
            process = self.process_selector.itemData(index)
            if isinstance(process, ProcessNetworkInfo) and process.pid == pid:
                self.process_selector.setCurrentIndex(index)
                return

        process = ProcessNetworkInfo(pid=pid, name=name, connections=())
        self.process_selector.addItem(self._process_display_label(process), process)
        self.process_selector.setCurrentIndex(self.process_selector.count() - 1)
        self.statusBar().showMessage(
            self._translator.format("Процесс назначен: {name} · PID {pid}", name=name, pid=pid),
            5000,
        )

    @Slot(str, int, str)
    def _save_captured_connection(self, host: str, port: int, profile_id: str) -> None:
        profile = self._preset_profiles.get(profile_id)
        if profile is None:
            return
        label, _previous_host, _previous_port = profile
        self._save_preset_profile(profile_id, label, host, port)
        self._active_preset = profile_id
        self.preset_buttons[profile_id].setChecked(True)
        self.target_input.setText(host)
        self.port_input.setValue(port)
        self.statusBar().showMessage(
            self._translator.format(
                "Подключение сохранено в профиль «{name}»: {host}:{port}",
                name=self._tr(label),
                host=host,
                port=port,
            ),
            5000,
        )

    @Slot()
    def refresh_processes(self) -> None:
        if self._process_scan_thread and self._process_scan_thread.isRunning():
            return
        self._stop_udp_port_monitor()
        self._set_udp_ports_status(None)
        self._set_task_button_busy(self.process_refresh_button, True, "Сканирование")
        self.process_refresh_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserStop)
        )
        self.process_status.setText(self._tr("Сканируем..."))
        self.process_selector.clear()
        self.process_selector.addItem(self._tr("Сканирование процессов..."), None)

        thread = QThread(self)
        worker = ProcessScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_process_scan_completed)
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_process_scan)
        self._process_scan_thread = thread
        self._process_scan_worker = worker
        thread.start()

    @Slot(object)
    def _on_process_scan_completed(self, result: object) -> None:
        self.process_selector.clear()
        if not isinstance(result, ProcessScanResult):
            result = ProcessScanResult((), "Список процессов не получен")
        if result.warning:
            self.process_status.setText(self._tr("Нет доступа"))
            self.process_selector.addItem(self._tr("Не удалось получить процессы"), None)
            self._append_log(f"Ошибка инспектора процессов: {result.warning}")
        elif not result.processes:
            self.process_status.setText(self._tr("Активные соединения не найдены"))
            self.process_selector.addItem(self._tr("Нет процессов с активной сетью"), None)
            self._append_log("Инспектор процессов: активные соединения не найдены")
        else:
            self.process_status.setText(
                self._translator.format("Найдено процессов: {count}", count=len(result.processes))
            )
            for process in result.processes:
                self.process_selector.addItem(self._process_display_label(process), process)
            self._append_log(f"Инспектор процессов: найдено {len(result.processes)} процессов")
        self._set_task_button_busy(self.process_refresh_button, False)
        self.process_refresh_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload)
        )
        self.process_refresh_button.setToolTip(
            self._tr("Обновить список процессов и сетевых соединений")
        )

    @Slot(int)
    def _on_process_selected(self, index: int) -> None:
        value = self.process_selector.itemData(index)
        self._selected_process = value if isinstance(value, ProcessNetworkInfo) else None
        self._selected_connection = None
        self.process_connection_selector.clear()
        if self._selected_process is None:
            self._stop_udp_port_monitor()
            self._set_udp_ports_status(None)
            self.process_connection_selector.addItem(self._tr("Сначала выберите процесс"), None)
            return
        for connection in self._selected_process.connections:
            self.process_connection_selector.addItem(self._connection_display_label(connection), connection)
        if not self._selected_process.connections:
            self.process_connection_selector.addItem(self._tr("Нет активных соединений"), None)
        self.process_status.setText(
            f"{self._selected_process.name}: {len(self._selected_process.connections)}"
        )
        self._append_log(f"Выбран процесс: {self._process_display_label(self._selected_process)}")
        self._start_udp_port_monitor(self._selected_process.pid)
        if self.lite_mode_button.isChecked() and self._selected_process.connections:
            self.process_connection_selector.setCurrentIndex(0)

    @Slot(int)
    def _on_connection_selected(self, index: int) -> None:
        connection = self.process_connection_selector.itemData(index)
        if not isinstance(connection, ProcessConnection):
            return
        self._selected_connection = connection
        if not connection.remote_address or connection.remote_port < 1:
            self.process_status.setText(
                f"{self._selected_process.name if self._selected_process else self._tr('Процесс')}: "
                f"{self._translator.format('локальный UDP-порт {port}', port=connection.local_port)}"
            )
            self._append_log(
                f"{self._translator.format('локальный UDP-порт {port}', port=connection.local_port)}; "
                f"{self._tr('цель диагностики не изменена')}"
            )
            return
        self.target_input.setText(connection.remote_address)
        self.port_input.setValue(connection.remote_port)
        self._append_log(
            f"Цель подставлена из процесса: {connection.remote_endpoint} ({connection.protocol})"
        )

    @Slot()
    def _clear_process_scan(self) -> None:
        if self.sender() is not self._process_scan_thread:
            return
        self._process_scan_thread = None
        self._process_scan_worker = None

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

    @Slot()
    def start_network_boost_scan(self) -> None:
        if self._network_boost_scan_thread and self._network_boost_scan_thread.isRunning():
            return
        self._set_network_boost_controls(True)
        self._set_network_boost_status("Network Boost: ищем известные фоновые приложения с активными сокетами...")
        thread = QThread(self)
        worker = NetworkBoostScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_network_boost_scan_completed)
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_network_boost_scan_worker)
        self._network_boost_scan_thread = thread
        self._network_boost_scan_worker = worker
        thread.start()

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

    @Slot(object)
    def _start_network_boost_termination(self, value: object) -> None:
        if self._network_boost_terminate_thread and self._network_boost_terminate_thread.isRunning():
            return
        if not isinstance(value, tuple) or not all(isinstance(item, BackgroundTrafficCandidate) for item in value):
            self._set_network_boost_status("Network Boost: не удалось проверить выбранные процессы")
            return
        dialog = self._network_boost_dialog
        if dialog is not None:
            dialog.set_busy(True)
        self._set_network_boost_controls(True)
        self._set_network_boost_status(self._tr("Завершаем выбранные процессы в фоновом потоке..."))
        thread = QThread(self)
        worker = NetworkBoostTerminateWorker(value)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_network_boost_terminated)
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_network_boost_terminate_worker)
        self._network_boost_terminate_thread = thread
        self._network_boost_terminate_worker = worker
        thread.start()

    @Slot(object)
    def _on_network_boost_terminated(self, value: object) -> None:
        self._set_network_boost_controls(False)
        if not isinstance(value, tuple) or not all(isinstance(item, ProcessTerminationResult) for item in value):
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
            self.start_packet_loss_analysis()
            return
        self.start_diagnostic()

    def _set_network_boost_controls(self, running: bool) -> None:
        for button in self._network_boost_buttons:
            self._set_task_button_busy(button, running, "Сканирование")

    def _set_network_boost_status(self, message: str) -> None:
        if hasattr(self, "loss_detector_status"):
            self.loss_detector_status.setText(message)
        if hasattr(self, "jitter_graph_status"):
            self.jitter_graph_status.setText(message)
        self.statusBar().showMessage(message, 6000)

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

    def _start_udp_port_monitor(self, pid: int) -> None:
        if self._udp_monitor_pid == pid and self._udp_monitor_thread and self._udp_monitor_thread.isRunning():
            return
        self._stop_udp_port_monitor()
        self._udp_monitor_pid = pid
        self._udp_monitor_warning = None
        self._udp_activity_history.clear()
        self._clear_udp_event_table()
        self._set_udp_ports_status(None)

        worker = UdpPortMonitorWorker(pid)
        worker.activity.connect(self._on_udp_port_activity, Qt.ConnectionType.QueuedConnection)
        thread = self._worker_registry.start(worker)
        thread.finished.connect(self._clear_udp_port_monitor)
        self._udp_monitor_thread = thread
        self._udp_monitor_worker = worker

    @Slot(object)
    def _on_udp_port_activity(self, activity: object) -> None:
        if self.sender() is not None and self.sender() is not self._udp_monitor_worker:
            return
        if not isinstance(activity, UdpPortActivity):
            return
        snapshot = activity.snapshot
        if not isinstance(snapshot, UdpPortSnapshot) or snapshot.pid != self._udp_monitor_pid:
            return
        self._udp_activity_history.append(activity)
        if len(self._udp_activity_history) > 120:
            del self._udp_activity_history[:-120]
        self._set_udp_ports_status(snapshot)
        warning_changed = bool(
            snapshot.warning and snapshot.warning != self._udp_monitor_warning
        )
        self._record_udp_activity(activity, include_warning=warning_changed)
        if warning_changed:
            self._udp_monitor_warning = snapshot.warning
            self._append_log(f"UDP-монитор: {snapshot.warning}")
        if activity.opened_ports or activity.closed_ports:
            changes = []
            if activity.opened_ports:
                changes.append("+" + ", +".join(str(port) for port in activity.opened_ports))
            if activity.closed_ports:
                changes.append("-" + ", -".join(str(port) for port in activity.closed_ports))
            self._append_log(f"UDP-порты PID {snapshot.pid}: {'; '.join(changes)}")
        if activity.potential_disconnect:
            closed = ", ".join(str(port) for port in activity.closed_ports)
            opened = ", ".join(str(port) for port in activity.opened_ports)
            if activity.anomaly.value == "all_ports_lost":
                message = f"UDP: возможный обрыв, исчезли порты {closed}"
            else:
                message = f"UDP: резкая смена портов {closed} -> {opened}"
            self._append_log(message)
            self.statusBar().showMessage(message, 6000)
            self._set_header_anomaly("error", "Возможный обрыв UDP-соединения")
        elif snapshot.warning:
            self._set_header_anomaly("warning", "Проблема UDP-монитора")

    def _record_udp_activity(self, activity: UdpPortActivity, include_warning: bool) -> None:
        snapshot = activity.snapshot
        rows: list[UdpEventRow] = []
        rows.extend(
            UdpEventRow(
                activity.observed_at,
                "Порт открыт",
                port,
                f"UDP-порт {port} появился у PID {snapshot.pid}",
                pid=snapshot.pid,
            )
            for port in activity.opened_ports
        )
        rows.extend(
            UdpEventRow(
                activity.observed_at,
                "Порт закрыт",
                port,
                f"UDP-порт {port} исчез у PID {snapshot.pid}",
                pid=snapshot.pid,
            )
            for port in activity.closed_ports
        )
        if activity.anomaly is not None:
            details = (
                "Все ранее активные UDP-порты исчезли между опросами"
                if activity.anomaly.value == "all_ports_lost"
                else "Набор UDP-портов полностью сменился между опросами"
            )
            rows.append(
                UdpEventRow(
                    activity.observed_at,
                    "Возможный обрыв",
                    None,
                    details,
                    is_anomaly=True,
                    pid=snapshot.pid,
                )
            )
        if include_warning and snapshot.warning:
            rows.append(
                UdpEventRow(
                    activity.observed_at,
                    "Ошибка мониторинга",
                    None,
                    snapshot.warning,
                    pid=snapshot.pid,
                )
            )
        if not rows:
            return
        self._udp_event_rows.extend(rows)
        if len(self._udp_event_rows) > 500:
            del self._udp_event_rows[:-500]
        self.export_udp_json_button.setEnabled(True)
        self.export_udp_csv_button.setEnabled(True)
        self._refresh_udp_event_table()

    @Slot()
    def _refresh_udp_event_table(self) -> None:
        anomalies_only = self.udp_anomaly_filter.isChecked()
        visible_rows = [
            row for row in self._udp_event_rows if not anomalies_only or row.is_anomaly
        ]
        self.udp_events_table.setRowCount(len(visible_rows))
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
                self.udp_events_table.setItem(row_index, column, item)
        total = len(self._udp_event_rows)
        if total == 0:
            self.udp_event_status.setText(self._tr("UDP-события появятся после изменения портов"))
        elif anomalies_only:
            self.udp_event_status.setText(
                self._translator.format(
                    "Показано аномалий: {visible} из {total} событий",
                    visible=len(visible_rows),
                    total=total,
                )
            )
        else:
            self.udp_event_status.setText(self._translator.format("Событий UDP: {total}", total=total))

    def _clear_udp_event_table(self) -> None:
        self._udp_event_rows.clear()
        if hasattr(self, "udp_events_table"):
            self.udp_events_table.setRowCount(0)
            self.udp_event_status.setText(self._tr("UDP-события появятся после изменения портов"))
            self.export_udp_json_button.setEnabled(False)
            self.export_udp_csv_button.setEnabled(False)

    @Slot(object)
    def _on_udp_port_snapshot(self, snapshot: object) -> None:
        """Compatibility seam for direct UI tests and external callers."""
        if isinstance(snapshot, UdpPortSnapshot):
            self._on_udp_port_activity(UdpPortHistory(max_entries=1).observe(snapshot))

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
        self._set_elided_text(self.udp_ports_status, text)

    def _stop_udp_port_monitor(self) -> None:
        thread = self._udp_monitor_thread
        self._worker_registry.stop(thread)
        if thread is self._udp_monitor_thread:
            self._udp_monitor_thread = None
            self._udp_monitor_worker = None
            self._udp_monitor_pid = None
            self._udp_monitor_warning = None

    @Slot()
    def _clear_udp_port_monitor(self) -> None:
        thread = self.sender()
        if thread is not self._udp_monitor_thread:
            return
        self._udp_monitor_thread = None
        self._udp_monitor_worker = None
        self._udp_monitor_pid = None
        self._udp_monitor_warning = None

    def _build_metrics(self) -> ResponsiveMetricGrid:
        self.metrics = {
            "dns": MetricTile("DNS", METRIC_TOOLTIPS["dns"], "🌐"),
            "ping": MetricTile("Ping", METRIC_TOOLTIPS["ping"], "⚡"),
            "loss": MetricTile("Потери", METRIC_TOOLTIPS["loss"], "📉"),
            "jitter": MetricTile("Jitter", METRIC_TOOLTIPS["jitter"], "📊"),
            "tcp": MetricTile("TCP", METRIC_TOOLTIPS["tcp"], "🔒"),
            "tls": MetricTile("TLS", METRIC_TOOLTIPS["tls"], "🔒"),
        }
        for tile in self.metrics.values():
            tile.set_compact()
        self.metrics["dns"].set_clickable(True)
        self._set_translatable_tooltip(
            self.metrics["dns"],
            METRIC_TOOLTIPS["dns"],
            "Открыть подробное сравнение DNS-серверов",
        )
        self.metrics["dns"].clicked.connect(self._open_dns_workspace)
        self.metrics["ping"].set_clickable(True)
        self._set_translatable_tooltip(
            self.metrics["ping"],
            METRIC_TOOLTIPS["ping"],
            "Открыть расширенный анализ задержки и игровых регионов",
        )
        self.metrics["ping"].clicked.connect(self._open_ping_workspace)
        self.metrics["loss"].set_clickable(True)
        self._set_translatable_tooltip(
            self.metrics["loss"],
            METRIC_TOOLTIPS["loss"],
            "Открыть анализ burst-потерь и проблемных hop",
        )
        self.metrics["loss"].clicked.connect(self._open_loss_workspace)
        self.metrics["jitter"].set_clickable(True)
        self._set_translatable_tooltip(
            self.metrics["jitter"],
            METRIC_TOOLTIPS["jitter"],
            "Открыть анализ колебаний RTT, VoIP и игровых сессий",
        )
        self.metrics["jitter"].clicked.connect(self._open_jitter_workspace)
        self.metrics["tcp"].set_clickable(True)
        self._set_translatable_tooltip(
            self.metrics["tcp"],
            METRIC_TOOLTIPS["tcp"],
            "Открыть анализ TCP-соединений, handshake и портов",
        )
        self.metrics["tcp"].clicked.connect(self._open_tcp_workspace)
        self.metrics["tls"].set_clickable(True)
        self._set_translatable_tooltip(
            self.metrics["tls"],
            METRIC_TOOLTIPS["tls"],
            "Открыть аудит TLS, сертификата и защищённого соединения",
        )
        self.metrics["tls"].clicked.connect(self._open_tls_workspace)
        self.metric_grid = ResponsiveMetricGrid(list(self.metrics.values()))
        return self.metric_grid

    def _build_dns_workspace(self) -> QFrame:
        workspace = QFrame()
        workspace.setObjectName("DnsWorkspace")
        layout = QVBoxLayout(workspace)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.dns_back_button = QPushButton("←  Назад")
        self.dns_back_button.setObjectName("DnsBackButton")
        self.dns_back_button.clicked.connect(self._close_dns_workspace)
        title_box = QVBoxLayout()
        title = QLabel("DNS DEEP-DIVE")
        title.setObjectName("DnsWorkspaceTitle")
        subtitle = QLabel("Сравнение отклика публичных и пользовательских DNS-серверов")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.dns_run_button = QPushButton("▶  Запустить тест")
        self.dns_run_button.setObjectName("DnsRunButton")
        self.dns_run_button.clicked.connect(self.start_dns_benchmark)
        self.dns_geohide_button = QPushButton("GeoHide DNS")
        self.dns_geohide_button.setObjectName("GeoHideButton")
        self.dns_geohide_button.clicked.connect(self._open_geohide_dialog)
        header.addWidget(self.dns_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.dns_geohide_button)
        layout.addLayout(header)

        system_panel = QWidget()
        system_layout = QVBoxLayout(system_panel)
        system_layout.setContentsMargins(0, 0, 0, 0)
        system_layout.setSpacing(8)

        info_panel = QFrame()
        info_panel.setObjectName("DnsInfoPanel")
        info_layout = QVBoxLayout(info_panel)
        info_layout.setContentsMargins(12, 10, 12, 10)
        info_layout.setSpacing(7)
        current_title = QLabel("ТЕКУЩИЕ DNS АДАПТЕРОВ")
        current_title.setObjectName("FieldLabel")
        self.dns_info_container = QWidget()
        self.dns_info_grid = QGridLayout(self.dns_info_container)
        self.dns_info_grid.setContentsMargins(0, 0, 0, 0)
        self.dns_info_grid.setHorizontalSpacing(6)
        self.dns_info_grid.setVerticalSpacing(6)

        info_layout.addWidget(current_title)
        info_layout.addWidget(self.dns_info_container)

        adapter_panel = QFrame()
        adapter_panel.setObjectName("DnsAdapterPanel")
        adapter_layout = QGridLayout(adapter_panel)
        adapter_layout.setContentsMargins(12, 10, 12, 10)
        adapter_layout.setHorizontalSpacing(10)
        adapter_layout.setVerticalSpacing(6)
        adapter_title = QLabel("АДАПТЕР")
        adapter_title.setObjectName("FieldLabel")
        self.dns_adapter_combo = QComboBox()
        self.dns_adapter_combo.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        _keep_wheel_scroll_local(self.dns_adapter_combo.view())
        self.dns_adapter_combo.setToolTip("Адаптер, для которого можно применить выбранный DNS-профиль")
        self.dns_adapter_properties_button = QPushButton("Открыть свойства адаптера")
        self.dns_adapter_properties_button.setObjectName("DnsAdapterPropertiesButton")
        self.dns_adapter_properties_button.setSizePolicy(
            QSizePolicy.Policy.Maximum,
            QSizePolicy.Policy.Fixed,
        )
        self.dns_adapter_properties_button.setMinimumHeight(30)
        self.dns_adapter_properties_button.clicked.connect(self._open_dns_adapter_properties)
        self.dns_apply_button = QPushButton("Применить выбранный DNS")
        self.dns_apply_button.setObjectName("DnsApplyButton")
        self.dns_apply_button.setEnabled(False)
        self.dns_apply_button.clicked.connect(self._apply_selected_dns_profile)
        self.dns_flush_button = QPushButton("🔄  Очистить кэш DNS")
        self.dns_flush_button.setObjectName("QuickActionPrimary")
        self.dns_flush_button.clicked.connect(
            lambda: self._run_system_action("Очистка DNS", flush_dns_cache, self.dns_flush_button)
        )
        adapter_layout.addWidget(adapter_title, 0, 0)
        adapter_layout.addWidget(self.dns_adapter_combo, 0, 1)
        adapter_layout.addWidget(self.dns_apply_button, 0, 2)
        adapter_layout.addWidget(self.dns_flush_button, 0, 3)
        adapter_layout.addWidget(
            self.dns_adapter_properties_button,
            1,
            1,
            1,
            3,
            alignment=Qt.AlignmentFlag.AlignLeft,
        )
        adapter_layout.setColumnStretch(1, 1)
        adapter_layout.setColumnStretch(2, 1)
        system_layout.addWidget(info_panel)
        system_layout.addWidget(adapter_panel)
        layout.addWidget(system_panel)

        custom_row = QHBoxLayout()
        custom_label = QLabel("СВОЙ DNS")
        custom_label.setObjectName("FieldLabel")
        self.dns_custom_input = QLineEdit()
        self.dns_custom_input.setPlaceholderText("Например, 10.0.0.53 или 2606:4700:4700::1111")
        self.dns_custom_input.setClearButtonEnabled(True)
        self.dns_custom_button = QPushButton("Добавить сервер")
        self.dns_custom_button.clicked.connect(self._add_custom_dns_profile)
        custom_row.addWidget(custom_label)
        custom_row.addWidget(self.dns_custom_input, 1)
        custom_row.addWidget(self.dns_custom_button)
        custom_row.addWidget(self.dns_run_button)
        layout.addLayout(custom_row)

        self.dns_status = QLabel("Нажмите «Запустить тест», чтобы сравнить резолверы")
        self.dns_status.setObjectName("Muted")
        self.dns_status.setWordWrap(True)
        layout.addWidget(self.dns_status)

        self.dns_table = QTableWidget(0, 5)
        self.dns_table.setObjectName("DnsBenchmarkTable")
        self.dns_table.setHorizontalHeaderLabels(["Провайдер", "Адреса", "Лучший адрес", "TCP/53", "Статус"])
        self._configure_table(self.dns_table, (150, 235, 145, 95, 120))
        layout.addWidget(self.dns_table, 1)
        layout.addWidget(self._build_quick_fix_panel("dns"))
        self._render_dns_info()
        self._render_dns_profiles()
        return workspace

    def _render_dns_profiles(self) -> None:
        self.dns_table.setRowCount(len(self._dns_profiles))
        for row, profile in enumerate(self._dns_profiles):
            values = [profile.name, profile.display_addresses, "--", "--", "Готов к тесту"]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.dns_table.setItem(row, column, item)

    def _open_dns_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.dns_view:
            self._previous_workspace = "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
        self._close_combo_popups()
        self.mode_stack.setCurrentWidget(self.dns_view)
        self.dns_back_button.setFocus()
        self._load_dns_configuration()

    @Slot()
    def _open_geohide_dialog(self) -> None:
        if self._geohide_dialog is None:
            self._geohide_dialog = GeoHideDialog(self, self._tr, self._use_geohide_dns)
            self._geohide_dialog.finished.connect(self._clear_geohide_dialog)
        self._geohide_dialog.show()
        self._geohide_dialog.raise_()
        self._geohide_dialog.activateWindow()

    def _use_geohide_dns(self, address: str) -> None:
        self.dns_custom_input.setText(address)
        self.dns_custom_input.setFocus()
        self.dns_status.setText(
            self._translator.format("Адрес GeoHide подставлен: {address}", address=address)
        )
        self.statusBar().showMessage(
            self._translator.format("Адрес GeoHide подставлен: {address}", address=address),
            4000,
        )

    @Slot(int)
    def _clear_geohide_dialog(self, _result: int) -> None:
        self._geohide_dialog = None

    def _close_dns_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _build_ping_workspace(self) -> QFrame:
        workspace = QFrame()
        workspace.setObjectName("PingWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("PingWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        content = QWidget()
        content.setObjectName("PingWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.ping_back_button = QPushButton("←  Назад")
        self.ping_back_button.setObjectName("PingBackButton")
        self.ping_back_button.clicked.connect(self._close_ping_workspace)
        title_box = QVBoxLayout()
        title = QLabel("PING & LATENCY ANALYTICS")
        title.setObjectName("PingWorkspaceTitle")
        subtitle = QLabel("RTT, jitter, региональные ориентиры и проверка MTU-пакетов")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.ping_run_button = QPushButton("▶  Запустить анализ")
        self.ping_run_button.setObjectName("PingRunButton")
        self.ping_run_button.setToolTip("Параллельно проверить региональные ориентиры и MTU целевого узла")
        self.ping_run_button.clicked.connect(self.start_ping_benchmark)
        header.addWidget(self.ping_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.ping_run_button)
        layout.addLayout(header)

        stats_panel = QFrame()
        stats_panel.setObjectName("PingStatsPanel")
        stats_layout = QGridLayout(stats_panel)
        stats_layout.setContentsMargins(12, 10, 12, 10)
        stats_layout.setHorizontalSpacing(16)
        stats_layout.setVerticalSpacing(6)
        stat_titles = (
            ("min RTT", "ping_stat_min"),
            ("max RTT", "ping_stat_max"),
            ("средний RTT", "ping_stat_average"),
            ("jitter", "ping_stat_jitter"),
            ("потери", "ping_stat_loss"),
            ("стабильность", "ping_stat_stability"),
        )
        for index, (caption, attribute) in enumerate(stat_titles):
            item = QFrame()
            item.setObjectName("PingStatItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption.upper())
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("PingStatValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            setattr(self, attribute, value)
            row, column = divmod(index, 6)
            stats_layout.addWidget(item, row, column)
            stats_layout.setColumnStretch(column, 1)
        layout.addWidget(stats_panel)

        matrix_panel = QFrame()
        matrix_panel.setObjectName("PingMatrixPanel")
        matrix_layout = QVBoxLayout(matrix_panel)
        matrix_layout.setContentsMargins(12, 10, 12, 12)
        matrix_layout.setSpacing(7)
        matrix_title = QLabel("МАТРИЦА ИГРОВЫХ РЕГИОНОВ")
        matrix_title.setObjectName("FieldLabel")
        matrix_note = QLabel(
            "Ориентиры проверяют доступность региональных сетей. Они не являются IP-адресами игровых серверов; "
            "для точной проверки используйте IP соединения выбранной игры."
        )
        matrix_note.setObjectName("Muted")
        matrix_note.setWordWrap(True)
        self.ping_matrix_selection_status = QLabel("Региональный узел не выбран")
        self.ping_matrix_selection_status.setObjectName("Muted")
        self.ping_matrix_selection_status.setWordWrap(True)
        self.ping_matrix_table = QTableWidget(0, 5)
        self.ping_matrix_table.setObjectName("PingMatrixTable")
        self.ping_matrix_table.setHorizontalHeaderLabels(["Регион", "Узел", "RTT", "Потери", "Статус"])
        self._configure_table(self.ping_matrix_table, (175, 215, 80, 92, 105))
        self.ping_matrix_table.setMinimumHeight(178)
        self.ping_matrix_table.cellClicked.connect(self._select_ping_region)
        matrix_layout.addWidget(matrix_title)
        matrix_layout.addWidget(matrix_note)
        matrix_layout.addWidget(self.ping_matrix_selection_status)
        matrix_layout.addWidget(self.ping_matrix_table)
        layout.addWidget(matrix_panel)

        spike_panel = QFrame()
        spike_panel.setObjectName("PingSpikePanel")
        spike_layout = QVBoxLayout(spike_panel)
        spike_layout.setContentsMargins(12, 10, 12, 12)
        spike_layout.setSpacing(7)
        spike_title = QLabel("SPIKE / LAG DETECTOR")
        spike_title.setObjectName("FieldLabel")
        self.ping_spike_status = QLabel("Пики выше 100 мс и потери появятся здесь во время мониторинга")
        self.ping_spike_status.setObjectName("Muted")
        self.ping_spike_status.setWordWrap(True)
        self.ping_spike_log = QPlainTextEdit()
        self.ping_spike_log.setObjectName("PingSpikeLog")
        self.ping_spike_log.setReadOnly(True)
        _keep_wheel_scroll_local(self.ping_spike_log)
        self.ping_spike_log.setMaximumBlockCount(80)
        self.ping_spike_log.setPlaceholderText("Событий задержки пока нет")
        self.ping_spike_log.setMinimumHeight(150)
        spike_layout.addWidget(spike_title)
        spike_layout.addWidget(self.ping_spike_status)
        spike_layout.addWidget(self.ping_spike_log, 1)

        mtu_panel = QFrame()
        mtu_panel.setObjectName("PingMtuPanel")
        mtu_layout = QVBoxLayout(mtu_panel)
        mtu_layout.setContentsMargins(12, 10, 12, 12)
        mtu_layout.setSpacing(7)
        mtu_title = QLabel("MTU / PACKET SIZE STRESS TEST")
        mtu_title.setObjectName("FieldLabel")
        mtu_note = QLabel("ICMP с флагом Don't Fragment: 32, 512 и 1472 байт")
        mtu_note.setObjectName("Muted")
        host_row = QHBoxLayout()
        host_label = QLabel("ЦЕЛЬ MTU")
        host_label.setObjectName("FieldLabel")
        self.ping_mtu_host_input = QLineEdit()
        self.ping_mtu_host_input.setPlaceholderText("Адрес для MTU-проверки")
        self.ping_mtu_host_input.setClearButtonEnabled(True)
        self.ping_mtu_run_button = QPushButton("Проверить MTU")
        self.ping_mtu_run_button.setObjectName("PingSecondaryButton")
        self.ping_mtu_run_button.clicked.connect(self.start_mtu_test)
        host_row.addWidget(host_label)
        host_row.addWidget(self.ping_mtu_host_input, 1)
        host_row.addWidget(self.ping_mtu_run_button)
        self.ping_mtu_table = QTableWidget(0, 4)
        self.ping_mtu_table.setObjectName("PingMtuTable")
        self.ping_mtu_table.setHorizontalHeaderLabels(["Payload", "Ответы", "Потери", "Результат"])
        self._configure_table(self.ping_mtu_table, (100, 95, 85, 220))
        self.ping_mtu_table.setMinimumHeight(150)
        mtu_layout.addWidget(mtu_title)
        mtu_layout.addWidget(mtu_note)
        mtu_layout.addLayout(host_row)
        mtu_layout.addWidget(self.ping_mtu_table, 1)

        self.ping_tools_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.ping_tools_splitter.setObjectName("WorkspaceSplitter")
        self.ping_tools_splitter.setChildrenCollapsible(False)
        self.ping_tools_splitter.addWidget(spike_panel)
        self.ping_tools_splitter.addWidget(mtu_panel)
        self.ping_tools_splitter.setStretchFactor(0, 1)
        self.ping_tools_splitter.setStretchFactor(1, 1)
        self.ping_tools_splitter.setSizes([560, 560])
        layout.addWidget(self.ping_tools_splitter)
        layout.addWidget(self._build_quick_fix_panel("ping"))
        layout.addStretch(1)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
        self._render_ping_matrix_placeholders()
        self._render_mtu_placeholders()
        self._set_ping_statistics(latency_statistics(()))
        return workspace

    def _render_ping_matrix_placeholders(self) -> None:
        self._ping_matrix_results = ()
        self.ping_matrix_table.setRowCount(len(REGIONAL_GAMING_TARGETS))
        for row, target in enumerate(REGIONAL_GAMING_TARGETS):
            is_preferred = target == self._preferred_ping_target
            status = self._tr("Основной") if is_preferred else self._tr("Готов к тесту")
            values = [target.region, target.host, "--", "--", status]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(target.note if column in {0, 1} else value)
                item.setData(Qt.ItemDataRole.UserRole, target)
                if is_preferred:
                    item.setBackground(QColor("#124F43"))
                    item.setForeground(QColor("#00E5A3"))
                self.ping_matrix_table.setItem(row, column, item)
        self._update_ping_matrix_selection_status()

    @Slot(int, int)
    def _select_ping_region(self, row: int, _column: int) -> None:
        item = self.ping_matrix_table.item(row, 0)
        target = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(target, RegionalPingTarget):
            return
        self._preferred_ping_target = target
        self._update_ping_matrix_selection_status()
        if self._ping_matrix_results:
            self._render_ping_matrix(self._ping_matrix_results)
        else:
            self._render_ping_matrix_placeholders()
        for current_row in range(self.ping_matrix_table.rowCount()):
            current = self.ping_matrix_table.item(current_row, 0)
            if current is not None and current.data(Qt.ItemDataRole.UserRole) == target:
                self.ping_matrix_table.selectRow(current_row)
                break
        self._append_log(f"Зафиксирован основной региональный узел: {target.region} ({target.host})")

    def _update_ping_matrix_selection_status(self) -> None:
        if self._preferred_ping_target is None:
            self.ping_matrix_selection_status.setText(self._tr("Региональный узел не выбран"))
            return
        self.ping_matrix_selection_status.setText(
            self._translator.format(
                "Основной узел: {region} ({host})",
                region=self._preferred_ping_target.region,
                host=self._preferred_ping_target.host,
            )
        )

    def _render_mtu_placeholders(self) -> None:
        self.ping_mtu_table.setRowCount(3)
        for row, payload_size in enumerate((32, 512, 1472)):
            values = [f"{payload_size} B", "--", "--", "Готов к тесту"]
            for column, value in enumerate(values):
                self.ping_mtu_table.setItem(row, column, QTableWidgetItem(value))

    def _open_ping_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.ping_view:
            self._previous_workspace = "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
        self._close_combo_popups()
        if not self.ping_mtu_host_input.text().strip():
            self.ping_mtu_host_input.setText(self.target_input.text().strip())
        self._refresh_ping_statistics()
        self.mode_stack.setCurrentWidget(self.ping_view)
        self.ping_back_button.setFocus()

    def _close_ping_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _build_jitter_workspace(self) -> QFrame:
        workspace = QFrame()
        workspace.setObjectName("JitterWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("JitterWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setObjectName("JitterWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.jitter_back_button = QPushButton("←  Назад")
        self.jitter_back_button.setObjectName("JitterBackButton")
        self.jitter_back_button.clicked.connect(self._close_jitter_workspace)
        title_box = QVBoxLayout()
        title = QLabel("JITTER & STABILITY ANALYTICS")
        title.setObjectName("JitterWorkspaceTitle")
        subtitle = QLabel("Вариация RTT, micro-spike и влияние на голосовые и игровые сессии")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.jitter_refresh_button = QPushButton("↻  Обновить показатели")
        self.jitter_refresh_button.setObjectName("JitterRunButton")
        self.jitter_refresh_button.clicked.connect(self._refresh_jitter_workspace)
        self.jitter_network_boost_button = self._make_network_boost_button()
        header.addWidget(self.jitter_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.jitter_network_boost_button)
        header.addWidget(self.jitter_refresh_button)
        layout.addLayout(header)

        impact_panel = QFrame()
        impact_panel.setObjectName("JitterImpactPanel")
        impact_layout = QGridLayout(impact_panel)
        impact_layout.setContentsMargins(12, 10, 12, 10)
        impact_layout.setHorizontalSpacing(16)
        impact_layout.setVerticalSpacing(6)
        impact_values = (
            ("ТЕКУЩИЙ JITTER", "current"),
            ("MAX Δ RTT", "maximum"),
            ("MICRO-SPIKE", "spikes"),
            ("VOIP / ЗВОНКИ", "voice"),
            ("СОРЕВНОВАТЕЛЬНЫЕ ИГРЫ", "gaming"),
            ("СТАБИЛЬНОСТЬ", "stability"),
        )
        self.jitter_impact_values: dict[str, QLabel] = {}
        for column, (caption, key) in enumerate(impact_values):
            item = QFrame()
            item.setObjectName("JitterImpactItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption)
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("JitterMetricValue")
            value.setProperty("state", "neutral")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            impact_layout.addWidget(item, 0, column)
            impact_layout.setColumnStretch(column, 1)
            self.jitter_impact_values[key] = value
        layout.addWidget(impact_panel)

        graph_panel = QFrame()
        graph_panel.setObjectName("JitterGraphPanel")
        graph_layout = QVBoxLayout(graph_panel)
        graph_layout.setContentsMargins(12, 10, 12, 12)
        graph_layout.setSpacing(7)
        graph_title = QLabel("REAL-TIME JITTER DISTRIBUTION & VARIANCE")
        graph_title.setObjectName("FieldLabel")
        self.jitter_graph_status = QLabel("Отклонения между соседними RTT будут появляться во время мониторинга")
        self.jitter_graph_status.setObjectName("Muted")
        self.jitter_graph_status.setWordWrap(True)
        self.jitter_chart = JitterChart()
        graph_layout.addWidget(graph_title)
        graph_layout.addWidget(self.jitter_graph_status)
        graph_layout.addWidget(self.jitter_chart, 1)
        layout.addWidget(graph_panel, 1)

        events_panel = QFrame()
        events_panel.setObjectName("JitterEventsPanel")
        events_layout = QVBoxLayout(events_panel)
        events_layout.setContentsMargins(12, 10, 12, 12)
        events_layout.setSpacing(7)
        events_header = QHBoxLayout()
        events_title = QLabel("SPIKE LOG & FREQUENCY")
        events_title.setObjectName("FieldLabel")
        self.jitter_event_status = QLabel("Критический порог: Δ RTT > 15 мс")
        self.jitter_event_status.setObjectName("Muted")
        self.jitter_event_status.setWordWrap(True)
        self.jitter_clear_button = QPushButton("Очистить журнал")
        self.jitter_clear_button.setObjectName("JitterSecondaryButton")
        self.jitter_clear_button.clicked.connect(self._clear_jitter_events)
        events_header.addWidget(events_title)
        events_header.addStretch(1)
        events_header.addWidget(self.jitter_clear_button)
        self.jitter_events_table = QTableWidget(0, 4)
        self.jitter_events_table.setObjectName("JitterEventsTable")
        self.jitter_events_table.setHorizontalHeaderLabels(["Время", "Δ RTT", "Целевой узел", "Детали"])
        self._configure_table(self.jitter_events_table, (110, 105, 220, 420))
        self.jitter_events_table.setMinimumHeight(210)
        events_layout.addLayout(events_header)
        events_layout.addWidget(self.jitter_event_status)
        events_layout.addWidget(self.jitter_events_table, 1)
        layout.addWidget(events_panel, 1)
        layout.addStretch(1)

        self._refresh_jitter_workspace()
        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
        return workspace

    def _open_jitter_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.jitter_view:
            self._previous_workspace = "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
        self._close_combo_popups()
        self._jitter_target_host = self.target_input.text().strip()
        self._refresh_jitter_workspace()
        self.mode_stack.setCurrentWidget(self.jitter_view)
        self.jitter_back_button.setFocus()

    def _close_jitter_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    @Slot()
    def _refresh_jitter_workspace(self) -> None:
        values = tuple(self._jitter_deviations)
        chart_samples = self.jitter_chart.samples
        current = chart_samples[-1] if chart_samples and chart_samples[-1] is not None else None
        maximum = max(values) if values else None
        spike_count = len(self._jitter_events)
        state = _jitter_state(current)
        self._set_jitter_impact_value("current", _ms(current), state)
        self._set_jitter_impact_value("maximum", _ms(maximum), _jitter_state(maximum))
        self._set_jitter_impact_value("spikes", str(spike_count), "bad" if spike_count else "good")
        self._set_jitter_impact_value("voice", self._tr(_voice_jitter_rating(current)), state)
        self._set_jitter_impact_value("gaming", self._tr(_gaming_jitter_rating(current)), state)
        self._set_jitter_impact_value(
            "stability",
            self._tr(_jitter_stability_rating(current, spike_count)),
            state,
        )
        self.jitter_graph_status.setText(
            self._tr("Нет достаточного числа измерений для расчёта jitter")
            if current is None
            else self._translator.format(
                "Текущий Δ RTT: {current:.1f} ms · порог micro-spike: 15 ms",
                current=current,
            )
        )
        self._render_jitter_events()

    def _set_jitter_impact_value(self, key: str, text: str, state: str) -> None:
        label = self.jitter_impact_values[key]
        label.setText(text)
        label.setToolTip(text)
        label.setProperty("state", state)
        label.style().unpolish(label)
        label.style().polish(label)

    def _record_jitter_sample(self, value: float | None, success: bool) -> None:
        previous = self._jitter_previous_rtt
        deviation = abs(value - previous) if success and value is not None and previous is not None else None
        self.jitter_chart.add_sample(deviation)
        if deviation is not None:
            self._jitter_deviations.append(deviation)
            self._jitter_deviations = self._jitter_deviations[-60:]
            if deviation > 15:
                self._jitter_events.append(
                    JitterEventRow(
                        datetime.now(),
                        deviation,
                        self._jitter_target_host or self.target_input.text().strip() or "не определён",
                        "Превышен безопасный порог вариации RTT",
                    )
                )
                self._jitter_events = self._jitter_events[-120:]
        elif not success:
            self._jitter_events.append(
                JitterEventRow(
                    datetime.now(),
                    0.0,
                    self._jitter_target_host or self.target_input.text().strip() or "не определён",
                    "Timeout: непрерывность RTT нарушена",
                )
            )
            self._jitter_events = self._jitter_events[-120:]
        self._jitter_previous_rtt = value if success and value is not None else None
        if self.mode_stack.currentWidget() is self.jitter_view:
            self._refresh_jitter_workspace()

    def _render_jitter_events(self) -> None:
        self.jitter_events_table.setRowCount(len(self._jitter_events))
        for row, event in enumerate(reversed(self._jitter_events)):
            deviation = "timeout" if event.deviation_ms == 0 else f"{event.deviation_ms:.1f} ms"
            values = (f"{event.observed_at:%H:%M:%S}", deviation, event.endpoint, event.details)
            color = QColor("#FF4757") if event.deviation_ms == 0 or event.deviation_ms > 30 else QColor("#FFB800")
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                item.setForeground(color)
                self.jitter_events_table.setItem(row, column, item)
        self.jitter_event_status.setText(
            self._translator.format(
                "Критический порог: Δ RTT > 15 мс · событий: {count}",
                count=len(self._jitter_events),
            )
        )

    @Slot()
    def _clear_jitter_events(self) -> None:
        self._jitter_events.clear()
        self._refresh_jitter_workspace()

    def _build_loss_workspace(self) -> QFrame:
        workspace = QFrame()
        workspace.setObjectName("LossWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("LossWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setObjectName("LossWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.loss_back_button = QPushButton("←  Назад")
        self.loss_back_button.setObjectName("LossBackButton")
        self.loss_back_button.clicked.connect(self._close_loss_workspace)
        title_box = QVBoxLayout()
        title = QLabel("PACKET LOSS & STABILITY ANALYTICS")
        title.setObjectName("LossWorkspaceTitle")
        subtitle = QLabel("Burst-потери, micro-drop, путь трассировки и контролируемые ICMP/UDP-проверки")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.loss_run_button = QPushButton("▶  Запустить анализ потерь")
        self.loss_run_button.setObjectName("LossRunButton")
        self.loss_run_button.clicked.connect(self.start_packet_loss_analysis)
        self.loss_game_auto_button = QPushButton(self._tr("⌕  Автопроверка Hunt"))
        self.loss_game_auto_button.setObjectName("LossAutoCheckButton")
        self.loss_game_auto_button.setToolTip(
            self._tr("Найти HuntGame.exe и проверить потери, jitter и активные сокеты")
        )
        self.loss_game_auto_button.clicked.connect(self._open_game_auto_check)
        self.loss_network_boost_button = self._make_network_boost_button()
        header.addWidget(self.loss_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.loss_game_auto_button)
        header.addWidget(self.loss_network_boost_button)
        header.addWidget(self.loss_run_button)
        layout.addLayout(header)

        stats_panel = QFrame()
        stats_panel.setObjectName("LossStatsPanel")
        stats_layout = QGridLayout(stats_panel)
        stats_layout.setContentsMargins(12, 10, 12, 10)
        stats_layout.setHorizontalSpacing(16)
        stats_layout.setVerticalSpacing(6)
        stat_titles = (
            ("окно", "loss_stat_window"),
            ("получено", "loss_stat_received"),
            ("потери", "loss_stat_percent"),
            ("текущий burst", "loss_stat_current_burst"),
            ("max burst", "loss_stat_longest_burst"),
            ("jitter-события", "loss_stat_jitter_drops"),
        )
        for column, (caption, attribute) in enumerate(stat_titles):
            item = QFrame()
            item.setObjectName("LossStatItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption.upper())
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("LossStatValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            setattr(self, attribute, value)
            stats_layout.addWidget(item, 0, column)
            stats_layout.setColumnStretch(column, 1)
        layout.addWidget(stats_panel)

        detector_panel = QFrame()
        detector_panel.setObjectName("LossDetectorPanel")
        detector_layout = QVBoxLayout(detector_panel)
        detector_layout.setContentsMargins(12, 10, 12, 12)
        detector_layout.setSpacing(7)
        detector_title = QLabel("BURST LOSS & MICRO-DROP DETECTOR")
        detector_title.setObjectName("FieldLabel")
        self.loss_detector_status = QLabel("Ожидание данных live-монитора")
        self.loss_detector_status.setObjectName("Muted")
        self.loss_detector_status.setWordWrap(True)
        self.loss_events_log = QPlainTextEdit()
        self.loss_events_log.setObjectName("LossEventsLog")
        self.loss_events_log.setReadOnly(True)
        _keep_wheel_scroll_local(self.loss_events_log)
        self.loss_events_log.setMaximumBlockCount(100)
        self.loss_events_log.setPlaceholderText("Потери и всплески стабильности появятся здесь")
        self.loss_events_log.setMinimumHeight(50)
        self.loss_events_log.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        detector_layout.addWidget(detector_title)
        detector_layout.addWidget(self.loss_detector_status)
        detector_layout.addWidget(self.loss_events_log, 1)

        stress_panel = QFrame()
        stress_panel.setObjectName("LossStressPanel")
        stress_layout = QVBoxLayout(stress_panel)
        stress_layout.setContentsMargins(12, 10, 12, 12)
        stress_layout.setSpacing(7)
        stress_title = QLabel("ICMP / UDP STRESS TEST")
        stress_title.setObjectName("FieldLabel")
        stress_note = QLabel("ICMP измеряет ответы. UDP отражает локальную отправку: без ACK приложения нельзя подтвердить доставку.")
        stress_note.setObjectName("Muted")
        stress_note.setWordWrap(True)
        target_row = QHBoxLayout()
        target_label = QLabel("ЦЕЛЬ")
        target_label.setObjectName("FieldLabel")
        self.loss_target_input = QLineEdit()
        self.loss_target_input.setPlaceholderText("Адрес или домен")
        self.loss_target_input.setClearButtonEnabled(True)
        port_label = QLabel("ПОРТ")
        port_label.setObjectName("FieldLabel")
        self.loss_port_input = QSpinBox()
        self.loss_port_input.setRange(1, 65535)
        self.loss_port_input.setValue(443)
        target_row.addWidget(target_label)
        target_row.addWidget(self.loss_target_input, 1)
        target_row.addWidget(port_label)
        target_row.addWidget(self.loss_port_input)
        self.loss_stress_table = QTableWidget(0, 5)
        self.loss_stress_table.setObjectName("LossStressTable")
        self.loss_stress_table.setHorizontalHeaderLabels(["Протокол", "Пакеты", "Ответы", "Потери", "Результат"])
        self._configure_table(self.loss_stress_table, (100, 90, 90, 105, 280))
        self.loss_stress_table.setMinimumHeight(50)
        self.loss_stress_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        stress_layout.addWidget(stress_title)
        stress_layout.addWidget(stress_note)
        stress_layout.addLayout(target_row)
        stress_layout.addWidget(self.loss_stress_table, 1)

        self.loss_tools_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.loss_tools_splitter.setObjectName("WorkspaceSplitter")
        self.loss_tools_splitter.setChildrenCollapsible(False)
        self.loss_tools_splitter.addWidget(detector_panel)
        self.loss_tools_splitter.addWidget(stress_panel)
        self.loss_tools_splitter.setStretchFactor(0, 1)
        self.loss_tools_splitter.setStretchFactor(1, 1)
        self.loss_tools_splitter.setSizes([560, 560])
        self.loss_tools_splitter.setMinimumHeight(150)
        self.loss_tools_splitter.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        hops_panel = QFrame()
        hops_panel.setObjectName("LossHopsPanel")
        hops_layout = QVBoxLayout(hops_panel)
        hops_layout.setContentsMargins(12, 10, 12, 12)
        hops_layout.setSpacing(7)
        hops_title = QLabel("HOP-BY-HOP LOSS BREAKDOWN")
        hops_title.setObjectName("FieldLabel")
        self.loss_hops_status = QLabel("Сначала запустите основную диагностику, чтобы получить трассировку.")
        self.loss_hops_status.setObjectName("Muted")
        self.loss_hops_status.setWordWrap(True)
        self.loss_hops_table = QTableWidget(0, 6)
        self.loss_hops_table.setObjectName("LossHopsTable")
        self.loss_hops_table.setHorizontalHeaderLabels(["Hop", "Узел", "ICMP", "Потери", "RTT", "Статус"])
        self._configure_table(self.loss_hops_table, (70, 230, 90, 95, 90, 155))
        self.loss_hops_table.setMinimumHeight(50)
        self.loss_hops_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        hops_layout.addWidget(hops_title)
        hops_layout.addWidget(self.loss_hops_status)
        hops_layout.addWidget(self.loss_hops_table, 1)
        hops_panel.setMinimumHeight(150)
        hops_panel.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        self.loss_workspace_splitter = QSplitter(Qt.Orientation.Vertical)
        self.loss_workspace_splitter.setObjectName("WorkspaceSplitter")
        self.loss_workspace_splitter.setChildrenCollapsible(False)
        self.loss_workspace_splitter.setHandleWidth(8)
        self.loss_workspace_splitter.addWidget(self.loss_tools_splitter)
        self.loss_workspace_splitter.addWidget(hops_panel)
        self.loss_workspace_splitter.setStretchFactor(0, 1)
        self.loss_workspace_splitter.setStretchFactor(1, 1)
        self.loss_workspace_splitter.setSizes([360, 260])
        layout.addWidget(self.loss_workspace_splitter, 1)
        layout.addWidget(self._build_quick_fix_panel("loss"))

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
        self._set_loss_snapshot(self._loss_analyzer_snapshot())
        self._render_loss_stress_placeholders()
        return workspace

    def _open_loss_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.loss_view:
            self._previous_workspace = "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
        self._close_combo_popups()
        self.loss_target_input.setText(self.target_input.text().strip())
        self.loss_port_input.setValue(self.port_input.value())
        self._refresh_loss_workspace()
        self.mode_stack.setCurrentWidget(self.loss_view)
        self.loss_back_button.setFocus()

    @Slot()
    def _open_game_auto_check(self) -> None:
        preferred_process = (
            self._selected_process.name
            if isinstance(self._selected_process, ProcessNetworkInfo)
            else None
        )
        dialog = GameAutoCheckDialog(self._tr, preferred_process, self)
        dialog.exec()

    def _close_loss_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _build_tcp_workspace(self) -> QFrame:
        workspace = QFrame()
        workspace.setObjectName("TcpWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("TcpWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setObjectName("TcpWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.tcp_back_button = QPushButton("←  Назад")
        self.tcp_back_button.setObjectName("TcpBackButton")
        self.tcp_back_button.clicked.connect(self._close_tcp_workspace)
        title_box = QVBoxLayout()
        title = QLabel("TCP CONNECTION & PORT ANALYTICS")
        title.setObjectName("TcpWorkspaceTitle")
        subtitle = QLabel("Сокеты, TCP connect, состояния соединений и проверка портов")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.tcp_run_button = QPushButton("▶  Обновить TCP-анализ")
        self.tcp_run_button.setObjectName("TcpRunButton")
        self.tcp_run_button.clicked.connect(self.start_tcp_diagnostics)
        header.addWidget(self.tcp_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.tcp_run_button)
        layout.addLayout(header)

        metrics_panel = QFrame()
        metrics_panel.setObjectName("TcpMetricsPanel")
        metrics_layout = QGridLayout(metrics_panel)
        metrics_layout.setContentsMargins(12, 10, 12, 10)
        metrics_layout.setHorizontalSpacing(16)
        metrics_layout.setVerticalSpacing(6)
        metric_titles = (
            ("TCP CONNECT", "tcp_handshake_connect"),
            ("SYN", "tcp_handshake_syn"),
            ("SYN-ACK", "tcp_handshake_syn_ack"),
            ("ACK", "tcp_handshake_ack"),
            ("СТАТУС", "tcp_handshake_status"),
        )
        for column, (caption, attribute) in enumerate(metric_titles):
            item = QFrame()
            item.setObjectName("TcpMetricItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption)
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("TcpMetricValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            setattr(self, attribute, value)
            metrics_layout.addWidget(item, 0, column)
            metrics_layout.setColumnStretch(column, 1)
        handshake_note = QLabel(
            "SYN / SYN-ACK / ACK — оценка по полному времени TCP connect. Точные отдельные фазы требуют packet capture."
        )
        handshake_note.setObjectName("Muted")
        handshake_note.setWordWrap(True)
        metrics_layout.addWidget(handshake_note, 1, 0, 1, len(metric_titles))
        layout.addWidget(metrics_panel)

        ports_panel = QFrame()
        ports_panel.setObjectName("TcpPortsPanel")
        ports_layout = QVBoxLayout(ports_panel)
        ports_layout.setContentsMargins(12, 10, 12, 12)
        ports_layout.setSpacing(7)
        ports_title = QLabel("PORT STATUS & FILTERING TESTER")
        ports_title.setObjectName("FieldLabel")
        ports_row = QHBoxLayout()
        host_label = QLabel("ЦЕЛЬ")
        host_label.setObjectName("FieldLabel")
        self.tcp_target_input = QLineEdit()
        self.tcp_target_input.setPlaceholderText("Адрес или домен")
        self.tcp_target_input.setClearButtonEnabled(True)
        ports_label = QLabel("ПОРТЫ")
        ports_label.setObjectName("FieldLabel")
        self.tcp_ports_input = QLineEdit("80, 443, 3389")
        self.tcp_ports_input.setPlaceholderText("80, 443, 27015")
        self.tcp_ports_input.setToolTip("Список TCP-портов через запятую")
        self.tcp_ports_input.setMaximumWidth(220)
        ports_row.addWidget(host_label)
        ports_row.addWidget(self.tcp_target_input, 1)
        ports_row.addWidget(ports_label)
        ports_row.addWidget(self.tcp_ports_input)
        self.tcp_ports_table = QTableWidget(0, 4)
        self.tcp_ports_table.setObjectName("TcpPortsTable")
        self.tcp_ports_table.setHorizontalHeaderLabels(["Порт", "Статус", "TCP connect", "Детали"])
        self._configure_table(self.tcp_ports_table, (90, 145, 130, 300))
        self.tcp_ports_table.setMinimumHeight(152)
        ports_layout.addWidget(ports_title)
        ports_layout.addLayout(ports_row)
        ports_layout.addWidget(self.tcp_ports_table, 1)
        layout.addWidget(ports_panel)

        sockets_panel = QFrame()
        sockets_panel.setObjectName("TcpSocketsPanel")
        sockets_layout = QVBoxLayout(sockets_panel)
        sockets_layout.setContentsMargins(12, 10, 12, 12)
        sockets_layout.setSpacing(7)
        socket_header = QHBoxLayout()
        socket_title = QLabel("ACTIVE CONNECTION MATRIX")
        socket_title.setObjectName("FieldLabel")
        self.tcp_socket_status = QLabel("Нажмите «Обновить TCP-анализ», чтобы просканировать сокеты")
        self.tcp_socket_status.setObjectName("Muted")
        self.tcp_socket_status.setWordWrap(True)
        self.tcp_socket_details_button = QPushButton("Детали сокета")
        self.tcp_socket_details_button.setObjectName("TcpSecondaryButton")
        self.tcp_socket_details_button.setEnabled(False)
        self.tcp_socket_details_button.clicked.connect(self._show_selected_tcp_socket_details)
        self.tcp_reset_stack_button = QPushButton("Сбросить TCP/IP")
        self.tcp_reset_stack_button.setObjectName("TcpSecondaryButton")
        self.tcp_reset_stack_button.clicked.connect(self._request_tcp_stack_reset)
        socket_header.addWidget(socket_title)
        socket_header.addStretch(1)
        socket_header.addWidget(self.tcp_socket_details_button)
        socket_header.addWidget(self.tcp_reset_stack_button)
        self.tcp_sockets_table = QTableWidget(0, 5)
        self.tcp_sockets_table.setObjectName("TcpSocketsTable")
        self.tcp_sockets_table.setHorizontalHeaderLabels(["PID / приложение", "Локальный endpoint", "Удалённый endpoint", "Состояние", "Детали"])
        self._configure_table(self.tcp_sockets_table, (190, 180, 210, 120, 220))
        self.tcp_sockets_table.setMinimumHeight(230)
        self.tcp_sockets_table.itemSelectionChanged.connect(self._update_tcp_socket_selection)
        sockets_layout.addLayout(socket_header)
        sockets_layout.addWidget(self.tcp_socket_status)
        sockets_layout.addWidget(self.tcp_sockets_table, 1)
        layout.addWidget(sockets_panel, 1)
        layout.addWidget(self._build_quick_fix_panel("tcp"))
        layout.addStretch(1)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
        self._render_tcp_port_placeholders()
        return workspace

    def _open_tcp_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.tcp_view:
            self._previous_workspace = "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
        self._close_combo_popups()
        self.tcp_target_input.setText(self.target_input.text().strip())
        self.tcp_ports_input.setText(self._default_tcp_port_text())
        self.mode_stack.setCurrentWidget(self.tcp_view)
        self.tcp_back_button.setFocus()

    def _close_tcp_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    def _default_tcp_port_text(self) -> str:
        primary = self.port_input.value()
        ports = tuple(dict.fromkeys((80, 443, 3389, primary)))
        return ", ".join(str(port) for port in ports)

    @Slot()
    def start_tcp_diagnostics(self) -> None:
        if self._tcp_diagnostics_thread and self._tcp_diagnostics_thread.isRunning():
            return
        try:
            target = parse_target(self.tcp_target_input.text(), self.port_input.value())
            ports = self._parse_tcp_ports(self.tcp_ports_input.text())
        except ValueError as exc:
            self.tcp_socket_status.setText(str(exc))
            return
        self.tcp_target_input.setText(target.host)
        self._set_task_button_busy(self.tcp_run_button, True, "Проверка")
        self.tcp_socket_details_button.setEnabled(False)
        self.tcp_socket_status.setText(
            self._tr("Сканируем TCP-сокеты и проверяем порты в фоновом потоке...")
        )
        self._render_tcp_port_placeholders(self._tr("Проверка..."))
        thread = QThread(self)
        worker = TcpDiagnosticsWorker(target.host, target.port, ports)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_tcp_diagnostics_completed)
        worker.failed.connect(self._on_tcp_diagnostics_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_tcp_diagnostics_worker)
        self._tcp_diagnostics_thread = thread
        self._tcp_diagnostics_worker = worker
        thread.start()

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

    @Slot(object, object, object)
    def _on_tcp_diagnostics_completed(self, sockets_value: object, primary_value: object, ports_value: object) -> None:
        self._set_task_button_busy(self.tcp_run_button, False)
        if not isinstance(sockets_value, tuple) or not all(isinstance(item, TcpSocketRecord) for item in sockets_value):
            self._on_tcp_diagnostics_failed("Сканер сокетов вернул некорректный результат")
            return
        if not isinstance(primary_value, TcpConnectMeasurement):
            self._on_tcp_diagnostics_failed("TCP connect вернул некорректный результат")
            return
        if not isinstance(ports_value, tuple) or not all(isinstance(item, TcpConnectMeasurement) for item in ports_value):
            self._on_tcp_diagnostics_failed("Проверка портов вернула некорректный результат")
            return
        self._render_tcp_handshake(primary_value)
        self._render_tcp_ports(ports_value)
        self._render_tcp_sockets(sockets_value)

    @Slot(str)
    def _on_tcp_diagnostics_failed(self, message: str) -> None:
        self._set_task_button_busy(self.tcp_run_button, False)
        self.tcp_socket_status.setText(message)

    @Slot()
    def _clear_tcp_diagnostics_worker(self) -> None:
        if self.sender() is not self._tcp_diagnostics_thread:
            return
        self._tcp_diagnostics_thread = None
        self._tcp_diagnostics_worker = None

    def _render_tcp_handshake(self, measurement: TcpConnectMeasurement) -> None:
        if measurement.connect_ms is None:
            values = ("--", "--", "--", "--")
        else:
            total = measurement.connect_ms
            values = (f"{total:.1f} ms", "оценка", "оценка", "оценка")
        self.tcp_handshake_connect.setText(values[0])
        self.tcp_handshake_syn.setText(values[1])
        self.tcp_handshake_syn_ack.setText(values[2])
        self.tcp_handshake_ack.setText(values[3])
        self.tcp_handshake_status.setText(measurement.status)
        self.tcp_handshake_status.setToolTip(measurement.error or "Полное время TCP connect")

    def _render_tcp_port_placeholders(self, status: str = "Готов к тесту") -> None:
        try:
            ports = self._parse_tcp_ports(self.tcp_ports_input.text())
        except ValueError:
            ports = (80, 443, 3389)
        self.tcp_ports_table.setRowCount(len(ports))
        for row, port in enumerate(ports):
            for column, value in enumerate((str(port), status, "--", "--")):
                self.tcp_ports_table.setItem(row, column, QTableWidgetItem(value))

    def _render_tcp_ports(self, results: tuple[TcpConnectMeasurement, ...]) -> None:
        self.tcp_ports_table.setRowCount(len(results))
        for row, result in enumerate(results):
            values = (str(result.port), result.status, _ms(result.connect_ms), result.error or "TCP connect завершён")
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(result.error or value)
                if result.is_open:
                    item.setForeground(QColor("#00E5A3"))
                elif result.status == "Фильтруется / timeout":
                    item.setForeground(QColor("#FFB800"))
                else:
                    item.setForeground(QColor("#FF6B78"))
                self.tcp_ports_table.setItem(row, column, item)

    def _render_tcp_sockets(self, sockets: tuple[TcpSocketRecord, ...]) -> None:
        self.tcp_sockets_table.setRowCount(len(sockets))
        self._tcp_socket_records = sockets
        for row, record in enumerate(sockets):
            identity = f"{record.pid if record.pid is not None else '--'} · {record.process_name}"
            values = (identity, record.local_endpoint, record.remote_endpoint, record.state, "Выберите строку")
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if record.state == "ESTABLISHED":
                    item.setForeground(QColor("#00E5A3"))
                elif record.state in {"SYN_SENT", "SYN_RECV"}:
                    item.setForeground(QColor("#FFB800"))
                elif record.state in {"CLOSE_WAIT", "TIME_WAIT"}:
                    item.setForeground(QColor("#8A99AD"))
                self.tcp_sockets_table.setItem(row, column, item)
        self.tcp_socket_status.setText(
            f"Отображено TCP-сокетов: {len(sockets)}" if sockets else "Доступных TCP-сокетов не найдено или доступ ограничен Windows."
        )

    @Slot()
    def _update_tcp_socket_selection(self) -> None:
        row = self.tcp_sockets_table.currentRow()
        selected = 0 <= row < len(getattr(self, "_tcp_socket_records", ()))
        self.tcp_socket_details_button.setEnabled(selected)
        if selected:
            record = self._tcp_socket_records[row]
            self.tcp_socket_status.setText(
                f"Выбран: {record.process_name} · {record.local_endpoint} → {record.remote_endpoint} · {record.state}"
            )

    @Slot()
    def _show_selected_tcp_socket_details(self) -> None:
        row = self.tcp_sockets_table.currentRow()
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
        self._trigger_quick_fix("stack", self.tcp_reset_stack_button, self.quick_fix_status["tcp"])

    def _build_tls_workspace(self) -> QFrame:
        workspace = QFrame()
        workspace.setObjectName("TlsWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("TlsWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setObjectName("TlsWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.tls_back_button = QPushButton("←  Назад")
        self.tls_back_button.setObjectName("TlsBackButton")
        self.tls_back_button.clicked.connect(self._close_tls_workspace)
        title_box = QVBoxLayout()
        title = QLabel("TLS SECURITY & CERTIFICATE ANALYTICS")
        title.setObjectName("TlsWorkspaceTitle")
        subtitle = QLabel("Проверка защищённого соединения, сертификата и параметров шифрования")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.tls_run_button = QPushButton("▶  Проверить сертификат")
        self.tls_run_button.setObjectName("TlsRunButton")
        self.tls_run_button.clicked.connect(self.start_tls_audit)
        header.addWidget(self.tls_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.tls_run_button)
        layout.addLayout(header)

        overview_panel = QFrame()
        overview_panel.setObjectName("TlsOverviewPanel")
        overview_layout = QGridLayout(overview_panel)
        overview_layout.setContentsMargins(12, 10, 12, 10)
        overview_layout.setHorizontalSpacing(16)
        overview_layout.setVerticalSpacing(6)
        overview_values = (
            ("TCP CONNECT", "tcp_connect"),
            ("TLS HANDSHAKE", "handshake"),
            ("ПРОТОКОЛ", "protocol"),
            ("ШИФР", "cipher"),
            ("СЕРТИФИКАТ", "certificate"),
            ("ДО ОКОНЧАНИЯ", "expiry"),
        )
        self.tls_overview_values: dict[str, QLabel] = {}
        for column, (caption, key) in enumerate(overview_values):
            item = QFrame()
            item.setObjectName("TlsOverviewItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption)
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("TlsMetricValue")
            value.setProperty("state", "neutral")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setToolTip("Данные появятся после TLS-аудита")
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            overview_layout.addWidget(item, 0, column)
            overview_layout.setColumnStretch(column, 1)
            self.tls_overview_values[key] = value
        layout.addWidget(overview_panel)

        tools_panel = QFrame()
        tools_panel.setObjectName("TlsToolsPanel")
        tools_layout = QVBoxLayout(tools_panel)
        tools_layout.setContentsMargins(12, 10, 12, 10)
        tools_layout.setSpacing(7)
        tools_title = QLabel("SMART TOOLS")
        tools_title.setObjectName("FieldLabel")
        target_row = QHBoxLayout()
        host_label = QLabel("ЦЕЛЬ")
        host_label.setObjectName("FieldLabel")
        self.tls_target_input = QLineEdit()
        self.tls_target_input.setPlaceholderText("Домен или IP-адрес TLS-сервера")
        self.tls_target_input.setClearButtonEnabled(True)
        port_label = QLabel("ПОРТ")
        port_label.setObjectName("FieldLabel")
        self.tls_port_input = QSpinBox()
        self.tls_port_input.setRange(1, 65535)
        self.tls_port_input.setValue(443)
        self.tls_port_input.setMinimumWidth(90)
        self.tls_check_button = QPushButton("Проверить сертификат")
        self.tls_check_button.setObjectName("TlsSecondaryButton")
        self.tls_check_button.clicked.connect(self.start_tls_audit)
        self.tls_copy_fingerprint_button = QPushButton("Копировать отпечаток")
        self.tls_copy_fingerprint_button.setObjectName("TlsSecondaryButton")
        self.tls_copy_fingerprint_button.setEnabled(False)
        self.tls_copy_fingerprint_button.clicked.connect(self._copy_tls_fingerprint)
        self.tls_refresh_button = QPushButton("Обновить аудит безопасности")
        self.tls_refresh_button.setObjectName("TlsSecondaryButton")
        self.tls_refresh_button.clicked.connect(self.start_tls_audit)
        target_row.addWidget(host_label)
        target_row.addWidget(self.tls_target_input, 1)
        target_row.addWidget(port_label)
        target_row.addWidget(self.tls_port_input)
        target_row.addWidget(self.tls_check_button)
        target_row.addWidget(self.tls_copy_fingerprint_button)
        target_row.addWidget(self.tls_refresh_button)
        self.tls_audit_status = QLabel("Укажите цель и запустите проверку сертификата")
        self.tls_audit_status.setObjectName("Muted")
        self.tls_audit_status.setWordWrap(True)
        tools_layout.addWidget(tools_title)
        tools_layout.addLayout(target_row)
        tools_layout.addWidget(self.tls_audit_status)
        layout.addWidget(tools_panel)

        handshake_panel = QFrame()
        handshake_panel.setObjectName("TlsHandshakePanel")
        handshake_layout = QVBoxLayout(handshake_panel)
        handshake_layout.setContentsMargins(12, 10, 12, 12)
        handshake_layout.setSpacing(7)
        handshake_title = QLabel("HANDSHAKE PHASE BREAKDOWN")
        handshake_title.setObjectName("FieldLabel")
        handshake_note = QLabel(
            "Стандартный Python SSL измеряет TCP connect и полный TLS handshake. "
            "Отдельные пакеты Client Hello, Server Hello и Key Exchange требуют packet capture."
        )
        handshake_note.setObjectName("Muted")
        handshake_note.setWordWrap(True)
        self.tls_handshake_table = QTableWidget(0, 3)
        self.tls_handshake_table.setObjectName("TlsHandshakeTable")
        self.tls_handshake_table.setHorizontalHeaderLabels(["Этап", "Время", "Статус / детали"])
        self._configure_table(self.tls_handshake_table, (230, 150, 450))
        self.tls_handshake_table.setMinimumHeight(180)
        handshake_layout.addWidget(handshake_title)
        handshake_layout.addWidget(handshake_note)
        handshake_layout.addWidget(self.tls_handshake_table)
        layout.addWidget(handshake_panel)

        certificate_panel = QFrame()
        certificate_panel.setObjectName("TlsCertificatePanel")
        certificate_layout = QVBoxLayout(certificate_panel)
        certificate_layout.setContentsMargins(12, 10, 12, 12)
        certificate_layout.setSpacing(7)
        certificate_title = QLabel("CERTIFICATE CHAIN DETAILS")
        certificate_title.setObjectName("FieldLabel")
        self.tls_chain_note = QLabel(
            "Python SSL предоставляет leaf-сертификат; доступные элементы цепочки появятся после аудита."
        )
        self.tls_chain_note.setObjectName("Muted")
        self.tls_chain_note.setWordWrap(True)
        self.tls_certificate_table = QTableWidget(0, 8)
        self.tls_certificate_table.setObjectName("TlsCertificateTable")
        self.tls_certificate_table.setHorizontalHeaderLabels(
            ["#", "Subject", "Issuer", "Serial", "Действует с", "Действует до", "Осталось", "SHA-256"]
        )
        self._configure_table(self.tls_certificate_table, (54, 210, 210, 150, 145, 145, 95, 310))
        self.tls_certificate_table.setMinimumHeight(210)
        certificate_layout.addWidget(certificate_title)
        certificate_layout.addWidget(self.tls_chain_note)
        certificate_layout.addWidget(self.tls_certificate_table)
        layout.addWidget(certificate_panel, 1)
        layout.addStretch(1)

        self._render_tls_placeholders()
        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
        return workspace

    def _open_tls_workspace(self) -> None:
        if self.mode_stack.currentWidget() is not self.tls_view:
            self._previous_workspace = "lite" if self.mode_stack.currentWidget() is self.lite_view else "expert"
        self._close_combo_popups()
        host = self.target_input.text().strip()
        port = self.port_input.value()
        self.tls_target_input.setText(host)
        self.tls_port_input.setValue(port)
        if self._tls_audit_result is None or (
            self._tls_audit_result.host != host or self._tls_audit_result.port != port
        ):
            self._render_tls_placeholders()
            if self._report and self._report.tls and self._report.target.host == host and self._report.target.port == port:
                self._render_tls_report_summary(self._report.tls)
        self.mode_stack.setCurrentWidget(self.tls_view)
        self.tls_back_button.setFocus()

    def _close_tls_workspace(self) -> None:
        target = self.lite_view if self._previous_workspace == "lite" else self.expert_view
        self.mode_stack.setCurrentWidget(target)

    @Slot()
    def start_tls_audit(self) -> None:
        if self._tls_audit_thread and self._tls_audit_thread.isRunning():
            return
        try:
            target = parse_target(self.tls_target_input.text(), self.tls_port_input.value())
        except ValueError as exc:
            self.tls_audit_status.setText(str(exc))
            return
        self.tls_target_input.setText(target.host)
        self._tls_audit_result = None
        self._set_tls_audit_running(True)
        self._render_tls_placeholders(self._tr("Проверка TLS-соединения..."))
        self.tls_audit_status.setText(
            self._tr("Устанавливаем защищённое соединение в фоновом потоке...")
        )
        thread = QThread(self)
        worker = TlsAuditWorker(target.host, target.port)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_tls_audit_completed)
        worker.failed.connect(self._on_tls_audit_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_tls_audit_worker)
        self._tls_audit_thread = thread
        self._tls_audit_worker = worker
        thread.start()

    @Slot(object)
    def _on_tls_audit_completed(self, value: object) -> None:
        self._set_tls_audit_running(False)
        if not isinstance(value, TlsAuditResult):
            self._on_tls_audit_failed("TLS-аудит вернул некорректный результат")
            return
        self._tls_audit_result = value
        self._render_tls_audit(value)

    @Slot(str)
    def _on_tls_audit_failed(self, message: str) -> None:
        self._set_tls_audit_running(False)
        self.tls_audit_status.setText(message)

    @Slot()
    def _clear_tls_audit_worker(self) -> None:
        if self.sender() is not self._tls_audit_thread:
            return
        self._tls_audit_thread = None
        self._tls_audit_worker = None

    def _set_tls_audit_running(self, running: bool) -> None:
        for button in (self.tls_run_button, self.tls_check_button, self.tls_refresh_button):
            self._set_task_button_busy(button, running, "Проверка")
        self.tls_run_button.setDisabled(running)
        self.tls_check_button.setDisabled(running)
        self.tls_refresh_button.setDisabled(running)
        if running:
            self.tls_copy_fingerprint_button.setDisabled(True)

    def _render_tls_placeholders(self, status: str = "Нажмите «Проверить сертификат», чтобы начать аудит") -> None:
        for value in self.tls_overview_values.values():
            self._set_tls_overview_value(value, "--", "neutral")
        self.tls_handshake_table.setRowCount(4)
        phases = (
            ("TCP connect", "--", status),
            ("TLS handshake", "--", status),
            ("Client Hello / Server Hello", "--", "Входит в полный TLS handshake"),
            ("Key exchange / проверка сертификата", "--", "Входит в полный TLS handshake"),
        )
        for row, values in enumerate(phases):
            for column, text in enumerate(values):
                self.tls_handshake_table.setItem(row, column, QTableWidgetItem(text))
        self.tls_certificate_table.setRowCount(1)
        self.tls_certificate_table.setItem(0, 0, QTableWidgetItem("--"))
        self.tls_certificate_table.setItem(0, 1, QTableWidgetItem(status))
        for column in range(2, self.tls_certificate_table.columnCount()):
            self.tls_certificate_table.setItem(0, column, QTableWidgetItem("--"))
        self.tls_chain_note.setText(
            self._tr("Python SSL покажет доступный leaf-сертификат после аудита.")
        )
        self.tls_copy_fingerprint_button.setEnabled(False)

    def _render_tls_report_summary(self, result: object) -> None:
        if not hasattr(result, "version"):
            return
        tls_ok = getattr(result, "status", None) == ProbeStatus.SUCCESS
        state = "good" if tls_ok else "bad"
        self._set_tls_overview_value(self.tls_overview_values["handshake"], _ms(getattr(result, "latency_ms", None)), state)
        self._set_tls_overview_value(self.tls_overview_values["protocol"], getattr(result, "version", None) or "--", state)
        self._set_tls_overview_value(self.tls_overview_values["cipher"], getattr(result, "cipher", None) or "--", state)
        self._set_tls_overview_value(
            self.tls_overview_values["certificate"],
            "Подтверждён" if tls_ok else "Нужна проверка",
            state,
        )
        expires = getattr(result, "expires_at", None)
        self._set_tls_overview_value(
            self.tls_overview_values["expiry"],
            expires.strftime("%Y-%m-%d") if expires else "--",
            state,
        )
        self.tls_audit_status.setText(
            self._tr("Показана сводка основной диагностики. Запустите аудит для сертификата и отпечатка.")
        )

    def _render_tls_audit(self, result: TlsAuditResult) -> None:
        certificate_state = _tls_certificate_state(result.certificate_status, result.certificate_valid)
        self._set_tls_overview_value(
            self.tls_overview_values["tcp_connect"],
            _ms(result.tcp_connect_ms),
            "good" if result.tcp_connect_ms is not None else "bad",
        )
        self._set_tls_overview_value(
            self.tls_overview_values["handshake"],
            _ms(result.handshake_ms),
            "good" if result.handshake_ms is not None else "bad",
        )
        self._set_tls_overview_value(self.tls_overview_values["protocol"], result.version or "--", certificate_state)
        self._set_tls_overview_value(self.tls_overview_values["cipher"], result.cipher or "--", certificate_state)
        self._set_tls_overview_value(
            self.tls_overview_values["certificate"],
            result.certificate_status,
            certificate_state,
        )
        leaf = result.chain[0] if result.chain else None
        expiry = "--" if leaf is None or leaf.days_remaining is None else f"{leaf.days_remaining} дн."
        self._set_tls_overview_value(self.tls_overview_values["expiry"], expiry, certificate_state)
        self._render_tls_handshake(result)
        self._render_tls_chain(result.chain)
        self.tls_copy_fingerprint_button.setEnabled(bool(result.fingerprint_sha256))
        details = result.error or "Защищённое соединение проверено"
        self.tls_audit_status.setText(f"{result.host}:{result.port} · {result.certificate_status} · {details}")

    def _render_tls_handshake(self, result: TlsAuditResult) -> None:
        phases = (
            ("TCP connect", _ms(result.tcp_connect_ms), "Установление сетевого соединения"),
            ("TLS handshake", _ms(result.handshake_ms), "Полный защищённый handshake"),
            ("Client Hello / Server Hello", "включено", "Отдельно не измеряется стандартным SSL API"),
            ("Key exchange / проверка сертификата", "включено", "Отдельно не измеряется стандартным SSL API"),
        )
        self.tls_handshake_table.setRowCount(len(phases))
        for row, values in enumerate(phases):
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                if row < 2 and result.handshake_ms is not None:
                    item.setForeground(QColor("#00E5A3"))
                self.tls_handshake_table.setItem(row, column, item)

    def _render_tls_chain(self, records: tuple[CertificateRecord, ...]) -> None:
        self.tls_certificate_table.setRowCount(len(records))
        if not records:
            self.tls_chain_note.setText(
                self._tr("Сертификат не получен. Проверьте адрес, порт и настройки TLS на сервере.")
            )
            return
        self.tls_chain_note.setText(
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
                self.tls_certificate_table.setItem(row, column, item)

    def _set_tls_overview_value(self, label: QLabel, text: str, state: str) -> None:
        label.setText(text)
        label.setToolTip(text)
        label.setProperty("state", state)
        label.style().unpolish(label)
        label.style().polish(label)

    @Slot()
    def _copy_tls_fingerprint(self) -> None:
        fingerprint = self._tls_audit_result.fingerprint_sha256 if self._tls_audit_result else None
        if not fingerprint:
            self.tls_audit_status.setText("Сначала выполните аудит, чтобы получить SHA-256 отпечаток.")
            return
        QApplication.clipboard().setText(fingerprint)
        self.tls_audit_status.setText("SHA-256 отпечаток скопирован в буфер обмена.")

    @Slot()
    def start_packet_loss_analysis(self) -> None:
        if self._loss_test_thread and self._loss_test_thread.isRunning():
            return
        try:
            target = parse_target(self.loss_target_input.text(), self.loss_port_input.value())
        except ValueError as exc:
            self.loss_detector_status.setText(str(exc))
            return
        hops = self._report.hops if self._report is not None else ()
        self._set_task_button_busy(self.loss_run_button, True, "Проверка")
        self._render_loss_stress_placeholders("Выполняется тест...")
        if hops:
            self._render_loss_hops_placeholders(hops, "Проверяем ICMP каждого hop...")
        else:
            self.loss_hops_table.setRowCount(0)
            self.loss_hops_status.setText("Трассировка ещё не получена: выполнен только стресс-тест цели.")
        self.loss_detector_status.setText(
            self._tr("Выполняются ICMP/UDP стресс-тесты в фоновом потоке...")
        )
        thread = QThread(self)
        worker = PacketLossTestWorker(hops, target.host, target.port)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_packet_loss_analysis_completed)
        worker.failed.connect(self._on_packet_loss_analysis_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_packet_loss_worker)
        self._loss_test_thread = thread
        self._loss_test_worker = worker
        thread.start()

    @Slot(object, object, object)
    def _on_packet_loss_analysis_completed(
        self,
        hop_value: object,
        icmp_value: object,
        udp_value: object,
    ) -> None:
        self._set_task_button_busy(self.loss_run_button, False)
        if not isinstance(hop_value, tuple) or not all(isinstance(item, HopLossResult) for item in hop_value):
            self._on_packet_loss_analysis_failed("Hop-анализ вернул некорректный результат")
            return
        if not isinstance(icmp_value, StressTestResult) or not isinstance(udp_value, StressTestResult):
            self._on_packet_loss_analysis_failed("Стресс-тест вернул некорректный результат")
            return
        if hop_value:
            self._render_loss_hop_results(hop_value)
        self._render_loss_stress_results((icmp_value, udp_value))
        self.loss_detector_status.setText(
            self._tr("Фоновый анализ потерь завершён. Live-монитор продолжает сбор burst-событий.")
        )

    @Slot(str)
    def _on_packet_loss_analysis_failed(self, message: str) -> None:
        self._set_task_button_busy(self.loss_run_button, False)
        self.loss_detector_status.setText(message)

    @Slot()
    def _clear_packet_loss_worker(self) -> None:
        if self.sender() is not self._loss_test_thread:
            return
        self._loss_test_thread = None
        self._loss_test_worker = None

    def _render_loss_stress_placeholders(self, status: str = "Готов к тесту") -> None:
        self.loss_stress_table.setRowCount(2)
        for row, protocol in enumerate(("ICMP", "UDP")):
            for column, value in enumerate((protocol, "10", "--", "--", status)):
                self.loss_stress_table.setItem(row, column, QTableWidgetItem(value))

    def _render_loss_hops_placeholders(self, hops: tuple[HopResult, ...], status: str) -> None:
        self.loss_hops_table.setRowCount(len(hops))
        for row, hop in enumerate(hops):
            values = [f"{hop.index:02}", hop.address or "--", "--", "--", _ms(hop.latency_ms), status]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if hop.timed_out:
                    item.setForeground(QColor("#FFB800"))
                self.loss_hops_table.setItem(row, column, item)

    def _render_loss_hop_results(self, results: tuple[HopLossResult, ...]) -> None:
        self.loss_hops_table.setRowCount(len(results))
        first_loss_hop = next((result for result in results if (result.loss_percent or 0) > 0), None)
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
                if result.loss_percent is not None and result.loss_percent >= 100:
                    item.setForeground(QColor("#FF6B78"))
                elif result.loss_percent and result.loss_percent > 0:
                    item.setForeground(QColor("#FFB800"))
                elif result.loss_percent == 0:
                    item.setForeground(QColor("#00E5A3"))
                self.loss_hops_table.setItem(row, column, item)
        if first_loss_hop is None:
            self.loss_hops_status.setText(self._tr("Потерь ICMP в ответах hop не обнаружено."))
        else:
            self.loss_hops_status.setText(
                f"Первый hop с потерями: {first_loss_hop.hop:02} · {first_loss_hop.address or 'адрес не определён'} · "
                f"{first_loss_hop.loss_percent:.0f}%"
            )

    def _render_loss_stress_results(self, results: tuple[StressTestResult, ...]) -> None:
        self.loss_stress_table.setRowCount(len(results))
        for row, result in enumerate(results):
            loss = "не подтверждается" if result.loss_percent is None else f"{result.loss_percent:.0f}%"
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
                self.loss_stress_table.setItem(row, column, item)

    def _loss_analyzer_snapshot(self) -> PacketLossSnapshot:
        return summarize_loss(self._loss_analyzer.samples)

    def _set_loss_snapshot(self, snapshot: PacketLossSnapshot) -> None:
        self.loss_stat_window.setText(str(snapshot.sent))
        self.loss_stat_received.setText(f"{snapshot.received}/{snapshot.sent}" if snapshot.sent else "--")
        self.loss_stat_percent.setText(f"{snapshot.loss_percent:.0f}%")
        self.loss_stat_current_burst.setText(str(snapshot.current_burst))
        self.loss_stat_longest_burst.setText(str(snapshot.longest_burst))
        self.loss_stat_jitter_drops.setText(str(snapshot.jitter_drops))

    def _refresh_loss_workspace(self) -> None:
        self._set_loss_snapshot(self._loss_analyzer_snapshot())
        events = self._loss_analyzer.events
        if events:
            self.loss_events_log.setPlainText(
                "\n".join(f"[{event.observed_at:%H:%M:%S}] {event.message}" for event in events)
            )
            self.loss_detector_status.setText(f"Событий в окне: {len(events)} · {events[-1].snapshot.status}")
        elif self._loss_analyzer.samples:
            self.loss_detector_status.setText(self._loss_analyzer_snapshot().status)

    @Slot()
    def start_ping_benchmark(self) -> None:
        self._start_ping_analysis(include_matrix=True, include_mtu=True)

    @Slot()
    def start_mtu_test(self) -> None:
        self._start_ping_analysis(include_matrix=False, include_mtu=True)

    def _start_ping_analysis(self, *, include_matrix: bool, include_mtu: bool) -> None:
        if self._ping_benchmark_thread and self._ping_benchmark_thread.isRunning():
            return
        mtu_host = self.ping_mtu_host_input.text().strip() or self.target_input.text().strip()
        try:
            parsed_target = parse_target(mtu_host, self.port_input.value())
        except ValueError as exc:
            self.ping_spike_status.setText(f"MTU-проверка: {exc}")
            return

        self.ping_mtu_host_input.setText(parsed_target.host)
        self._set_task_button_busy(self.ping_run_button, include_matrix, "Проверка")
        self._set_task_button_busy(self.ping_mtu_run_button, include_mtu, "Проверка")
        self.ping_run_button.setDisabled(True)
        self.ping_mtu_run_button.setDisabled(True)
        if include_matrix:
            self._render_ping_matrix_placeholders()
        if include_mtu:
            self._render_mtu_placeholders()
        running_parts = []
        if include_matrix:
            running_parts.append("региональные ориентиры")
        if include_mtu:
            running_parts.append(f"MTU для {parsed_target.host}")
        self.ping_spike_status.setText(f"Проверяем: {', '.join(running_parts)}...")

        thread = QThread(self)
        regional_targets = None
        if include_matrix and self._preferred_ping_target is not None:
            regional_targets = (
                self._preferred_ping_target,
                *(
                    target
                    for target in REGIONAL_GAMING_TARGETS
                    if target != self._preferred_ping_target
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
        worker.completed.connect(self._on_ping_benchmark_completed)
        worker.failed.connect(self._on_ping_benchmark_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_ping_benchmark_worker)
        self._ping_benchmark_thread = thread
        self._ping_benchmark_worker = worker
        thread.start()

    @Slot(object, object)
    def _on_ping_benchmark_completed(self, regional_value: object, mtu_value: object) -> None:
        self._set_task_button_busy(self.ping_run_button, False)
        self._set_task_button_busy(self.ping_mtu_run_button, False)
        self.ping_run_button.setEnabled(True)
        self.ping_mtu_run_button.setEnabled(True)
        if not isinstance(regional_value, tuple) or not all(
            isinstance(item, RegionalPingResult) for item in regional_value
        ):
            self._on_ping_benchmark_failed("Матрица регионов вернула некорректный результат")
            return
        if not isinstance(mtu_value, tuple) or not all(isinstance(item, MtuProbeResult) for item in mtu_value):
            self._on_ping_benchmark_failed("MTU-проверка вернула некорректный результат")
            return
        if regional_value:
            self._render_ping_matrix(regional_value)
        if mtu_value:
            self._render_mtu_results(mtu_value)
        tested = []
        if regional_value:
            tested.append(f"регионов: {len(regional_value)}")
        if mtu_value:
            tested.append(f"MTU: {len(mtu_value)} размера")
        self.ping_spike_status.setText(f"Анализ завершён ({', '.join(tested)}).")

    @Slot(str)
    def _on_ping_benchmark_failed(self, message: str) -> None:
        self._set_task_button_busy(self.ping_run_button, False)
        self._set_task_button_busy(self.ping_mtu_run_button, False)
        self.ping_run_button.setEnabled(True)
        self.ping_mtu_run_button.setEnabled(True)
        self.ping_spike_status.setText(message)

    @Slot()
    def _clear_ping_benchmark_worker(self) -> None:
        if self.sender() is not self._ping_benchmark_thread:
            return
        self._ping_benchmark_thread = None
        self._ping_benchmark_worker = None

    def _render_ping_matrix(self, results: tuple[RegionalPingResult, ...]) -> None:
        self._ping_matrix_results = results
        self.ping_matrix_table.setRowCount(len(results))
        successful = [result for result in results if result.success]
        fastest = min(successful, key=lambda result: result.latency_ms or float("inf")) if successful else None
        for row, result in enumerate(results):
            latency = _ms(result.latency_ms)
            is_preferred = result.target == self._preferred_ping_target
            status = (
                self._tr("Основной")
                if is_preferred
                else self._tr("Лучший")
                if result is fastest
                else self._tr("Доступен") if result.success else self._tr("Нет ответа")
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
                self.ping_matrix_table.setItem(row, column, item)
        self._update_ping_matrix_selection_status()

    def _render_mtu_results(self, results: tuple[MtuProbeResult, ...]) -> None:
        self.ping_mtu_table.setRowCount(len(results))
        for row, result in enumerate(results):
            outcome = _ms(result.average_ms) if result.success else (result.error or "Нет ответа")
            values = [
                f"{result.payload_size} B",
                f"{result.received}/{result.sent}",
                f"{result.loss_percent:.0f}%",
                outcome,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(result.error or value)
                if result.success:
                    item.setForeground(QColor("#00E5A3"))
                else:
                    item.setForeground(QColor("#FF6B78"))
                self.ping_mtu_table.setItem(row, column, item)

    def _refresh_ping_statistics(self) -> None:
        values = [value for value in self._latency_window if value is not None]
        self._set_ping_statistics(latency_statistics(values, sent=len(self._latency_window)))
        if self._ping_spike_events:
            self.ping_spike_log.setPlainText("\n".join(self._ping_spike_events))

    def _set_ping_statistics(self, statistics: LatencyStatistics) -> None:
        self.ping_stat_min.setText(_ms(statistics.minimum_ms))
        self.ping_stat_max.setText(_ms(statistics.maximum_ms))
        self.ping_stat_average.setText(_ms(statistics.average_ms))
        self.ping_stat_jitter.setText(_ms(statistics.jitter_ms))
        self.ping_stat_loss.setText(f"{statistics.loss_percent:.0f}%")
        self.ping_stat_stability.setText(statistics.stability)

    def _load_dns_configuration(self) -> None:
        if self._dns_config_thread and self._dns_config_thread.isRunning():
            return
        thread = QThread(self)
        worker = DnsConfigurationWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_dns_configuration_completed)
        worker.failed.connect(self._on_dns_configuration_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_dns_configuration_worker)
        self._dns_config_thread = thread
        self._dns_config_worker = worker
        thread.start()

    @Slot(object, object)
    def _on_dns_configuration_completed(
        self,
        configuration: object,
        public_addresses: object,
    ) -> None:
        if not isinstance(configuration, DnsConfiguration):
            self._on_dns_configuration_failed("Системные DNS не распознаны")
            return
        self.dns_adapter_combo.clear()
        for name in configuration.adapter_names:
            self.dns_adapter_combo.addItem(name, name)
        self._dns_configuration = configuration
        self._dns_public_addresses = (
            public_addresses if isinstance(public_addresses, PublicIpAddresses) else PublicIpAddresses()
        )
        self._render_dns_info()
        self.dns_apply_button.setEnabled(bool(configuration.adapter_names))

    @Slot(str)
    def _on_dns_configuration_failed(self, message: str) -> None:
        self._dns_configuration = None
        self._dns_public_addresses = PublicIpAddresses(error=message)
        self._render_dns_info()
        self.dns_status.setText(message)

    def _render_dns_info(self) -> None:
        while self.dns_info_grid.count():
            item = self.dns_info_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        configuration = self._dns_configuration
        public_addresses = self._dns_public_addresses or PublicIpAddresses()
        chips: list[tuple[str, str | None, str]] = []
        if configuration is not None:
            for index, address in enumerate(configuration.servers):
                provider = self._tr(self._dns_provider_name(address))
                ip_version = "IPv6" if ":" in address else "IPv4"
                chips.append(
                    (
                        f"{ip_version} · {provider}",
                        address,
                        self._translator.format(
                            "Основной DNS-резолвер {provider} ({version}). Используется для преобразования доменных имён в IP-адреса. Нажмите, чтобы скопировать."
                            if index == 0
                            else "Дополнительный DNS-резолвер {provider} ({version}). Используется, если основной сервер недоступен. Нажмите, чтобы скопировать.",
                            provider=provider,
                            version=ip_version,
                        ),
                    )
                )
        if not chips:
            chips.append((self._tr("DNS-серверы не определены"), None, ""))

        chips.extend(
            (
                (
                    self._tr("Публичный IPv4"),
                    public_addresses.ipv4,
                    public_addresses.error or self._tr(
                        "Ваш внешний IPv4-адрес: так вашу сеть видят сайты и интернет-сервисы. Нажмите, чтобы скопировать."
                    ),
                ),
                (
                    self._tr("Публичный IPv6"),
                    public_addresses.ipv6,
                    public_addresses.error or self._tr(
                        "Ваш внешний IPv6-адрес: так вашу сеть видят сайты и интернет-сервисы через IPv6. Нажмите, чтобы скопировать."
                    ),
                ),
            )
        )
        for index, (caption, address, tooltip) in enumerate(chips):
            chip = QPushButton(f"{caption}\n{address or self._tr('Не определён')}")
            chip.setObjectName("DnsInfoChip")
            chip.setToolTip(tooltip or (address or ""))
            chip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            if address:
                chip.setCursor(Qt.CursorShape.PointingHandCursor)
                chip.clicked.connect(lambda _checked=False, value=address: self._copy_dns_info(value))
            else:
                chip.setEnabled(False)
            row, column = divmod(index, 3)
            self.dns_info_grid.addWidget(chip, row, column)
            self.dns_info_grid.setColumnStretch(column, 1)

    @staticmethod
    def _dns_provider_name(address: str) -> str:
        value = address.casefold()
        if value in {"159.194.200.33", "193.233.112.67", "193.233.112.88", "193.233.112.68", "37.230.192.51", "46.8.158.6"}:
            return "GeoHide DNS"
        if value.startswith(("8.8.", "2001:4860:4860:")):
            return "Google DNS"
        if value.startswith(("1.1.", "1.0.", "2606:4700:4700:")):
            return "Cloudflare DNS"
        if value.startswith(("9.9.", "149.112.")):
            return "Quad9 DNS"
        if value.startswith("208.67."):
            return "OpenDNS"
        if value.startswith(("77.88.", "2a02:6b8:")):
            return "Yandex DNS"
        if value.startswith(("94.140.", "2a10:50c0:")):
            return "AdGuard DNS"
        return "DNS провайдера"

    def _copy_dns_info(self, address: str) -> None:
        QApplication.clipboard().setText(address)
        QToolTip.showText(QCursor.pos(), self._tr("Скопировано"), self.dns_info_container)

    @Slot()
    def _clear_dns_configuration_worker(self) -> None:
        if self.sender() is not self._dns_config_thread:
            return
        self._dns_config_thread = None
        self._dns_config_worker = None

    @Slot()
    def _add_custom_dns_profile(self) -> None:
        try:
            profile = custom_dns_profile(self.dns_custom_input.text())
        except ValueError as exc:
            self.dns_status.setText(str(exc))
            return
        if any(profile.addresses == item.addresses for item in self._dns_profiles):
            self.dns_status.setText(self._tr("Этот DNS-сервер уже добавлен"))
            return
        self._dns_profiles.append(profile)
        self._render_dns_profiles()
        self.dns_custom_input.clear()
        self.dns_status.setText(
            self._translator.format(
                "Добавлен {addresses}. Запустите тест для проверки.",
                addresses=profile.display_addresses,
            )
        )

    @Slot()
    def start_dns_benchmark(self) -> None:
        if self._dns_benchmark_thread and self._dns_benchmark_thread.isRunning():
            return
        self._set_task_button_busy(self.dns_run_button, True, "Проверка")
        self.dns_status.setText(self._tr("Проверяем TCP/53 параллельно для всех резолверов..."))
        self._render_dns_profiles()
        thread = QThread(self)
        worker = DnsBenchmarkWorker(tuple(self._dns_profiles))
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_dns_benchmark_completed)
        worker.failed.connect(self._on_dns_benchmark_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_dns_benchmark_worker)
        self._dns_benchmark_thread = thread
        self._dns_benchmark_worker = worker
        thread.start()

    @Slot(object)
    def _on_dns_benchmark_completed(self, value: object) -> None:
        self._set_task_button_busy(self.dns_run_button, False)
        if not isinstance(value, tuple) or not all(isinstance(item, DnsBenchmarkResult) for item in value):
            self._on_dns_benchmark_failed("DNS-бенчмарк вернул некорректный результат")
            return
        successful = [item for item in value if item.success]
        fastest = min(successful, key=lambda item: item.latency_ms or float("inf")) if successful else None
        for row, result in enumerate(value):
            latency = f"{result.latency_ms:.1f} мс" if result.latency_ms is not None else "--"
            status = "Лучший" if fastest is result else ("Доступен" if result.success else "Нет ответа")
            values = [result.profile.name, result.profile.display_addresses, result.address or "--", latency, status]
            for column, value_text in enumerate(values):
                item = QTableWidgetItem(value_text)
                item.setToolTip(result.error if column == 4 and result.error else value_text)
                if fastest is result:
                    item.setBackground(QColor("#124F43"))
                    item.setForeground(QColor("#00E5A3"))
                elif not result.success:
                    item.setForeground(QColor("#FF6B78"))
                self.dns_table.setItem(row, column, item)
        if fastest:
            self.dns_status.setText(
                self._translator.format(
                    "Лучший резолвер: {name} · {address} · {latency:.1f} мс",
                    name=fastest.profile.name,
                    address=fastest.address,
                    latency=fastest.latency_ms,
                )
            )
        else:
            self.dns_status.setText(self._tr("Доступных DNS-серверов не найдено"))

    @Slot(str)
    def _on_dns_benchmark_failed(self, message: str) -> None:
        self._set_task_button_busy(self.dns_run_button, False)
        self.dns_status.setText(message)

    @Slot()
    def _clear_dns_benchmark_worker(self) -> None:
        if self.sender() is not self._dns_benchmark_thread:
            return
        self._dns_benchmark_thread = None
        self._dns_benchmark_worker = None

    @Slot()
    def _apply_selected_dns_profile(self) -> None:
        row = self.dns_table.currentRow()
        if row < 0 or row >= len(self._dns_profiles):
            self.dns_status.setText(self._tr("Выберите DNS-профиль в таблице"))
            return
        adapter = self.dns_adapter_combo.currentData()
        profile = self._dns_profiles[row]
        if not isinstance(adapter, str):
            self.dns_status.setText(self._tr("Активный сетевой адаптер не найден"))
            return
        self._run_system_action(
            f"Применение DNS {profile.name}",
            lambda profile=profile, adapter=adapter: apply_dns_servers(adapter, profile.addresses),
            self.dns_apply_button,
        )

    @Slot()
    def _open_dns_adapter_properties(self) -> None:
        """Open Windows Network Connections without blocking the DNS workspace."""
        self._run_system_action(
            self._tr("Открыть свойства адаптера"),
            open_network_adapters,
            self.dns_adapter_properties_button,
            self.dns_status,
        )

    def _build_topology_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("SidePanel")
        apply_panel_shadow(panel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        self.topology = TopologyWidget()
        self.topology.node_selected.connect(self._show_node_details)
        scroll = self._make_scroll_area(self.topology)
        scroll.setObjectName("TopologyScrollArea")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.topology_scroll = scroll
        layout.addWidget(scroll)
        return panel

    def _build_tabs(self) -> QTabWidget:
        tabs = QTabWidget()
        self.workspace_tabs = tabs
        tabs.setMinimumWidth(0)
        tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        tabs.addTab(self._build_details_tab(), "Обзор")
        tabs.addTab(self._build_path_tab(), "Маршруты / Geo")
        tabs.addTab(self._build_interfaces_tab(), "Интерфейсы")
        tabs.addTab(self._build_udp_history_tab(), "UDP-события")
        self.log_tab = self._build_log_tab()
        tabs.addTab(self.log_tab, "Журнал")
        tabs.addTab(self._build_analysis_tab(), "Диагноз")
        tabs.addTab(self._build_internet_quality_tab(), "Качество")
        return tabs

    def _build_internet_quality_tab(self) -> QWidget:
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(9)

        heading_row = QHBoxLayout()
        heading = QLabel("КАЧЕСТВО ИНТЕРНЕТА")
        heading.setObjectName("FieldLabel")
        self.quality_test_button = QPushButton("Проверить качество")
        self.quality_test_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.quality_test_button.setToolTip("Запустить Ookla Speedtest и запросить данные Интернетометра")
        self.quality_test_button.clicked.connect(self.start_quality_check)
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.quality_test_button)

        self.quality_progress = QProgressBar()
        self.quality_progress.setObjectName("QualityProgress")
        self.quality_progress.setRange(0, 0)
        self.quality_progress.setTextVisible(False)
        self.quality_progress.setFixedHeight(6)
        self.quality_progress.setToolTip("Проверка выполняется в фоновом режиме")
        self.quality_progress.hide()
        self.quality_status = QLabel("Проверка ещё не запускалась")
        self.quality_status.setObjectName("Muted")
        self.quality_status.setWordWrap(True)

        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(7)
        self.quality_metrics = {
            "download": MetricTile("Скачивание"),
            "upload": MetricTile("Отдача"),
            "ping": MetricTile("Ping"),
            "loaded_ping": MetricTile("Ping под нагрузкой"),
        }
        for index, tile in enumerate(self.quality_metrics.values()):
            metrics_grid.addWidget(tile, index // 2, index % 2)

        details_title = QLabel("ВНЕШНЯЯ СЕТЬ И АДАПТЕР")
        details_title.setObjectName("FieldLabel")
        self.quality_details: dict[str, QLabel] = {}
        details_grid = QGridLayout()
        details_grid.setHorizontalSpacing(10)
        details_grid.setVerticalSpacing(5)
        detail_items = (
            ("ipv4", "Внешний IPv4"),
            ("ipv6", "Внешний IPv6"),
            ("local_ip", "Локальный IP"),
            ("isp", "Провайдер"),
            ("location", "Регион / город"),
            ("vpn_proxy", "VPN / прокси"),
            ("adapter", "Адаптер / скорость"),
        )
        for row, (key, title) in enumerate(detail_items):
            title_label = QLabel(title.upper())
            title_label.setObjectName("FieldLabel")
            value_label = QLabel("--")
            value_label.setWordWrap(True)
            if key == "adapter":
                value_label.setToolTip("Это согласованная скорость локального Wi-Fi/Ethernet-канала, а не скорость тарифа провайдера.")
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.quality_details[key] = value_label
            details_grid.addWidget(title_label, row, 0, Qt.AlignmentFlag.AlignTop)
            details_grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)
        details_grid.setColumnStretch(1, 1)

        report_title = QLabel("СВОДКА")
        report_title.setObjectName("FieldLabel")
        self.quality_report_output = QPlainTextEdit()
        self.quality_report_output.setReadOnly(True)
        _keep_wheel_scroll_local(self.quality_report_output)
        self.quality_report_output.setMaximumHeight(112)
        self.quality_report_output.setPlaceholderText("Здесь появится сопоставление результатов Speedtest, Яндекса и локального адаптера.")

        layout.addLayout(heading_row)
        layout.addWidget(self.quality_progress)
        layout.addWidget(self.quality_status)
        layout.addLayout(metrics_grid)
        layout.addWidget(details_title)
        layout.addLayout(details_grid)
        layout.addWidget(report_title)
        layout.addWidget(self.quality_report_output)
        layout.addStretch(1)
        scroll.setWidget(content)
        tab_layout.addWidget(scroll)
        return tab

    def _build_analysis_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        caption = QLabel("АНАЛИЗ ПРИЧИНЫ ПРОБЛЕМЫ")
        caption.setObjectName("FieldLabel")
        self.analysis_title = QLabel("Диагностика ещё не запускалась")
        self.analysis_title.setObjectName("AnalysisTitle")
        self.analysis_title.setWordWrap(True)
        self.analysis_output = QPlainTextEdit()
        self.analysis_output.setReadOnly(True)
        _keep_wheel_scroll_local(self.analysis_output)
        self.analysis_output.setPlaceholderText("После проверки здесь появится понятное объяснение результата.")

        layout.addWidget(caption)
        layout.addWidget(self.analysis_title)
        layout.addWidget(self.analysis_output, 1)
        return self._make_scroll_area(tab)

    def _build_details_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        caption = QLabel("ОБЗОР УЗЛА")
        caption.setObjectName("FieldLabel")
        self.detail_title = QLabel("Выберите узел на карте")
        self.detail_title.setObjectName("NodeDetailTitle")
        self.detail_title.setWordWrap(True)

        self.detail_grid = QGridLayout()
        self.detail_grid.setHorizontalSpacing(10)
        self.detail_grid.setVerticalSpacing(6)
        self.detail_grid.setColumnStretch(1, 1)

        self.stage_label = QLabel("Ожидание запуска")
        self.stage_label.setObjectName("Muted")
        self.stage_label.setWordWrap(True)

        chart_title = QLabel("ЗАДЕРЖКА / СТАБИЛЬНОСТЬ")
        chart_title.setObjectName("FieldLabel")
        self.latency_chart = LatencyChart()

        layout.addWidget(chart_title)
        layout.addWidget(self.latency_chart)
        layout.addWidget(caption)
        layout.addWidget(self.detail_title)
        layout.addLayout(self.detail_grid)
        layout.addStretch(1)
        layout.addWidget(self.stage_label)
        scroll = self._make_scroll_area(tab)
        scroll.setObjectName("DetailsScrollArea")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.details_scroll = scroll
        return scroll

    @staticmethod
    def _make_scroll_area(content: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(content)
        return scroll

    @staticmethod
    def _configure_table(table: QTableWidget, initial_widths: tuple[int, ...]) -> None:
        """Apply the shared resizable-table contract without resetting user widths."""
        if table.columnCount() != len(initial_widths):
            raise ValueError("Количество стартовых ширин не соответствует числу колонок")

        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(True)
        table.setWordWrap(False)
        table.setTextElideMode(Qt.TextElideMode.ElideRight)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        _keep_wheel_scroll_local(table)

        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setSectionsClickable(True)
        header.setHighlightSections(False)
        header.setCascadingSectionResizes(True)
        header.setMinimumSectionSize(64)
        for column, width in enumerate(initial_widths):
            table.setColumnWidth(column, width)

        vertical_header = table.verticalHeader()
        vertical_header.setVisible(False)
        vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        vertical_header.setDefaultSectionSize(28)

    def _build_path_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        routes_title = QLabel("ДОСТУПНЫЕ МАРШРУТЫ / VPN")
        routes_title.setObjectName("FieldLabel")
        self.routes_table = QTableWidget(0, 4)
        self.routes_table.setHorizontalHeaderLabels(["Путь", "Интерфейс", "Шлюз", "Метрика"])
        self._configure_table(self.routes_table, (150, 160, 170, 80))

        geo_title = QLabel("ASN / GEOIP ДЛЯ ПУБЛИЧНЫХ УЗЛОВ МАРШРУТА")
        geo_title.setObjectName("FieldLabel")
        self.geo_status = QLabel("GeoIP ещё не получен")
        self.geo_status.setObjectName("Muted")
        self.geo_table = QTableWidget(0, 4)
        self.geo_table.setHorizontalHeaderLabels(["IP", "Страна / город", "ASN", "Провайдер"])
        self._configure_table(self.geo_table, (150, 220, 100, 230))

        layout.addWidget(routes_title)
        layout.addWidget(self.routes_table, 1)
        layout.addWidget(geo_title)
        layout.addWidget(self.geo_status)
        layout.addWidget(self.geo_table, 2)
        return tab

    def _build_interfaces_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        self.interfaces_table = QTableWidget(0, 4)
        self.interfaces_table.setHorizontalHeaderLabels(["Имя", "Тип", "IPv4", "Состояние"])
        self._configure_table(self.interfaces_table, (180, 110, 200, 100))
        layout.addWidget(self.interfaces_table)
        return tab

    def _build_udp_history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        heading_row = QHBoxLayout()
        heading = QLabel("ИСТОРИЯ UDP-АКТИВНОСТИ ВЫБРАННОГО ПРОЦЕССА")
        heading.setObjectName("FieldLabel")
        self.udp_anomaly_filter = QCheckBox("Только аномалии")
        self.udp_anomaly_filter.setObjectName("UdpAnomalyFilter")
        self.udp_anomaly_filter.setToolTip(
            "Показывать только возможные обрывы и полную смену набора UDP-портов."
        )
        self.udp_anomaly_filter.toggled.connect(self._refresh_udp_event_table)
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.udp_anomaly_filter)

        actions_row = QHBoxLayout()
        self.export_udp_json_button = QPushButton("Экспорт JSON")
        self.export_udp_json_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.export_udp_json_button.setToolTip("Сохранить историю UDP-событий в JSON")
        self.export_udp_json_button.setEnabled(False)
        self.export_udp_json_button.clicked.connect(self._export_udp_events_json)
        self.export_udp_csv_button = QPushButton("Экспорт CSV")
        self.export_udp_csv_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.export_udp_csv_button.setToolTip("Сохранить историю UDP-событий в CSV")
        self.export_udp_csv_button.setEnabled(False)
        self.export_udp_csv_button.clicked.connect(self._export_udp_events_csv)
        actions_row.addStretch(1)
        actions_row.addWidget(self.export_udp_json_button)
        actions_row.addWidget(self.export_udp_csv_button)

        self.udp_event_status = QLabel("Выберите процесс для мониторинга UDP-событий")
        self.udp_event_status.setObjectName("Muted")

        self.udp_events_table = QTableWidget(0, 4)
        self.udp_events_table.setObjectName("UdpEventsTable")
        self.udp_events_table.setHorizontalHeaderLabels(["Время", "Событие", "Порт", "Детали"])
        self.udp_events_table.setSortingEnabled(False)
        self._configure_table(self.udp_events_table, (100, 150, 75, 310))

        layout.addLayout(heading_row)
        layout.addLayout(actions_row)
        layout.addWidget(self.udp_event_status)
        layout.addWidget(self.udp_events_table, 1)
        return tab

    def _build_log_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        _keep_wheel_scroll_local(self.log_output)
        self.log_output.setMaximumBlockCount(500)
        self.log_output.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.log_output)
        return tab

    @Slot()
    def start_quality_check(self) -> None:
        if self._quality_thread and self._quality_thread.isRunning():
            return
        self._quality_report = None
        self._set_task_button_busy(self.quality_test_button, True, "Проверка")
        self.quality_progress.show()
        self.quality_status.setText("Подготавливаем проверку качества...")
        self.quality_report_output.clear()
        for tile in self.quality_metrics.values():
            tile.set_metric("--", "выполняется")
        for label in self.quality_details.values():
            label.setText("--")
        self._append_log("Запуск проверки качества интернета")

        snapshot = self._report.system if self._report else None
        thread = QThread(self)
        worker = InternetQualityWorker(snapshot)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_quality_progress)
        worker.completed.connect(self._on_quality_completed)
        worker.failed.connect(self._on_quality_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_quality_worker)
        self._quality_thread = thread
        self._quality_worker = worker
        thread.start()

    @Slot(str)
    def _on_quality_progress(self, message: str) -> None:
        self.quality_status.setText(message)
        self._append_log(message)

    @Slot(object)
    def _on_quality_completed(self, value: object) -> None:
        self._finish_quality_check()
        if not isinstance(value, InternetQualityReport):
            self._on_quality_failed("Модуль качества вернул неизвестный результат")
            return
        self._quality_report = value
        speed = value.speedtest
        network = value.network
        local = value.local
        self.quality_metrics["download"].set_metric(
            _speed(speed.download_mbps),
            "HTTP CDN, 10 МБ",
            "good" if speed.download_mbps is not None else "neutral",
        )
        self.quality_metrics["upload"].set_metric("N/A", "автономный тест не измеряет", "neutral")
        self.quality_metrics["ping"].set_metric(
            _latency(speed.ping_ms),
            speed.server_name or "TCP DNS",
            "good" if speed.ping_ms is not None else "neutral",
        )
        self.quality_metrics["loaded_ping"].set_metric("N/A", "нет нагрузки upload", "neutral")
        self.quality_details["ipv4"].setText(network.ipv4 or "не определён")
        self.quality_details["ipv6"].setText(network.ipv6 or "не определён")
        self.quality_details["local_ip"].setText(
            ", ".join(local.local_ipv4 + local.local_ipv6) or "не определён"
        )
        self.quality_details["local_ip"].setToolTip(local.local_ip_tooltip or "")
        self.quality_details["isp"].setText(network.isp or "не определён")
        self.quality_details["location"].setText(
            ", ".join(value for value in (network.city, network.region) if value) or "не определён"
        )
        if local.vpn_detected or local.proxy_detected or network.vpn_detected is True or network.proxy_detected is True:
            vpn_proxy = "обнаружен"
        elif network.vpn_detected is False and network.proxy_detected is False:
            vpn_proxy = "не обнаружен"
        else:
            vpn_proxy = "не определён"
        self.quality_details["vpn_proxy"].setText(vpn_proxy)
        adapter_speed = (
            f"{local.adapter_speed_mbps} Мбит/с"
            if local.adapter_speed_mbps is not None
            else "скорость не определена"
        )
        self.quality_details["adapter"].setText(
            f"{local.adapter_name or 'не определён'} · {adapter_speed}"
        )
        self.quality_report_output.setPlainText(build_smart_report(value))
        if value.errors:
            self.quality_status.setText(
                speed.error
                or "Проверка завершена частично: часть источников недоступна"
            )
            self._set_status("PARTIAL", "warning")
            for error in value.errors:
                self._append_log(f"Качество: {error}")
        else:
            self.quality_status.setText(f"Проверка качества завершена · Geo API: {network.source}")
            self._set_status("QUALITY READY", "success")
        self._append_log("Проверка качества интернета завершена")

    @Slot(str)
    def _on_quality_failed(self, message: str) -> None:
        self._finish_quality_check()
        self.quality_status.setText(message)
        self._set_status("QUALITY ERROR", "error")
        self._append_log(f"Ошибка качества: {message}")

    def _finish_quality_check(self) -> None:
        self._set_task_button_busy(self.quality_test_button, False)
        self.quality_test_button.setEnabled(True)
        self.quality_progress.hide()

    @Slot()
    def _clear_quality_worker(self) -> None:
        if self.sender() is not self._quality_thread:
            return
        self._quality_thread = None
        self._quality_worker = None

    @Slot()
    def start_diagnostic(self) -> None:
        if self._thread and self._thread.isRunning():
            return
        try:
            target = parse_target(self.target_input.text(), self.port_input.value())
        except ValueError as exc:
            QMessageBox.warning(self, "Некорректный адрес", str(exc))
            self.target_input.setFocus()
            return

        self._report = None
        self._start_diagnostic_session()
        self._reset_results(target)
        self._start_latency_monitor(target.host, target.port)
        self._set_running(True)
        self._append_log(f"Запуск диагностики {target.display_name}")

        thread = QThread(self)
        worker = DiagnosticWorker(target)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.completed.connect(self._on_completed)
        worker.failed.connect(self._on_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._clear_worker)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(str, str)
    def _on_progress(self, stage: str, message: str) -> None:
        self.stage_label.setText(self._tr(message))
        self.topology.set_active_stage(stage)
        self._append_log(message)

    @Slot(object)
    def _on_completed(self, report: object) -> None:
        if not isinstance(report, DiagnosticReport):
            self._on_failed("Диагностический модуль вернул неизвестный результат")
            return
        self._report = report
        self.topology.set_report(report)
        self._fill_metrics(report)
        self._set_ping_statistics(
            latency_statistics(tuple(report.ping.samples_ms), sent=report.ping.sent)
        )
        self._render_loss_hops_placeholders(
            report.hops,
            self._tr("Нажмите «Запустить анализ потерь»"),
        )
        self.loss_hops_status.setText(
            self._tr("Трассировка получена. Запустите анализ, чтобы проверить ICMP-потери по каждому hop.")
        )
        self._fill_interfaces(report.system.interfaces)
        self._fill_route_analysis(report)
        self._show_system_details(report)
        self._update_lite_summary(report)
        self._update_root_cause_analysis(report)
        self.export_button.setEnabled(True)
        self._set_running(False)
        state = "CONNECTED" if report.tcp.status == ProbeStatus.SUCCESS else "ISSUES FOUND"
        self._set_status(state, "success" if report.tcp.status == ProbeStatus.SUCCESS else "warning")
        if report.tcp.status != ProbeStatus.SUCCESS:
            self._set_header_anomaly("error", "Нет подключения к целевому узлу")
        elif report.ping.loss_percent >= 20:
            self._set_header_anomaly("error", "Потери пакетов: {loss:.0f}%", loss=report.ping.loss_percent)
        elif report.ping.loss_percent > 0:
            self._set_header_anomaly("warning", "Потери пакетов: {loss:.0f}%", loss=report.ping.loss_percent)
        elif (report.ping.average_ms or 0.0) >= 150:
            self._set_header_anomaly(
                "error",
                "Пик пинга > {latency:.0f} мс",
                latency=report.ping.average_ms or 0.0,
            )
        elif (report.ping.average_ms or 0.0) >= 100:
            self._set_header_anomaly(
                "warning",
                "Высокий пинг: {latency:.0f} мс",
                latency=report.ping.average_ms or 0.0,
            )
        else:
            self._set_header_anomaly("good", "Связь стабильна")
        self.stage_label.setText(
            self._translator.format("Готово за {seconds:.1f} с", seconds=report.total_ms / 1000)
        )
        for error in report.errors:
            self._append_log(f"Предупреждение: {error}")
        self._append_log("Диагностика завершена")

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._set_running(False)
        self._set_status("ERROR", "error")
        self._set_header_anomaly("error", "Ошибка диагностики")
        self.stage_label.setText(self._tr("Диагностика остановлена из-за ошибки"))
        self._append_log(f"Ошибка: {message}")
        QMessageBox.critical(self, self._tr("Ошибка диагностики"), message)

    @Slot(object)
    def _show_node_details(self, value: object) -> None:
        if not isinstance(value, TopologyNode):
            return
        self.detail_title.setText(value.primary)
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
            self.detail_grid.addWidget(key_label, row, 0, Qt.AlignmentFlag.AlignTop)
            self.detail_grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)

    def _fill_metrics(self, report: DiagnosticReport) -> None:
        dns_ok = report.dns.status == ProbeStatus.SUCCESS
        dns_value = _ms(report.dns.latency_ms) if dns_ok else "ERROR"
        self.metrics["dns"].set_metric(
            dns_value,
            self._tr("Имя сайта найдено" if dns_ok else "Не удалось найти адрес сайта"),
            "good" if dns_ok else "bad",
        )

        self.metrics["ping"].set_metric(
            _ms(report.ping.average_ms),
            self._tr(_ping_verdict(report.ping.average_ms)),
            _latency_state(report.ping.average_ms, 100),
        )
        self.metrics["loss"].set_metric(
            f"{report.ping.loss_percent:.0f}%",
            self._tr(_loss_verdict(report.ping.loss_percent)),
            "good" if report.ping.loss_percent == 0 else "bad",
        )
        self.metrics["jitter"].set_metric(
            _ms(report.ping.jitter_ms),
            self._tr(_jitter_verdict(report.ping.jitter_ms)),
            _latency_state(report.ping.jitter_ms, 20),
        )

        tcp_ok = report.tcp.status == ProbeStatus.SUCCESS
        tcp_value = _ms(report.tcp.latency_ms) if tcp_ok else "CLOSED"
        self.metrics["tcp"].set_metric(
            tcp_value,
            self._tr("Сайт принимает соединение" if tcp_ok else "Соединение с сайтом не установлено"),
            "good" if tcp_ok else "bad",
        )

        if report.tls:
            tls_ok = report.tls.status == ProbeStatus.SUCCESS
            self.metrics["tls"].set_metric(
                report.tls.version or "ERROR",
                self._tr(
                    "Безопасное соединение подтверждено"
                    if tls_ok
                    else "Сертификат или шифрование не прошли проверку"
                ),
                "good" if tls_ok else "bad",
            )
            if hasattr(self, "tls_overview_values") and self._tls_audit_result is None:
                self._render_tls_report_summary(report.tls)
        else:
            self.metrics["tls"].set_metric("N/A", self._tr("Проверка защиты не требуется"), "neutral")

    def _fill_route_analysis(self, report: DiagnosticReport) -> None:
        routes = report.system.default_routes
        self.routes_table.setRowCount(len(routes))
        for row, route in enumerate(routes):
            values = [
                "VPN · активен" if row == 0 and route.is_vpn else (
                    "Обычный · активен" if row == 0 else ("VPN" if route.is_vpn else "Обычный")
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
                self.routes_table.setItem(row, column, item)

        if not routes:
            self.routes_table.setRowCount(1)
            self.routes_table.setItem(0, 0, QTableWidgetItem("Default routes не найдены"))

        self.geo_table.setRowCount(len(report.geolocation))
        successful_geo = 0
        for row, result in enumerate(report.geolocation):
            if result.status == ProbeStatus.SUCCESS:
                successful_geo += 1
            values = [
                result.address,
                ", ".join(part for part in (result.country, result.region, result.city) if part) or "--",
                result.asn or "--",
                result.isp or "--",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.geo_table.setItem(row, column, item)
        self.geo_status.setText(
            f"{successful_geo}/{len(report.geolocation)} узлов · источник ipwho.is"
            if report.geolocation
            else "Публичные IP узлов маршрута не найдены"
        )

    def _fill_interfaces(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self.interfaces_table.setRowCount(len(interfaces))
        for row, interface in enumerate(interfaces):
            values = [
                interface.name,
                self._tr(interface.kind),
                ", ".join(interface.ipv4) or "--",
                "UP" if interface.is_up else "DOWN",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 3:
                    item.setForeground(Qt.GlobalColor.green if interface.is_up else Qt.GlobalColor.gray)
                self.interfaces_table.setItem(row, column, item)

    def _show_system_details(self, report: DiagnosticReport) -> None:
        self.detail_title.setText(report.system.hostname)
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
            self.detail_grid.addWidget(key_label, row, 0, Qt.AlignmentFlag.AlignTop)
            self.detail_grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)

    def _reset_results(self, target: Target) -> None:
        self.latency_chart.reset()
        self.jitter_chart.reset()
        self._latency_window.clear()
        self._ping_spike_events.clear()
        self._jitter_events.clear()
        self._jitter_deviations.clear()
        self._jitter_previous_rtt = None
        self._jitter_target_host = target.host
        self._loss_analyzer.reset()
        self.ping_spike_log.clear()
        self.ping_spike_status.setText(
            self._tr("Пики выше 100 мс и потери появятся здесь во время мониторинга")
        )
        self._set_ping_statistics(latency_statistics(()))
        self.ping_mtu_host_input.setText(target.host)
        self._render_ping_matrix_placeholders()
        self._render_mtu_placeholders()
        self.loss_events_log.clear()
        self.loss_detector_status.setText(self._tr("Ожидание данных live-монитора"))
        self._set_loss_snapshot(self._loss_analyzer_snapshot())
        self.loss_hops_table.setRowCount(0)
        self.loss_hops_status.setText(
            self._tr("Диагностика выполняется: трассировка будет доступна после завершения.")
        )
        self._render_loss_stress_placeholders()
        self.topology.reset(target.display_name)
        self._clear_detail_grid()
        self.detail_title.setText(self._tr("Диагностика выполняется"))
        self.interfaces_table.setRowCount(0)
        self.routes_table.setRowCount(0)
        self.geo_table.setRowCount(0)
        self.geo_status.setText(self._tr("GeoIP ещё не получен"))
        self.lite_title.setText(self._tr("Проверка выполняется"))
        self.lite_message.setText(
            self._translator.format("Проверяем соединение с {target}.", target=target.display_name)
        )
        self.lite_cause.setText(self._tr("Анализ причины появится после завершения проверки."))
        self.analysis_title.setText(self._tr("Анализ выполняется"))
        self.analysis_output.clear()
        self._clear_lite_details()
        self._set_lite_status_style(LiteStatus.WARNING)
        self.export_button.setEnabled(False)
        for tile in self.metrics.values():
            tile.set_waiting(self._tr("Проверка выполняется"))

    def _clear_detail_grid(self) -> None:
        while self.detail_grid.count():
            item = self.detail_grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _set_running(self, running: bool) -> None:
        self._set_task_button_busy(self.start_button, running, "Диагностика")
        self.start_button.setDisabled(running)
        self.target_input.setDisabled(running)
        self.port_input.setDisabled(running)
        for button in self.preset_buttons.values():
            button.setDisabled(running)
        if running:
            self._set_status("ANALYZING", "running")

    def _set_status(self, text: str, state: str) -> None:
        self._status_state = state
        colors = {
            "idle": ("#0B0E14", "#00E5A3", "#00F5B4"),
            "running": ("#FFB800", "#2A2110", "#806000"),
            "success": ("#0B0E14", "#00E5A3", "#00F5B4"),
            "warning": ("#FFB800", "#2A2110", "#806000"),
            "error": ("#FF4757", "#2A1218", "#8F2633"),
        }
        health_labels = {
            "idle": "🟢  Сеть работает отлично",
            "running": "🟡  Есть задержки / Высокий пинг",
            "success": "🟢  Сеть работает отлично",
            "warning": "🟡  Есть задержки / Высокий пинг",
            "error": "🔴  Нет подключения",
        }
        foreground, background, border = colors[state]
        self.status_badge.setStyleSheet(
            f"color: {foreground}; background: {background}; border: 1px solid {border}; "
            "border-radius: 10px; padding: 6px 12px; font-size: 9pt; font-weight: 700;"
        )
        health_text = self._tr(health_labels[state])
        self.status_badge.setProperty("fullText", health_text)
        self.status_badge.setToolTip(health_text)
        self.status_badge.setText(health_text)
        required_width = self.status_badge.fontMetrics().horizontalAdvance(health_text) + 34
        compact_width = max(250, required_width)
        self.status_badge.setFixedWidth(compact_width)

    def _set_interface_mode(self, mode: str) -> None:
        self._close_combo_popups()
        self.mode_stack.setCurrentWidget(self.lite_view if mode == "lite" else self.expert_view)
        self._update_process_display(mode == "lite")
        QTimer.singleShot(0, self._update_responsive_layout)
        self._append_log(
            "Включён простой режим" if mode == "lite" else "Включён экспертный режим"
        )

    def _close_combo_popups(self) -> None:
        for combo in self.findChildren(QComboBox):
            combo.hidePopup()
        if hasattr(self, "embedded_dropdown"):
            self.embedded_dropdown.hide()
            self.embedded_dropdown_list.clear()
            self._active_embedded_combo = None

    @Slot(object)
    def _show_embedded_dropdown(self, combo: object) -> None:
        if not isinstance(combo, QComboBox):
            return
        if self._active_embedded_combo is combo and self.embedded_dropdown.isVisible():
            self._close_combo_popups()
            return

        self._close_combo_popups()
        self._active_embedded_combo = combo
        for index in range(combo.count()):
            item = QListWidgetItem(combo.itemText(index))
            item.setData(Qt.ItemDataRole.UserRole, index)
            item.setToolTip(combo.itemText(index))
            self.embedded_dropdown_list.addItem(item)
        self.embedded_dropdown_list.setCurrentRow(combo.currentIndex())
        self.embedded_dropdown.show()
        self.embedded_dropdown.raise_()

    @Slot(QListWidgetItem)
    def _select_embedded_dropdown_item(self, item: QListWidgetItem) -> None:
        combo = self._active_embedded_combo
        if combo is not None:
            index = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(index, int):
                combo.setCurrentIndex(index)
        self._close_combo_popups()

    def _process_display_label(self, process: ProcessNetworkInfo) -> str:
        if self.lite_mode_button.isChecked():
            return process.friendly_name
        count = len(process.connections)
        noun = self._tr("соединение") if count == 1 else self._tr("соединений")
        return f"{process.name} · PID {process.pid} · {count} {noun}"

    def _connection_display_label(self, connection: ProcessConnection) -> str:
        if not connection.remote_address or connection.remote_port < 1:
            endpoint = self._translator.format(
                "локальный UDP-порт {port}", port=connection.local_port
            )
        else:
            endpoint = connection.remote_endpoint
        return f"{connection.protocol} · {endpoint} · {connection.status}"

    def _refresh_dynamic_process_text(self) -> None:
        if not hasattr(self, "process_selector"):
            return
        for index in range(self.process_selector.count()):
            process = self.process_selector.itemData(index)
            if isinstance(process, ProcessNetworkInfo):
                self.process_selector.setItemText(index, self._process_display_label(process))
        if isinstance(self._selected_process, ProcessNetworkInfo):
            self.process_status.setText(
                f"{self._selected_process.name}: {len(self._selected_process.connections)}"
            )
            for index in range(self.process_connection_selector.count()):
                connection = self.process_connection_selector.itemData(index)
                if isinstance(connection, ProcessConnection):
                    self.process_connection_selector.setItemText(
                        index, self._connection_display_label(connection)
                    )
        self._set_udp_ports_status(self._last_udp_snapshot)

    def _update_process_display(self, lite_mode: bool) -> None:
        if not hasattr(self, "process_connection_selector"):
            return
        self.process_panel.setVisible(not lite_mode)
        self.port_label.setVisible(not lite_mode)
        self.port_input.setVisible(not lite_mode)
        self.connection_title.setVisible(not lite_mode)
        self.process_connection_selector.setVisible(not lite_mode)
        self.process_status.setVisible(not lite_mode)
        self.udp_ports_status.setVisible(not lite_mode)
        for index in range(self.process_selector.count()):
            process = self.process_selector.itemData(index)
            if isinstance(process, ProcessNetworkInfo):
                self.process_selector.setItemText(index, self._process_display_label(process))

    def _update_lite_summary(self, report: DiagnosticReport) -> None:
        summary = summarize_report(report)
        self.lite_title.setText(summary.title)
        self.lite_message.setText(summary.message)
        self._set_lite_status_style(summary.status)
        self._clear_lite_details()
        cards = _lite_summary_cards(report)
        for index, (title, value, state) in enumerate(cards):
            label = QLabel(f"{title}\n{value}")
            label.setObjectName("LiteDetailCard")
            label.setProperty("cardState", state)
            label.setWordWrap(True)
            label.setMinimumHeight(70)
            label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            label.setToolTip(f"{title}: {value}")
            label.style().unpolish(label)
            label.style().polish(label)
            self.lite_details.addWidget(label, index // 2, index % 2)
            self.lite_detail_labels.append(label)

    def _update_root_cause_analysis(self, report: DiagnosticReport) -> None:
        analysis = analyze_report(report, self._selected_process, self._selected_connection)
        self.analysis_title.setText(f"{analysis.subject}: {analysis.headline}")
        primary = analysis.findings[0]
        self.lite_cause.setText(f"Диагноз: {primary.title}. {primary.explanation}")
        lines = []
        for finding in analysis.findings:
            lines.extend(
                (
                    f"{_severity_label(finding.severity)} · {finding.title}",
                    finding.explanation,
                    f"Основание: {finding.evidence}",
                    "",
                )
            )
        self.analysis_output.setPlainText("\n".join(lines).rstrip())

    def _clear_lite_details(self) -> None:
        while self.lite_details.count():
            item = self.lite_details.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.lite_detail_labels.clear()

    def _set_lite_status_style(self, status: LiteStatus) -> None:
        styles = {
            LiteStatus.SUCCESS: ("#00E5A3", "#102A26", "#00F5B4"),
            LiteStatus.WARNING: ("#FFB800", "#2A2110", "#806000"),
            LiteStatus.ERROR: ("#FF4757", "#2A1218", "#8F2633"),
        }
        foreground, background, border = styles[status]
        self.lite_status_indicator.setStyleSheet(
            f"color: {foreground}; background: {background}; border: 1px solid {border}; "
            "border-radius: 32px; font-size: 22pt; font-weight: 700;"
        )
        icons = {
            LiteStatus.SUCCESS: "🟢",
            LiteStatus.WARNING: "⚠️",
            LiteStatus.ERROR: "🔴",
        }
        self.lite_status_indicator.setText(icons[status])
        self.lite_title.setStyleSheet("color: #E1E7EF; font-size: 19pt; font-weight: 700;")

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.appendPlainText(f"[{timestamp}] {message}")

    def _run_system_action(
        self,
        label: str,
        action: Callable[[], SystemActionResult],
        button: QPushButton,
        status_label: QLabel | None = None,
    ) -> None:
        if not button.isEnabled():
            return
        self._set_task_button_busy(button, True, "Выполняется")
        if status_label is not None:
            status_label.setText(self._tr("Выполняется..."))
            self._system_action_status[button] = status_label
        self._append_log(f"Запуск системного действия: {label}")

        thread = QThread(self)
        worker = SystemActionWorker(label, button, action)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._on_system_action_completed)
        worker.completed.connect(thread.quit)
        self._worker_registry.retain(thread, worker)
        thread.finished.connect(self._release_system_action)
        self._system_action_threads.add(thread)
        self._system_action_workers[thread] = worker
        thread.start()

    @Slot(str, object, object)
    def _on_system_action_completed(
        self,
        label: str,
        button: QPushButton,
        result: object,
    ) -> None:
        self._set_task_button_busy(button, False)
        button.setEnabled(True)
        status_label = self._system_action_status.pop(button, None)
        if not isinstance(result, SystemActionResult):
            message = f"{label}: получен неизвестный результат"
            self._append_log(f"Ошибка: {message}")
            self.statusBar().showMessage(message, 6000)
            if status_label is not None:
                status_label.setText(message)
            return

        message = f"{label}: {result.message}"
        prefix = "" if result.success else "Ошибка: "
        self._append_log(prefix + message)
        self.statusBar().showMessage(message, 6000)
        if status_label is not None:
            status_label.setText(
                f"Успешно: {result.message}" if result.success else f"Ошибка: {result.message}"
            )

    @Slot()
    def _release_system_action(self) -> None:
        thread = self.sender()
        if not isinstance(thread, QThread):
            return
        self._system_action_threads.discard(thread)
        self._system_action_workers.pop(thread, None)

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

    @Slot()
    def _export_udp_events_json(self) -> None:
        self._export_udp_events("json")

    @Slot()
    def _export_udp_events_csv(self) -> None:
        self._export_udp_events("csv")

    def _export_udp_events(self, file_format: str) -> None:
        if not self._udp_event_rows:
            return
        if file_format not in {"json", "csv"}:
            raise ValueError(f"Unsupported UDP export format: {file_format}")
        suggested_name = f"NetVision_UDP_{datetime.now():%Y%m%d_%H%M%S}.{file_format}"
        filter_text = "JSON (*.json)" if file_format == "json" else "CSV (*.csv)"
        path, _filter = QFileDialog.getSaveFileName(
            self,
            "Экспорт UDP-событий",
            str(Path.home() / suggested_name),
            filter_text,
        )
        if not path:
            return
        suffix = f".{file_format}"
        if not path.lower().endswith(suffix):
            path += suffix
        payload = (
            serialize_udp_events_json(self._udp_event_rows)
            if file_format == "json"
            else serialize_udp_events_csv(self._udp_event_rows)
        ).encode("utf-8")
        if self._write_export_payload(path, payload):
            self._append_log(f"UDP-события сохранены в {file_format.upper()}: {path}")

    def _write_export_payload(self, path: str, payload: bytes) -> bool:
        output = QSaveFile(path)
        if not output.open(QIODevice.OpenModeFlag.WriteOnly):
            QMessageBox.critical(self, "Экспорт не выполнен", output.errorString())
            return False
        if output.write(payload) != len(payload) or not output.commit():
            QMessageBox.critical(self, "Экспорт не выполнен", output.errorString())
            return False
        return True

    @Slot()
    def _clear_worker(self) -> None:
        if self.sender() is not self._thread:
            return
        self._thread = None
        self._worker = None

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if self._latency_thread is None:
            try:
                target = parse_target(self.target_input.text(), self.port_input.value())
            except ValueError:
                return
            self._start_latency_monitor(target.host, target.port)

    def _start_latency_monitor(self, host: str, port: int) -> None:
        if self._closing:
            return
        self._stop_latency_monitor()
        worker = LatencyMonitorWorker(host, port)
        worker.sample.connect(self._on_latency_sample, Qt.ConnectionType.QueuedConnection)
        thread = self._worker_registry.start(worker)
        thread.finished.connect(self._clear_latency_monitor)
        self._latency_thread = thread
        self._latency_worker = worker

    @Slot(object, bool)
    def _on_latency_sample(self, latency_ms: object, success: bool) -> None:
        if self.sender() is not None and self.sender() is not self._latency_worker:
            return
        value = float(latency_ms) if isinstance(latency_ms, (int, float)) else None
        self._record_jitter_sample(value, success)
        self._latency_window.append(value if success else None)
        if len(self._latency_window) > 60:
            del self._latency_window[:-60]
        if value is not None and value >= 100:
            event = f"[{datetime.now():%H:%M:%S}] Пик задержки: {value:.1f} ms"
            self._ping_spike_events.append(event)
            self._ping_spike_events = self._ping_spike_events[-80:]
        elif not success:
            event = f"[{datetime.now():%H:%M:%S}] Потеря ответа / timeout"
            self._ping_spike_events.append(event)
            self._ping_spike_events = self._ping_spike_events[-80:]
        self.latency_chart.add_sample(value, success)
        loss_snapshot, loss_event = self._loss_analyzer.observe(success, value)
        self._set_loss_snapshot(loss_snapshot)
        if loss_event is not None:
            self.loss_events_log.setPlainText(
                "\n".join(
                    f"[{event.observed_at:%H:%M:%S}] {event.message}"
                    for event in self._loss_analyzer.events
                )
            )
            self.loss_detector_status.setText(
                f"{loss_event.snapshot.status} · событий: {len(self._loss_analyzer.events)}"
            )
        elif loss_snapshot.sent:
            self.loss_detector_status.setText(loss_snapshot.status)
        self._set_ping_statistics(
            latency_statistics(
                [sample for sample in self._latency_window if sample is not None],
                sent=len(self._latency_window),
            )
        )
        if self._ping_spike_events:
            self.ping_spike_log.setPlainText("\n".join(self._ping_spike_events))
            self.ping_spike_status.setText(f"Зафиксировано событий: {len(self._ping_spike_events)}")
        self._update_live_header_anomaly(value, success, loss_snapshot)

    def _update_live_header_anomaly(
        self,
        latency_ms: float | None,
        success: bool,
        loss_snapshot: PacketLossSnapshot,
    ) -> None:
        """Project ping and loss monitor results into the compact header summary."""
        if not success:
            self._set_header_anomaly("warning", "Потеря ответа")
            return
        if loss_snapshot.loss_percent >= 20:
            self._set_header_anomaly(
                "error",
                "Потери пакетов: {loss:.0f}%",
                loss=loss_snapshot.loss_percent,
            )
            return
        if loss_snapshot.loss_percent > 0:
            self._set_header_anomaly(
                "warning",
                "Потери пакетов: {loss:.0f}%",
                loss=loss_snapshot.loss_percent,
            )
            return
        if latency_ms is not None and latency_ms >= 150:
            self._set_header_anomaly(
                "error",
                "Пик пинга > {latency:.0f} мс",
                latency=latency_ms,
            )
            return
        if latency_ms is not None and latency_ms >= 100:
            self._set_header_anomaly(
                "warning",
                "Высокий пинг: {latency:.0f} мс",
                latency=latency_ms,
            )
            return
        self._set_header_anomaly("good", "Связь стабильна")

    def _stop_latency_monitor(self) -> None:
        thread = self._latency_thread
        self._worker_registry.stop(thread)
        if thread is self._latency_thread:
            self._latency_thread = None
            self._latency_worker = None

    @Slot()
    def _clear_latency_monitor(self) -> None:
        thread = self.sender()
        if thread is not self._latency_thread:
            return
        self._latency_thread = None
        self._latency_worker = None

    def closeEvent(self, event: QCloseEvent) -> None:
        action_running = any(thread.isRunning() for thread in self._system_action_threads)
        process_scan_running = bool(
            self._process_scan_thread and self._process_scan_thread.isRunning()
        )
        network_boost_scan_running = bool(
            self._network_boost_scan_thread and self._network_boost_scan_thread.isRunning()
        )
        network_boost_termination_running = bool(
            self._network_boost_terminate_thread and self._network_boost_terminate_thread.isRunning()
        )
        quality_running = bool(self._quality_thread and self._quality_thread.isRunning())
        dns_benchmark_running = bool(
            self._dns_benchmark_thread and self._dns_benchmark_thread.isRunning()
        )
        dns_configuration_running = bool(
            self._dns_config_thread and self._dns_config_thread.isRunning()
        )
        ping_benchmark_running = bool(
            self._ping_benchmark_thread and self._ping_benchmark_thread.isRunning()
        )
        tcp_diagnostics_running = bool(
            self._tcp_diagnostics_thread and self._tcp_diagnostics_thread.isRunning()
        )
        tls_audit_running = bool(self._tls_audit_thread and self._tls_audit_thread.isRunning())
        loss_analysis_running = bool(
            self._loss_test_thread and self._loss_test_thread.isRunning()
        )
        if (
            (self._thread and self._thread.isRunning())
            or action_running
            or process_scan_running
            or network_boost_scan_running
            or network_boost_termination_running
            or quality_running
            or dns_benchmark_running
            or dns_configuration_running
            or ping_benchmark_running
            or tcp_diagnostics_running
            or tls_audit_running
            or loss_analysis_running
        ):
            event.ignore()
            QMessageBox.information(
                self,
                "Операция выполняется",
                "Дождитесь завершения текущей операции перед закрытием NetVision.",
            )
            return
        self._closing = True
        self._session_timer.stop()
        self._stop_latency_monitor()
        self._stop_udp_port_monitor()
        self._worker_registry.stop_all()
        if self._worker_registry.busy:
            self.setEnabled(False)
            self.statusBar().showMessage(self._tr("Завершаем сетевой мониторинг…"))
            event.ignore()
            return
        event.accept()

    @Slot()
    def _finish_monitor_shutdown(self) -> None:
        if self._closing:
            QTimer.singleShot(0, self.close)


def _is_background_cdn(address: str) -> bool:
    normalized = address.strip().casefold()
    return normalized.startswith(
        (
            "104.18.",
            "104.19.",
            "172.64.",
            "172.65.",
            "162.158.",
            "162.159.",
        )
    )


def _is_game_remote_port(port: int) -> bool:
    return any(
        start <= port <= end
        for start, end in (
            (27000, 27100),
            (3074, 3074),
            (3478, 3480),
            (3659, 3659),
            (7777, 7777),
            (30000, 30100),
        )
    )


def _game_connection_key(connection: ProcessConnection) -> tuple[int, int, int, str]:
    return (
        0 if _is_game_remote_port(connection.remote_port) else 1,
        0 if connection.protocol == "UDP" else 1,
        0 if connection.status == "ESTABLISHED" else 1,
        connection.remote_address,
    )


def _ms(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} ms"


def _speed(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} Мбит/с"


def _tls_datetime(value: datetime | None) -> str:
    return "--" if value is None else value.astimezone().strftime("%Y-%m-%d %H:%M")


def _tls_certificate_state(status: str, valid: bool) -> str:
    normalized = status.casefold()
    if valid and "истекает" not in normalized:
        return "good"
    if "истекает" in normalized or "окончания не указана" in normalized:
        return "warning"
    return "bad"


def _tls_state_color(state: str) -> QColor:
    return {
        "good": QColor("#00E5A3"),
        "warning": QColor("#FFB800"),
        "bad": QColor("#FF4757"),
        "neutral": QColor("#8A99AD"),
    }.get(state, QColor("#8A99AD"))


def _jitter_state(value: float | None) -> str:
    if value is None:
        return "neutral"
    if value > 30:
        return "bad"
    if value > 15:
        return "warning"
    return "good"


def _voice_jitter_rating(value: float | None) -> str:
    if value is None:
        return "N/A"
    if value <= 5:
        return "Отлично"
    if value <= 15:
        return "Допустимо"
    if value <= 30:
        return "Рывки"
    return "Плохо"


def _gaming_jitter_rating(value: float | None) -> str:
    if value is None:
        return "N/A"
    if value <= 5:
        return "Стабильно"
    if value <= 15:
        return "Играбельно"
    if value <= 30:
        return "Микрофризы"
    return "Нестабильно"


def _jitter_stability_rating(value: float | None, spike_count: int) -> str:
    if value is None:
        return "Нестабильно" if spike_count else "Ожидание"
    if value > 30 or spike_count >= 3:
        return "Критично"
    if value > 15 or spike_count:
        return "Есть колебания"
    return "Стабильно"


def _udp_event_color(event: UdpEventRow) -> QColor:
    if event.is_anomaly:
        return QColor("#FF4757")
    if event.event_type == "Порт открыт":
        return QColor("#00E5A3")
    if event.event_type == "Порт закрыт":
        return QColor("#FFB800")
    return QColor("#8A99AD")


def _latency(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} мс"


def _latency_state(value: float | None, warning_threshold: float) -> str:
    if value is None:
        return "neutral"
    return "good" if value <= warning_threshold else "bad"


def _ping_verdict(value: float | None) -> str:
    if value is None:
        return "Нет ответа от сервера"
    if value < 30:
        return "Отлично для игр и звонков"
    if value <= 80:
        return "Нормально для веб-серфинга"
    if value > 100:
        return "Высокая задержка"
    return "Задержка выше комфортной"


def _loss_verdict(loss_percent: float) -> str:
    return "Связь стабильная" if loss_percent == 0 else "Возможны фризы и задержки"


def _jitter_verdict(value: float | None) -> str:
    if value is None:
        return "Стабильность не удалось оценить"
    if value <= 10:
        return "Связь ровная, без заметных скачков"
    if value <= 20:
        return "Небольшие колебания связи"
    return "Задержка заметно скачет"


def _lite_summary_cards(report: DiagnosticReport) -> tuple[tuple[str, str, str], ...]:
    dns_latency = report.dns.latency_ms
    if report.dns.status == ProbeStatus.SUCCESS and dns_latency is not None:
        dns_value = (
            f"{dns_latency:.1f} мс (Быстрый отклик)"
            if dns_latency <= 30
            else f"{dns_latency:.1f} мс (Медленный отклик)"
        )
        dns_state = "good" if dns_latency <= 80 else "bad"
    else:
        dns_value = "Нет ответа"
        dns_state = "bad"

    port_open = report.tcp.status == ProbeStatus.SUCCESS
    port_value = "Открыт" if port_open else "Закрыт"
    port_state = "good" if port_open else "bad"

    if report.ping.loss_percent == 0:
        loss_value = "0% (Связь стабильная)"
        loss_state = "good"
    elif report.ping.loss_percent >= 100:
        loss_value = "100% (Обрыв связи)"
        loss_state = "bad"
    else:
        loss_value = f"{report.ping.loss_percent:.0f}% (Возможны задержки)"
        loss_state = "bad"

    vpn_active = any(route.is_vpn for route in report.system.default_routes)
    route_value = "VPN активен" if vpn_active else "Прямое соединение"
    route_state = "good" if vpn_active else "neutral"
    return (
        ("🌐 DNS", dns_value, dns_state),
        (f"🔓 Порт {report.target.port}", port_value, port_state),
        ("📉 Потери", loss_value, loss_state),
        ("🛡️ Маршрут", route_value, route_state),
    )


def _severity_label(severity: object) -> str:
    return {
        "error": "КРИТИЧНО",
        "warning": "ПРЕДУПРЕЖДЕНИЕ",
        "info": "ИНФОРМАЦИЯ",
    }.get(str(severity), "РЕЗУЛЬТАТ")

