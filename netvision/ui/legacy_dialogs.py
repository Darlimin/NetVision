"""Additional dialogs used by NetVision diagnostic workflows."""

from __future__ import annotations

from collections.abc import Callable
import csv
import ctypes
from datetime import datetime
import json
import subprocess
import sys

from PySide6.QtCore import QThread, QTimer, Qt, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netvision.core.network_boost import BackgroundTrafficCandidate, ProcessTerminationResult
from netvision.core.packet_capture import CaptureState
from netvision.core.process_inspector import ProcessConnection
from netvision.core.process_utils import EndpointChoice, _explain_game_connection
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds
from netvision.ui.game_check_worker import GameAutoCheckResult, GameAutoCheckWorker
from netvision.ui.utils import keep_wheel_scroll_local
from netvision.version import __version__, display_version


def _admin_restart_command() -> tuple[str, str]:
    """Build the command that should be relaunched through ShellExecuteW."""
    arguments = list(sys.argv[1:])
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(arguments)
    return sys.executable, subprocess.list2cmdline(["-m", "netvision", *arguments])


class GameAutoCheckDialog(QDialog):
    """Compact background process and packet-stability check for a game."""

    endpoint_chosen = Signal(object)
    capture_started = Signal(object)
    check_completed = Signal(object)

    def __init__(
        self,
        translate: Callable[[str], str],
        preferred_process: str | None = None,
        parent: QWidget | None = None,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        super().__init__(parent)
        self._translate = translate
        self._preferred_process = preferred_process
        self._thresholds = th
        self._thread: QThread | None = None
        self._worker: GameAutoCheckWorker | None = None
        self._monitor_timer = QTimer(self)
        self._monitor_timer.setInterval(8000)
        self._monitor_timer.timeout.connect(self._start_check)
        self._history: list[dict[str, object]] = []
        self._samples: list[dict[str, object]] = []
        self._last_result: GameAutoCheckResult | None = None
        self.setObjectName("GameAutoCheckDialog")
        self.setWindowTitle(f"{self._translate('Автопроверка игры')} · {display_version()}")
        self.setModal(True)
        self.resize(600, 480)
        self.setMinimumSize(500, 380)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title_row = QHBoxLayout()
        title = QLabel(self._translate("Автоматическая проверка процесса"))
        title.setObjectName("GameAutoCheckTitle")
        self.version_label = QLabel(
            self._translate("Версия {version}").format(version=display_version())
        )
        self.version_label.setObjectName("GameAutoCheckVersion")
        title_row.addWidget(title)
        title_row.addStretch(1)
        title_row.addWidget(self.version_label)
        subtitle = QLabel(
            self._translate(
                "Поиск игрового процесса, сокетов и быстрый тест стабильности соединения"
            )
        )
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        layout.addLayout(title_row)
        layout.addWidget(subtitle)

        cards = QGridLayout()
        cards.setHorizontalSpacing(8)
        cards.setVerticalSpacing(8)
        self.process_value = self._add_status_card(cards, 0, 0, "Процесс", "Проверка...")
        self.socket_value = self._add_status_card(cards, 0, 1, "Активные сокеты", "Проверка...")
        self.loss_value = self._add_status_card(cards, 1, 0, "Уровень потерь", "Проверка...")
        self.stability_value = self._add_status_card(
            cards, 1, 1, "Стабильность соединения", "Проверка..."
        )
        layout.addLayout(cards)

        self.endpoint_label = QLabel(self._translate("Удалённая цель: проверка..."))
        self.endpoint_label.setObjectName("Muted")
        layout.addWidget(self.endpoint_label)
        self.socket_list = QListWidget()
        self.socket_list.setObjectName("GameAutoCheckSocketList")
        self.socket_list.setMinimumHeight(100)
        self.socket_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        keep_wheel_scroll_local(self.socket_list)
        layout.addWidget(self.socket_list, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        self.status_label = QLabel(self._translate("Проверка выполняется..."))
        self.status_label.setObjectName("GameAutoCheckStatus")
        layout.addWidget(self.status_label)

        self.admin_button = QPushButton(self._translate("Перезапустить как Администратор"))
        self.admin_button.setVisible(False)
        self.admin_button.clicked.connect(self._restart_as_admin)
        layout.addWidget(self.admin_button)

        history_title = QLabel(self._translate("История критических всплесков"))
        history_title.setObjectName("FieldLabel")
        layout.addWidget(history_title)
        self.history_table = QTableWidget(0, 4)
        self.history_table.setObjectName("GameAutoCheckHistoryTable")
        self.history_table.setHorizontalHeaderLabels(
            [
                self._translate("Время"),
                self._translate("Потери"),
                self._translate("RTT"),
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
        keep_wheel_scroll_local(self.history_table)
        layout.addWidget(self.history_table)

        actions = QVBoxLayout()
        actions.setSpacing(6)
        self.monitor_checkbox = QCheckBox(self._translate("Непрерывный мониторинг в бою"))
        self.monitor_checkbox.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
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
        monitor_row = QHBoxLayout()
        monitor_row.addWidget(self.monitor_checkbox, 1)
        actions.addLayout(monitor_row)
        button_row = QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(self.export_button)
        button_row.addWidget(close_button)
        button_row.addWidget(self.refresh_button)
        actions.addLayout(button_row)
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
        worker.capture_started.connect(
            self._on_capture_started,
            Qt.ConnectionType.QueuedConnection,
        )
        worker.completed.connect(self._on_check_completed, Qt.ConnectionType.QueuedConnection)
        worker.completed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        thread.finished.connect(self._clear_check_worker)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _on_capture_started(self, value: object) -> None:
        self.capture_started.emit(value)

    @Slot(object)
    def _on_check_completed(self, value: object) -> None:
        self.refresh_button.setEnabled(True)
        self.progress.hide()
        self._update_admin_restart_action(value)
        if not isinstance(value, GameAutoCheckResult):
            self.status_label.setText(self._translate("Не удалось завершить проверку"))
            self._set_alert_state("error")
            self.check_completed.emit(value)
            return
        self._last_result = value
        if value.process is None:
            self._render_missing_process_result()
            self.check_completed.emit(value)
            return

        self.process_value.setText(f"{value.process.name} · PID {value.process.pid}")
        self.socket_value.setText(str(len(value.connections)))
        self._render_socket_list(value)

        choice = self._render_selected_endpoint(value)
        self._render_ping_result(value, choice)
        self.status_label.setText(
            self._translate_runtime_warning(value.warning)
            if value.warning
            else self._translate("Проверка завершена")
        )
        self.check_completed.emit(value)

    def _render_socket_list(self, value: GameAutoCheckResult) -> None:
        self.socket_list.clear()
        captured = (
            value.selected_connection
            if value.capture_state is CaptureState.ENDPOINT_FOUND
            else None
        )
        connections = list(value.connections)
        if captured is not None:
            connections = [captured] + [item for item in connections if item != captured]
        for connection in connections:
            suffix = self._translate("ЗАХВАЧЕН") if connection == captured else connection.status
            self.socket_list.addItem(
                f"{connection.protocol} · {connection.local_port} → "
                f"{connection.remote_endpoint} · {suffix}"
            )
        if not connections:
            self.socket_list.addItem(self._translate("Активные соединения не найдены"))

    def _render_missing_process_result(self) -> None:
        self.process_value.setText(self._translate("Процесс не найден"))
        self.socket_value.setText("--")
        self.loss_value.setText("--")
        self.stability_value.setText(self._translate("Нет данных"))
        self.endpoint_label.setText(self._translate("Удалённая цель: не определена"))
        self.endpoint_label.setToolTip("")
        self.socket_list.clear()
        self.status_label.setText(self._translate("Запустите игру и повторите проверку"))
        self._set_alert_state("warning")

    def _render_selected_endpoint(self, value: GameAutoCheckResult) -> EndpointChoice | None:
        choice = _explain_game_connection(value.selected_connection, value.connections)
        if choice is not None and value.capture_state is CaptureState.ENDPOINT_FOUND:
            choice = EndpointChoice(
                choice.connection,
                "Перехват UDP-заголовков",
                choice.candidates,
                choice.excluded_cdn,
            )
        if choice is None:
            return None
        endpoint = choice.connection.remote_endpoint
        reason = self._translate(value.selection_reason or choice.rule)
        self.endpoint_label.setText(
            self._translate("Игровой узел: {endpoint} · {reason}").format(
                endpoint=endpoint,
                reason=reason,
            )
        )
        self.endpoint_label.setToolTip(
            self._translate(
                "Правило выбора: {rule}. Кандидатов: {count}; исключено CDN: {excluded}."
            ).format(
                rule=reason,
                count=choice.candidates,
                excluded=choice.excluded_cdn,
            )
        )
        self.endpoint_chosen.emit(choice)
        return choice

    def _render_ping_result(
        self, value: GameAutoCheckResult, choice: EndpointChoice | None
    ) -> None:
        ping = value.ping
        if ping is None:
            if choice is None:
                self.endpoint_label.setText(self._translate("Удалённая цель: не определена"))
                self.endpoint_label.setToolTip("")
            self.loss_value.setText("--")
            self.stability_value.setText(self._translate("Нет удалённой цели"))
            self._set_alert_state("warning")
            return
        if choice is None:
            self.endpoint_label.setText(
                self._translate("Игровой узел: {endpoint}").format(endpoint=ping.host)
            )
            self.endpoint_label.setToolTip("")
        self.loss_value.setText(f"{ping.loss_percent:.1f}%")
        jitter = "--" if ping.jitter_ms is None else f"{ping.jitter_ms:.1f} ms"
        self.stability_value.setText(
            self._translate("RTT {rtt} · jitter {jitter}").format(
                rtt="--" if ping.average_ms is None else f"{ping.average_ms:.1f} ms",
                jitter=jitter,
            )
        )
        self._record_sample(ping, value.selected_connection)
        self._record_critical_event(ping)
        self._set_alert_state("error" if self._is_critical_ping(ping) else "good")

    def _update_admin_restart_action(self, value: object) -> None:
        self.admin_button.setVisible(
            isinstance(value, GameAutoCheckResult)
            and value.capture_state is CaptureState.PERMISSION_DENIED
        )

    def _translate_runtime_warning(self, warning: str) -> str:
        prefix = "Не удалось получить сетевые соединения: "
        if warning.startswith(prefix):
            return self._translate("Не удалось получить сетевые соединения: {error}").format(
                error=warning.removeprefix(prefix),
            )
        return self._translate(warning)

    def _is_critical_ping(self, ping: object) -> bool:
        return bool(
            getattr(ping, "loss_percent", 0.0) >= 5.0
            or (getattr(ping, "jitter_ms", None) or 0.0) >= self._thresholds.jitter_critical_ms
            or (getattr(ping, "average_ms", None) or 0.0) >= self._thresholds.rtt_high_ms
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
        if (jitter or 0.0) >= self._thresholds.jitter_critical_ms:
            reasons.append(self._translate("резкий jitter"))
        if (rtt or 0.0) >= self._thresholds.rtt_high_ms:
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
            "--" if rtt is None else f"{float(rtt):.1f} ms",
            str(row["status"]),
        )
        for column, text in enumerate(values):
            self.history_table.setItem(table_row, column, QTableWidgetItem(text))
        self.history_table.scrollToBottom()

    def _record_sample(
        self,
        ping: object,
        connection: ProcessConnection | None,
    ) -> None:
        """Keep bounded session measurements even when no alert is raised."""
        sample = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "endpoint": (
                connection.remote_endpoint
                if connection is not None
                else str(getattr(ping, "host", ""))
            ),
            "protocol": connection.protocol if connection is not None else None,
            "loss_percent": round(float(getattr(ping, "loss_percent", 0.0) or 0.0), 1),
            "rtt_ms": _optional_rounded(getattr(ping, "average_ms", None)),
            "jitter_ms": _optional_rounded(getattr(ping, "jitter_ms", None)),
            "critical": self._is_critical_ping(ping),
        }
        self._samples.append(sample)
        del self._samples[:-300]

    @Slot(bool)
    def _toggle_monitoring(self, enabled: bool) -> None:
        if enabled:
            self._monitor_timer.start()
            self.status_label.setText(self._translate("Мониторинг включён"))
            self._start_check()
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
    def _restart_as_admin(self) -> None:
        try:
            executable, parameters = _admin_restart_command()
            shell32 = ctypes.windll.shell32
            result = shell32.ShellExecuteW(None, "runas", executable, parameters, None, 1)
        except (AttributeError, OSError, TypeError) as exc:
            self.status_label.setText(
                self._translate("Не удалось запросить права администратора: {error}").format(
                    error=exc
                )
            )
            return
        if result <= 32:
            self.status_label.setText(self._translate("Запуск с правами администратора отменён"))
            return
        self.status_label.setText(self._translate("Перезапуск с правами администратора запущен"))

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
            "app_version": __version__,
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
            "selected_connection": (
                {
                    "protocol": self._last_result.selected_connection.protocol,
                    "remote_endpoint": self._last_result.selected_connection.remote_endpoint,
                    "remote_address": self._last_result.selected_connection.remote_address,
                    "remote_port": self._last_result.selected_connection.remote_port,
                }
                if self._last_result and self._last_result.selected_connection is not None
                else None
            ),
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
            "samples": self._samples,
            "history": self._history,
        }
        try:
            if "CSV" in selected_filter or path.casefold().endswith(".csv"):
                if not path.casefold().endswith(".csv"):
                    path += ".csv"
                process_name = report["process"]["name"] if report["process"] else ""
                process_pid = report["process"]["pid"] if report["process"] else ""
                socket_count = len(report["connections"])
                source_rows = self._history or self._samples
                csv_rows = [
                    {
                        "timestamp": row.get("timestamp", ""),
                        "process_name": process_name,
                        "process_pid": process_pid,
                        "socket_count": socket_count,
                        "endpoint": row.get("endpoint", ""),
                        "loss_percent": row.get("loss_percent", ""),
                        "rtt_ms": row.get("rtt_ms", ""),
                        "jitter_ms": row.get("jitter_ms", ""),
                        "status": row.get(
                            "status",
                            (
                                self._translate("Критический всплеск")
                                if row.get("critical")
                                else self._translate("Стабильно")
                            ),
                        ),
                    }
                    for row in source_rows
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
        if self._worker is not None:
            self._worker.stop()
        if self._thread is not None and self._thread.isRunning():
            event.ignore()
            self.status_label.setText(self._translate("Остановка проверки..."))
            return
        super().closeEvent(event)

    def reject(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            if self._worker is not None:
                self._worker.stop()
            self.status_label.setText(self._translate("Остановка проверки..."))
            return
        super().reject()


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
        keep_wheel_scroll_local(self.candidate_scroll)
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
            self._empty_label = QLabel(
                "Подходящих фоновых приложений с активными сетевыми сокетами не найдено."
            )
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
                self._translate(
                    "Подходящих фоновых приложений с активными сетевыми сокетами не найдено."
                )
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
        socket_label = (
            "активный сокет" if candidate.active_connection_count == 1 else "активных сокетов"
        )
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
        return tuple(
            candidate
            for candidate, checkbox in self._candidate_checkboxes.items()
            if checkbox.isChecked()
        )

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
                checkbox.setText(
                    f"{self._candidate_text(candidate)} · {self._translate('завершён')}"
                )
            else:
                failures.append(f"{candidate.display_name}: {result.message}")
        if success_count:
            message = self._translate("Завершено процессов: {count}.").format(count=success_count)
            if failures:
                message += " " + self._translate("Не удалось") + ": " + "; ".join(failures)
        else:
            message = (
                self._translate("Процессы не завершены.")
                + " "
                + "; ".join(failures or [self._translate("Неизвестная ошибка")])
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
                )
                + "\n\n"
                + names,
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


def _optional_rounded(value: object) -> float | None:
    return round(float(value), 1) if isinstance(value, (int, float)) else None
