"""Reusable dialogs for profile editing and reversible changes."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QThread, QTimer, QUrl, Qt, Signal, Slot
from PySide6.QtGui import (
    QCloseEvent,
    QCursor,
)  # noqa: F401  # Used by the GeoHide dialog migration.
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QProgressBar,
    QScrollArea,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView  # noqa: F401
except Exception:  # QtWebEngine remains optional for portable builds.
    QWebEngineView = None

from netvision.core.process_inspector import (
    ProcessConnection,
    ProcessScanResult,
    is_loopback_address,
)
from netvision.core.geohide import GeoHideResult
from netvision.core.system_actions import SystemChange
from netvision.ui.legacy_workers import GeoHideWorker, ProcessScanWorker
from netvision.ui.monitor_workers import WorkerRegistry  # noqa: F401
from netvision.ui.utils import keep_wheel_scroll_local
from netvision.ui.presentation import HELP_SECTIONS
from netvision.ui.theme import busy_button_colors
from netvision.version import display_version


class HelpDialog(QDialog):
    """A local, translated guide that inherits the active application theme."""

    def __init__(self, parent: QWidget, translate: Callable[[str], str]) -> None:
        super().__init__(parent)
        self.setModal(True)
        screen = parent.screen() or QApplication.primaryScreen()
        available = screen.availableGeometry() if screen else None
        width = min(1100, available.width()) if available else 1100
        height = min(620, int(available.height() * 0.85)) if available else 620
        self.setMinimumSize(min(900, width), min(320, height))
        self.resize(width, height)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)
        self.tabs.tabBar().setObjectName("HelpTabs")
        self.tabs.tabBar().setExpanding(False)
        self._labels: list[tuple[QLabel, str]] = []
        for title, entries in HELP_SECTIONS:
            scroll = QScrollArea(self.tabs)
            scroll.setWidgetResizable(True)
            content = QWidget(scroll)
            body = QVBoxLayout(content)
            body.setContentsMargins(20, 18, 20, 18)
            body.setSpacing(7)
            for term, paragraph in entries:
                heading = QLabel(content)
                heading.setObjectName("HelpSectionHeading")
                heading.setWordWrap(True)
                body.addWidget(heading)
                self._labels.append((heading, term))
                label = QLabel(content)
                label.setObjectName("HelpParagraph")
                label.setWordWrap(True)
                label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                body.addWidget(label)
                self._labels.append((label, paragraph))
                body.addSpacing(10)
            body.addStretch()
            scroll.setWidget(content)
            self.tabs.addTab(scroll, title)
        layout.addWidget(self.tabs)
        self.close_button = QPushButton(self)
        self.close_button.clicked.connect(self.accept)
        layout.addWidget(self.close_button, alignment=Qt.AlignmentFlag.AlignRight)
        self.retranslate(translate)
        if available:
            frame = self.frameGeometry()
            frame.moveCenter(parent.frameGeometry().center())
            frame.moveLeft(
                max(available.left(), min(frame.left(), available.right() - frame.width() + 1))
            )
            frame.moveTop(
                max(available.top(), min(frame.top(), available.bottom() - frame.height() + 1))
            )
            self.move(frame.topLeft())

    def retranslate(self, translate: Callable[[str], str]) -> None:
        self.setWindowTitle(f"{translate('Справка')} · NetVision V {display_version()[1:]}")
        self.close_button.setText(translate("Закрыть"))
        for index, (title, _) in enumerate(HELP_SECTIONS):
            self.tabs.setTabText(index, translate(title))
        for label, source in self._labels:
            label.setText(translate(source))


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


class RollbackConfirmDialog(QDialog):
    """Require a short explicit confirmation for a reversible system change."""

    def __init__(
        self,
        change: SystemChange,
        translate: Callable[[str], str],
        parent: QWidget | None = None,
        seconds: float = 20.0,
    ) -> None:
        super().__init__(parent)
        self._change = change
        self._translate = translate
        self._remaining_seconds = max(0.05, float(seconds))
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._expiry_timer = QTimer(self)
        self._expiry_timer.setSingleShot(True)
        self._expiry_timer.setInterval(round(self._remaining_seconds * 1000))
        self._expiry_timer.timeout.connect(self.reject)
        self.setModal(True)
        self.setWindowTitle(self._translate("Подтвердите изменения"))
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)
        description = QLabel(
            self._translate(
                "Настройки {kind} для «{adapter}» изменены. Подтвердите сохранение, иначе настройки будут восстановлены."
            ).format(kind=change.kind.upper(), adapter=change.adapter)
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        self.countdown_label = QLabel()
        self.countdown_label.setObjectName("RollbackCountdown")
        layout.addWidget(self.countdown_label)

        actions = QHBoxLayout()
        self.rollback_button = QPushButton(self._translate("Откатить изменения"))
        self.confirm_button = QPushButton(self._translate("Сохранить изменения"))
        self.rollback_button.clicked.connect(self.reject)
        self.confirm_button.clicked.connect(self.accept)
        actions.addWidget(self.rollback_button)
        actions.addStretch(1)
        actions.addWidget(self.confirm_button)
        layout.addLayout(actions)
        self._update_countdown()
        self._timer.start()
        self._expiry_timer.start()

    @Slot()
    def _tick(self) -> None:
        self._remaining_seconds -= 1
        if self._remaining_seconds <= 0:
            self.reject()
            return
        self._update_countdown()

    def _update_countdown(self) -> None:
        self.countdown_label.setText(
            self._translate("Осталось {seconds} с").format(
                seconds=max(0, round(self._remaining_seconds))
            )
        )

    def done(self, result: int) -> None:
        self._timer.stop()
        self._expiry_timer.stop()
        super().done(result)


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
        keep_wheel_scroll_local(self.table)
        header = self.table.horizontalHeader()
        for column in range(self.table.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        bottom_row = QHBoxLayout()
        bottom_row.addWidget(QLabel(self._translate("Целевой профиль")))
        self.profile_combo = QComboBox()
        self.profile_combo.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        keep_wheel_scroll_local(self.profile_combo.view())
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
        worker.completed.connect(self._on_scan_completed, Qt.ConnectionType.QueuedConnection)
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
                self._translator_message(
                    "Не удалось получить соединения: {error}", error=value.warning
                )
            )
            return
        for process in sorted(
            value.processes,
            key=lambda item: (
                item.name.casefold() != "huntgame.exe",
                item.name.casefold(),
                item.pid,
            ),
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
            if is_loopback_address(connection.remote_address):
                remote = f"{remote} (локальный прокси/loopback)"
            remote_port = connection.remote_port if connection.remote_address else 0
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f"{process_name} · PID {pid}"))
            self.table.setItem(row, 1, QTableWidgetItem(remote))
            self.table.setItem(row, 2, QTableWidgetItem(str(remote_port) if remote_port else "—"))
            self.table.setItem(
                row, 3, QTableWidgetItem(f"{connection.protocol} · {connection.status}")
            )

    @staticmethod
    def _best_connection_key(row: tuple[str, int, ProcessConnection]) -> tuple[int, int, int, str]:
        process_name, _pid, connection = row
        return (
            1 if is_loopback_address(connection.remote_address) else 0,
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
            connection is not None
            and bool(connection.remote_address)
            and connection.remote_port > 0
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
            self.status_label.setText(
                self._translate("Дождитесь завершения сканирования соединений")
            )
            return
        super().closeEvent(event)


class GeoHideDialog(QDialog):
    """Show the current DNS-over-UDP data published by GeoHide."""

    STATUS_URL = "https://hetrixtools.com/r/f1e2a8d87f855e5a611040c56ca5d5b0/"

    def __init__(
        self,
        parent: QWidget | None = None,
        translate: Callable[[str], str] | None = None,
        apply_dns: Callable[[str], None] | None = None,
        worker_registry: WorkerRegistry | None = None,
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
        self._close_pending = False
        self._worker_registry = worker_registry or WorkerRegistry(self)
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
        keep_wheel_scroll_local(self.data_table)
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

    def showEvent(self, event: object) -> None:
        super().showEvent(event)
        if self._result is None and self._thread is None and not self._close_pending:
            self._refresh()

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
        foreground, border, background = busy_button_colors(
            self.refresh_button, self._refresh_phase
        )
        self.refresh_button.setStyleSheet(
            f"{self._refresh_button_style}\n"
            f"QPushButton {{ color: {foreground}; "
            f"background-color: {background}; border: 1px solid {border}; }}"
        )

    def _refresh(self) -> None:
        if self._thread is not None:
            return
        self._set_refresh_button_busy(True)
        self.progress.setVisible(True)
        self._set_status("Загрузка данных GeoHide...")
        worker = GeoHideWorker()
        worker.completed.connect(self._on_loaded, Qt.ConnectionType.QueuedConnection)
        worker.failed.connect(self._on_failed, Qt.ConnectionType.QueuedConnection)
        self._worker = worker
        self._thread = self._worker_registry.start(worker)
        self._thread.finished.connect(self._clear_thread)

    @Slot(object)
    def _on_loaded(self, value: object) -> None:
        if not isinstance(value, GeoHideResult):
            self._on_failed("Некорректный ответ GeoHide")
            return
        self._result = value
        self._render_result()
        if value.used_fallback:
            status = "GeoHide недоступен, показан резервный список: {count} адресов"
        elif value.truncated:
            status = "Данные GeoHide частично загружены: {count} адресов"
        elif not value.confirmed:
            status = "Адреса GeoHide найдены, но не подтверждены контекстом DNS: {count}"
        else:
            status = "Данные GeoHide обновлены: {count} адресов"
        self._set_status(status, count=len(value.servers))

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._set_status("GeoHide недоступен: {error}", error=message)

    def _render_result(self) -> None:
        self.data_table.setRowCount(0)
        if self._result is None:
            return
        rows = [
            (server.server_type, server.region, server.address) for server in self._result.servers
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
        if self._close_pending:
            QTimer.singleShot(0, self.reject)

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None:
            self._close_pending = True
            self._worker_registry.stop(self._thread)
            self._refresh_timer.stop()
            self.hide()
            event.ignore()
            return
        self._refresh_timer.stop()
        self._dispose_status_web_view()
        super().closeEvent(event)

    def _dispose_status_web_view(self) -> None:
        if self.status_web_view is not None:
            self.status_web_view.stop()
            self.status_web_view.setUrl(QUrl("about:blank"))
            self.status_web_view.deleteLater()
            self.status_web_view = None

    def reject(self) -> None:
        if self._worker_registry.busy:
            self.close()
            return
        if self._close_pending:
            self._dispose_status_web_view()
        super().reject()
