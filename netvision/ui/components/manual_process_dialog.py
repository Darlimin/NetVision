from __future__ import annotations

from collections.abc import Callable
from PySide6.QtCore import QThread, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from netvision.core.process_inspector import ProcessListResult, RunningProcess
from netvision.ui.legacy_workers import RunningProcessListWorker
from netvision.ui.utils import keep_wheel_scroll_local


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
            self._translate("Введите имя процесса, например Game.exe")
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
        keep_wheel_scroll_local(self.process_list)
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
        worker.completed.connect(self._on_processes_loaded, Qt.ConnectionType.QueuedConnection)
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
