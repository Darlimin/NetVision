"""MtrWorkspace widgets."""

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui.components import factory


class MtrWorkspace(QWidget):
    def __init__(self, translate: Callable[[str], str], default_host: str) -> None:
        super().__init__()
        tab = self
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("TracerouteScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(9)

        heading_row = QHBoxLayout()
        heading = QLabel(translate("ВИЗУАЛЬНАЯ ТРАССИРОВКА"))
        heading.setObjectName("FieldLabel")

        self.traceroute_target_input = QLineEdit(default_host)
        self.traceroute_target_input.setPlaceholderText(translate("Введите домен или IP-адрес"))
        self.traceroute_target_input.setClearButtonEnabled(True)
        self.traceroute_start_button = QPushButton(translate("▶  Запустить трассировку"))
        self.traceroute_start_button.setObjectName("TracerouteStartButton")
        self.mtr_start_button = QPushButton(translate("▶  Непрерывный MTR"))
        self.mtr_start_button.setObjectName("TracerouteStartButton")
        self.mtr_start_button.setCheckable(True)
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.traceroute_target_input, 1)
        heading_row.addWidget(self.traceroute_start_button)
        heading_row.addWidget(self.mtr_start_button)

        self.traceroute_progress = QProgressBar()
        self.traceroute_progress.setObjectName("TracerouteProgress")
        self.traceroute_progress.setRange(0, 0)
        self.traceroute_progress.setTextVisible(False)
        self.traceroute_progress.setFixedHeight(6)
        self.traceroute_progress.hide()
        self.traceroute_status = QLabel(translate("Трассировка ещё не запускалась"))
        self.traceroute_status.setObjectName("Muted")
        self.traceroute_status.setWordWrap(True)

        note = QLabel(
            translate(
                "Пакеты отправляются с возрастающим TTL. Каждый найденный узел появляется в таблице по мере получения ответа."
            )
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)

        self.traceroute_table = QTableWidget(0, 6)
        self.traceroute_table.setObjectName("TracerouteTable")
        self.traceroute_table.setHorizontalHeaderLabels(
            [
                translate("Прыжок"),
                translate("IP-адрес"),
                translate("Имя узла"),
                translate("Задержка"),
                translate("Статус"),
                translate("Описание"),
            ]
        )
        factory.configure_table(self.traceroute_table, (75, 155, 240, 110, 130, 300))
        self.traceroute_table.setMinimumHeight(220)
        self.traceroute_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self.traceroute_table.setAlternatingRowColors(True)

        self.mtr_status = QLabel(translate("Непрерывный MTR ещё не запускался"))
        self.mtr_status.setObjectName("Muted")
        self.mtr_status.setWordWrap(True)
        self.mtr_table = QTableWidget(0, 12)
        self.mtr_table.setObjectName("MtrTable")
        self.mtr_table.setHorizontalHeaderLabels(
            [
                translate("Прыжок"),
                translate("IP-адрес"),
                translate("Имя узла"),
                translate("Отправлено"),
                translate("Получено"),
                translate("Потери"),
                translate("Последний"),
                translate("Средний"),
                translate("Лучший"),
                translate("Худший"),
                translate("Jitter"),
                translate("Статус"),
            ]
        )
        factory.configure_table(
            self.mtr_table,
            (62, 155, 150, 90, 90, 82, 88, 88, 88, 88, 88, 170),
        )
        self.mtr_table.setMinimumHeight(220)
        self.mtr_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.mtr_table.setAlternatingRowColors(True)

        route_tabs = QTabWidget()
        route_tabs.setObjectName("TracerouteModeTabs")
        traceroute_panel = QWidget()
        traceroute_layout = QVBoxLayout(traceroute_panel)
        traceroute_layout.setContentsMargins(0, 0, 0, 0)
        traceroute_layout.addWidget(self.traceroute_table)
        mtr_panel = QWidget()
        mtr_layout = QVBoxLayout(mtr_panel)
        mtr_layout.setContentsMargins(0, 0, 0, 0)
        mtr_layout.addWidget(self.mtr_status)
        mtr_layout.addWidget(self.mtr_table)
        route_tabs.addTab(traceroute_panel, translate("Таблица трассировки"))
        route_tabs.addTab(mtr_panel, translate("Непрерывный MTR"))
        self.traceroute_mode_tabs = route_tabs

        layout.addLayout(heading_row)
        layout.addWidget(self.traceroute_progress)
        layout.addWidget(self.traceroute_status)
        layout.addWidget(note)
        layout.addWidget(route_tabs, 1)
        layout.addStretch(1)
        scroll.setWidget(content)
        tab_layout.addWidget(scroll)
