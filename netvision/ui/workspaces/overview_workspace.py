"""Dashboard overview cards."""

from collections.abc import Callable
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QSizePolicy,
    QTableWidget,
    QVBoxLayout,
)
from netvision.ui.components import factory


class RegionCard(QFrame):
    def __init__(self, translate: Callable[[str], str]) -> None:
        super().__init__()
        card = self
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(card)
        title_row = QHBoxLayout()
        title_row.addWidget(
            factory.card_title(translate("Матрица игровых регионов и активных узлов"))
        )
        title_row.addStretch(1)
        mode_label = QLabel(translate("Режим: обзор"))
        mode_label.setObjectName("SubLabel")
        title_row.addWidget(mode_label)
        layout.addLayout(title_row)
        self.dashboard_region_table = QTableWidget(0, 5)
        self.dashboard_region_table.setObjectName("DashboardRegionTable")
        self.dashboard_region_table.setHorizontalHeaderLabels(
            (
                translate("Регион / процесс"),
                translate("Узел (endpoint)"),
                "RTT",
                translate("Потери"),
                translate("Статус"),
            )
        )
        self.dashboard_region_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.dashboard_region_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.dashboard_region_table.verticalHeader().setVisible(False)
        self.dashboard_region_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.dashboard_region_table.setMinimumHeight(180)
        layout.addWidget(self.dashboard_region_table, 1)


class EventsCard(QFrame):
    def __init__(self, translate: Callable[[str], str]) -> None:
        super().__init__()
        card = self
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        card.setProperty("dashboardRole", "events")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        title_row = QHBoxLayout()
        title_row.addWidget(factory.card_title(translate("Системные события")))
        title_row.addStretch(1)
        self.dashboard_action_status = QLabel()
        self.dashboard_action_status.setObjectName("SubLabel")
        title_row.addWidget(self.dashboard_action_status)
        layout.addLayout(title_row)
        self.dashboard_event_output = QPlainTextEdit()
        self.dashboard_event_output.setObjectName("DashboardEventLog")
        self.dashboard_event_output.setReadOnly(True)
        self.dashboard_event_output.setMaximumBlockCount(5)
        self.dashboard_event_output.setMinimumHeight(64)
        self.dashboard_event_output.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        layout.addWidget(self.dashboard_event_output, 1)
