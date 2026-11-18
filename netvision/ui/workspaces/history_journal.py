"""Workspace widgets."""

from collections.abc import Callable

from PySide6.QtWidgets import (
    QComboBox,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStyle,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui.components import factory


class HistoryWorkspace(QWidget):
    def __init__(self, translate: Callable[[str], str]) -> None:
        super().__init__()
        tab = self
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        heading_row = QHBoxLayout()
        heading = QLabel(translate("ИСТОРИЯ / ТРЕНДЫ"))
        heading.setObjectName("FieldLabel")
        self.history_refresh_button = QPushButton(translate("Обновить историю"))
        self.history_clear_button = QPushButton(translate("Очистить историю"))
        self.history_clear_button.setObjectName("HistoryClearButton")
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.history_refresh_button)
        heading_row.addWidget(self.history_clear_button)

        self.history_summary = QLabel(translate("История тестов пока пуста"))
        self.history_summary.setObjectName("Muted")
        self.history_summary.setWordWrap(True)
        self.history_trend = QLabel(translate("Для тренда нужны минимум два теста качества."))
        self.history_trend.setObjectName("Muted")
        self.history_trend.setWordWrap(True)

        self.history_table = QTableWidget(0, 6)
        self.history_table.setObjectName("TestHistoryTable")
        self.history_table.setHorizontalHeaderLabels(
            [
                translate("Дата и время"),
                translate("Тип теста"),
                translate("Скачивание"),
                translate("Отдача"),
                translate("Ping"),
                translate("Bufferbloat"),
            ]
        )
        factory.configure_table(self.history_table, (170, 170, 120, 120, 110, 120))
        self.history_table.setMinimumHeight(240)
        self.history_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        layout.addLayout(heading_row)
        layout.addWidget(self.history_summary)
        layout.addWidget(self.history_trend)
        layout.addWidget(self.history_table, 1)


class UdpHistoryWorkspace(QWidget):
    def __init__(self) -> None:
        super().__init__()
        tab = self
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
        self.export_udp_csv_button = QPushButton("Экспорт CSV")
        self.export_udp_csv_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.export_udp_csv_button.setToolTip("Сохранить историю UDP-событий в CSV")
        self.export_udp_csv_button.setEnabled(False)
        actions_row.addStretch(1)
        actions_row.addWidget(self.export_udp_json_button)
        actions_row.addWidget(self.export_udp_csv_button)

        self.udp_event_status = QLabel("Выберите процесс для мониторинга UDP-событий")
        self.udp_event_status.setObjectName("Muted")

        self.udp_events_table = QTableWidget(0, 4)
        self.udp_events_table.setObjectName("UdpEventsTable")
        self.udp_events_table.setHorizontalHeaderLabels(["Время", "Событие", "Порт", "Детали"])
        self.udp_events_table.setSortingEnabled(False)
        factory.configure_table(self.udp_events_table, (100, 150, 75, 310))

        layout.addLayout(heading_row)
        layout.addLayout(actions_row)
        layout.addWidget(self.udp_event_status)
        layout.addWidget(self.udp_events_table, 1)


class JournalWorkspace(QWidget):
    def __init__(self) -> None:
        super().__init__()
        tab = self
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        heading_row = QHBoxLayout()
        self.journal_heading = QLabel("ЕДИНЫЙ ЖУРНАЛ СЕССИИ")
        self.journal_heading.setObjectName("FieldLabel")
        self.journal_layer_filter = QComboBox()
        self.journal_layer_filter.setObjectName("JournalLayerFilter")
        self.journal_include_past_sessions = QCheckBox("Прошлые сессии")
        heading_row.addWidget(self.journal_heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.journal_layer_filter)
        heading_row.addWidget(self.journal_include_past_sessions)

        actions_row = QHBoxLayout()
        self.export_journal_json_button = QPushButton("Экспорт JSON")
        self.export_journal_json_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.export_journal_csv_button = QPushButton("Экспорт CSV")
        self.export_journal_csv_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.clear_journal_button = QPushButton("Очистить журнал")
        actions_row.addStretch(1)
        actions_row.addWidget(self.export_journal_json_button)
        actions_row.addWidget(self.export_journal_csv_button)
        actions_row.addWidget(self.clear_journal_button)

        self.journal_status = QLabel("Журнал текущей сессии пока пуст")
        self.journal_status.setObjectName("Muted")
        self.journal_table = QTableWidget(0, 5)
        self.journal_table.setObjectName("SessionJournalTable")
        self.journal_table.setSortingEnabled(False)
        factory.configure_table(self.journal_table, (100, 105, 145, 180, 400))

        layout.addLayout(heading_row)
        layout.addLayout(actions_row)
        layout.addWidget(self.journal_status)
        layout.addWidget(self.journal_table, 1)
