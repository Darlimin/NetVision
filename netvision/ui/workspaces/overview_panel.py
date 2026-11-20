"""Summary and diagnostic workspace widgets."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui.components import factory
from netvision.ui.utils import keep_wheel_scroll_local
from netvision.ui.widgets import LatencyChart, apply_panel_shadow


class LiteView(QFrame):
    def __init__(self) -> None:
        super().__init__()
        panel = self
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

        summary_header = QLabel("КОРОТКАЯ СВОДКА")
        summary_header.setObjectName("FieldLabel")
        layout.addWidget(self.lite_hero)
        layout.addWidget(summary_header)
        layout.addLayout(self.lite_details)
        layout.addStretch(1)


class AnalysisView(QWidget):
    def __init__(self) -> None:
        super().__init__()
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
        keep_wheel_scroll_local(self.analysis_output)
        self.analysis_output.setPlaceholderText(
            "После проверки здесь появится понятное объяснение результата."
        )

        layout.addWidget(caption)
        layout.addWidget(self.analysis_title)
        layout.addWidget(self.analysis_output, 1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(factory.make_scroll_area(tab))


class InterfacesView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        tab = self
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        self.interfaces_table = QTableWidget(0, 4)
        self.interfaces_table.setObjectName("InterfacesTable")
        self.interfaces_table.setHorizontalHeaderLabels(["Имя", "Тип", "IPv4", "Состояние"])
        factory.configure_table(self.interfaces_table, (280, 110, 200, 150))
        self.interfaces_table.verticalHeader().setDefaultSectionSize(36)
        self.wifi_status_label = QLabel("Wi-Fi: ожидание активного маршрута")
        self.wifi_status_label.setObjectName("Muted")
        self.wifi_status_label.setWordWrap(True)
        self.wifi_status_label.setToolTip(
            "В Windows 11 для данных Wi-Fi может потребоваться разрешение «Расположение»."
        )
        self.interfaces_actions_host = QFrame()
        self.interfaces_actions_host.setObjectName("InterfaceActionsHost")
        self.interfaces_actions_host.setLayout(QVBoxLayout())
        self.interfaces_actions_host.layout().setContentsMargins(0, 0, 0, 0)
        self.interfaces_actions_host.layout().setSpacing(0)
        layout.addWidget(self.interfaces_table, 1)
        layout.addWidget(self.wifi_status_label)
        layout.addWidget(self.interfaces_actions_host)


class NodeDetailsView(QWidget):
    def __init__(self) -> None:
        super().__init__()
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
        scroll = factory.make_scroll_area(tab)
        scroll.setObjectName("DetailsScrollArea")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.details_scroll = scroll
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
