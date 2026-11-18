"""JitterWorkspace widgets."""

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui import constants as ui_constants
from netvision.ui.components import factory
from netvision.ui.widgets import JitterChart


class JitterWorkspace(QFrame):
    def __init__(
        self, boost_button: QPushButton, format_message: Callable[..., str], jitter_spike_ms: float
    ) -> None:
        super().__init__()
        workspace = self
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
        self.jitter_network_boost_button = boost_button
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
        impact_values = ui_constants.DASHBOARD_JITTER_IMPACT_VALUES
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
        self.jitter_graph_status = QLabel(
            "Отклонения между соседними RTT будут появляться во время мониторинга"
        )
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
        self.jitter_event_status = QLabel(
            format_message(
                "Критический порог: Δ RTT > {threshold:.0f} мс · событий: {count}",
                threshold=jitter_spike_ms,
                count=0,
            )
        )
        self.jitter_event_status.setObjectName("Muted")
        self.jitter_event_status.setWordWrap(True)
        self.jitter_clear_button = QPushButton("Очистить журнал")
        self.jitter_clear_button.setObjectName("JitterSecondaryButton")
        events_header.addWidget(events_title)
        events_header.addStretch(1)
        events_header.addWidget(self.jitter_clear_button)
        self.jitter_events_table = QTableWidget(0, 4)
        self.jitter_events_table.setObjectName("JitterEventsTable")
        self.jitter_events_table.setHorizontalHeaderLabels(
            ["Время", "Δ RTT", "Целевой узел", "Детали"]
        )
        factory.configure_table(self.jitter_events_table, (110, 105, 220, 420))
        self.jitter_events_table.setMinimumHeight(210)
        events_layout.addLayout(events_header)
        events_layout.addWidget(self.jitter_event_status)
        events_layout.addWidget(self.jitter_events_table, 1)
        layout.addWidget(events_panel, 1)
        layout.addStretch(1)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
