"""Ping workspace widgets."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)
from netvision.ui import constants as ui_constants
from netvision.ui.components import factory
from netvision.ui.utils import keep_wheel_scroll_local
from netvision.ui.workspaces.mtu_optimizer import MtuWorkspace


class PingWorkspace(QFrame):
    def __init__(self, controller) -> None:
        super().__init__()
        workspace = self
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
        self.ping_back_button.clicked.connect(controller._close_ping_workspace)
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
        self.ping_run_button.setToolTip(
            "Параллельно проверить региональные ориентиры и MTU целевого узла"
        )
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
        stat_titles = ui_constants.DASHBOARD_PING_STAT_TITLES
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
        self.ping_matrix_table.setHorizontalHeaderLabels(
            ["Регион", "Узел", "RTT", "Потери", "Статус"]
        )
        factory.configure_table(self.ping_matrix_table, (175, 215, 80, 92, 105))
        self.ping_matrix_table.setMinimumHeight(178)
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
        self.ping_spike_status = QLabel(
            controller._translator.format(
                "Пики выше {threshold:.0f} мс и потери появятся здесь во время мониторинга",
                threshold=controller._thresholds.rtt_high_ms,
            )
        )
        self.ping_spike_status.setObjectName("Muted")
        self.ping_spike_status.setWordWrap(True)
        self.ping_spike_log = QPlainTextEdit()
        self.ping_spike_log.setObjectName("PingSpikeLog")
        self.ping_spike_log.setReadOnly(True)
        keep_wheel_scroll_local(self.ping_spike_log)
        self.ping_spike_log.setMaximumBlockCount(80)
        self.ping_spike_log.setPlaceholderText("Событий задержки пока нет")
        self.ping_spike_log.setMinimumHeight(150)
        spike_layout.addWidget(spike_title)
        spike_layout.addWidget(self.ping_spike_status)
        spike_layout.addWidget(self.ping_spike_log, 1)

        controller.mtu_workspace = MtuWorkspace(
            controller._tr, controller.core_workspace.target_input.text().strip()
        )
        controller._ping_mtu_host_manually_edited = False
        mtu_panel = controller.mtu_workspace

        self.ping_tools_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.ping_tools_splitter.setObjectName("WorkspaceSplitter")
        self.ping_tools_splitter.setChildrenCollapsible(False)
        self.ping_tools_splitter.addWidget(spike_panel)
        controller._mount_mtu_section(self.ping_tools_splitter, mtu_panel)
        self.ping_tools_splitter.setStretchFactor(0, 1)
        self.ping_tools_splitter.setStretchFactor(1, 1)
        self.ping_tools_splitter.setSizes([560, 560])
        layout.addWidget(self.ping_tools_splitter)
        layout.addWidget(controller.core_workspace._build_quick_fix_panel("ping"))
        layout.addStretch(1)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
