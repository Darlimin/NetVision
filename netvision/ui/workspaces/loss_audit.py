"""LossWorkspace widgets."""

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui import constants as ui_constants
from netvision.ui.components import factory
from netvision.ui.utils import keep_wheel_scroll_local


class LossWorkspace(QFrame):
    def __init__(
        self, translate: Callable[[str], str], boost_button: QPushButton, quick_fix_panel: QWidget
    ) -> None:
        super().__init__()
        workspace = self
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
        title_box = QVBoxLayout()
        title = QLabel("PACKET LOSS & STABILITY ANALYTICS")
        title.setObjectName("LossWorkspaceTitle")
        subtitle = QLabel(
            "Burst-потери, micro-drop, путь трассировки и контролируемые ICMP/UDP-проверки"
        )
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.loss_run_button = QPushButton("▶  Запустить анализ потерь")
        self.loss_run_button.setObjectName("LossRunButton")
        self.loss_game_auto_button = QPushButton(translate("⌕  Автопроверка игры"))
        self.loss_game_auto_button.setObjectName("LossAutoCheckButton")
        self.loss_game_auto_button.setToolTip(
            translate("Найти игровой процесс и проверить потери, jitter и активные сокеты")
        )
        self.loss_network_boost_button = boost_button
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
        stat_titles = ui_constants.DASHBOARD_LOSS_STAT_TITLES
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
        keep_wheel_scroll_local(self.loss_events_log)
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
        stress_note = QLabel(
            translate(
                "ICMP измеряет ответы. UDP-строка показывает локальную отправку; отдельный UDP-тест ниже измеряет ответы DNS."
            )
        )
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

        udp_target_row = QHBoxLayout()
        udp_target_label = QLabel(translate("Цель UDP"))
        udp_target_label.setObjectName("FieldLabel")
        self.udp_stress_target_input = QLineEdit("1.1.1.1")
        self.udp_stress_target_input.setPlaceholderText(translate("DNS-сервер или IP-адрес"))
        self.udp_stress_target_input.setClearButtonEnabled(True)
        udp_port_label = QLabel(translate("Порт UDP"))
        udp_port_label.setObjectName("FieldLabel")
        self.udp_stress_port_input = QSpinBox()
        self.udp_stress_port_input.setRange(1, 65535)
        self.udp_stress_port_input.setValue(53)
        self.udp_stress_button = QPushButton(translate("▶  Запустить UDP-тест"))
        self.udp_stress_button.setObjectName("UdpStressButton")
        self.udp_stress_button.setToolTip(
            translate(
                "UDP тест измеряет ответы DNS по UDP/53; это не замена тесту игрового сервера."
            )
        )
        udp_target_row.addWidget(udp_target_label)
        udp_target_row.addWidget(self.udp_stress_target_input, 1)
        udp_target_row.addWidget(udp_port_label)
        udp_target_row.addWidget(self.udp_stress_port_input)
        udp_target_row.addWidget(self.udp_stress_button)

        udp_metrics_row = QHBoxLayout()
        self.udp_stress_sent_value = QLabel("--")
        self.udp_stress_received_value = QLabel("--")
        self.udp_stress_loss_value = QLabel("--")
        self.udp_stress_status = QLabel(translate("UDP-тест ещё не запускался"))
        self.udp_stress_status.setObjectName("Muted")
        for caption, value in (
            ("Отправлено", self.udp_stress_sent_value),
            ("Получено", self.udp_stress_received_value),
            ("Потери", self.udp_stress_loss_value),
        ):
            metric = QVBoxLayout()
            metric.setSpacing(1)
            label = QLabel(translate(caption))
            label.setObjectName("FieldLabel")
            value.setObjectName("LossStatValue")
            metric.addWidget(label)
            metric.addWidget(value)
            udp_metrics_row.addLayout(metric)
        udp_metrics_row.addStretch(1)
        udp_metrics_row.addWidget(self.udp_stress_status, 1)
        self.udp_stress_progress = QProgressBar()
        self.udp_stress_progress.setObjectName("UdpStressProgress")
        self.udp_stress_progress.setRange(0, 0)
        self.udp_stress_progress.setTextVisible(False)
        self.udp_stress_progress.setFixedHeight(6)
        self.udp_stress_progress.setVisible(False)
        self.loss_stress_table = QTableWidget(0, 5)
        self.loss_stress_table.setObjectName("LossStressTable")
        self.loss_stress_table.setHorizontalHeaderLabels(
            ["Протокол", "Пакеты", "Ответы", "Потери", "Результат"]
        )
        factory.configure_table(self.loss_stress_table, (100, 90, 90, 105, 280))
        self.loss_stress_table.setMinimumHeight(50)
        self.loss_stress_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        stress_layout.addWidget(stress_title)
        stress_layout.addWidget(stress_note)
        stress_layout.addLayout(target_row)
        stress_layout.addLayout(udp_target_row)
        stress_layout.addLayout(udp_metrics_row)
        stress_layout.addWidget(self.udp_stress_progress)
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
        self.loss_hops_status = QLabel(
            "Сначала запустите основную диагностику, чтобы получить трассировку."
        )
        self.loss_hops_status.setObjectName("Muted")
        self.loss_hops_status.setWordWrap(True)
        self.loss_hops_table = QTableWidget(0, 6)
        self.loss_hops_table.setObjectName("LossHopsTable")
        self.loss_hops_table.setHorizontalHeaderLabels(
            ["Hop", "Узел", "ICMP", "Потери", "RTT", "Статус"]
        )
        factory.configure_table(self.loss_hops_table, (70, 230, 90, 95, 90, 155))
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
        layout.addWidget(quick_fix_panel)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
