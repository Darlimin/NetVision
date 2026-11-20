"""MtuWorkspace widgets."""

from collections.abc import Callable

from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
)

from netvision.ui.components import factory


class MtuWorkspace(QFrame):
    def __init__(self, translate: Callable[[str], str], target_host: str) -> None:
        super().__init__()
        """Build the shared MTU controls for the legacy and dashboard surfaces."""
        mtu_panel = self
        mtu_panel.setObjectName("PingMtuPanel")
        self.mtu_optimizer_panel = mtu_panel
        mtu_layout = QVBoxLayout(mtu_panel)
        mtu_layout.setContentsMargins(12, 10, 12, 12)
        mtu_layout.setSpacing(7)
        self.mtu_section_title = QLabel("MTU OPTIMIZER RESULTS")
        self.mtu_section_title.setObjectName("FieldLabel")
        mtu_note = QLabel("Последние результаты DF-проверок оптимального MTU")
        mtu_note.setObjectName("Muted")
        mtu_controls = QHBoxLayout()
        mtu_target_label = QLabel("ЦЕЛЬ MTU")
        mtu_target_label.setObjectName("FieldLabel")
        self.ping_mtu_host_input = QLineEdit()
        self.ping_mtu_host_input.setPlaceholderText("Адрес для MTU-проверки")
        self.ping_mtu_host_input.setClearButtonEnabled(True)
        self.ping_mtu_host_input.setText(target_host)

        self.ping_mtu_run_button = QPushButton("Найти оптимальный MTU")
        self.ping_mtu_run_button.setObjectName("PingSecondaryButton")
        self.ping_mtu_status = QLabel("Готов к проверке")
        self.ping_mtu_status.setObjectName("Muted")
        self.mtu_optimizer_progress = QProgressBar()
        self.mtu_optimizer_progress.setRange(0, 0)
        self.mtu_optimizer_progress.setTextVisible(False)
        self.mtu_optimizer_progress.setFixedHeight(5)
        self.mtu_optimizer_progress.hide()
        mtu_controls.addWidget(mtu_target_label)
        mtu_controls.addWidget(self.ping_mtu_host_input, 1)
        mtu_controls.addWidget(self.ping_mtu_run_button)
        self.ping_mtu_table = QTableWidget(0, 5)
        self.ping_mtu_table.setObjectName("MtuOptimizerTable")
        self.ping_mtu_table.setHorizontalHeaderLabels(["MTU", "Payload", "RTT", "Статус", "Детали"])
        factory.configure_table(self.ping_mtu_table, (70, 85, 75, 240, 300))
        self.ping_mtu_table.setMinimumHeight(190)
        self.mtu_optimizer_target_input = self.ping_mtu_host_input
        self.mtu_optimizer_start_button = self.ping_mtu_run_button
        self.mtu_optimizer_status = self.ping_mtu_status
        self.mtu_optimizer_table = self.ping_mtu_table
        self.mtu_current_value = QLabel("--")
        self.mtu_optimal_value = QLabel("--")
        self.mtu_fragmentation_value = QLabel(translate("Ожидание проверки"))
        mtu_metrics = QGridLayout()
        mtu_metrics.setSpacing(6)
        for index, (title, value) in enumerate(
            (
                (translate("Текущий системный MTU"), self.mtu_current_value),
                (translate("Оптимальный MTU"), self.mtu_optimal_value),
                (translate("Проверка фрагментации"), self.mtu_fragmentation_value),
            )
        ):
            card = QFrame()
            card.setObjectName("MetricTile")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(8, 7, 8, 7)
            card_layout.setSpacing(3)
            title_label = QLabel(title)
            title_label.setObjectName("Muted")
            value.setObjectName("MtuOptimizerValue")
            card_layout.addWidget(title_label)
            card_layout.addWidget(value)
            mtu_metrics.addWidget(card, 0, index)
        self.mtu_optimizer_apply_button = QPushButton(translate("Применить найденный MTU"))
        self.mtu_optimizer_apply_button.setEnabled(False)
        mtu_layout.addWidget(self.mtu_section_title)
        mtu_layout.addWidget(mtu_note)
        mtu_layout.addLayout(mtu_controls)
        mtu_layout.addWidget(self.mtu_optimizer_progress)
        mtu_layout.addWidget(self.ping_mtu_status)
        mtu_layout.addLayout(mtu_metrics)
        mtu_layout.addWidget(self.ping_mtu_table, 1)
        mtu_layout.addWidget(self.mtu_optimizer_apply_button)
