"""Workspace widgets."""

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from netvision.ui import constants as ui_constants
from netvision.ui.utils import keep_wheel_scroll_local
from netvision.ui.widgets import MetricTile


class QualityNatWorkspace(QWidget):
    def __init__(self, translate: Callable[[str], str]) -> None:
        super().__init__()
        tab = self
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(9)

        heading_row = QHBoxLayout()
        heading = QLabel("КАЧЕСТВО ИНТЕРНЕТА")
        heading.setObjectName("FieldLabel")
        self.quality_test_button = QPushButton("Проверить качество")
        self.quality_test_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        )
        self.quality_test_button.setToolTip(
            "Запустить Ookla Speedtest и запросить данные Интернетометра"
        )
        self.quality_export_image_button = QPushButton(translate("Экспортировать сводку PNG"))
        self.quality_export_image_button.setObjectName("QualityExportImageButton")
        self.quality_export_image_button.setToolTip(
            translate("Сохранить сводку качества как изображение PNG")
        )
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.quality_export_image_button)
        heading_row.addWidget(self.quality_test_button)

        self.quality_progress = QProgressBar()
        self.quality_progress.setObjectName("QualityProgress")
        self.quality_progress.setRange(0, 0)
        self.quality_progress.setTextVisible(False)
        self.quality_progress.setFixedHeight(6)
        self.quality_progress.setToolTip("Проверка выполняется в фоновом режиме")
        self.quality_progress.hide()
        self.quality_status = QLabel("Проверка ещё не запускалась")
        self.quality_status.setObjectName("Muted")
        self.quality_status.setWordWrap(True)

        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(7)
        self.quality_metrics = {
            "download": MetricTile("Скачивание"),
            "upload": MetricTile("Отдача"),
            "ping": MetricTile("Ping"),
            "loaded_ping": MetricTile("Ping под нагрузкой"),
        }
        for index, tile in enumerate(self.quality_metrics.values()):
            metrics_grid.addWidget(tile, index // 2, index % 2)

        details_title = QLabel("ВНЕШНЯЯ СЕТЬ И АДАПТЕР")
        details_title.setObjectName("FieldLabel")
        self.quality_details: dict[str, QLabel] = {}
        details_grid = QGridLayout()
        details_grid.setHorizontalSpacing(10)
        details_grid.setVerticalSpacing(5)
        detail_items = ui_constants.DASHBOARD_QUALITY_DETAIL_ITEMS
        for row, (key, title) in enumerate(detail_items):
            title_label = QLabel(title.upper())
            title_label.setObjectName("FieldLabel")
            value_label = QLabel("--")
            value_label.setWordWrap(True)
            if key == "adapter":
                value_label.setToolTip(
                    "Это согласованная скорость локального Wi-Fi/Ethernet-канала, а не скорость тарифа провайдера."
                )
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.quality_details[key] = value_label
            details_grid.addWidget(title_label, row, 0, Qt.AlignmentFlag.AlignTop)
            details_grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)
        details_grid.setColumnStretch(1, 1)

        report_title = QLabel("СВОДКА")
        report_title.setObjectName("FieldLabel")
        self.quality_report_output = QPlainTextEdit()
        self.quality_report_output.setReadOnly(True)
        keep_wheel_scroll_local(self.quality_report_output)
        self.quality_report_output.setMaximumHeight(112)
        self.quality_report_output.setPlaceholderText(
            "Здесь появится сопоставление результатов Speedtest, Яндекса и локального адаптера."
        )

        nat_heading = QLabel("NAT / STUN")
        nat_heading.setObjectName("FieldLabel")
        self.nat_probe_button = QPushButton("Проверить NAT")
        self.nat_probe_button.setToolTip("Определить тип UDP NAT через публичные STUN-серверы")
        self.nat_probe_status = QLabel("Проверка NAT ещё не запускалась")
        self.nat_probe_status.setObjectName("Muted")
        self.nat_probe_status.setWordWrap(True)
        nat_row = QHBoxLayout()
        nat_row.addWidget(nat_heading)
        nat_row.addStretch(1)
        nat_row.addWidget(self.nat_probe_button)

        layout.addLayout(heading_row)
        layout.addWidget(self.quality_progress)
        layout.addWidget(self.quality_status)
        layout.addLayout(metrics_grid)
        layout.addWidget(details_title)
        layout.addLayout(details_grid)
        layout.addWidget(report_title)
        layout.addWidget(self.quality_report_output)
        layout.addLayout(nat_row)
        layout.addWidget(self.nat_probe_status)
        layout.addStretch(1)
        scroll.setWidget(content)
        tab_layout.addWidget(scroll)
