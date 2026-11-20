"""Workspace widgets."""

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from netvision.ui import constants as ui_constants


class BufferbloatWorkspace(QWidget):
    def __init__(self, translate: Callable[[str], str], boost_button: QPushButton) -> None:
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
        heading = QLabel("BUFFERBLOAT")
        self.help_heading = heading
        heading.setObjectName("FieldLabel")
        self.bufferbloat_start_button = QPushButton("Начать тест")
        self.bufferbloat_start_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        )
        self.bufferbloat_export_image_button = QPushButton(translate("Экспортировать сводку PNG"))
        self.bufferbloat_export_image_button.setObjectName("BufferbloatExportImageButton")
        self.bufferbloat_export_image_button.setToolTip(
            translate("Сохранить сводку bufferbloat как изображение PNG")
        )
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.bufferbloat_export_image_button)
        heading_row.addWidget(self.bufferbloat_start_button)

        self.bufferbloat_progress = QProgressBar()
        self.bufferbloat_progress.setObjectName("BufferbloatProgress")
        self.bufferbloat_progress.setRange(0, 0)
        self.bufferbloat_progress.setTextVisible(False)
        self.bufferbloat_progress.setFixedHeight(6)
        self.bufferbloat_progress.hide()
        self.bufferbloat_status = QLabel("Тест ещё не запускался")
        self.bufferbloat_status.setObjectName("Muted")
        self.bufferbloat_status.setWordWrap(True)
        self.bufferbloat_phase_labels: list[QLabel] = []
        phase_status_row = QHBoxLayout()
        for source in ("Базовая задержка", "Скачивание под нагрузкой", "Отдача под нагрузкой"):
            phase_label = QLabel(source)
            phase_label.setObjectName("Muted")
            phase_status_row.addWidget(phase_label, 1)
            self.bufferbloat_phase_labels.append(phase_label)

        phases_grid = QGridLayout()
        phases_grid.setSpacing(7)
        self.bufferbloat_values: dict[str, QLabel] = {}
        self.bufferbloat_phase_details: dict[str, QLabel] = {}
        phase_items = ui_constants.DASHBOARD_BUFFERBLOAT_PHASE_ITEMS
        for column, (key, title, hint) in enumerate(phase_items):
            card = QFrame()
            card.setObjectName("BufferbloatPhaseCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 10, 12, 10)
            title_label = QLabel(title)
            title_label.setObjectName("FieldLabel")
            value_label = QLabel("--")
            value_label.setObjectName("BufferbloatValue")
            detail_label = QLabel(hint)
            detail_label.setObjectName("Muted")
            detail_label.setWordWrap(True)
            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card_layout.addWidget(detail_label)
            phases_grid.addWidget(card, 0, column)
            self.bufferbloat_values[key] = value_label
            self.bufferbloat_phase_details[key] = detail_label

        grade_panel = QFrame()
        grade_panel.setObjectName("BufferbloatGrade")
        grade_layout = QVBoxLayout(grade_panel)
        grade_layout.setContentsMargins(14, 12, 14, 12)
        grade_title = QLabel("ИТОГОВАЯ ОЦЕНКА БУФЕРА")
        grade_title.setObjectName("FieldLabel")
        self.bufferbloat_grade = QLabel("--")
        self.bufferbloat_grade.setObjectName("BufferbloatGradeValue")
        self.bufferbloat_verdict = QLabel("Недостаточно данных для оценки bufferbloat")
        self.bufferbloat_verdict.setWordWrap(True)
        self.bufferbloat_delta = QLabel("Δ download: -- · Δ upload: --")
        self.bufferbloat_delta.setObjectName("Muted")
        self.bufferbloat_network_boost_button = boost_button
        self.bufferbloat_network_boost_button.hide()
        grade_layout.addWidget(grade_title)
        grade_layout.addWidget(self.bufferbloat_grade)
        grade_layout.addWidget(self.bufferbloat_verdict)
        grade_layout.addWidget(self.bufferbloat_delta)
        grade_layout.addWidget(self.bufferbloat_network_boost_button, 0, Qt.AlignmentFlag.AlignLeft)

        recommendations_panel = QFrame()
        recommendations_panel.setObjectName("BufferbloatRecommendations")
        recommendations_layout = QVBoxLayout(recommendations_panel)
        recommendations_layout.setContentsMargins(14, 12, 14, 12)
        recommendations_title = QLabel("Рекомендации")
        recommendations_title.setObjectName("FieldLabel")
        self.bufferbloat_recommendations = QLabel(
            "После теста здесь появятся рекомендации по настройке сети."
        )
        self.bufferbloat_recommendations.setObjectName("BufferbloatRecommendationsText")
        self.bufferbloat_recommendations.setWordWrap(True)
        recommendations_layout.addWidget(recommendations_title)
        recommendations_layout.addWidget(self.bufferbloat_recommendations)

        layout.addLayout(heading_row)
        layout.addWidget(self.bufferbloat_progress)
        layout.addWidget(self.bufferbloat_status)
        layout.addLayout(phase_status_row)
        layout.addLayout(phases_grid)
        layout.addWidget(grade_panel)
        layout.addWidget(recommendations_panel)
        layout.addStretch(1)
        scroll.setWidget(content)
        tab_layout.addWidget(scroll)
