"""Reusable construction helpers for common dashboard widgets."""

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QWidget,
)

from netvision.ui.utils import keep_wheel_scroll_local


class _TableFontObserver(QObject):
    def __init__(self, parent):
        super().__init__(parent)
        self._updating = False

    def eventFilter(self, watched, event):
        if not self._updating and event.type() in (
            QEvent.Type.FontChange,
            QEvent.Type.ApplicationFontChange,
        ):
            height = max(28, watched.fontMetrics().height() + 12)
            header = watched.verticalHeader()
            if header.defaultSectionSize() != height:
                self._updating = True
                try:
                    header.setDefaultSectionSize(height)
                finally:
                    self._updating = False
        return super().eventFilter(watched, event)


def configure_table(table: QTableWidget, initial_widths: tuple[int, ...]) -> None:
    """Apply the shared resizable-table contract without resetting user widths."""
    if table.columnCount() != len(initial_widths):
        raise ValueError("Количество стартовых ширин не соответствует числу колонок")

    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setAlternatingRowColors(True)
    table.setShowGrid(True)
    table.setWordWrap(False)
    table.setTextElideMode(Qt.TextElideMode.ElideRight)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    keep_wheel_scroll_local(table)

    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    header.setSectionsClickable(True)
    header.setHighlightSections(False)
    header.setCascadingSectionResizes(True)
    header.setMinimumSectionSize(64)
    for column, width in enumerate(initial_widths):
        table.setColumnWidth(column, width)

    vertical_header = table.verticalHeader()
    vertical_header.setVisible(False)
    vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
    vertical_header.setDefaultSectionSize(max(28, table.fontMetrics().height() + 12))
    observer = _TableFontObserver(table)
    table.installEventFilter(observer)


def make_scroll_area(content: QWidget) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setWidget(content)
    return scroll


def new_card() -> QFrame:
    card = QFrame()
    card.setObjectName("Card")
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    return card


def field_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("DashboardFieldLabel")
    return label


def card_title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("CardTitle")
    return label
