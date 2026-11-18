from __future__ import annotations

import math
from typing import Iterable
from PySide6.QtCore import QPointF
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget


class SparklineWidget(QWidget):
    """Small, data-only graph that stays safe for empty and single samples."""

    def __init__(self, color_hex: str = "#22D3EE", minimum_height: int = 30) -> None:
        super().__init__()
        self._data: tuple[float, ...] = ()
        self._color = QColor(color_hex)
        self.setMinimumHeight(minimum_height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    @property
    def data(self) -> tuple[float, ...]:
        return self._data

    def set_samples(self, values: Iterable[float]) -> None:
        self._data = tuple(
            value
            for item in values
            if isinstance(item, (int, float)) and math.isfinite(value := float(item))
        )
        self.update()

    @staticmethod
    def _build_smooth_path(points: list[QPointF]) -> QPainterPath:
        """Build a smooth, non-overshooting curve through every sample point."""
        path = QPainterPath(points[0])
        for previous, current in zip(points, points[1:]):
            midpoint_x = (previous.x() + current.x()) / 2
            path.cubicTo(
                midpoint_x,
                previous.y(),
                midpoint_x,
                current.y(),
                current.x(),
                current.y(),
            )
        return path

    def paintEvent(self, _event: object) -> None:
        if not self._data:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(4, 4, -4, -4)
        if rect.width() < 2 or rect.height() < 2:
            return

        painter.setPen(QPen(self._color, 2))
        if len(self._data) == 1:
            painter.drawLine(rect.left(), rect.center().y(), rect.right(), rect.center().y())
            return

        minimum = min(self._data)
        span = max(self._data) - minimum
        if span <= 0:
            span = 1.0
        step = rect.width() / (len(self._data) - 1)
        points = [
            QPointF(
                rect.left() + index * step,
                rect.bottom() - ((value - minimum) / span) * rect.height(),
            )
            for index, value in enumerate(self._data)
        ]
        painter.drawPath(self._build_smooth_path(points))
