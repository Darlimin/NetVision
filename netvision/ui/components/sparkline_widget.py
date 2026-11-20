from __future__ import annotations

import math
from typing import Iterable
from PySide6.QtCore import QPointF
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget


class SparklineWidget(QWidget):
    """Small, data-only graph that stays safe for empty and single samples."""

    def __init__(self, color_hex: str = "#22D3EE", minimum_height: int = 30) -> None:
        super().__init__()
        self._data: tuple[float, ...] = ()
        self._color = QColor(color_hex)
        self.show_axis = False
        self.translate = lambda text: text
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
            if self.show_axis:
                painter.setPen(QPen(QColor("#64748b"), 1))
                painter.drawText(6, 14, f"{self.translate('макс')} {self._data[0]:.1f} ms")
                painter.drawText(
                    6, rect.bottom(), f"{self.translate('мин')} {self._data[0]:.1f} ms"
                )
                painter.setPen(QPen(self._color, 2))
            painter.drawLine(rect.left(), rect.center().y(), rect.right(), rect.center().y())
            return

        minimum = min(self._data)
        span = max(self._data) - minimum
        if self.show_axis:
            span = max(span, 30.0)
            painter.setPen(QPen(QColor("#64748b"), 1))
            painter.drawText(6, 14, f"{self.translate('макс')} {max(self._data):.1f} ms")
            painter.drawText(6, rect.bottom(), f"{self.translate('мин')} {minimum:.1f} ms")
            painter.setPen(QPen(self._color, 2))
        if span <= 0:
            span = 1.0
        if self.show_axis:
            rect.adjust(0, 14, 0, -16)
            grid_color = self.palette().color(self.foregroundRole())
            grid_color.setAlpha(35)
            painter.setPen(QPen(grid_color, 1))
            for index in range(5):
                y = rect.top() + rect.height() * index / 4
                painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
                x = rect.left() + rect.width() * index / 4
                painter.drawLine(QPointF(x, rect.top()), QPointF(x, rect.bottom()))
        step = rect.width() / (len(self._data) - 1)
        points = [
            QPointF(
                rect.left() + index * step,
                rect.bottom() - ((value - minimum) / span) * rect.height(),
            )
            for index, value in enumerate(self._data)
        ]
        path = self._build_smooth_path(points)
        if self.show_axis:
            fill = QPainterPath(path)
            fill.lineTo(points[-1].x(), rect.bottom())
            fill.lineTo(points[0].x(), rect.bottom())
            fill.closeSubpath()
            gradient = QLinearGradient(0, rect.top(), 0, rect.bottom())
            top = QColor(self._color)
            top.setAlpha(70)
            bottom = QColor(self._color)
            bottom.setAlpha(5)
            gradient.setColorAt(0, top)
            gradient.setColorAt(1, bottom)
            painter.fillPath(fill, gradient)
        painter.setPen(QPen(self._color, 2))
        painter.drawPath(path)
