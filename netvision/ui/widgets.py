from __future__ import annotations

import math
from collections.abc import Callable
from collections import deque
from dataclasses import dataclass, field

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QLinearGradient,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QFrame,
    QComboBox,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from netvision.models import DiagnosticReport, ProbeStatus


@dataclass(frozen=True, slots=True)
class TopologyNode:
    label: str
    primary: str
    secondary: str
    kind: str
    status: ProbeStatus = ProbeStatus.PENDING
    latency_ms: float | None = None
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LatencySample:
    latency_ms: float | None
    success: bool


class EmbeddedComboBox(QComboBox):
    """A combo control whose choices are rendered by an in-layout list."""

    popup_requested = Signal(object)

    def showPopup(self) -> None:
        self.popup_requested.emit(self)

    def hidePopup(self) -> None:
        # Native QComboBox popups are deliberately never opened for this control.
        return


class ThemedCanvas(QWidget):
    """Use the widget's QSS palette also for manually painted surfaces."""

    _LIGHT_COLORS = {
        "#161b22": "#FFFFFF", "#18202e": "#F4F7F8", "#222c3d": "#EAF8F3",
        "#1e2638": "#D9E2E5", "#263247": "#E4ECEE",
        "#e1e7ef": "#17212B", "#e2e8f0": "#17212B",
        "#a0aec0": "#50616D", "#78869a": "#667784",
        "#8a99ad": "#667784", "#5b6b82": "#50616D",
        "#00e5a3": "#008E65", "#00e6a8": "#008E65",
        "#ffb800": "#9A6500", "#ff4757": "#C53B49",
    }

    def _color(self, dark_color: str) -> QColor:
        light = self.palette().color(QPalette.ColorRole.Window).lightness() > 128
        return QColor(self._LIGHT_COLORS.get(dark_color.lower(), dark_color) if light else dark_color)

    def _paint_header(self, painter: QPainter, title: str, legend: tuple[tuple[str, str], ...]) -> None:
        font = painter.font()
        font.setPixelSize(10)
        font.setBold(False)
        painter.setFont(font)
        widths = [painter.fontMetrics().horizontalAdvance(label) for label, _ in legend]
        legend_width = sum(widths) + 12 * len(widths) if self.width() >= 440 else 0
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(self._color("#5B6B82"))
        title_rect = QRectF(12, 2, max(0, self.width() - legend_width - 24), 23)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignVCenter,
                         painter.fontMetrics().elidedText(title, Qt.TextElideMode.ElideRight, int(title_rect.width())))
        if legend_width:
            font.setBold(False)
            painter.setFont(font)
            x = self.width() - legend_width
            for (label, color), width in zip(legend, widths):
                painter.setPen(self._color(color))
                painter.drawText(x, 17, label)
                x += width + 12


class LatencyChart(ThemedCanvas):
    """Compact, dependency-free chart for the latest latency samples."""

    _MAX_SAMPLES = 60

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("LatencyChart")
        self.setMinimumHeight(180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMouseTracking(True)
        self._translate: Callable[[str], str] = lambda text: text
        self._samples: deque[LatencySample] = deque(maxlen=self._MAX_SAMPLES)
        self._hovered_sample_index = -1
        self._sample_x: dict[int, float] = {}
        self._sample_points: dict[int, QPointF] = {}
        self._plot_rect = QRectF()
        self._hover_tooltip = QLabel(self)
        self._hover_tooltip.setObjectName("LatencyTooltip")
        self._hover_tooltip.setTextFormat(Qt.TextFormat.RichText)
        self._hover_tooltip.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._hover_tooltip.hide()
        self._pulse_phase = 0.0
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(60)
        self._pulse_timer.timeout.connect(self._animate_hover_marker)
        self._pulse_timer.start()

    @property
    def samples(self) -> tuple[LatencySample, ...]:
        return tuple(self._samples)

    def reset(self) -> None:
        self._samples.clear()
        self.update()

    def add_sample(self, latency_ms: float | None, success: bool) -> None:
        self._samples.append(LatencySample(latency_ms, success))
        self.update()

    def set_translator(self, translate: Callable[[str], str]) -> None:
        """Set the runtime translator used by painter-rendered labels."""
        self._translate = translate
        self.update()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), self._color("#161B22"))

        plot = QRectF(58, 28, max(40.0, self.width() - 74), max(50.0, self.height() - 60))
        self._plot_rect = plot
        painter.setPen(QPen(self._color("#1E2638"), 1))
        painter.setBrush(self._color("#18202E"))
        painter.drawRoundedRect(plot, 5, 5)
        self._draw_header(painter)
        values = [sample.latency_ms for sample in self._samples if sample.success and sample.latency_ms is not None]
        minimum, maximum = self._axis_range(values)
        self._draw_grid(painter, plot, minimum, maximum)
        self._sample_x.clear()
        self._sample_points.clear()

        if not self._samples:
            painter.setPen(self._color("#8A99AD"))
            painter.drawText(
                plot,
                Qt.AlignmentFlag.AlignCenter,
                self._translate("Ожидание измерений задержки..."),
            )
            return

        step_x = plot.width() / max(1, self._MAX_SAMPLES - 1)
        points: list[QPointF | None] = []
        for index, sample in enumerate(self._samples):
            x = plot.left() + (self._MAX_SAMPLES - len(self._samples) + index) * step_x
            self._sample_x[index] = x
            if sample.latency_ms is None or not sample.success:
                points.append(None)
                continue
            ratio = (sample.latency_ms - minimum) / max(0.001, maximum - minimum)
            y = plot.bottom() - max(0.0, min(1.0, ratio)) * plot.height()
            point = QPointF(x, y)
            points.append(point)
            self._sample_points[index] = point

        previous_point: QPointF | None = None
        for index, point in enumerate(points):
            if point is None:
                previous_point = None
                continue
            sample = self._samples[index]
            if previous_point is not None:
                self._draw_curve_segment(painter, previous_point, point, _latency_color(sample), plot)
            previous_point = point

        self._draw_hover_marker(painter, plot)

    def _animate_hover_marker(self) -> None:
        if self._hovered_sample_index >= 0:
            self._pulse_phase += 0.22
            self.update()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if not self._sample_x or not self._plot_rect.contains(event.position()):
            self._set_hovered_sample(-1)
            return

        x = event.position().x()
        index = min(self._sample_x, key=lambda item: abs(self._sample_x[item] - x))
        distance = abs(self._sample_x[index] - x)
        step = self._plot_rect.width() / max(1, self._MAX_SAMPLES - 1)
        if distance > max(12.0, step * 0.7):
            index = -1
        self._set_hovered_sample(index)
        if index >= 0:
            sample = self._samples[index]
            message = (
                f"<span style='color:#8A99AD'>{self._translate('Задержка')}</span> "
                f"<span style='color:#00E6A8'><b>{sample.latency_ms:.1f} ms</b></span>"
                if sample.success and sample.latency_ms is not None
                else f"<span style='color:#FF6B78'><b>{self._translate('Потеря пакета')}</b></span>"
            )
            point = self._sample_points.get(index, QPointF(self._sample_x[index], self._plot_rect.bottom()))
            self._show_hover_tooltip(message, point)

    def leaveEvent(self, _event: object) -> None:
        self._set_hovered_sample(-1)
        self._hover_tooltip.hide()

    def _set_hovered_sample(self, index: int) -> None:
        if index == self._hovered_sample_index:
            return
        self._hovered_sample_index = index
        if index < 0:
            self._hover_tooltip.hide()
        self.update()

    def _show_hover_tooltip(self, message: str, point: QPointF) -> None:
        self._hover_tooltip.setText(message)
        self._hover_tooltip.adjustSize()
        x = min(max(8, int(point.x() + 10)), self.width() - self._hover_tooltip.width() - 8)
        y = max(30, int(point.y() - self._hover_tooltip.height() - 10))
        self._hover_tooltip.move(x, y)
        self._hover_tooltip.raise_()
        self._hover_tooltip.show()

    @staticmethod
    def _axis_range(values: list[float | None]) -> tuple[float, float]:
        numbers = [value for value in values if value is not None]
        if not numbers:
            return 0.0, 100.0
        minimum = min(numbers)
        maximum = max(numbers)
        span = max(maximum - minimum, abs(maximum) * 0.1, 1.0)
        padding = span * 0.18
        return max(0.0, minimum - padding), maximum + padding

    def _draw_hover_marker(self, painter: QPainter, plot: QRectF) -> None:
        index = self._hovered_sample_index
        if index < 0 or index >= len(self._samples):
            return
        sample = self._samples[index]
        x = self._sample_x.get(index)
        if x is None:
            return
        point = self._sample_points.get(index)
        if point is None:
            self._draw_loss_marker(painter, x, plot.bottom())
            return
        color = self._color(_latency_color(sample).name())
        painter.setPen(QPen(self._color("#78869A"), 1, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
        painter.setPen(Qt.PenStyle.NoPen)
        pulse = 4.0 + 0.8 * (1.0 + math.sin(self._pulse_phase)) / 2.0
        painter.setBrush(_marker_gradient(color, point, 8.0 + pulse))
        painter.drawEllipse(point, pulse, pulse)
        painter.setPen(QPen(self._color("#E2E8F0"), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(point, pulse, pulse)

    def _draw_curve_segment(
        self,
        painter: QPainter,
        previous: QPointF,
        current: QPointF,
        color: QColor,
        plot: QRectF,
    ) -> None:
        midpoint = (previous.x() + current.x()) / 2
        curve = QPainterPath(previous)
        curve.cubicTo(
            QPointF(midpoint, previous.y()),
            QPointF(midpoint, current.y()),
            current,
        )
        area = QPainterPath(previous)
        area.cubicTo(
            QPointF(midpoint, previous.y()),
            QPointF(midpoint, current.y()),
            current,
        )
        area.lineTo(QPointF(current.x(), plot.bottom()))
        area.lineTo(QPointF(previous.x(), plot.bottom()))
        area.closeSubpath()
        gradient = QLinearGradient(QPointF(0, plot.top()), QPointF(0, plot.bottom()))
        color = self._color(color.name())
        fill = QColor(color)
        fill.setAlpha(38)
        transparent = QColor(color)
        transparent.setAlpha(0)
        gradient.setColorAt(0.0, fill)
        gradient.setColorAt(1.0, transparent)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawPath(area)

        glow = QColor(color)
        glow.setAlpha(112)
        painter.setPen(QPen(glow, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawPath(curve)
        painter.setPen(QPen(color, 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawPath(curve)

    def _draw_header(self, painter: QPainter) -> None:
        self._paint_header(painter, self._translate("ЗАДЕРЖКА / СТАБИЛЬНОСТЬ · ПОСЛЕДНИЕ 60 СЕКУНД"), (
            (self._translate("● живая"), "#00E5A3"), ("● ping", "#FFB800"),
            (self._translate("● сбой"), "#FF4757"),
        ))

    def _draw_grid(self, painter: QPainter, plot: QRectF, minimum: float, maximum: float) -> None:
        painter.setPen(QPen(self._color("#263247"), 1, Qt.PenStyle.DashLine))
        for fraction in (0.0, 1 / 3, 2 / 3, 1.0):
            y = plot.top() + plot.height() * fraction
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        painter.setPen(self._color("#8A99AD"))
        font = painter.font()
        font.setPixelSize(11)
        painter.setFont(font)
        for fraction in (0.0, 1 / 3, 2 / 3, 1.0):
            value = maximum - (maximum - minimum) * fraction
            y = plot.top() + plot.height() * fraction
            label = f"{value:.0f} ms"
            painter.drawText(QRectF(2, y - 8, plot.left() - 8, 16), Qt.AlignmentFlag.AlignRight, label)
        painter.drawText(
            QRectF(plot.left(), plot.bottom() + 7, 76, 18),
            Qt.AlignmentFlag.AlignLeft,
            self._translate("60с назад"),
        )
        painter.drawText(QRectF(plot.center().x() - 25, plot.bottom() + 7, 50, 18), Qt.AlignmentFlag.AlignCenter, "30с")
        painter.drawText(
            QRectF(plot.right() - 58, plot.bottom() + 7, 58, 18),
            Qt.AlignmentFlag.AlignRight,
            self._translate("сейчас"),
        )

    def _draw_loss_marker(self, painter: QPainter, x: float, bottom: float) -> None:
        painter.setPen(QPen(self._color("#FF4757"), 2))
        painter.drawLine(QPointF(x - 4, bottom - 7), QPointF(x + 4, bottom + 1))
        painter.drawLine(QPointF(x + 4, bottom - 7), QPointF(x - 4, bottom + 1))


class JitterChart(ThemedCanvas):
    """Live chart of absolute RTT deltas between consecutive responses."""

    _MAX_SAMPLES = 60

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("JitterChart")
        self.setMinimumHeight(210)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._translate: Callable[[str], str] = lambda text: text
        self._samples: deque[float | None] = deque(maxlen=self._MAX_SAMPLES)

    @property
    def samples(self) -> tuple[float | None, ...]:
        return tuple(self._samples)

    def reset(self) -> None:
        self._samples.clear()
        self.update()

    def add_sample(self, deviation_ms: float | None) -> None:
        self._samples.append(deviation_ms)
        self.update()

    def set_translator(self, translate: Callable[[str], str]) -> None:
        self._translate = translate
        self.update()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), self._color("#161B22"))
        plot = QRectF(58, 28, max(40.0, self.width() - 74), max(60.0, self.height() - 60))
        painter.setPen(QPen(self._color("#1E2638"), 1))
        painter.setBrush(self._color("#18202E"))
        painter.drawRoundedRect(plot, 5, 5)
        self._draw_header(painter)
        upper = self._axis_upper()
        self._draw_grid(painter, plot, upper)

        if not self._samples:
            painter.setPen(self._color("#8A99AD"))
            painter.drawText(
                plot,
                Qt.AlignmentFlag.AlignCenter,
                self._translate("Ожидание пары RTT-измерений..."),
            )
            return

        step_x = plot.width() / max(1, self._MAX_SAMPLES - 1)
        previous: QPointF | None = None
        for index, value in enumerate(self._samples):
            x = plot.left() + (self._MAX_SAMPLES - len(self._samples) + index) * step_x
            if value is None:
                previous = None
                continue
            y = plot.bottom() - min(1.0, value / upper) * plot.height()
            point = QPointF(x, y)
            if previous is not None:
                self._draw_segment(painter, previous, point, self._color(_jitter_color(value).name()), plot)
            previous = point

    def _axis_upper(self) -> float:
        values = [sample for sample in self._samples if sample is not None]
        if not values:
            return 20.0
        return max(20.0, max(values) * 1.2)

    def _draw_header(self, painter: QPainter) -> None:
        self._paint_header(painter, self._translate("JITTER / ОТКЛОНЕНИЕ RTT · ПОСЛЕДНИЕ 60 СЕКУНД"), (
            (self._translate("● стабильно"), "#00E5A3"), ("● spike", "#FFB800"),
            (self._translate("● критично"), "#FF4757"),
        ))

    def _draw_grid(self, painter: QPainter, plot: QRectF, upper: float) -> None:
        painter.setPen(QPen(self._color("#263247"), 1, Qt.PenStyle.DashLine))
        for fraction in (0.0, 1 / 3, 2 / 3, 1.0):
            y = plot.top() + plot.height() * fraction
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        painter.setPen(self._color("#8A99AD"))
        font = painter.font()
        font.setPixelSize(11)
        painter.setFont(font)
        for fraction in (0.0, 1 / 3, 2 / 3, 1.0):
            value = upper * (1 - fraction)
            y = plot.top() + plot.height() * fraction
            painter.drawText(
                QRectF(2, y - 8, plot.left() - 8, 16),
                Qt.AlignmentFlag.AlignRight,
                f"{value:.0f} ms",
            )
        painter.drawText(
            QRectF(plot.left(), plot.bottom() + 7, 76, 18),
            Qt.AlignmentFlag.AlignLeft,
            self._translate("60с назад"),
        )
        painter.drawText(QRectF(plot.center().x() - 25, plot.bottom() + 7, 50, 18), Qt.AlignmentFlag.AlignCenter, "30с")
        painter.drawText(
            QRectF(plot.right() - 58, plot.bottom() + 7, 58, 18),
            Qt.AlignmentFlag.AlignRight,
            self._translate("сейчас"),
        )

    @staticmethod
    def _draw_segment(
        painter: QPainter,
        previous: QPointF,
        current: QPointF,
        color: QColor,
        plot: QRectF,
    ) -> None:
        midpoint = (previous.x() + current.x()) / 2
        curve = QPainterPath(previous)
        curve.cubicTo(
            QPointF(midpoint, previous.y()),
            QPointF(midpoint, current.y()),
            current,
        )
        area = QPainterPath(curve)
        area.lineTo(QPointF(current.x(), plot.bottom()))
        area.lineTo(QPointF(previous.x(), plot.bottom()))
        area.closeSubpath()
        gradient = QLinearGradient(QPointF(0, plot.top()), QPointF(0, plot.bottom()))
        fill = QColor(color)
        fill.setAlpha(30)
        transparent = QColor(color)
        transparent.setAlpha(0)
        gradient.setColorAt(0.0, fill)
        gradient.setColorAt(1.0, transparent)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawPath(area)
        glow = QColor(color)
        glow.setAlpha(70)
        painter.setPen(QPen(glow, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawPath(curve)
        painter.setPen(QPen(color, 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawPath(curve)


class MetricTile(QFrame):
    clicked = Signal()

    def __init__(
        self,
        label: str,
        help_text: str = "",
        icon: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("MetricTile")
        self._metric_label = label.strip().casefold()
        self.setMinimumWidth(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        apply_panel_shadow(self)
        if help_text:
            self.setToolTip(help_text)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(4)
        self.icon_label = QLabel(icon)
        self.icon_label.setObjectName("MetricIcon")
        self.icon_label.setVisible(bool(icon))
        self.icon_label.setAccessibleName(f"Иконка метрики {label}")
        title_row.addWidget(self.icon_label)
        self.title_label = QLabel(label.upper())
        self.title_label.setObjectName("MetricLabel")
        title_row.addWidget(self.title_label)
        title_row.addStretch(1)
        if help_text:
            self.help_button = QToolButton()
            self.help_button.setObjectName("MetricHelpButton")
            self.help_button.setText("?")
            self.help_button.setToolTip(help_text)
            self.help_button.setAccessibleName(f"Подсказка: {label}")
            self.help_button.setFixedSize(22, 22)
            self.help_button.setAutoRaise(True)
            self.help_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            title_row.addWidget(self.help_button)
        self.value = QLabel("--")
        self.value.setObjectName("MetricValue")
        self.value.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.value.setMinimumHeight(24)
        self.value.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._value_glow = QGraphicsDropShadowEffect(self.value)
        self._value_glow.setOffset(0, 0)
        self.value.setGraphicsEffect(self._value_glow)
        self._set_metric_state("neutral")
        self.hint = QLabel("Нажмите для проверки")
        self.hint.setObjectName("MetricVerdict")
        self.hint.setWordWrap(True)
        self.hint.setAccessibleName(f"Вердикт метрики {label}")
        self._set_waiting_style(True)
        layout.addLayout(title_row)
        layout.addWidget(self.value)
        layout.addWidget(self.hint)

    def set_clickable(self, clickable: bool) -> None:
        self.setProperty("clickable", clickable)
        self.setCursor(
            Qt.CursorShape.PointingHandCursor if clickable else Qt.CursorShape.ArrowCursor
        )
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.property("clickable"):
            self.clicked.emit()
        super().mousePressEvent(event)

    def set_compact(self, compact: bool = True) -> None:
        self.setProperty("compact", compact)
        layout = self.layout()
        if isinstance(layout, QVBoxLayout):
            layout.setContentsMargins(10, 6, 10, 6) if compact else layout.setContentsMargins(14, 10, 14, 10)
            layout.setSpacing(0 if compact else 2)
        self.setMinimumHeight(82 if compact else 0)
        self.style().unpolish(self)
        self.style().polish(self)

    def set_metric(self, value: str, hint: str = "", state: str = "auto") -> None:
        self.value.setText(self._remove_redundant_label(value))
        self.hint.setText(hint or " ")
        resolved_state = state if state != "auto" else _infer_metric_state(value)
        self._set_metric_state(resolved_state)
        self._set_waiting_style(False)

    def set_waiting(self, text: str = "Нажмите для проверки") -> None:
        self.value.setText("--")
        self.hint.setText(text)
        self._set_metric_state("neutral")
        self._set_waiting_style(True)

    def _set_metric_state(self, state: str) -> None:
        self.value.setProperty("metricState", state)
        self.value.style().unpolish(self.value)
        self.value.style().polish(self.value)
        colors = {
            "good": QColor(46, 204, 113, 89),
            "warning": QColor(231, 76, 60, 102),
            "bad": QColor(231, 76, 60, 102),
            "neutral": QColor(0, 0, 0, 0),
        }
        color = colors.get(state, colors["neutral"])
        self._value_glow.setBlurRadius(10 if state in {"good", "warning", "bad"} else 0)
        self._value_glow.setColor(color)

    def _set_waiting_style(self, waiting: bool) -> None:
        self.hint.setProperty("waiting", waiting)
        self.hint.style().unpolish(self.hint)
        self.hint.style().polish(self.hint)

    def _remove_redundant_label(self, value: str) -> str:
        """Keep a caller-provided metric value from repeating the card title."""
        cleaned = value.strip()
        prefix = f"{self._metric_label} "
        if cleaned.casefold().startswith(prefix):
            cleaned = cleaned[len(prefix):].lstrip(" :-–—")
        return cleaned or "--"


class ResponsiveMetricGrid(QWidget):
    """Reflow metric tiles into as many columns as the available width allows."""

    # 170 px leaves space for metric verdicts instead of merely fitting six tiles.
    _MINIMUM_CARD_WIDTH = 170

    def __init__(
        self,
        cards: list[MetricTile],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._cards = cards
        self._columns = 0
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(6)
        self.grid.setVerticalSpacing(6)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.relayout_metrics()

    @property
    def columns(self) -> int:
        return self._columns

    def resizeEvent(self, event: object) -> None:
        super().resizeEvent(event)
        self.relayout_metrics()

    def relayout_metrics(self) -> None:
        """Keep all card instances while adapting their rows and columns."""
        minimum_card_width = max(
            self._MINIMUM_CARD_WIDTH,
            *(card.minimumWidth() for card in self._cards),
        )
        available_width = max(self.contentsRect().width(), minimum_card_width)
        spacing = self.grid.horizontalSpacing()
        columns = min(
            len(self._cards),
            max(1, (available_width + spacing) // (minimum_card_width + spacing)),
        )
        if columns == self._columns and self.grid.count() == len(self._cards):
            return

        while self.grid.count():
            self.grid.takeAt(0)
        for index, card in enumerate(self._cards):
            row, column = divmod(index, columns)
            self.grid.addWidget(card, row, column)
        for column in range(len(self._cards)):
            self.grid.setColumnStretch(column, 1 if column < columns else 0)
        self._columns = columns
        self.updateGeometry()


def apply_panel_shadow(widget: QWidget) -> None:
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(16)
    effect.setOffset(0, 4)
    effect.setColor(QColor(0, 0, 0, 102))
    widget.setGraphicsEffect(effect)


def apply_accent_glow(widget: QWidget) -> None:
    """Add a soft mint halo to a persistent primary control."""
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(16)
    effect.setOffset(0, 0)
    effect.setColor(QColor(0, 229, 163, 82))
    widget.setGraphicsEffect(effect)


def _marker_gradient(color: QColor, center: QPointF, radius: float) -> QRadialGradient:
    """Create a compact neon marker with a soft transparent edge."""
    gradient = QRadialGradient(center, radius)
    core = QColor(color)
    core.setAlpha(255)
    halo = QColor(color)
    halo.setAlpha(45)
    edge = QColor(color)
    edge.setAlpha(0)
    gradient.setColorAt(0.0, core)
    gradient.setColorAt(0.45, halo)
    gradient.setColorAt(1.0, edge)
    return gradient


def _latency_color(sample: LatencySample) -> QColor:
    if not sample.success or sample.latency_ms is None or sample.latency_ms > 100:
        return QColor("#FF4757")
    if sample.latency_ms > 50:
        return QColor("#FFB800")
    return QColor("#00E5A3")


def _jitter_color(value: float) -> QColor:
    if value > 30:
        return QColor("#FF4757")
    if value > 15:
        return QColor("#FFB800")
    return QColor("#00E5A3")


def _infer_metric_state(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized in {"--", "n/a", "na", "не измерена", "выполняется", "ожидание"}:
        return "neutral"
    if normalized in {"error", "closed", "ошибка", "недоступен"}:
        return "bad"
    return "good"


class TopologyWidget(ThemedCanvas):
    node_selected = Signal(object)

    _STATUS_COLORS = {
        ProbeStatus.PENDING: QColor("#78869A"),
        ProbeStatus.RUNNING: QColor("#00E5A3"),
        ProbeStatus.SUCCESS: QColor("#00E5A3"),
        ProbeStatus.WARNING: QColor("#FFB800"),
        ProbeStatus.ERROR: QColor("#FF4757"),
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._translate: Callable[[str], str] = lambda text: text
        self._nodes = self._placeholder_nodes("example.com:443")
        self._node_rects: list[QRectF] = []
        self._hovered_index = -1
        self._active_index = -1
        self._phase = 0.0
        self._dns_label = "DNS определяется"
        self._connection_statuses = [ProbeStatus.PENDING, ProbeStatus.PENDING]

        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._animate)
        self._timer.start()
        self._update_height()

    def sizeHint(self) -> QSize:
        return QSize(0, max(520, len(self._nodes) * 132 + 96))

    def set_translator(self, translate: Callable[[str], str]) -> None:
        self._translate = translate
        self.update()

    def reset(self, target: str) -> None:
        self._nodes = self._placeholder_nodes(target)
        self._dns_label = "DNS определяется"
        self._active_index = 0
        self._connection_statuses = [ProbeStatus.PENDING] * max(0, len(self._nodes) - 1)
        self._hovered_index = -1
        self._update_height()
        self.update()

    def set_active_stage(self, stage: str) -> None:
        stage_index = {
            "system": 0,
            "parallel": 0,
            "dns": 1,
            "tcp": 2,
            "tls": 2,
            "route": 1,
            "geo": max(0, len(self._nodes) - 1),
        }.get(stage, -1)
        self._active_index = min(stage_index, len(self._nodes) - 1)
        self.update()

    def set_report(self, report: DiagnosticReport) -> None:
        active_interface = next(
            (item for item in report.system.interfaces if item.is_up and item.ipv4 and item.kind != "Loopback"),
            next((item for item in report.system.interfaces if item.is_up), None),
        )
        local_ip = active_interface.ipv4[0] if active_interface and active_interface.ipv4 else "IP не определён"
        interface_name = active_interface.name if active_interface else "Активный интерфейс не найден"
        nodes: list[TopologyNode] = [
            TopologyNode(
                label="ВАШ ПК",
                primary=local_ip,
                secondary=interface_name,
                kind="device",
                status=ProbeStatus.SUCCESS,
                details={
                    "Устройство": report.system.hostname,
                    "Интерфейс": interface_name,
                    "Локальный IP": local_ip,
                    "Внешний IP": report.system.external_ip or "не определён",
                },
            )
        ]

        gateway = report.system.gateway
        if gateway:
            nodes.append(
                TopologyNode(
                    label="ШЛЮЗ",
                    primary=gateway.address,
                    secondary=gateway.interface or "основной маршрут",
                    kind="gateway",
                    status=ProbeStatus.SUCCESS,
                    details={
                        "IP": gateway.address,
                        "Интерфейс": gateway.interface or "не определён",
                        "Метрика": str(gateway.metric) if gateway.metric is not None else "не определена",
                    },
                )
            )

        known_addresses = {gateway.address} if gateway else set()
        geo_by_address = {result.address: result for result in report.geolocation}
        for hop in report.hops:
            if hop.address in known_addresses:
                continue
            if hop.address:
                known_addresses.add(hop.address)
            geo = geo_by_address.get(hop.address or "")
            geo_description = _geo_description(geo)
            nodes.append(
                TopologyNode(
                    label=f"HOP {hop.index:02d}",
                    primary=hop.address or "нет ответа",
                    secondary=geo_description or (
                        "маршрутный узел" if hop.address else "запрос превысил тайм-аут"
                    ),
                    kind="timeout" if hop.timed_out else "hop",
                    status=ProbeStatus.WARNING if hop.timed_out else ProbeStatus.SUCCESS,
                    latency_ms=hop.latency_ms,
                    details={
                        "Номер": str(hop.index),
                        "IP": hop.address or "нет ответа",
                        "Задержка": _format_ms(hop.latency_ms),
                        "Состояние": "тайм-аут" if hop.timed_out else "ответ получен",
                        **_geo_details(geo),
                    },
                )
            )

        if len(nodes) == 1 and gateway is None:
            nodes.append(
                TopologyNode(
                    label="ЛОКАЛЬНАЯ СЕТЬ",
                    primary="Маршрут недоступен",
                    secondary="остальные проверки продолжены",
                    kind="timeout",
                    status=ProbeStatus.WARNING,
                )
            )

        if nodes[-1].primary != report.target.host:
            target_geo = geo_by_address.get(report.tcp.peer_address or "")
            nodes.append(
                TopologyNode(
                    label="ЦЕЛЕВОЙ УЗЕЛ",
                    primary=report.target.host,
                    secondary=f"TCP {report.target.port}",
                    kind="target",
                    status=report.tcp.status,
                    latency_ms=report.tcp.latency_ms,
                    details={
                        "Адрес": report.target.host,
                        "Порт": str(report.target.port),
                        "IP соединения": report.tcp.peer_address or "не установлено",
                        "TCP": _status_text(report.tcp.status),
                        "Задержка": _format_ms(report.tcp.latency_ms),
                        **_geo_details(target_geo),
                    },
                )
            )

        self._nodes = nodes
        addresses = ", ".join(report.dns.addresses[:2]) or "нет ответа"
        self._dns_label = f"{_format_ms(report.dns.latency_ms)}  ·  {addresses}"
        self._connection_statuses = _connection_statuses(report, nodes)
        self._active_index = -1
        self._update_height()
        self.update()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), self._color("#161B22"))

        center_x = self.width() / 2
        top = 48.0
        node_width = max(0.0, min(460.0, self.width() - 32.0))
        node_height = 94.0
        gap = 38.0
        self._node_rects = []

        self._draw_dns_branch(painter, center_x, top, node_width)
        for index, node in enumerate(self._nodes):
            rect = QRectF(center_x - node_width / 2, top + index * (node_height + gap), node_width, node_height)
            self._node_rects.append(rect)
            if index > 0:
                previous = self._node_rects[index - 1]
                status = self._connection_statuses[index - 1]
                self._draw_connection(
                    painter,
                    previous,
                    rect,
                    node.latency_ms,
                    status,
                    index == self._active_index,
                )
            self._draw_node(painter, rect, node, index)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        hovered = next((i for i, rect in enumerate(self._node_rects) if rect.contains(event.position())), -1)
        if hovered != self._hovered_index:
            self._hovered_index = hovered
            self.setCursor(Qt.CursorShape.PointingHandCursor if hovered >= 0 else Qt.CursorShape.ArrowCursor)
            self.update()

    def leaveEvent(self, _event: object) -> None:
        self._hovered_index = -1
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self.update()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._hovered_index >= 0:
            self.node_selected.emit(self._nodes[self._hovered_index])

    def _draw_node(self, painter: QPainter, rect: QRectF, node: TopologyNode, index: int) -> None:
        color = self._color(_status_color(node.status).name())
        fill = self._color("#18202E") if index != self._hovered_index else self._color("#222C3D")
        border = color if index in {self._hovered_index, self._active_index} else self._color("#1E2638")

        if index == self._active_index:
            pulse = int(28 + 18 * (1 + math.sin(self._phase)) / 2)
            glow = QColor(color)
            glow.setAlpha(pulse)
            painter.setPen(QPen(glow, 8))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-3, -3, 3, 3), 7, 7)

        painter.setPen(QPen(border, 1.2))
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, 7, 7)
        painter.fillRect(QRectF(rect.left(), rect.top() + 10, 4, rect.height() - 20), color)

        painter.setPen(self._color("#78869A"))
        label_font = painter.font()
        label_font.setPixelSize(10)
        label_font.setBold(True)
        painter.setFont(label_font)
        painter.drawText(
            QRectF(rect.left() + 20, rect.top() + 13, rect.width() - 40, 16),
            self._translate(node.label),
        )

        painter.setPen(self._color("#E1E7EF"))
        primary_font = painter.font()
        primary_font.setPixelSize(17)
        primary_font.setBold(True)
        painter.setFont(primary_font)
        painter.drawText(
            QRectF(rect.left() + 20, rect.top() + 33, rect.width() - 40, 24),
            painter.fontMetrics().elidedText(self._translate(node.primary), Qt.TextElideMode.ElideRight, max(0, int(rect.width() - 40))),
        )

        painter.setPen(self._color("#A0AEC0"))
        secondary_font = painter.font()
        secondary_font.setPixelSize(10)
        secondary_font.setBold(False)
        painter.setFont(secondary_font)
        painter.drawText(
            QRectF(rect.left() + 20, rect.top() + 65, rect.width() - 40, 16),
            painter.fontMetrics().elidedText(self._translate(node.secondary), Qt.TextElideMode.ElideRight, max(0, int(rect.width() - 40))),
        )

        dot = QPointF(rect.right() - 20, rect.top() + 20)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(_marker_gradient(color, dot, 7.0))
        painter.drawEllipse(dot, 4, 4)

    def _draw_connection(
        self,
        painter: QPainter,
        previous: QRectF,
        current: QRectF,
        latency_ms: float | None,
        status: ProbeStatus,
        active: bool,
    ) -> None:
        start = QPointF(previous.center().x(), previous.bottom())
        end = QPointF(current.center().x(), current.top())
        color = self._color(_status_color(status).name())
        painter.setPen(QPen(color, 2.4 if active or status != ProbeStatus.PENDING else 1.4, Qt.PenStyle.SolidLine))
        painter.drawLine(start, end)

        arrow = QPainterPath()
        arrow.moveTo(end.x() - 4, end.y() - 7)
        arrow.lineTo(end)
        arrow.lineTo(end.x() + 4, end.y() - 7)
        painter.drawPath(arrow)

        if latency_ms is not None:
            label = _format_ms(latency_ms)
            badge = QRectF(end.x() + 12, start.y() + (end.y() - start.y()) / 2 - 10, 58, 20)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self._color("#18202E"))
            painter.drawRoundedRect(badge, 4, 4)
            painter.setPen(self._color("#A0AEC0"))
            font = painter.font()
            font.setPixelSize(9)
            painter.setFont(font)
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, label)

    def _draw_dns_branch(self, painter: QPainter, center_x: float, top: float, node_width: float) -> None:
        if self.width() < 690:
            painter.setPen(self._color("#78869A"))
            font = painter.font()
            font.setPixelSize(9)
            painter.setFont(font)
            painter.drawText(QRectF(24, 15, self.width() - 48, 20), Qt.AlignmentFlag.AlignCenter, self._dns_label)
            return

        anchor_x = center_x + node_width / 2
        branch_rect = QRectF(anchor_x + 24, top + 15, min(220, self.width() - anchor_x - 42), 45)
        painter.setPen(QPen(self._color("#1E2638"), 1.2, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(anchor_x, top + 37), QPointF(branch_rect.left(), branch_rect.center().y()))
        painter.setBrush(self._color("#18202E"))
        painter.setPen(QPen(self._color("#FFB800"), 1))
        painter.drawRoundedRect(branch_rect, 5, 5)
        painter.setPen(self._color("#FFB800"))
        font = painter.font()
        font.setPixelSize(9)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(branch_rect.adjusted(10, 6, -10, -22), "DNS")
        painter.setPen(self._color("#A0AEC0"))
        font.setBold(False)
        painter.setFont(font)
        painter.drawText(branch_rect.adjusted(10, 21, -10, -4), _elide(self._dns_label, 29))

    def _placeholder_nodes(self, target: str) -> list[TopologyNode]:
        return [
            TopologyNode("ВАШ ПК", "Локальная система", "интерфейсы ожидают проверки", "device"),
            TopologyNode("ЛОКАЛЬНАЯ СЕТЬ", "Шлюз определяется", "маршрут ещё не запущен", "gateway"),
            TopologyNode("ЦЕЛЕВОЙ УЗЕЛ", target, "TCP-проверка ожидает запуска", "target"),
        ]

    def _animate(self) -> None:
        if self._active_index >= 0:
            self._phase += 0.18
            self.update()

    def _update_height(self) -> None:
        self.setMinimumHeight(max(520, len(self._nodes) * 132 + 88))
        self.updateGeometry()


def _status_color(status: ProbeStatus) -> QColor:
    return {
        ProbeStatus.SUCCESS: QColor("#00E5A3"),
        ProbeStatus.WARNING: QColor("#FFB800"),
        ProbeStatus.ERROR: QColor("#FF4757"),
        ProbeStatus.RUNNING: QColor("#00E5A3"),
        ProbeStatus.PENDING: QColor("#78869A"),
    }[status]


def _connection_statuses(report: DiagnosticReport, nodes: list[TopologyNode]) -> list[ProbeStatus]:
    """Map diagnostic results to visual statuses for every route segment."""
    if len(nodes) < 2:
        return []

    statuses = [ProbeStatus.SUCCESS] * (len(nodes) - 1)
    if report.ping.loss_percent > 0:
        statuses[-1] = ProbeStatus.WARNING
    if report.tcp.status != ProbeStatus.SUCCESS:
        statuses[-1] = ProbeStatus.ERROR

    for index, node in enumerate(nodes[1:-1], start=1):
        if node.status in {ProbeStatus.WARNING, ProbeStatus.ERROR}:
            statuses[index - 1] = node.status
            statuses[index] = node.status
    return statuses


def _status_text(status: ProbeStatus) -> str:
    return {
        ProbeStatus.SUCCESS: "успешно",
        ProbeStatus.WARNING: "предупреждение",
        ProbeStatus.ERROR: "ошибка",
        ProbeStatus.RUNNING: "выполняется",
        ProbeStatus.PENDING: "ожидание",
    }[status]


def _format_ms(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} ms"


def _elide(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _geo_description(result: object | None) -> str | None:
    if result is None:
        return None
    parts = [getattr(result, "country", None), getattr(result, "city", None)]
    asn = getattr(result, "asn", None)
    location = ", ".join(part for part in parts if part)
    return " · ".join(part for part in (location, f"AS{asn}" if asn else None) if part) or None


def _geo_details(result: object | None) -> dict[str, str]:
    if result is None:
        return {}
    values = {
        "Страна": getattr(result, "country", None),
        "Регион": getattr(result, "region", None),
        "Город": getattr(result, "city", None),
        "ASN": getattr(result, "asn", None),
        "Организация": getattr(result, "organization", None),
        "Провайдер": getattr(result, "isp", None),
    }
    return {key: value for key, value in values.items() if value}

