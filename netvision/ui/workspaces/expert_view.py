"""Expert dashboard view."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSplitter, QVBoxLayout, QWidget
from netvision.ui.constants import METRIC_TOOLTIPS
from netvision.ui.widgets import MetricTile, ResponsiveMetricGrid


class ExpertView(QWidget):
    def __init__(self, controller) -> None:
        super().__init__()
        self.metrics = {
            "dns": MetricTile("DNS", METRIC_TOOLTIPS["dns"], "🌐"),
            "ping": MetricTile("Ping", METRIC_TOOLTIPS["ping"], "⚡"),
            "loss": MetricTile("Потери", METRIC_TOOLTIPS["loss"], "📉"),
            "jitter": MetricTile("Jitter", METRIC_TOOLTIPS["jitter"], "📊"),
            "tcp": MetricTile("TCP", METRIC_TOOLTIPS["tcp"], "🔒"),
            "tls": MetricTile("TLS", METRIC_TOOLTIPS["tls"], "🔒"),
        }
        for tile in self.metrics.values():
            tile.set_compact()
        self.metrics["dns"].set_clickable(True)
        controller._set_translatable_tooltip(
            self.metrics["dns"],
            METRIC_TOOLTIPS["dns"],
            "Открыть подробное сравнение DNS-серверов",
        )
        self.metrics["dns"].clicked.connect(controller._open_dns_workspace)
        self.metrics["ping"].set_clickable(True)
        controller._set_translatable_tooltip(
            self.metrics["ping"],
            METRIC_TOOLTIPS["ping"],
            "Открыть расширенный анализ задержки и игровых регионов",
        )
        self.metrics["ping"].clicked.connect(controller._open_ping_workspace)
        self.metrics["loss"].set_clickable(True)
        controller._set_translatable_tooltip(
            self.metrics["loss"],
            METRIC_TOOLTIPS["loss"],
            "Открыть анализ burst-потерь и проблемных hop",
        )
        self.metrics["loss"].clicked.connect(controller._open_loss_workspace)
        self.metrics["jitter"].set_clickable(True)
        controller._set_translatable_tooltip(
            self.metrics["jitter"],
            METRIC_TOOLTIPS["jitter"],
            "Открыть анализ колебаний RTT, VoIP и игровых сессий",
        )
        self.metrics["jitter"].clicked.connect(controller._open_jitter_workspace)
        self.metrics["tcp"].set_clickable(True)
        controller._set_translatable_tooltip(
            self.metrics["tcp"],
            METRIC_TOOLTIPS["tcp"],
            "Открыть анализ TCP-соединений, handshake и портов",
        )
        self.metrics["tcp"].clicked.connect(controller._open_tcp_workspace)
        self.metrics["tls"].set_clickable(True)
        controller._set_translatable_tooltip(
            self.metrics["tls"],
            METRIC_TOOLTIPS["tls"],
            "Открыть аудит TLS, сертификата и защищённого соединения",
        )
        self.metrics["tls"].clicked.connect(controller._open_tls_workspace)
        self.metric_grid = ResponsiveMetricGrid(list(self.metrics.values()))

    def assemble(self, topology: QWidget, tabs: QWidget, actions: QWidget) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.metric_grid)
        self.workspace_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.workspace_splitter.setChildrenCollapsible(False)
        self.workspace_splitter.addWidget(topology)
        self.workspace_splitter.addWidget(tabs)
        self.workspace_splitter.setSizes([580, 740])
        self.workspace_splitter.setStretchFactor(0, 4)
        self.workspace_splitter.setStretchFactor(1, 5)
        layout.addWidget(self.workspace_splitter, 1)
        layout.addWidget(actions)
