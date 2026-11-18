"""Workspace widgets."""

from PySide6.QtWidgets import QLabel, QSizePolicy, QTableWidget, QVBoxLayout, QWidget

from netvision.ui.components import factory


class TopologyPathWorkspace(QWidget):
    def __init__(self) -> None:
        super().__init__()
        tab = self
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        routes_title = QLabel("ДОСТУПНЫЕ МАРШРУТЫ / VPN")
        routes_title.setObjectName("FieldLabel")
        routes_title.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Fixed,
        )
        self.routes_table = QTableWidget(0, 4)
        self.routes_table.setHorizontalHeaderLabels(["Путь", "Интерфейс", "Шлюз", "Метрика"])
        factory.configure_table(self.routes_table, (150, 160, 170, 80))

        geo_title = QLabel("ASN / GEOIP ДЛЯ ПУБЛИЧНЫХ УЗЛОВ МАРШРУТА")
        geo_title.setObjectName("FieldLabel")
        geo_title.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Fixed,
        )
        self.geo_status = QLabel("GeoIP ещё не получен")
        self.geo_status.setObjectName("Muted")
        self.geo_status.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Fixed,
        )
        self.geo_table = QTableWidget(0, 4)
        self.geo_table.setHorizontalHeaderLabels(["IP", "Страна / город", "ASN", "Провайдер"])
        factory.configure_table(self.geo_table, (150, 220, 100, 230))

        layout.addWidget(routes_title)
        layout.addWidget(self.routes_table, 1)
        layout.addWidget(geo_title)
        layout.addWidget(self.geo_status)
        layout.addWidget(self.geo_table, 2)
