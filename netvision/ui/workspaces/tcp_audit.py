"""TCP audit workspace widgets."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui import constants as ui_constants
from netvision.ui.components import factory


class TcpAuditWorkspace(QFrame):
    def __init__(self) -> None:
        super().__init__()
        workspace = self
        workspace.setObjectName("TcpWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("TcpWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setObjectName("TcpWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.tcp_back_button = QPushButton("←  Назад")
        self.tcp_back_button.setObjectName("TcpBackButton")
        title_box = QVBoxLayout()
        title = QLabel("TCP CONNECTION & PORT ANALYTICS")
        title.setObjectName("TcpWorkspaceTitle")
        subtitle = QLabel("Сокеты, TCP connect, состояния соединений и проверка портов")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.tcp_run_button = QPushButton("▶  Обновить TCP-анализ")
        self.tcp_run_button.setObjectName("TcpRunButton")
        header.addWidget(self.tcp_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.tcp_run_button)
        layout.addLayout(header)

        metrics_panel = QFrame()
        metrics_panel.setObjectName("TcpMetricsPanel")
        metrics_layout = QGridLayout(metrics_panel)
        metrics_layout.setContentsMargins(12, 10, 12, 10)
        metrics_layout.setHorizontalSpacing(16)
        metrics_layout.setVerticalSpacing(6)
        metric_titles = ui_constants.DASHBOARD_NETWORK_METRIC_TITLES
        for column, (caption, attribute) in enumerate(metric_titles):
            item = QFrame()
            item.setObjectName("TcpMetricItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption)
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("TcpMetricValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            setattr(self, attribute, value)
            metrics_layout.addWidget(item, 0, column)
            metrics_layout.setColumnStretch(column, 1)
        handshake_note = QLabel(
            "SYN / SYN-ACK / ACK — оценка по полному времени TCP connect. Точные отдельные фазы требуют packet capture."
        )
        handshake_note.setObjectName("Muted")
        handshake_note.setWordWrap(True)
        metrics_layout.addWidget(handshake_note, 1, 0, 1, len(metric_titles))
        layout.addWidget(metrics_panel)

        ports_panel = QFrame()
        ports_panel.setObjectName("TcpPortsPanel")
        ports_layout = QVBoxLayout(ports_panel)
        ports_layout.setContentsMargins(12, 10, 12, 12)
        ports_layout.setSpacing(7)
        ports_title = QLabel("PORT STATUS & FILTERING TESTER")
        ports_title.setObjectName("FieldLabel")
        ports_row = QHBoxLayout()
        host_label = QLabel("ЦЕЛЬ")
        host_label.setObjectName("FieldLabel")
        self.tcp_target_input = QLineEdit()
        self.tcp_target_input.setPlaceholderText("Адрес или домен")
        self.tcp_target_input.setClearButtonEnabled(True)
        ports_label = QLabel("ПОРТЫ")
        ports_label.setObjectName("FieldLabel")
        self.tcp_ports_input = QLineEdit("80, 443, 3389")
        self.tcp_ports_input.setPlaceholderText("80, 443, 27015")
        self.tcp_ports_input.setToolTip("Список TCP-портов через запятую")
        self.tcp_ports_input.setMaximumWidth(220)
        ports_row.addWidget(host_label)
        ports_row.addWidget(self.tcp_target_input, 1)
        ports_row.addWidget(ports_label)
        ports_row.addWidget(self.tcp_ports_input)
        self.tcp_ports_table = QTableWidget(0, 4)
        self.tcp_ports_table.setObjectName("TcpPortsTable")
        self.tcp_ports_table.setHorizontalHeaderLabels(["Порт", "Статус", "TCP connect", "Детали"])
        factory.configure_table(self.tcp_ports_table, (75, 110, 120, 220))
        self.tcp_ports_table.setMinimumHeight(152)
        ports_layout.addWidget(ports_title)
        ports_layout.addLayout(ports_row)
        ports_layout.addWidget(self.tcp_ports_table, 1)
        layout.addWidget(ports_panel)

        sockets_panel = QFrame()
        sockets_panel.setObjectName("TcpSocketsPanel")
        sockets_layout = QVBoxLayout(sockets_panel)
        sockets_layout.setContentsMargins(12, 10, 12, 12)
        sockets_layout.setSpacing(7)
        socket_header = QHBoxLayout()
        socket_title = QLabel("ACTIVE CONNECTION MATRIX")
        socket_title.setObjectName("FieldLabel")
        self.tcp_socket_status = QLabel(
            "Нажмите «Обновить TCP-анализ», чтобы просканировать сокеты"
        )
        self.tcp_socket_status.setObjectName("Muted")
        self.tcp_socket_status.setWordWrap(True)
        self.tcp_socket_details_button = QPushButton("Детали сокета")
        self.tcp_socket_details_button.setObjectName("TcpSecondaryButton")
        self.tcp_socket_details_button.setEnabled(False)
        self.tcp_reset_stack_button = QPushButton("Сбросить TCP/IP")
        self.tcp_reset_stack_button.setObjectName("TcpSecondaryButton")
        socket_header.addWidget(socket_title)
        socket_header.addStretch(1)
        socket_header.addWidget(self.tcp_socket_details_button)
        socket_header.addWidget(self.tcp_reset_stack_button)
        self.tcp_sockets_table = QTableWidget(0, 5)
        self.tcp_sockets_table.setObjectName("TcpSocketsTable")
        self.tcp_sockets_table.setHorizontalHeaderLabels(
            ["PID / приложение", "Локальный endpoint", "Удалённый endpoint", "Состояние", "Детали"]
        )
        factory.configure_table(self.tcp_sockets_table, (130, 130, 145, 105, 210))
        self.tcp_sockets_table.setMinimumHeight(230)
        sockets_layout.addLayout(socket_header)
        sockets_layout.addWidget(self.tcp_socket_status)
        sockets_layout.addWidget(self.tcp_sockets_table, 1)
        layout.addWidget(sockets_panel, 1)
        self.quick_fix_layout = QVBoxLayout()
        self.quick_fix_layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self.quick_fix_layout)
        layout.addStretch(1)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
