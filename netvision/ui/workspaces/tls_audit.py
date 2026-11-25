"""TLS audit workspace widgets."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui import constants as ui_constants
from netvision.ui.components import factory


class TlsAuditWorkspace(QFrame):
    def __init__(self) -> None:
        super().__init__()
        workspace = self
        workspace.setObjectName("TlsWorkspace")
        outer_layout = QVBoxLayout(workspace)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setObjectName("TlsWorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setObjectName("TlsWorkspaceContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.tls_back_button = QPushButton("←  Назад")
        self.tls_back_button.setObjectName("TlsBackButton")
        title_box = QVBoxLayout()
        title = QLabel("TLS SECURITY & CERTIFICATE ANALYTICS")
        title.setObjectName("TlsWorkspaceTitle")
        subtitle = QLabel("Проверка защищённого соединения, сертификата и параметров шифрования")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.tls_run_button = QPushButton("▶  Проверить сертификат")
        self.tls_run_button.setObjectName("TlsRunButton")
        header.addWidget(self.tls_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.tls_run_button)
        layout.addLayout(header)

        overview_panel = QFrame()
        overview_panel.setObjectName("TlsOverviewPanel")
        overview_layout = QGridLayout(overview_panel)
        overview_layout.setContentsMargins(12, 10, 12, 10)
        overview_layout.setHorizontalSpacing(16)
        overview_layout.setVerticalSpacing(6)
        overview_values = ui_constants.DASHBOARD_TLS_OVERVIEW_VALUES
        self.tls_overview_values: dict[str, QLabel] = {}
        for column, (caption, key) in enumerate(overview_values):
            item = QFrame()
            item.setObjectName("TlsOverviewItem")
            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(1)
            label = QLabel(caption)
            label.setObjectName("FieldLabel")
            value = QLabel("--")
            value.setObjectName("TlsMetricValue")
            value.setProperty("state", "neutral")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setToolTip("Данные появятся после TLS-аудита")
            item_layout.addWidget(label)
            item_layout.addWidget(value)
            overview_layout.addWidget(item, 0, column)
            overview_layout.setColumnStretch(column, 1)
            self.tls_overview_values[key] = value
        layout.addWidget(overview_panel)

        tools_panel = QFrame()
        tools_panel.setObjectName("TlsToolsPanel")
        tools_layout = QVBoxLayout(tools_panel)
        tools_layout.setContentsMargins(12, 10, 12, 10)
        tools_layout.setSpacing(7)
        tools_title = QLabel("SMART TOOLS")
        tools_title.setObjectName("FieldLabel")
        target_row = QHBoxLayout()
        host_label = QLabel("ЦЕЛЬ")
        host_label.setObjectName("FieldLabel")
        self.tls_target_input = QLineEdit()
        self.tls_target_input.setPlaceholderText("Домен или IP-адрес TLS-сервера")
        self.tls_target_input.setClearButtonEnabled(True)
        port_label = QLabel("ПОРТ")
        port_label.setObjectName("FieldLabel")
        self.tls_port_input = QSpinBox()
        self.tls_port_input.setRange(1, 65535)
        self.tls_port_input.setValue(443)
        self.tls_port_input.setMinimumWidth(90)
        self.tls_check_button = QPushButton("Проверить сертификат")
        self.tls_check_button.setObjectName("TlsSecondaryButton")
        self.tls_copy_fingerprint_button = QPushButton("Копировать отпечаток")
        self.tls_copy_fingerprint_button.setObjectName("TlsSecondaryButton")
        self.tls_copy_fingerprint_button.setEnabled(False)
        self.tls_refresh_button = QPushButton("Обновить аудит безопасности")
        self.tls_refresh_button.setObjectName("TlsSecondaryButton")
        target_row.addWidget(host_label)
        target_row.addWidget(self.tls_target_input, 1)
        target_row.addWidget(port_label)
        target_row.addWidget(self.tls_port_input)
        target_row.addWidget(self.tls_check_button)
        target_row.addWidget(self.tls_copy_fingerprint_button)
        target_row.addWidget(self.tls_refresh_button)
        self.tls_audit_status = QLabel("Укажите цель и запустите проверку сертификата")
        self.tls_audit_status.setObjectName("Muted")
        self.tls_audit_status.setWordWrap(True)
        tools_layout.addWidget(tools_title)
        tools_layout.addLayout(target_row)
        tools_layout.addWidget(self.tls_audit_status)
        layout.addWidget(tools_panel)

        handshake_panel = QFrame()
        handshake_panel.setObjectName("TlsHandshakePanel")
        handshake_layout = QVBoxLayout(handshake_panel)
        handshake_layout.setContentsMargins(12, 10, 12, 12)
        handshake_layout.setSpacing(7)
        handshake_title = QLabel("HANDSHAKE PHASE BREAKDOWN")
        handshake_title.setObjectName("FieldLabel")
        handshake_note = QLabel(
            "Стандартный Python SSL измеряет TCP connect и полный TLS handshake. "
            "Отдельные пакеты Client Hello, Server Hello и Key Exchange требуют packet capture."
        )
        handshake_note.setObjectName("Muted")
        handshake_note.setWordWrap(True)
        self.tls_handshake_table = QTableWidget(0, 3)
        self.tls_handshake_table.setObjectName("TlsHandshakeTable")
        self.tls_handshake_table.setHorizontalHeaderLabels(["Этап", "Время", "Статус / детали"])
        factory.configure_table(self.tls_handshake_table, (145, 75, 240))
        self.tls_handshake_table.setWordWrap(True)
        self.tls_handshake_table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tls_handshake_table.horizontalHeader().sectionResized.connect(
            lambda *_: self._resize_visible_rows(self.tls_handshake_table)
        )
        self.tls_handshake_table.setMinimumHeight(180)
        handshake_layout.addWidget(handshake_title)
        handshake_layout.addWidget(handshake_note)
        handshake_layout.addWidget(self.tls_handshake_table)
        layout.addWidget(handshake_panel)

        certificate_panel = QFrame()
        certificate_panel.setObjectName("TlsCertificatePanel")
        certificate_layout = QVBoxLayout(certificate_panel)
        certificate_layout.setContentsMargins(12, 10, 12, 12)
        certificate_layout.setSpacing(7)
        certificate_title = QLabel("CERTIFICATE CHAIN DETAILS")
        certificate_title.setObjectName("FieldLabel")
        self.tls_chain_note = QLabel(
            "Python SSL предоставляет leaf-сертификат; доступные элементы цепочки появятся после аудита."
        )
        self.tls_chain_note.setObjectName("Muted")
        self.tls_chain_note.setWordWrap(True)
        self.tls_certificate_table = QTableWidget(0, 8)
        self.tls_certificate_table.setObjectName("TlsCertificateTable")
        self.tls_certificate_table.setHorizontalHeaderLabels(
            [
                "#",
                "Subject",
                "Issuer",
                "Serial",
                "Действует с",
                "Действует до",
                "Осталось",
                "SHA-256",
            ]
        )
        factory.configure_table(self.tls_certificate_table, (64, 145, 145, 100, 110, 110, 85, 160))
        self.tls_certificate_table.setWordWrap(True)
        self.tls_certificate_table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tls_certificate_table.horizontalHeader().sectionResized.connect(
            lambda *_: self._resize_visible_rows(self.tls_certificate_table)
        )
        self.tls_certificate_table.setMinimumHeight(210)
        certificate_layout.addWidget(certificate_title)
        certificate_layout.addWidget(self.tls_chain_note)
        certificate_layout.addWidget(self.tls_certificate_table)
        layout.addWidget(certificate_panel, 1)
        layout.addStretch(1)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)

    @staticmethod
    def _resize_visible_rows(table: QTableWidget) -> None:
        if table.isVisible() and table.rowCount():
            table.resizeRowsToContents()
