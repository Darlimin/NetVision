"""DnsWorkspace widgets."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from netvision.ui.components import factory
from netvision.ui.utils import keep_wheel_scroll_local


class DnsWorkspace(QFrame):
    def __init__(self, quick_fix_panel: QWidget) -> None:
        super().__init__()
        workspace = self
        workspace.setObjectName("DnsWorkspace")
        layout = QVBoxLayout(workspace)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        self.dns_back_button = QPushButton("←  Назад")
        self.dns_back_button.setObjectName("DnsBackButton")
        title_box = QVBoxLayout()
        title = QLabel("ДИАГНОСТИКА DNS")
        title.setObjectName("DnsWorkspaceTitle")
        subtitle = QLabel("Сравнение отклика публичных и пользовательских DNS-серверов")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.dns_run_button = QPushButton("▶  Запустить тест")
        self.dns_run_button.setObjectName("DnsRunButton")
        self.dns_geohide_button = QPushButton("GeoHide DNS")
        self.dns_geohide_button.setObjectName("GeoHideButton")
        header.addWidget(self.dns_back_button)
        header.addLayout(title_box, 1)
        header.addWidget(self.dns_geohide_button)
        layout.addLayout(header)
        self.vpn_hint = QLabel()
        self.vpn_hint.setObjectName("Muted")
        self.vpn_hint.setWordWrap(True)
        self.vpn_hint.hide()
        layout.addWidget(self.vpn_hint)

        system_panel = QWidget()
        system_layout = QVBoxLayout(system_panel)
        system_layout.setContentsMargins(0, 0, 0, 0)
        system_layout.setSpacing(8)

        info_panel = QFrame()
        info_panel.setObjectName("DnsInfoPanel")
        info_layout = QVBoxLayout(info_panel)
        info_layout.setContentsMargins(12, 10, 12, 10)
        info_layout.setSpacing(7)
        current_title = QLabel("ТЕКУЩИЕ DNS АДАПТЕРОВ")
        current_title.setObjectName("FieldLabel")
        self.dns_info_container = QWidget()
        self.dns_info_grid = QGridLayout(self.dns_info_container)
        self.dns_info_grid.setContentsMargins(0, 0, 0, 0)
        self.dns_info_grid.setHorizontalSpacing(6)
        self.dns_info_grid.setVerticalSpacing(6)

        info_layout.addWidget(current_title)
        info_layout.addWidget(self.dns_info_container)

        adapter_panel = QFrame()
        adapter_panel.setObjectName("DnsAdapterPanel")
        adapter_layout = QGridLayout(adapter_panel)
        adapter_layout.setContentsMargins(12, 10, 12, 10)
        adapter_layout.setHorizontalSpacing(10)
        adapter_layout.setVerticalSpacing(6)
        adapter_title = QLabel("АДАПТЕР")
        adapter_title.setObjectName("FieldLabel")
        self.dns_adapter_combo = QComboBox()
        self.dns_adapter_combo.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        keep_wheel_scroll_local(self.dns_adapter_combo.view())
        self.dns_adapter_combo.setToolTip(
            "Адаптер, для которого можно применить выбранный DNS-профиль"
        )
        self.dns_adapter_properties_button = QPushButton("Открыть свойства адаптера")
        self.dns_adapter_properties_button.setObjectName("DnsAdapterPropertiesButton")
        self.dns_adapter_properties_button.setSizePolicy(
            QSizePolicy.Policy.Maximum,
            QSizePolicy.Policy.Fixed,
        )
        self.dns_adapter_properties_button.setMinimumHeight(30)
        self.dns_apply_button = QPushButton("Применить выбранный DNS")
        self.dns_apply_button.setObjectName("DnsApplyButton")
        self.dns_apply_button.setEnabled(False)
        self.dns_flush_button = QPushButton("🔄  Очистить кэш DNS")
        self.dns_flush_button.setObjectName("QuickActionPrimary")
        adapter_layout.addWidget(adapter_title, 0, 0)
        adapter_layout.addWidget(self.dns_adapter_combo, 0, 1)
        adapter_layout.addWidget(self.dns_apply_button, 0, 2)
        adapter_layout.addWidget(self.dns_flush_button, 0, 3)
        adapter_layout.addWidget(
            self.dns_adapter_properties_button,
            1,
            1,
            1,
            3,
            alignment=Qt.AlignmentFlag.AlignLeft,
        )
        adapter_layout.setColumnStretch(1, 1)
        adapter_layout.setColumnStretch(2, 1)
        system_layout.addWidget(info_panel)
        system_layout.addWidget(adapter_panel)
        layout.addWidget(system_panel)

        custom_row = QHBoxLayout()
        custom_label = QLabel("СВОЙ DNS")
        custom_label.setObjectName("FieldLabel")
        self.dns_custom_input = QLineEdit()
        self.dns_custom_input.setPlaceholderText("Например, 10.0.0.53 или 2606:4700:4700::1111")
        self.dns_custom_input.setClearButtonEnabled(True)
        self.dns_custom_button = QPushButton("Добавить сервер")
        custom_row.addWidget(custom_label)
        custom_row.addWidget(self.dns_custom_input, 1)
        custom_row.addWidget(self.dns_custom_button)
        custom_row.addWidget(self.dns_run_button)
        layout.addLayout(custom_row)

        self.dns_status = QLabel("Нажмите «Запустить тест», чтобы сравнить резолверы")
        self.dns_status.setObjectName("Muted")
        self.dns_status.setWordWrap(True)
        layout.addWidget(self.dns_status)

        self.dns_table = QTableWidget(0, 5)
        self.dns_table.setObjectName("DnsBenchmarkTable")
        self.dns_table.setHorizontalHeaderLabels(
            ["Провайдер", "Адреса", "Лучший адрес", "TCP/53", "Статус"]
        )
        factory.configure_table(self.dns_table, (150, 235, 145, 95, 120))
        layout.addWidget(self.dns_table, 1)
        layout.addWidget(quick_fix_panel)
