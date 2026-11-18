"""Process and connection selector panel."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QSizePolicy,
    QSpinBox,
    QStyle,
    QToolButton,
    QVBoxLayout,
)

from netvision.ui.utils import keep_wheel_scroll_local
from netvision.ui.widgets import EmbeddedComboBox, apply_panel_shadow


class ProcessSelector(QFrame):
    def __init__(self, controller) -> None:
        super().__init__()
        panel = self
        self.process_panel = panel
        panel.setObjectName("ProcessInspectorBar")
        apply_panel_shadow(panel)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(12, 5, 12, 5)
        panel_layout.setSpacing(6)
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        self.process_title = QLabel("ПРОЦЕСС")
        title = self.process_title
        title.setObjectName("ProcessSelectorLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        title.setMinimumHeight(36)
        title.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.process_selector = EmbeddedComboBox()
        self.process_selector.setMinimumWidth(140)
        self.process_selector.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        self.process_selector.setToolTip("Выберите приложение с активными сетевыми соединениями")
        self.process_selector.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        keep_wheel_scroll_local(self.process_selector.view())
        self.process_selector.addItem("Список процессов не обновлён", None)
        self.process_selector.popup_requested.connect(controller._show_embedded_dropdown)

        self.connection_title = QLabel("СОЕДИНЕНИЕ")
        connection_title = self.connection_title
        connection_title.setObjectName("ProcessSelectorLabel")
        connection_title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        connection_title.setMinimumHeight(36)
        connection_title.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.process_connection_selector = EmbeddedComboBox()
        self.process_connection_selector.setMinimumWidth(180)
        self.process_connection_selector.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        self.process_connection_selector.setToolTip("Выберите IP-адрес и порт процесса")
        self.process_connection_selector.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        keep_wheel_scroll_local(self.process_connection_selector.view())
        self.process_connection_selector.addItem("Сначала выберите процесс", None)
        self.process_connection_selector.popup_requested.connect(controller._show_embedded_dropdown)

        self.process_refresh_button = QToolButton()
        self.process_refresh_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload)
        )
        self.process_refresh_button.setToolTip(
            controller._tr("Обновить список процессов и сетевых соединений")
        )
        self.process_refresh_button.setAccessibleName("Обновить список процессов")
        self.process_refresh_button.setFixedSize(36, 36)

        self.game_monitor_checkbox = QCheckBox(controller._tr("Мониторинг запуска игры"))
        self.game_monitor_checkbox.setObjectName("GameLaunchMonitorToggle")
        self.game_monitor_checkbox.setMinimumWidth(136)
        self.game_monitor_checkbox.setToolTip(
            controller._tr("Автоматически отслеживать запуск и завершение выбранной игры")
        )
        self.game_monitor_checkbox.toggled.connect(controller._toggle_game_launch_monitor)
        self.game_monitor_checkbox.toggled.connect(controller._sync_tray_game_monitor)

        self.process_status = QLabel()
        self.process_status.setObjectName("Muted")
        self.process_status.setVisible(False)

        self.udp_ports_status = QLabel("UDP: выберите процесс для мониторинга")
        self.udp_ports_status.setObjectName("UdpPortStatus")
        self.udp_ports_status.setToolTip(
            "В реальном времени показывает локальные UDP-порты, занятые выбранным процессом."
        )
        self.monitor_scope_label = QLabel("Наблюдение: только цель")
        self.monitor_scope_label.setObjectName("MonitorScopeLabel")

        layout.addWidget(title, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.process_selector, 1)
        layout.addWidget(
            controller.header_panel.manual_process_button, 0, Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(
            controller.header_panel.connection_capture_button, 0, Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(connection_title, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.process_connection_selector, 1)
        layout.addWidget(self.process_refresh_button)
        layout.addWidget(self.game_monitor_checkbox, 0, Qt.AlignmentFlag.AlignVCenter)
        panel_layout.addLayout(layout)
        panel_layout.addWidget(self.udp_ports_status)
        panel_layout.addWidget(self.monitor_scope_label)

        self.game_monitor_status = QLabel(controller._tr("Мониторинг игры выключен"))
        self.game_monitor_status.setObjectName("Muted")
        panel_layout.addWidget(self.game_monitor_status)

        alarms_layout = QHBoxLayout()
        alarms_layout.setContentsMargins(0, 0, 0, 0)
        alarms_layout.setSpacing(6)
        self.network_alarm_checkbox = QCheckBox(controller._tr("Уведомления о качестве сети"))
        self.network_alarm_checkbox.setObjectName("NetworkHealthAlarmToggle")
        self.network_alarm_checkbox.setChecked(bool(controller._network_alarm_enabled))
        self.network_alarm_checkbox.setToolTip(
            controller._tr("Показывать уведомления Windows при высоком ping или потерях")
        )
        self.network_alarm_checkbox.toggled.connect(controller._save_network_alarm_settings)
        ping_alarm_label = QLabel(controller._tr("Ping >"))
        ping_alarm_label.setObjectName("Muted")
        self.network_ping_alarm_spin = QSpinBox()
        self.network_ping_alarm_spin.setRange(50, 2000)
        self.network_ping_alarm_spin.setValue(int(controller._network_ping_alarm_threshold))
        self.network_ping_alarm_spin.setSuffix(" ms")
        self.network_ping_alarm_spin.setFixedWidth(82)
        self.network_ping_alarm_spin.valueChanged.connect(controller._save_network_alarm_settings)
        loss_alarm_label = QLabel(controller._tr("Потери >"))
        loss_alarm_label.setObjectName("Muted")
        self.network_loss_alarm_spin = QDoubleSpinBox()
        self.network_loss_alarm_spin.setRange(0.1, 100.0)
        self.network_loss_alarm_spin.setDecimals(1)
        self.network_loss_alarm_spin.setValue(float(controller._network_loss_alarm_threshold))
        self.network_loss_alarm_spin.setSuffix(" %")
        self.network_loss_alarm_spin.setFixedWidth(78)
        self.network_loss_alarm_spin.valueChanged.connect(controller._save_network_alarm_settings)
        alarms_layout.addWidget(self.network_alarm_checkbox)
        alarms_layout.addWidget(ping_alarm_label)
        alarms_layout.addWidget(self.network_ping_alarm_spin)
        alarms_layout.addWidget(loss_alarm_label)
        alarms_layout.addWidget(self.network_loss_alarm_spin)
        alarms_layout.addStretch(1)
        panel_layout.addLayout(alarms_layout)

        self.embedded_dropdown = QFrame(panel)
        self.embedded_dropdown.setObjectName("EmbeddedDropdown")
        dropdown_layout = QVBoxLayout(self.embedded_dropdown)
        dropdown_layout.setContentsMargins(6, 6, 6, 6)
        dropdown_layout.setSpacing(0)
        self.embedded_dropdown_list = QListWidget(self.embedded_dropdown)
        keep_wheel_scroll_local(self.embedded_dropdown_list)
        self.embedded_dropdown_list.setObjectName("EmbeddedDropdownList")
        self.embedded_dropdown_list.setMaximumHeight(180)
        self.embedded_dropdown_list.itemActivated.connect(controller._select_embedded_dropdown_item)
        self.embedded_dropdown_list.itemClicked.connect(controller._select_embedded_dropdown_item)
        dropdown_layout.addWidget(self.embedded_dropdown_list)
        self.embedded_dropdown.hide()
        controller._active_embedded_combo: QComboBox | None = None
        panel_layout.addWidget(self.embedded_dropdown)
