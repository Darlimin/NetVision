"""Shared overview components."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QLayout,
    QStackedWidget,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from netvision.core.system_actions import (
    flush_dns_cache,
    open_network_adapters,
    open_network_proxy_settings,
    open_windows_firewall,
)
from netvision.ui import constants as ui_constants
from netvision.ui.presentation import GAME_AUTO_HELP, GAME_PRESET_HELP, LATENCY_HELP, METRIC_HELP
from netvision.ui.components import factory
from netvision.ui.widgets import TopologyWidget, apply_accent_glow, apply_panel_shadow
from netvision.version import display_version


class CoreOverviewWorkspace(QWidget):
    def __init__(self, controller, metric_card_type, sparkline_type) -> None:
        super().__init__()
        self.controller = controller
        self.metric_card_type = metric_card_type
        self.sparkline_type = sparkline_type

    def quick_actions(self) -> QFrame:
        panel = QFrame()
        self.quick_actions_panel = panel
        panel.setObjectName("QuickActions")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)

        title = QLabel("БЫСТРЫЕ СИСТЕМНЫЕ ДЕЙСТВИЯ WINDOWS")
        title.setObjectName("QuickActionsTitle")
        layout.addWidget(title)

        self.flush_dns_button = self.controller._make_quick_action_button(
            "🔄  Сброс DNS",
            flush_dns_cache,
            primary=True,
        )
        apply_accent_glow(self.flush_dns_button)
        self.adapters_button = self.controller._make_quick_action_button(
            "🖥️  Сетевые адаптеры",
            open_network_adapters,
        )
        self.proxy_settings_button = self.controller._make_quick_action_button(
            "⚙️  Параметры прокси",
            open_network_proxy_settings,
        )
        self.firewall_button = self.controller._make_quick_action_button(
            "🛡️  Брандмауэр",
            open_windows_firewall,
        )
        layout.addWidget(self.flush_dns_button, 1)
        layout.addWidget(self.adapters_button, 1)
        layout.addWidget(self.proxy_settings_button, 1)
        layout.addWidget(self.firewall_button, 1)
        return panel

    def topology_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("SidePanel")
        apply_panel_shadow(panel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        self.topology = TopologyWidget()
        self.topology.node_selected.connect(self.controller._show_node_details)
        scroll = factory.make_scroll_area(self.topology)
        scroll.setObjectName("TopologyScrollArea")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.topology_scroll = scroll
        layout.addWidget(scroll)
        return panel

    def _build_top_row(self) -> QSplitter:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("DashboardTopRowSplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Minimum,
        )

        status_card = factory.new_card()
        status_card.setMinimumWidth(220)
        status_card.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Minimum,
        )
        status_layout = QVBoxLayout(status_card)
        status_layout.setSpacing(7)
        status_layout.addWidget(factory.card_title(self.controller._tr("Статус сети")))
        self.dashboard_status_pill = QLabel()
        self.dashboard_status_pill.setObjectName("StatusPill")
        self.dashboard_status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dashboard_status_subtitle = QLabel()
        self.dashboard_status_subtitle.setObjectName("SubLabel")
        self.dashboard_verdict = QLabel()
        self.dashboard_verdict.setObjectName("SubLabel")
        self.dashboard_verdict.setWordWrap(True)
        self.dashboard_vpn_hint = QLabel()
        self.dashboard_vpn_hint.setObjectName("SubLabel")
        self.dashboard_vpn_hint.setWordWrap(True)
        self.dashboard_vpn_hint.hide()
        status_layout.addWidget(self.dashboard_status_pill)
        status_layout.addWidget(self.dashboard_status_subtitle)
        status_layout.addWidget(self.dashboard_verdict)
        status_layout.addWidget(self.dashboard_vpn_hint)
        splitter.addWidget(status_card)

        process_card = factory.new_card()
        process_card.setMinimumWidth(390)
        process_card.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Minimum,
        )
        process_layout = QGridLayout(process_card)
        process_layout.setContentsMargins(12, 10, 12, 10)
        process_layout.setHorizontalSpacing(8)
        process_layout.setVerticalSpacing(5)
        process_layout.addWidget(
            factory.card_title(self.controller._tr("Процесс и соединение")), 0, 0, 1, 4
        )
        process_layout.addWidget(factory.field_label(self.controller._tr("Процесс")), 1, 0)
        self.dashboard_process_combo = QComboBox()
        self.dashboard_process_combo.setObjectName("DashboardCombo")
        self.dashboard_process_combo.setMinimumWidth(160)
        self.dashboard_process_combo.currentIndexChanged.connect(
            self.controller.process_controller._dashboard_process_selected
        )
        process_layout.addWidget(self.dashboard_process_combo, 1, 1, 1, 3)
        process_layout.addWidget(factory.field_label(self.controller._tr("Сокет процесса")), 2, 0)
        self.dashboard_connection_combo = QComboBox()
        self.dashboard_connection_combo.setObjectName("DashboardCombo")
        self.dashboard_connection_combo.currentIndexChanged.connect(
            self.controller.process_controller._dashboard_connection_selected
        )
        process_layout.addWidget(self.dashboard_connection_combo, 2, 1, 1, 3)
        process_layout.addWidget(factory.field_label(self.controller._tr("Адрес проверки")), 3, 0)
        self.dashboard_target_input = QLineEdit()
        self.dashboard_target_input.setObjectName("DashboardInput")
        self.dashboard_target_input.textChanged.connect(self.controller._dashboard_sync_mtu_target)
        self.dashboard_target_input.textChanged.connect(
            self.controller.process_controller._update_target_mode
        )
        self.dashboard_target_input.textChanged.connect(
            self.controller.tls_workspace.tls_target_input.setText
        )
        self.dashboard_target_input.textChanged.connect(
            self.controller.tcp_workspace.tcp_target_input.setText
        )
        self.dashboard_target_input.textChanged.connect(self.controller._dashboard_reset_tls)
        self.dashboard_target_input.editingFinished.connect(self.controller._dashboard_apply_target)
        process_layout.addWidget(self.dashboard_target_input, 3, 1, 1, 2)
        self.dashboard_port_input = QSpinBox()
        self.dashboard_port_input.setObjectName("DashboardPort")
        self.dashboard_port_input.setRange(1, 65535)
        self.dashboard_port_input.valueChanged.connect(self.controller._dashboard_apply_port)
        self.dashboard_port_input.valueChanged.connect(
            self.controller.tls_workspace.tls_port_input.setValue
        )
        self.dashboard_port_input.valueChanged.connect(self.controller._dashboard_sync_tcp_ports)
        self.dashboard_port_input.valueChanged.connect(self.controller._dashboard_reset_tls)
        process_layout.addWidget(self.dashboard_port_input, 3, 3)
        self.dashboard_target_mode = QLabel(self.controller._tr("Режим: проверка по адресу"))
        self.dashboard_target_mode.setObjectName("SubLabel")
        process_layout.addWidget(self.dashboard_target_mode, 4, 1, 1, 3)
        preset_label = factory.field_label(self.controller._tr("Профили"))
        process_layout.addWidget(preset_label, 5, 0)
        for column, button in enumerate(self.controller.preset_buttons.values(), start=1):
            process_layout.addWidget(button, 5, column, 1, 1)
        self.controller.preset_buttons["Игровой сервер"].setToolTip(
            self.controller._tr(GAME_PRESET_HELP)
        )
        splitter.addWidget(process_card)

        action_card = factory.new_card()
        action_card.setMinimumWidth(220)
        action_layout = QVBoxLayout(action_card)
        action_layout.setSpacing(8)
        action_title = factory.card_title(self.controller._tr("Запустить диагностику"))
        action_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_layout.addWidget(action_title)
        self.dashboard_start_button = QPushButton(self.controller._tr("Начать диагностику"))
        self.dashboard_start_button.setObjectName("StartBtn")
        self.dashboard_start_button.setMinimumWidth(180)
        self.dashboard_start_button.clicked.connect(self.controller._dashboard_start_diagnostics)
        self.dashboard_game_auto_check_button = QPushButton(
            self.controller._tr("Автопроверка игры")
        )
        self.dashboard_game_auto_check_button.setObjectName("SecondaryActionBtn")
        self.dashboard_game_auto_check_button.setToolTip(self.controller._tr(GAME_AUTO_HELP))
        self.dashboard_game_auto_check_button.clicked.connect(self.controller._open_game_auto_check)
        action_layout.addWidget(self.dashboard_start_button)
        action_layout.addWidget(self.dashboard_game_auto_check_button)
        action_layout.addStretch(1)
        splitter.addWidget(action_card)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 4)
        splitter.setStretchFactor(2, 2)

        self.dashboard_top_row_splitter = splitter
        self.controller._restore_dashboard_splitter_state(
            splitter,
            ui_constants.DASHBOARD_TOP_ROW_SPLITTER_STATE_KEY,
            ui_constants.DASHBOARD_TOP_ROW_SPLITTER_DEFAULT_SIZES,
        )
        return splitter

    def _build_metric_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        definitions = ui_constants.DASHBOARD_DASHBOARD_METRIC_DEFINITIONS
        self.dashboard_metric_cards = {}
        for key, title, color in definitions:
            card = self.metric_card_type(title, color)
            card.title.setToolTip(self.controller._tr(METRIC_HELP[key]))
            self.dashboard_metric_cards[key] = card
            row.addWidget(card, 1)
        return row

    def _build_overview_page(self) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setObjectName("DashboardScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setObjectName("DashboardOverviewSplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        top_zone = self._build_overview_top_zone()
        regions_card = self.controller.region_card
        regions_card.setMinimumHeight(190)
        regions_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        events_card = self.controller.events_card
        events_card.setMinimumHeight(108)
        events_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        for zone in (top_zone, regions_card, events_card):
            splitter.addWidget(zone)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 4)
        splitter.setStretchFactor(2, 2)

        self.dashboard_overview_splitter = splitter
        self.controller._restore_dashboard_splitter_state(
            splitter,
            ui_constants.DASHBOARD_SPLITTER_STATE_KEY,
            ui_constants.DASHBOARD_SPLITTER_DEFAULT_SIZES,
        )
        regions_card.hide()
        layout.addWidget(splitter, 1)
        scroll.setWidget(content)
        return scroll

    def _build_quick_fix_panel(self, context: str) -> QFrame:
        panel = QFrame()
        panel.setObjectName("QuickFixPanel")
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        heading = QHBoxLayout()
        title = QLabel("БЫСТРЫЕ РЕШЕНИЯ / QUICK FIXES")
        title.setObjectName("QuickFixTitle")
        status = QLabel("Готово к применению")
        status.setObjectName("QuickFixStatus")
        status.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        heading.addWidget(title)
        heading.addStretch(1)
        heading.addWidget(status)
        layout.addLayout(heading)

        actions = QGridLayout()
        actions.setHorizontalSpacing(8)
        actions.setVerticalSpacing(8)
        definitions = ui_constants.DASHBOARD_QUICK_FIX_DEFINITIONS
        buttons: list[QPushButton] = []
        for index, (action_key, label, primary) in enumerate(definitions):
            button = QPushButton(label)
            button.setObjectName("QuickFixPrimary" if primary else "QuickFixButton")
            button.setAccessibleName(label)
            button.setToolTip(self.controller._quick_fix_tooltip(action_key))
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(
                lambda _checked=False, action_key=action_key, button=button, status=status: self.controller.event_bus.quick_fix_requested.emit(
                    action_key, button, status
                )
            )
            row, column = divmod(index, 2)
            actions.addWidget(button, row, column)
            actions.setColumnStretch(column, 1)
            buttons.append(button)
        layout.addLayout(actions)
        self.controller.quick_fix_status[context] = status
        self.controller.quick_fix_buttons[context] = buttons
        return panel

    def _build_controls(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("ControlBar")
        apply_panel_shadow(panel)
        layout = QGridLayout(panel)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setHorizontalSpacing(7)
        layout.setVerticalSpacing(6)
        self.control_layout = layout

        host_label = QLabel("АДРЕС")
        host_label.setObjectName("FieldLabel")
        self.target_input = QLineEdit("example.com")
        self.target_input.setPlaceholderText("example.com или https://example.com")
        self.target_input.setClearButtonEnabled(True)
        self.target_input.returnPressed.connect(self.controller.start_diagnostic)

        preset_label = QLabel("ПРОФИЛЬ")
        preset_label.setObjectName("FieldLabel")
        preset_group = QButtonGroup(self)
        preset_group.setExclusive(True)
        for profile_id in self.controller._preset_defaults:
            button = QPushButton()
            button.setObjectName("PresetButton")
            button.setCheckable(True)
            button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            button.clicked.connect(
                lambda _checked=False, profile_id=profile_id: self.controller._apply_preset(
                    profile_id
                )
            )
            button.customContextMenuRequested.connect(
                lambda _position, profile_id=profile_id: self.controller._edit_preset(profile_id)
            )
            preset_group.addButton(button)
            self.controller.preset_buttons[profile_id] = button
            self.controller._update_preset_button(profile_id)

        self.port_label = QLabel("ПОРТ")
        port_label = self.port_label
        port_label.setObjectName("FieldLabel")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)
        self.controller._set_translatable_tooltip(
            self.port_input,
            "Сетевой порт целевого узла.",
            "• 443 — для защищенных HTTPS-соединений и большинства веб-серверов",
            "• 80 — для обычных HTTP-соединений",
            "Оставьте стандартное значение, если не уверены.",
        )
        self.port_input.setFixedWidth(108)

        self.start_button = QPushButton("Запустить диагностику")
        self.start_button.clicked.connect(self.controller.start_diagnostic)

        self._control_host_label = host_label
        self._control_preset_label = preset_label
        self.controller.state_synchronizer._reflow_control_bar(compact=False)
        return panel

    def _build_dashboard_port_tls(self) -> QWidget:
        scroll = self.controller.tls_view.findChild(QScrollArea, "TlsWorkspaceScroll")
        content = scroll.takeWidget()
        scroll.setParent(None)
        self.controller.tls_view.layout().addWidget(content)

        tcp = QWidget()
        layout = QVBoxLayout(tcp)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        tcp_scroll = self.controller.tcp_view.findChild(QScrollArea, "TcpWorkspaceScroll")
        if tcp_scroll is not None:
            tcp_content = tcp_scroll.takeWidget()
            tcp_scroll.setParent(None)
            tcp_content.setParent(None)
        metrics = tcp_content.findChild(QFrame, "TcpMetricsPanel")
        ports = tcp_content.findChild(QFrame, "TcpPortsPanel")
        sockets = tcp_content.findChild(QFrame, "TcpSocketsPanel")
        for widget in (self.controller.tcp_workspace.tcp_run_button, metrics, ports, sockets):
            widget.setParent(None)
            layout.addWidget(widget)
            widget.show()
        self.controller.tcp_workspace.tcp_ports_table.setMinimumHeight(100)
        self.controller.tcp_workspace.tcp_sockets_table.setMinimumHeight(100)
        layout.setStretchFactor(ports, 1)
        layout.setStretchFactor(sockets, 1)
        if self.controller.mode_stack.indexOf(self.controller.tcp_view) >= 0:
            self.controller.mode_stack.removeWidget(self.controller.tcp_view)
            self.controller.tcp_view.setParent(None)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(tcp)
        splitter.addWidget(self.controller.tls_view)
        splitter.setSizes([500, 500])
        return splitter

    def _build_hop_history_card(self) -> QFrame:
        card = factory.new_card()
        card.setObjectName("HopHistoryCard")
        card.setMinimumHeight(148)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)
        self.dashboard_hop_history_title = factory.card_title(
            self.controller._tr("Выберите узел в таблице для просмотра графика")
        )
        self.dashboard_hop_history_title.setWordWrap(True)
        self.dashboard_hop_history_chart = self.sparkline_type("#22D3EE", 102)
        self.dashboard_hop_history_chart.setToolTip(
            self.controller._tr(
                "Последние измерения RTT выбранного узла; тайм-ауты не отображаются"
            )
        )
        layout.addWidget(self.dashboard_hop_history_title)
        layout.addWidget(self.dashboard_hop_history_chart, 1)
        return card

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setMinimumWidth(212)
        sidebar.setMaximumWidth(240)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 18, 14, 18)
        layout.setSpacing(6)

        brand = QLabel(f"N  NETVISION {display_version()}")
        brand.setObjectName("DashboardBrand")
        caption = QLabel("Network Diagnostics & Insight")
        caption.setObjectName("SubLabel")
        layout.addWidget(brand)
        layout.addWidget(caption)
        layout.addSpacing(10)

        definitions = ui_constants.DASHBOARD_DASHBOARD_NAV_DEFINITIONS
        self.dashboard_nav_buttons: dict[str, QPushButton] = {}
        for key, label in definitions:
            button = QPushButton(self.controller._tr(label))
            button.setObjectName("NavBtn")
            button.setCheckable(True)
            button.clicked.connect(
                lambda checked=False, item=key: self.controller._show_dashboard_section(item)
            )
            self.dashboard_nav_buttons[key] = button
            layout.addWidget(button)
        self.dashboard_nav_buttons["overview"].setChecked(True)
        layout.addStretch(1)

        self.dashboard_export_button = QPushButton(self.controller._tr("Экспорт отчёта"))
        self.dashboard_export_button.setObjectName("SideActionBtn")
        self.dashboard_export_button.setEnabled(False)
        self.dashboard_export_button.clicked.connect(self.controller._export_report)
        self.dashboard_support_button = QPushButton(self.controller._tr("Пакет для техподдержки"))
        self.dashboard_support_button.setObjectName("SideActionBtn")
        self.dashboard_support_button.setEnabled(False)
        self.dashboard_support_button.clicked.connect(
            self.controller.diagnostics_coordinator._export_support_bundle
        )

        sidebar_tools = QFrame()
        sidebar_tools.setObjectName("SidebarTools")
        tools_layout = QHBoxLayout(sidebar_tools)
        tools_layout.setContentsMargins(6, 6, 6, 6)
        tools_layout.setSpacing(8)
        self.controller.header_panel.language_combo.setMinimumWidth(1)
        self.controller.header_panel.language_combo.setMaximumWidth(sidebar.maximumWidth())
        self.controller.header_panel.language_combo.setFixedHeight(36)
        self.controller.header_panel.language_combo.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Fixed,
        )
        self.controller.header_panel.theme_button.setMinimumWidth(1)
        self.controller.header_panel.theme_button.setMaximumWidth(sidebar.maximumWidth())
        self.controller.header_panel.theme_button.setFixedHeight(36)
        self.controller.header_panel.theme_button.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Fixed,
        )
        tools_layout.addWidget(self.controller.header_panel.language_combo, 1)
        tools_layout.addWidget(self.controller.header_panel.theme_button, 1)
        layout.addWidget(sidebar_tools)
        layout.addWidget(self.dashboard_export_button)
        layout.addWidget(self.dashboard_support_button)
        return sidebar

    def _build_overview_top_zone(self) -> QWidget:
        zone = QWidget()
        zone.setObjectName("DashboardOverviewTopZone")
        zone.setMinimumHeight(ui_constants.DASHBOARD_TOP_ZONE_MINIMUM_HEIGHT)
        zone.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(zone)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        layout.addWidget(self._build_top_row())
        layout.addLayout(self._build_metric_row())
        layout.addLayout(self._build_middle_row())
        return zone

    def _build_middle_row(self) -> QVBoxLayout:
        row = QVBoxLayout()
        row.setSpacing(12)
        chart_card = factory.new_card()
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.addWidget(
            factory.card_title(self.controller._tr("Задержка / Стабильность (60 секунд)"))
        )
        self.dashboard_latency_chart = self.sparkline_type("#34D399", 165)
        self.dashboard_latency_chart.setFixedHeight(165)
        self.dashboard_latency_chart.show_axis = True
        self.dashboard_latency_chart.translate = self.controller._tr
        self.dashboard_latency_chart.setToolTip(self.controller._tr(LATENCY_HELP))
        chart_layout.addWidget(self.dashboard_latency_chart)

        topology_card = factory.new_card()
        topology_layout = QVBoxLayout(topology_card)
        topology_layout.addWidget(factory.card_title(self.controller._tr("Обзор узла / Схема")))
        self.dashboard_topology_label = QLabel()
        self.dashboard_topology_label.setObjectName("TopologySummary")
        self.dashboard_topology_label.setWordWrap(True)
        self.dashboard_topology_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        topology_layout.addWidget(self.dashboard_topology_label, 1)
        row.addWidget(topology_card)
        row.addWidget(chart_card)
        return row

    def _build_details_page(self) -> QWidget:
        page = QWidget()
        page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.dashboard_details_stack = QStackedWidget()
        self.dashboard_details_stack.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self.dashboard_details_stack.addWidget(self.controller.workspace_tabs)
        self.dashboard_details_stack.addWidget(self.controller.dashboard_quality_tabs)
        self.controller.workspace_tabs.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self.dashboard_details_stack, 1)
        self.controller.workspace_tabs.show()
        self.controller.dashboard_quality_tabs.show()
        return page
