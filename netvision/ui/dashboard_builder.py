"""Build the dashboard shell and its workspaces."""

from __future__ import annotations
from PySide6.QtWidgets import QSizePolicy, QStackedWidget, QTabWidget, QVBoxLayout, QWidget
from netvision.core.ping_benchmark import latency_statistics
from netvision.core.system_actions import flush_dns_cache
from netvision.ui.lite_mode import LiteStatus
from netvision.ui.workspaces.tcp_audit import TcpAuditWorkspace
from netvision.ui.workspaces.tls_audit import TlsAuditWorkspace
from netvision.ui.workspaces.mtr_audit import MtrWorkspace
from netvision.ui.workspaces.loss_audit import LossWorkspace
from netvision.ui.workspaces.jitter_audit import JitterWorkspace
from netvision.ui.workspaces.quality_nat_audit import QualityNatWorkspace
from netvision.ui.workspaces.bufferbloat_audit import BufferbloatWorkspace
from netvision.ui.workspaces.history_journal import (
    HistoryWorkspace,
    UdpHistoryWorkspace,
    JournalWorkspace,
)
from netvision.ui.workspaces.topology_path import TopologyPathWorkspace
from netvision.ui.workspaces.dns_audit import DnsWorkspace
from netvision.ui.workspaces.overview_panel import (
    LiteView,
    AnalysisView,
    InterfacesView,
    NodeDetailsView,
)
from netvision.ui.workspaces.header_panel import HeaderPanel
from netvision.ui.workspaces.process_selector import ProcessSelector
from netvision.ui.workspaces.ping_audit import PingWorkspace
from netvision.ui.workspaces.expert_view import ExpertView
from netvision.ui.workspaces.core_workspace import CoreOverviewWorkspace
from netvision.ui.workspaces.system_network import SystemNetworkWorkspace
from netvision.ui.controllers.tcp_audit import TcpAuditController
from netvision.ui.controllers.tls_audit import TlsAuditController
from netvision.ui.controllers.mtr_audit import MtrController
from netvision.ui.controllers.loss_audit import LossController
from netvision.ui.controllers.ping_audit import PingController
from netvision.ui.controllers.jitter_audit import JitterController
from netvision.ui.controllers.dns_audit import DnsController
from netvision.ui.controllers.mtu_optimizer import MtuController
from netvision.ui.controllers.process_controller import ProcessController
from netvision.ui.controllers.overview_controller import OverviewController
from netvision.ui.components import factory


class DashboardBuilder:
    def __init__(self, metric_card, sparkline_widget):
        self.metric_card = metric_card
        self.sparkline_widget = sparkline_widget

    def build_main_layout(self, host) -> None:
        central = QWidget()
        central.setObjectName("AppSurface")
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)
        host.setCentralWidget(central)
        host.core_workspace = CoreOverviewWorkspace(host, self.metric_card, self.sparkline_widget)
        host.overview_controller = OverviewController(host.core_workspace, host._facts, parent=host)
        host.header_panel = HeaderPanel(host)
        root.addWidget(host.header_panel)
        root.addWidget(host.core_workspace._build_controls())
        host.process_selector_panel = ProcessSelector(host)
        host.process_controller = ProcessController(
            host.process_selector_panel, host._facts, parent=host
        )
        host.state_synchronizer._update_monitor_scope_label(host._monitor_scope())
        root.addWidget(host.process_selector_panel)
        host.mode_stack = QStackedWidget()
        host.expert_view = ExpertView(host)
        host.expert_view.assemble(
            host.core_workspace.topology_panel(),
            self.build_tabs(host),
            host.core_workspace.quick_actions(),
        )
        host.lite_panel = LiteView()
        host.lite_view = host.lite_panel
        host._set_lite_status_style(LiteStatus.WARNING)
        host.dns_workspace = DnsWorkspace(host.core_workspace._build_quick_fix_panel("dns"))
        host.dns_controller = DnsController(
            host.dns_workspace, host._facts, host._worker_registry, parent=host
        )
        host.dns_view = host.dns_workspace
        host.dns_workspace.dns_back_button.clicked.connect(host._close_dns_workspace)
        host.dns_workspace.dns_geohide_button.clicked.connect(host._open_geohide_dialog)
        host.dns_workspace.dns_flush_button.clicked.connect(
            lambda: host._run_system_action(
                "Очистка DNS", flush_dns_cache, host.dns_workspace.dns_flush_button
            )
        )
        host.dns_controller._render_dns_info()
        host.dns_controller._render_dns_profiles()
        host.ping_workspace = PingWorkspace(host)
        host.mtu_controller = MtuController(
            host.mtu_workspace, host._facts, host._worker_registry, parent=host
        )
        host.ping_controller = PingController(
            host.ping_workspace, host._facts, host._worker_registry, parent=host
        )
        host.ping_view = host.ping_workspace
        host.ping_controller._render_ping_matrix_placeholders()
        host._render_quality_mtu_placeholders()
        host.ping_controller._set_ping_statistics(latency_statistics((), th=host._thresholds))
        host.loss_workspace = LossWorkspace(
            host._tr,
            host._make_network_boost_button(),
            host.core_workspace._build_quick_fix_panel("loss"),
        )
        host.loss_controller = LossController(
            host.loss_workspace, host._facts, host._worker_registry, parent=host
        )
        host.loss_view = host.loss_workspace
        host.loss_workspace.loss_back_button.clicked.connect(host._close_loss_workspace)
        host.loss_workspace.loss_game_auto_button.clicked.connect(host._open_game_auto_check)
        host._set_loss_snapshot(host._loss_analyzer_snapshot())
        host.loss_controller._render_loss_stress_placeholders()
        host.tcp_workspace = TcpAuditWorkspace()
        host.tcp_controller = TcpAuditController(host.tcp_workspace, host._facts, parent=host)
        host.tcp_view = host.tcp_workspace
        host.tcp_workspace.tcp_back_button.clicked.connect(host._close_tcp_workspace)
        host.tcp_workspace.tcp_socket_details_button.clicked.connect(
            host._show_selected_tcp_socket_details
        )
        host.tcp_workspace.tcp_reset_stack_button.clicked.connect(host._request_tcp_stack_reset)
        host.tcp_workspace.tcp_sockets_table.itemSelectionChanged.connect(
            host._update_tcp_socket_selection
        )
        host.tcp_workspace.quick_fix_layout.addWidget(
            host.core_workspace._build_quick_fix_panel("tcp")
        )
        host.tcp_controller._render_tcp_port_placeholders()
        host.tls_workspace = TlsAuditWorkspace()
        host.tls_controller = TlsAuditController(host.tls_workspace, host._facts, parent=host)
        host.tls_view = host.tls_workspace
        host.tls_workspace.tls_back_button.clicked.connect(host._close_tls_workspace)
        host.tls_workspace.tls_copy_fingerprint_button.clicked.connect(host._copy_tls_fingerprint)
        host._render_tls_placeholders()
        host.jitter_workspace = JitterWorkspace(
            host._make_network_boost_button(),
            host._translator.format,
            host._thresholds.jitter_spike_ms,
        )
        host.jitter_controller = JitterController(
            host.jitter_workspace, host._facts, host._worker_registry, parent=host
        )
        host.jitter_view = host.jitter_workspace
        host.jitter_workspace.jitter_back_button.clicked.connect(host._close_jitter_workspace)
        host.jitter_controller._refresh_jitter_workspace()
        host.mode_stack.addWidget(host.expert_view)
        host.mode_stack.addWidget(host.lite_view)
        host._mount_dns_workspace()
        host.mode_stack.addWidget(host.ping_view)
        host.mode_stack.addWidget(host.loss_view)
        host.mode_stack.addWidget(host.tcp_view)
        host.mode_stack.addWidget(host.tls_view)
        host.mode_stack.addWidget(host.jitter_view)
        host.mode_scroll = factory.make_scroll_area(host.mode_stack)
        host.mode_scroll.setObjectName("ModeScrollArea")
        root.addWidget(host.mode_scroll, 1)
        host._schedule_responsive_layout_update()

    def build_tabs(self, host) -> QTabWidget:
        tabs = QTabWidget()
        host.workspace_tabs = tabs
        tabs.setMinimumWidth(0)
        tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        host.node_details = NodeDetailsView()
        tabs.addTab(host.node_details, "Обзор")
        host.path_workspace = TopologyPathWorkspace()
        tabs.addTab(host.path_workspace, "Маршруты / Geo")
        host.mtr_workspace = MtrWorkspace(
            host._tr,
            (
                host.core_workspace.target_input.text().strip()
                if hasattr(getattr(host, "core_workspace", None), "target_input")
                else ""
            ),
        )
        host.mtr_controller = MtrController(
            host.mtr_workspace, host._facts, host._worker_registry, parent=host
        )
        tabs.addTab(host.mtr_workspace, "Трассировка")
        host.interfaces_panel = InterfacesView()
        tabs.addTab(host.interfaces_panel, "Интерфейсы")
        host.journal_tabs = QTabWidget()
        host.journal_tabs.setObjectName("JournalModeTabs")
        host.journal_workspace = JournalWorkspace()
        host.journal_workspace.journal_layer_filter.currentIndexChanged.connect(
            lambda _index: host._render_journal()
        )
        host.journal_workspace.journal_include_past_sessions.toggled.connect(
            lambda _checked: host._render_journal()
        )
        host.journal_workspace.export_journal_json_button.clicked.connect(
            lambda: host._export_journal("json")
        )
        host.journal_workspace.export_journal_csv_button.clicked.connect(
            lambda: host._export_journal("csv")
        )
        host.journal_workspace.clear_journal_button.clicked.connect(host._clear_journal)
        host._retranslate_journal_filter()
        host._render_journal()
        host.journal_tabs.addTab(host.journal_workspace, host._tr("Журнал сессии"))
        host.udp_history_workspace = UdpHistoryWorkspace()
        host.history_controller.watch_tables()
        host.udp_history_workspace.udp_anomaly_filter.toggled.connect(host._refresh_udp_event_table)
        host.udp_history_workspace.export_udp_json_button.clicked.connect(
            host._export_udp_events_json
        )
        host.udp_history_workspace.export_udp_csv_button.clicked.connect(
            host._export_udp_events_csv
        )
        host.journal_tabs.addTab(host.udp_history_workspace, host._tr("UDP-события"))
        tabs.addTab(host.journal_tabs, host._tr("Журнал и UDP"))
        host.log_content_tab = host.journal_tabs.widget(0)
        host.log_tab = host.journal_tabs
        host.analysis_panel = AnalysisView()
        tabs.addTab(host.analysis_panel, "Диагноз")
        host.quality_workspace = QualityNatWorkspace(host._tr)
        host.quality_workspace.quality_test_button.clicked.connect(host.start_quality_check)
        host.quality_workspace.nat_probe_button.clicked.connect(host.start_nat_probe)
        host.quality_workspace.quality_export_image_button.clicked.connect(
            lambda: host._export_widget_png(host.quality_workspace, "Качество")
        )
        tabs.addTab(host.quality_workspace, "Качество")
        host.bufferbloat_workspace = BufferbloatWorkspace(
            host._tr, host._make_network_boost_button()
        )
        host.bufferbloat_recommendation_sources: tuple[str, ...] = ()
        host.bufferbloat_workspace.bufferbloat_start_button.clicked.connect(
            host.start_bufferbloat_test
        )
        host.bufferbloat_workspace.bufferbloat_export_image_button.clicked.connect(
            lambda: host._export_widget_png(host.bufferbloat_workspace, "Bufferbloat")
        )
        tabs.addTab(host.bufferbloat_workspace, "Bufferbloat")
        host.history_workspace = HistoryWorkspace(host._tr)
        host.history_workspace.history_refresh_button.clicked.connect(host._refresh_history_view)
        host.history_workspace.history_clear_button.clicked.connect(host._clear_test_history)
        host._refresh_history_view()
        tabs.addTab(host.history_workspace, "История / Тренды")
        host.system_network_workspace = SystemNetworkWorkspace(host)
        tabs.addTab(host.system_network_workspace, "Системная сеть")
        return tabs
