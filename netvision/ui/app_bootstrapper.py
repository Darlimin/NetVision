"""Initialise dashboard state and Qt infrastructure."""

from __future__ import annotations
from collections import deque
from PySide6.QtCore import QSettings, QThread, QTimer
from PySide6.QtWidgets import QAbstractButton, QMenu, QLabel, QPushButton, QWidgetAction
from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo
from netvision.core.dns_benchmark import PUBLIC_DNS_PROFILES, DnsResolverProfile
from netvision.core.packet_loss import PacketLossAnalyzer
from netvision.core.ping_benchmark import RegionalPingResult, RegionalPingTarget
from netvision.core.bufferbloat import BufferbloatReport
from netvision.core.system import DnsConfiguration
from netvision.core.system_actions import SystemChange
from netvision.core.session_journal import JournalStore, SessionJournal
from netvision.core.session import Scope, StateStore
from netvision.core.rust_backend import rust_parser_availability
from netvision.core.test_history import TestHistoryStore
from netvision.core.internet_quality import InternetQualityReport, PublicIpAddresses
from netvision.core.nat_diagnostics import NatReport
from netvision.core.tls_diagnostics import TlsAuditResult
from netvision.core.udp_monitor import UdpPortActivity, UdpPortSnapshot
from netvision.core.mtu_optimizer import MtuOptimizerReport
from netvision.core.models import PendingAction
from netvision.core.thresholds import DEFAULT_THRESHOLDS
from netvision.core.traceroute import MtrSnapshot
from netvision.models import WifiSnapshot, DiagnosticReport, MonitorScope
from netvision.ui.dialogs import GeoHideDialog, RollbackConfirmDialog
from netvision.ui.game_check_worker import GameAutoCheckWorker
from netvision.ui.legacy_workers import (
    DiagnosticWorker,
    ProcessScanWorker,
    ProcessSocketsWorker,
    SystemActionWorker,
    TracerouteWorker,
)
from netvision.ui.legacy_workers import (
    BufferbloatWorker,
    InternetQualityWorker,
    NatProbeWorker,
    PingBenchmarkWorker,
)
from netvision.ui.legacy_dialogs import NetworkBoostDialog
from netvision.ui.legacy_workers import (
    DnsBenchmarkWorker,
    DnsConfigurationWorker,
    GameLaunchMonitorWorker,
    MtuOptimizerWorker,
    NetworkBoostScanWorker,
    NetworkBoostTerminateWorker,
    PacketLossTestWorker,
    TcpDiagnosticsWorker,
    TlsAuditWorker,
    UdpStressWorker,
)
from netvision.ui.monitor_workers import (
    LatencyMonitorWorker,
    MtrMonitorWorker,
    UdpPortMonitorWorker,
    WifiMonitorWorker,
    WifiSignalTracker,
    WorkerRegistry,
)
from netvision.ui.i18n import UiTranslator
from netvision.ui.ui_models import HeaderAnomalyEvent, JitterEventRow, UdpEventRow
from netvision.ui.controllers.state_synchronizer import StateSynchronizer
from netvision.ui.controllers.diagnostics_coordinator import DiagnosticsCoordinator
from netvision.ui.controllers.udp_controller import UdpController
from netvision.ui.controllers.wifi_controller import WifiController
from netvision.ui.controllers.game_monitor_controller import GameMonitorController
from netvision.ui.dashboard_builder import DashboardBuilder
from netvision.ui.controllers.teardown_coordinator import TeardownCoordinator
from netvision.ui.events import AppEventBus
from netvision.ui.event_router import EventRouter
from netvision.ui.timer_registry import TimerRegistry
from netvision.ui.controllers.history_controller import HistoryController
from netvision.ui.controllers.alarms_controller import AlarmsController
from netvision.ui.constants import QUICK_PRESETS
from netvision.version import window_title


class AppBootstrapper:
    def bootstrap(self, host, bootstrap, metric_card, sparkline_widget, dispatcher_type):
        host._dashboard_ready = False
        host._dashboard_autoprobe = bootstrap
        host._dashboard_regions_probed = False
        host._dashboard_tls_generation = 0
        host._dashboard_tls_audit_generation = 0
        host._dashboard_histories = {
            name: deque(maxlen=30)
            for name in ("dns", "ping", "loss", "jitter", "tcp", "tls", "latency")
        }
        host._dashboard_events: deque[str] = deque(maxlen=5)
        host._dashboard_syncing = False
        host._dashboard_closing = False
        host._dashboard_bootstrap_timer: QTimer | None = None
        host._dashboard_local_thread = None
        host._dashboard_game_connection = None
        host._dashboard_game_metrics: tuple[float | None, float, bool] | None = None
        host._dashboard_last_cause = ""
        host._dashboard_hop_histories: dict[int, deque[float]] = {}
        host._dashboard_hop_addresses: dict[int, str] = {}
        host._dashboard_selected_hop: int | None = None
        host._dashboard_mtu_hint_chips: tuple[QPushButton, ...] = ()
        host._facts = StateStore()
        host._run_scope: Scope | None = None
        host.setWindowTitle(window_title())
        host.resize(1280, 820)
        host.setMinimumSize(960, 680)
        host._thread: QThread | None = None
        host._worker: DiagnosticWorker | None = None
        host._report: DiagnosticReport | None = None
        host._diagnostic_failure_text: str | None = None
        host._thresholds = DEFAULT_THRESHOLDS
        host._selected_process: ProcessNetworkInfo | None = None
        host._selected_connection: ProcessConnection | None = None
        host._connection_pick_auto = False
        host._endpoint_choice_state: tuple[str, int, str, int, str] | None = None
        host._published_monitor_scope: MonitorScope | None = None
        host._system_action_threads: set[QThread] = set()
        host._system_action_workers: dict[QThread, SystemActionWorker] = {}
        host._system_action_status: dict[QPushButton, QLabel] = {}
        host._rollback_actions: dict[str, tuple[SystemChange, PendingAction]] = {}
        host.quick_fix_status: dict[str, QLabel] = {}
        host.quick_fix_buttons: dict[str, list[QPushButton]] = {}
        host._process_scan_thread: QThread | None = None
        host._process_scan_worker: ProcessScanWorker | None = None
        host._process_sockets_thread: QThread | None = None
        host._process_sockets_worker: ProcessSocketsWorker | None = None
        host._process_sockets_pid: int | None = None
        host._process_sockets_report: DiagnosticReport | None = None
        host._vpn_process_sockets: ProcessNetworkInfo | None = None
        host._vpn_process_sockets_ready = False
        host._network_boost_scan_thread: QThread | None = None
        host._network_boost_scan_worker: NetworkBoostScanWorker | None = None
        host._network_boost_terminate_thread: QThread | None = None
        host._network_boost_terminate_worker: NetworkBoostTerminateWorker | None = None
        host._network_boost_dialog: NetworkBoostDialog | None = None
        host._network_boost_buttons: list[QPushButton] = []
        host._udp_monitor_thread: QThread | None = None
        host._udp_monitor_worker: UdpPortMonitorWorker | None = None
        host._udp_monitor_pid: int | None = None
        host._udp_monitor_warning: str | None = None
        host._last_udp_snapshot: UdpPortSnapshot | None = None
        host._udp_activity_history: list[UdpPortActivity] = []
        host._udp_event_rows: list[UdpEventRow] = []
        host._quality_thread: QThread | None = None
        host._quality_worker: InternetQualityWorker | None = None
        host._quality_report: InternetQualityReport | None = None
        host._nat_thread: QThread | None = None
        host._nat_worker: NatProbeWorker | None = None
        host._nat_report: NatReport | None = None
        host._bufferbloat_thread: QThread | None = None
        host._bufferbloat_worker: BufferbloatWorker | None = None
        host._bufferbloat_report: BufferbloatReport | None = None
        host._game_monitor_thread: QThread | None = None
        host._game_monitor_worker: GameLaunchMonitorWorker | None = None
        host._latency_thread: QThread | None = None
        host._latency_worker: LatencyMonitorWorker | None = None
        host._wifi_thread: QThread | None = None
        host._wifi_worker: WifiMonitorWorker | None = None
        host._wifi_snapshot: WifiSnapshot | None = None
        host._wifi_signal_low = False
        host._wifi_signal_tracker = WifiSignalTracker()
        host._wifi_probe_state: str | None = None
        host._worker_registry = WorkerRegistry(host)
        host.udp_controller = UdpController(host)
        host.wifi_controller = WifiController(host)
        host.game_monitor_controller = GameMonitorController(host)
        host.event_bus = AppEventBus(host)
        host.event_router = EventRouter(host, host.event_bus)
        host.event_router.setup_registry()
        host._ui_dispatcher = dispatcher_type(host)
        host._closing = False
        host.timer_registry = TimerRegistry(host)
        host._responsive_layout_timer = host.timer_registry.responsive_layout
        host._task_button_states: dict[QAbstractButton, tuple[str, str]] = {}
        host._task_button_timer = host.timer_registry.task_buttons
        host.event_router.setup_layout_timers()
        host._task_button_phase = 0
        host._dns_benchmark_thread: QThread | None = None
        host._dns_benchmark_worker: DnsBenchmarkWorker | None = None
        host._dns_config_thread: QThread | None = None
        host._dns_config_worker: DnsConfigurationWorker | None = None
        host._dns_configuration: DnsConfiguration | None = None
        host._dns_public_addresses: PublicIpAddresses | None = None
        host._geohide_dialog: GeoHideDialog | None = None
        host._ping_benchmark_thread: QThread | None = None
        host._ping_benchmark_worker: PingBenchmarkWorker | None = None
        host._mtu_optimizer_thread: QThread | None = None
        host._mtu_optimizer_worker: MtuOptimizerWorker | None = None
        host._mtu_optimizer_report: MtuOptimizerReport | None = None
        host._mtu_optimizer_active_button: QPushButton | None = None
        host._mtu_trial_probe_thread: QThread | None = None
        host._mtu_trial_probe_ok: bool | None = None
        host._mtu_trial_dialog: RollbackConfirmDialog | None = None
        host._mtu_trial_change: SystemChange | None = None
        host._mtu_rollback_reasons: dict[str, str] = {}
        host._preferred_ping_target: RegionalPingTarget | None = None
        host._ping_matrix_results: tuple[RegionalPingResult, ...] = ()
        host._loss_test_thread: QThread | None = None
        host._loss_test_worker: PacketLossTestWorker | None = None
        host._udp_stress_thread: QThread | None = None
        host._udp_stress_worker: UdpStressWorker | None = None
        host._traceroute_thread: QThread | None = None
        host._traceroute_worker: TracerouteWorker | None = None
        host._mtr_thread: QThread | None = None
        host._mtr_worker: MtrMonitorWorker | None = None
        host._mtr_snapshot: MtrSnapshot | None = None
        host._mtr_stop_logged = False
        host._test_history_store = TestHistoryStore()
        host._test_history_records = host._test_history_store.load()
        host._journal_store = JournalStore()
        host._journal = SessionJournal.create(host._journal_store)
        host._tcp_diagnostics_thread: QThread | None = None
        host._tcp_diagnostics_worker: TcpDiagnosticsWorker | None = None
        host._tls_audit_thread: QThread | None = None
        host._tls_audit_worker: TlsAuditWorker | None = None
        host._tls_audit_result: TlsAuditResult | None = None
        host._dns_profiles: list[DnsResolverProfile] = list(PUBLIC_DNS_PROFILES)
        host._latency_window: list[float | None] = []
        host._ping_spike_events: list[str] = []
        host._jitter_events: list[JitterEventRow] = []
        host._jitter_deviations: list[float] = []
        host._jitter_previous_rtt: float | None = None
        host._jitter_episode_tracker = host._new_jitter_episode_tracker()
        host._jitter_episode_row_index: int | None = None
        host._jitter_timeout_row_index: int | None = None
        host._rtt_episode_tracker = host._new_rtt_episode_tracker()
        host._rtt_episode_log_index: int | None = None
        host._jitter_target_host = (
            host.core_workspace.target_input.text().strip()
            if hasattr(getattr(host, "core_workspace", None), "target_input")
            else ""
        )
        host._loss_analyzer = PacketLossAnalyzer(th=host._thresholds)
        host._previous_workspace = "expert"
        host._active_preset: str | None = None
        host._theme = "dark"
        host._translator = UiTranslator("ru", host)
        host._language = host._translator.language
        host._session_elapsed_seconds = 0
        host._session_timer = host.timer_registry.session
        host.event_router.setup_session()
        host._header_anomaly_state = "good"
        host._header_anomaly_source = "Связь стабильна"
        host._header_anomaly_values: dict[str, object] = {}
        host._header_anomaly_history: deque[HeaderAnomalyEvent] = deque(maxlen=5)
        host._last_header_anomaly_signature: tuple[str, str] | None = None
        host._header_anomaly_menu: QMenu | None = None
        host._header_anomaly_action: QWidgetAction | None = None
        host._preset_defaults = {name: (name, host, port) for name, host, port in QUICK_PRESETS}
        host._preset_settings = QSettings()
        host._alarm_settings = QSettings()
        host._background_enabled = host._alarm_settings.value(
            "background/enabled", False, type=bool
        )
        host._background_auto_monitor = host._alarm_settings.value(
            "background/auto_monitor", False, type=bool
        )
        host._notifications_paused = host._alarm_settings.value(
            "background/notifications_paused", False, type=bool
        )
        host._quit_requested = False
        host._background_hidden = False
        host._auto_monitor_active = False
        host._auto_monitor_thread: QThread | None = None
        host._auto_monitor_worker: GameAutoCheckWorker | None = None
        host._last_network_alarm_at: dict[str, float] = {}
        host._network_alarm_enabled = host._alarm_settings.value(
            "network_health/alarms_enabled", True, type=bool
        )
        host._network_ping_alarm_threshold = host._alarm_settings.value(
            "network_health/ping_threshold_ms", int(DEFAULT_THRESHOLDS.rtt_high_ms), type=int
        )
        host._network_loss_alarm_threshold = host._alarm_settings.value(
            "network_health/loss_threshold_percent", 3.0, type=float
        )
        host._preset_profiles = host._load_preset_profiles()
        host.preset_buttons: dict[str, QPushButton] = {}
        host.state_synchronizer = StateSynchronizer(host, host._facts, host.event_bus)
        host.diagnostics_coordinator = DiagnosticsCoordinator(host, host._facts, host.event_bus)
        host.history_controller = HistoryController(host, host._facts, parent=host)
        host.alarms_controller = AlarmsController(host, host._facts, parent=host)
        host.event_router.setup_wiring()
        host.teardown_coordinator = TeardownCoordinator(host)
        DashboardBuilder(metric_card, sparkline_widget).build_main_layout(host)
        host.history_controller.workspace = host.history_workspace
        host.alarms_controller.workspace = host.core_workspace
        host._setup_network_health_tray()
        host.process_selector_panel.game_monitor_checkbox.setChecked(host._background_auto_monitor)
        host._refresh_session_capsule()
        host._set_status("READY", "idle")
        host._append_log("NetVision готов к диагностике")
        host._retranslate_ui(host._language)
        host._dashboard_settings = QSettings()
        host._install_dashboard_shell()
        host._dashboard_ready = True
        host._dashboard_set_waiting_state()
        host._dashboard_sync_controls()
        host.process_controller._dashboard_sync_process_choices()
        ping_native, tracert_native = rust_parser_availability()
        rust_status = (
            f"Rust: ping={'активен' if ping_native else 'Python'}, "
            f"tracert={'активен' if tracert_native else 'Python'}"
        )
        host._append_log(rust_status)
        if bootstrap:
            host._dashboard_bootstrap_timer = host.timer_registry.create_bootstrap()
            host.event_router.setup_bootstrap()
            host._dashboard_bootstrap_timer.start(0)
