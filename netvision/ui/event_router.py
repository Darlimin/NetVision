"""Connect the application event bus to its receiving controllers."""

from PySide6.QtCore import Qt

from netvision.ui.events import AppEventBus


class EventRouter:
    def __init__(self, host: object, event_bus: AppEventBus) -> None:
        self.host = host
        self.event_bus = event_bus

    def setup_wiring(self) -> None:
        self.event_bus.log_requested.connect(self.host.history_controller.handle_log_requested)
        self.event_bus.history_update_requested.connect(
            self.host.history_controller.handle_history_requested
        )
        self.event_bus.journal_event_requested.connect(
            self.host.history_controller.handle_journal_requested
        )
        self.event_bus.quick_fix_requested.connect(self.host.alarms_controller._trigger_quick_fix)
        self.event_bus.anomaly_detected.connect(self.host.alarms_controller._notify)

    def setup_registry(self) -> None:
        self.host._worker_registry.idle.connect(
            self.host._finish_monitor_shutdown, Qt.ConnectionType.QueuedConnection
        )
        self.host._ui_log_requested.connect(
            self.host._append_log, Qt.ConnectionType.QueuedConnection
        )

    def setup_layout_timers(self) -> None:
        self.host._responsive_layout_timer.timeout.connect(self.host._update_responsive_layout)
        self.host._task_button_timer.timeout.connect(self.host._animate_task_buttons)

    def setup_session(self) -> None:
        self.host._translator.language_changed.connect(self.host._retranslate_ui)
        self.host._session_timer.timeout.connect(self.host._advance_session_timer)

    def setup_bootstrap(self) -> None:
        self.host._dashboard_bootstrap_timer.timeout.connect(self.host._load_local_network_snapshot)
