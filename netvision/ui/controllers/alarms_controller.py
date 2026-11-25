"""Dashboard alarms orchestration."""

from __future__ import annotations
from collections.abc import Callable
import time
from PySide6.QtCore import QObject, QThread
from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton, QSystemTrayIcon
from netvision.core.system_actions import (
    SystemActionResult,
    reset_tcpip_stack,
    restart_adapter_verified,
)
from netvision.core.session_journal import JournalEvent
from netvision.core.system_actions import flush_dns_cache
from netvision.ui.legacy_workers import SystemActionWorker

from PySide6.QtWidgets import QFrame, QVBoxLayout, QWidgetAction
from shiboken6 import isValid


class AlarmsController(QObject):
    def __init__(self, workspace, facts, parent):
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts

    def _notification_tray(self) -> QSystemTrayIcon | None:

        if not self.host._network_alarm_enabled or self.host._notifications_paused:
            return None

        tray = getattr(self.host, "_network_health_tray", None)

        return tray if tray is not None and tray.isSystemTrayAvailable() else None

    def _notification_message(self, event: JournalEvent) -> str:

        try:
            return self.host._translator.format(event.template, **event.values)

        except (KeyError, ValueError):
            return event.template or event.kind

    def _trigger_quick_fix(self, action_key: str, button: QPushButton, status: QLabel) -> None:

        if action_key == "dns":
            self.host._run_system_action("Сброс кэша DNS", flush_dns_cache, button, status)

            return

        if action_key == "mtu":
            self.host._mtu_optimizer_active_button = button

            self.host.mtu_controller.start_mtu_optimizer()

            return

        adapter = self.host._active_adapter_name()

        if not adapter:
            status.setText(self.host._tr("Активный адаптер не определён"))

            return

        confirmations = {
            "stack": (
                "Сброс TCP/IP",
                "Сбросить TCP/IP и Winsock? Потребуется перезагрузка Windows, а текущие соединения будут закрыты.",
            ),
            "adapter": (
                "Перезапуск адаптера",
                f"Отключить и снова включить адаптер «{adapter}»? Текущее соединение будет временно потеряно.",
            ),
        }

        title, message = confirmations[action_key]

        answer = QMessageBox.question(
            self.host,
            self.host._tr(title),
            self.host._tr(message),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            status.setText(self.host._tr("Действие отменено"))

            return

        actions: dict[str, tuple[str, Callable[[], SystemActionResult]]] = {
            "stack": ("Сброс TCP/IP и Winsock", reset_tcpip_stack),
            "adapter": (
                "Перезапуск адаптера",
                lambda adapter=adapter: restart_adapter_verified(adapter),
            ),
        }

        label, action = actions[action_key]

        self.host._run_system_action(label, action, button, status)

    def _save_network_alarm_settings(self, _value: object = True) -> None:

        if not hasattr(
            getattr(self.host, "process_selector_panel", None), "network_alarm_checkbox"
        ):
            return

        self.host._network_alarm_enabled = (
            self.host.process_selector_panel.network_alarm_checkbox.isChecked()
        )

        self.host._network_ping_alarm_threshold = (
            self.host.process_selector_panel.network_ping_alarm_spin.value()
        )

        self.host._network_loss_alarm_threshold = (
            self.host.process_selector_panel.network_loss_alarm_spin.value()
        )

        self.host._alarm_settings.setValue(
            "network_health/alarms_enabled", self.host._network_alarm_enabled
        )

        self.host._alarm_settings.setValue(
            "network_health/ping_threshold_ms", self.host._network_ping_alarm_threshold
        )

        self.host._alarm_settings.setValue(
            "network_health/loss_threshold_percent", self.host._network_loss_alarm_threshold
        )

    def _run_system_action(
        self,
        label: str,
        action: Callable[[], SystemActionResult],
        button: QPushButton,
        status_label: QLabel | None = None,
    ) -> None:

        if not button.isEnabled():
            return

        self.host._set_task_button_busy(button, True, "Выполняется")

        if status_label is not None:
            status_label.setText(self.host._tr("Выполняется..."))

            self.host._system_action_status[button] = status_label

        self.event_bus.log_requested.emit(f"Запуск системного действия: {label}", "INFO")

        self.event_bus.journal_event_requested.emit(
            "action.system_started",
            {
                "subject": label,
                "template": "Запуск системного действия: {action}",
                "values": {"action": label},
            },
        )

        thread = QThread(self.host)

        worker = SystemActionWorker(label, button, action)

        worker.moveToThread(thread)

        thread.started.connect(worker.run)

        worker.completed.connect(self.host._queue_ui_slot(self.host._on_system_action_completed))

        worker.completed.connect(thread.quit)

        self.host._worker_registry.retain(thread, worker)

        thread.finished.connect(self.host._release_system_action)

        self.host._system_action_threads.add(thread)

        self.host._system_action_workers[thread] = worker

        thread.start()

    def _notify(self, event: JournalEvent) -> None:

        if not self._notification_is_eligible(event):
            return

        tray = self._notification_tray()

        if tray is None or not self._notification_is_due(event):
            return

        tray.showMessage(
            self.host._tr("Ухудшение качества сети"),
            self._notification_message(event),
            QSystemTrayIcon.MessageIcon.Warning,
            5000,
        )

    def _on_system_action_completed(self, label: str, button: QPushButton, result: object) -> None:

        status_label = self.host._finish_system_action_button(button)

        if not isinstance(result, SystemActionResult):
            self.host._handle_unknown_system_action(label, status_label)

            return

        self.host._publish_system_action_result(label, result, status_label)

        if result.success and button is self.host.dns_workspace.dns_apply_button:
            self.host.dns_controller.on_dns_applied()

        if self.host.mtu_controller._handle_mtu_system_action(label, button, result, status_label):
            return

        if self.host._handle_rollback_system_action(label, result):
            return

        if result.success and result.change is not None:
            self.host._confirm_system_change(label, button, status_label, result.change)

    def _release_system_action(self) -> None:

        thread = self.host.sender()

        if not isinstance(thread, QThread):
            return

        self.host._system_action_threads.discard(thread)

        self.host._system_action_workers.pop(thread, None)

    def _notification_is_eligible(self, event: JournalEvent) -> bool:

        severe = {"warning", "error"}

        supported = {"loss.episode", "jitter.episode", "game.session_ended", "mtu.rolled_back"}

        if event.severity not in severe or event.kind not in supported:
            return False

        if event.kind == "loss.episode":
            return event.refs.get("kind") in {"drop", "burst"}

        return event.kind != "jitter.episode" or event.refs.get("kind") != "timeout"

    def _notification_is_due(self, event: JournalEvent) -> bool:

        now = time.monotonic()

        previous = self.host._last_network_alarm_at.get(event.kind, 0.0)

        if now - previous < self.host._thresholds.alarm_cooldown_s:
            return False

        self.host._last_network_alarm_at[event.kind] = now

        return True

    def _set_notification_pause(self, paused: bool) -> None:

        self.host._notifications_paused = paused

        self.host._alarm_settings.setValue("background/notifications_paused", paused)

    def _populate_header_anomaly_menu(self) -> None:
        """Update owned popup widgets without rebuilding the Qt ownership tree."""
        menu = self.host._header_anomaly_menu
        if menu is None or not isValid(menu):
            return
        action = self.host._header_anomaly_action
        if action is None or not isValid(action):
            action = QWidgetAction(menu)
            content = QFrame(menu)
            content.setObjectName("SessionAnomalyMenuContent")
            content.setFixedWidth(322)
            layout = QVBoxLayout(content)
            layout.setContentsMargins(10, 10, 10, 10)
            layout.setSpacing(6)
            self._anomaly_title = QLabel(content)
            self._anomaly_title.setObjectName("SessionAnomalyMenuTitle")
            layout.addWidget(self._anomaly_title)
            self._anomaly_rows = [QLabel(content) for _ in range(8)]
            for row in self._anomaly_rows:
                row.setWordWrap(True)
                layout.addWidget(row)
            self._anomaly_empty = QLabel(content)
            self._anomaly_empty.setObjectName("SessionAnomalyEmptyState")
            self._anomaly_empty.setWordWrap(True)
            layout.addWidget(self._anomaly_empty)
            self._anomaly_open_log = QPushButton(content)
            self._anomaly_open_log.setObjectName("SessionAnomalyOpenLogButton")
            self._anomaly_open_log.clicked.connect(self.host._open_full_log_from_anomaly_menu)
            layout.addWidget(self._anomaly_open_log)
            # Keep the Python wrappers as well as Qt ownership for the popup's lifetime.
            self._anomaly_content = content
            self._anomaly_layout = layout
            self.host._header_anomaly_action = action
            action.setDefaultWidget(content)
            menu.addAction(action)
        self._anomaly_title.setText(self.host._tr("ПОСЛЕДНИЕ АНОМАЛИИ"))
        events = list(reversed(self.host._header_anomaly_history))[:8]
        for index, row in enumerate(self._anomaly_rows):
            active = index < len(events)
            row.setObjectName("SessionAnomalyItem" if active else "SessionAnomalyUnused")
            row.setVisible(active)
            if active:
                event = events[index]
                row.setText(
                    f"{event.observed_at:%H:%M:%S}  -  {self.host._header_anomaly_text(event)}"
                )
                row.setProperty("anomalyState", event.state)
                row.setToolTip(row.text())
        self._anomaly_empty.setVisible(not events)
        self._anomaly_empty.setText(self.host._tr("Нет недавних аномалий"))
        self._anomaly_open_log.setText(self.host._tr("Открыть полный журнал"))
