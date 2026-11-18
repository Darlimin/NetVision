"""Coordinate safe dashboard shutdown."""

from __future__ import annotations
from PySide6.QtCore import QObject
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon
from netvision.ui import constants as ui_constants
from netvision.ui.utils import _is_thread_alive

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QStyle


class TeardownCoordinator(QObject):
    def __init__(self, host):
        super().__init__(host)
        self.host = host

    def _close(self, host, event: QCloseEvent) -> None:
        action_running = any((_is_thread_alive(thread) for thread in host._system_action_threads))
        if action_running:
            event.ignore()
            QMessageBox.information(
                host,
                "Операция выполняется",
                "Дождитесь завершения текущего системного действия перед закрытием NetVision.",
            )
            return
        process_scan_running = _is_thread_alive(host._process_scan_thread)
        process_sockets_running = _is_thread_alive(host._process_sockets_thread)
        network_boost_scan_running = _is_thread_alive(host._network_boost_scan_thread)
        network_boost_termination_running = _is_thread_alive(host._network_boost_terminate_thread)
        quality_running = _is_thread_alive(host._quality_thread)
        dns_benchmark_running = _is_thread_alive(host._dns_benchmark_thread)
        dns_configuration_running = _is_thread_alive(host._dns_config_thread)
        ping_benchmark_running = _is_thread_alive(host._ping_benchmark_thread)
        mtu_optimizer_running = _is_thread_alive(host._mtu_optimizer_thread)
        tcp_diagnostics_running = _is_thread_alive(host._tcp_diagnostics_thread)
        tls_audit_running = _is_thread_alive(host._tls_audit_thread)
        loss_analysis_running = _is_thread_alive(host._loss_test_thread)
        udp_stress_running = _is_thread_alive(host._udp_stress_thread)
        traceroute_running = _is_thread_alive(host._traceroute_thread)
        blocking_operation = (
            _is_thread_alive(host._thread)
            or process_scan_running
            or process_sockets_running
            or network_boost_scan_running
            or network_boost_termination_running
            or quality_running
            or dns_benchmark_running
            or dns_configuration_running
            or ping_benchmark_running
            or mtu_optimizer_running
            or tcp_diagnostics_running
            or tls_audit_running
            or loss_analysis_running
            or udp_stress_running
            or traceroute_running
        )
        monitor_active = any(
            (
                _is_thread_alive(thread)
                for thread in (
                    host._latency_thread,
                    host._udp_monitor_thread,
                    host._game_monitor_thread,
                    host._mtr_thread,
                    host._wifi_thread,
                )
            )
        )
        tray = getattr(host, "_network_health_tray", None)
        if (
            host._background_enabled
            and tray is not None
            and tray.isSystemTrayAvailable()
            and (not host._quit_requested)
            and monitor_active
            and (not blocking_operation)
        ):
            event.ignore()
            first_background_hide = not host._background_hidden
            host._background_hidden = True
            host.hide()
            if first_background_hide:
                host._record_journal_event(
                    "app.background_entered",
                    subject="application",
                    template="Приложение продолжает мониторинг в фоне",
                )
                if not host._notifications_paused:
                    tray.showMessage(
                        "NetVision",
                        "Мониторинг продолжается в системном трее",
                        QSystemTrayIcon.MessageIcon.Information,
                        4000,
                    )
            return
        if host._bufferbloat_worker is not None:
            host._bufferbloat_worker.stop()
        cancellable_running = (
            dns_benchmark_running
            or dns_configuration_running
            or mtu_optimizer_running
            or tcp_diagnostics_running
        )
        other_running = (
            _is_thread_alive(host._thread)
            or process_scan_running
            or process_sockets_running
            or network_boost_scan_running
            or network_boost_termination_running
            or quality_running
            or ping_benchmark_running
            or tls_audit_running
            or loss_analysis_running
            or udp_stress_running
            or traceroute_running
        )
        if cancellable_running and (not other_running):
            host._closing = True
            host._worker_registry.stop_all()
            host.setEnabled(False)
            host.statusBar().showMessage(host._tr("Завершаем сетевой мониторинг…"))
            event.ignore()
            return
        host.mtr_controller.stop_mtr_monitor("shutdown")
        if (
            _is_thread_alive(host._thread)
            or process_scan_running
            or process_sockets_running
            or network_boost_scan_running
            or network_boost_termination_running
            or quality_running
            or dns_benchmark_running
            or dns_configuration_running
            or ping_benchmark_running
            or mtu_optimizer_running
            or tcp_diagnostics_running
            or tls_audit_running
            or loss_analysis_running
            or udp_stress_running
            or traceroute_running
        ):
            event.ignore()
            QMessageBox.information(
                host,
                "Операция выполняется",
                "Дождитесь завершения текущей операции перед закрытием NetVision.",
            )
            return
        host._closing = True
        host._session_timer.stop()
        host.jitter_controller._sync_jitter_episode(
            "closed", host._jitter_episode_tracker.close("shutdown")
        )
        host._sync_rtt_episode_log("closed", host._rtt_episode_tracker.close("shutdown"))
        host.ping_controller._stop_latency_monitor()
        host._stop_udp_port_monitor()
        host._stop_game_launch_monitor()
        host._worker_registry.stop_all()
        if host._worker_registry.busy:
            host.setEnabled(False)
            host.statusBar().showMessage(host._tr("Завершаем сетевой мониторинг…"))
            event.ignore()
            return
        event.accept()
        QApplication.quit()

    def execute_teardown(self, event: QCloseEvent) -> None:
        host = self.host
        if host._dashboard_bootstrap_timer is not None:
            host._dashboard_bootstrap_timer.stop()
        host._dashboard_closing = True
        host._dashboard_ready = False
        self._close(host, event)
        if event.isAccepted():
            host.timer_registry.stop_all()
            host._save_dashboard_splitter_state(
                host.core_workspace.dashboard_overview_splitter,
                ui_constants.DASHBOARD_SPLITTER_STATE_KEY,
            )
            host._save_dashboard_splitter_state(
                host.core_workspace.dashboard_top_row_splitter,
                ui_constants.DASHBOARD_TOP_ROW_SPLITTER_STATE_KEY,
            )
        else:
            host._dashboard_closing = False
            host._dashboard_ready = True

    def _setup_network_health_tray(self) -> None:
        self.host._network_health_tray = QSystemTrayIcon(self.host)
        icon = QApplication.windowIcon()
        if icon.isNull():
            icon = self.host.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.host._network_health_tray.setIcon(icon)
        self.host._network_health_tray.setToolTip("NetVision — Network Health")
        menu = QMenu(self.host)
        self.host._tray_show_action = QAction(self.host._tr("Показать"), self.host)
        self.host._tray_show_action.triggered.connect(self.host._show_from_tray)
        self.host._tray_background_action = QAction(self.host._tr("Работа в фоне"), self.host)
        self.host._tray_background_action.setCheckable(True)
        self.host._tray_background_action.setChecked(self.host._background_enabled)
        self.host._tray_background_action.toggled.connect(self.host._set_background_enabled)
        self.host._tray_game_monitor_action = QAction(
            self.host._tr("Мониторинг запуска игры"), self.host
        )
        self.host._tray_game_monitor_action.setCheckable(True)
        self.host._tray_game_monitor_action.setChecked(self.host._background_auto_monitor)
        self.host._tray_game_monitor_action.toggled.connect(self.host._set_game_monitor_from_tray)
        self.host._tray_pause_action = QAction(self.host._tr("Пауза уведомлений"), self.host)
        self.host._tray_pause_action.setCheckable(True)
        self.host._tray_pause_action.setChecked(self.host._notifications_paused)
        self.host._tray_pause_action.toggled.connect(self.host._set_notification_pause)
        self.host._tray_exit_action = QAction(self.host._tr("Выход"), self.host)
        self.host._tray_exit_action.triggered.connect(self.host._exit_from_tray)
        menu.addAction(self.host._tray_show_action)
        menu.addSeparator()
        menu.addAction(self.host._tray_background_action)
        menu.addAction(self.host._tray_game_monitor_action)
        menu.addAction(self.host._tray_pause_action)
        menu.addSeparator()
        menu.addAction(self.host._tray_exit_action)
        self.host._network_health_tray.setContextMenu(menu)
        self.host._network_health_tray.activated.connect(self.host._on_tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.host._network_health_tray.show()
