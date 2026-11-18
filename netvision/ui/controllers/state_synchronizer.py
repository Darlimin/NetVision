"""Dashboard StateSynchronizer operations."""

from __future__ import annotations
from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import QLabel
from netvision.core.process_inspector import ProcessNetworkInfo
from netvision.core.packet_loss import PacketLossSnapshot
from netvision.models import DiagnosticReport, MonitorScope
from netvision.ui.lite_mode import summarize_report
from netvision.ui.utils import _lite_summary_cards

from netvision.core.episodes import Episode

from PySide6.QtWidgets import QFrame, QHBoxLayout, QSizePolicy, QSplitter, QWidget

from PySide6.QtWidgets import QTabWidget, QVBoxLayout
from netvision.core.tls_diagnostics import TlsAuditResult
from netvision.ui import constants as ui_constants
from netvision.ui.utils import _ms
from netvision.ui.utils import _tls_certificate_state


class StateSynchronizer(QObject):
    def __init__(self, parent, facts, event_bus):
        super().__init__(parent)
        self.host = parent
        self.facts = facts
        self.event_bus = event_bus

    def _update_monitor_scope_label(self, scope: MonitorScope) -> None:
        if not hasattr(getattr(self.host, "process_selector_panel", None), "monitor_scope_label"):
            return
        if scope.pid is not None and scope.process_name:
            text = self.host._translator.format(
                "Наблюдение: {process} · PID {pid} → {host}:{port}",
                process=scope.process_name,
                pid=scope.pid,
                host=scope.host,
                port=scope.port,
            )
        else:
            text = self.host._translator.format(
                "Наблюдение: только цель {host}:{port}", host=scope.host, port=scope.port
            )
        self.host.process_selector_panel.monitor_scope_label.setText(text)
        self.host.process_selector_panel.monitor_scope_label.setToolTip(text)

    def _update_lite_summary(self, report: DiagnosticReport) -> None:
        summary = summarize_report(report, self.host._thresholds)
        self.host.lite_panel.lite_title.setText(summary.title)
        self.host.lite_panel.lite_message.setText(summary.message)
        self.host._set_lite_status_style(summary.status)
        self.host._clear_lite_details()
        cards = _lite_summary_cards(report)
        for index, (title, value, state) in enumerate(cards):
            label = QLabel(f"{title}\n{value}")
            label.setObjectName("LiteDetailCard")
            label.setProperty("cardState", state)
            label.setWordWrap(True)
            label.setMinimumHeight(70)
            label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            label.setToolTip(f"{title}: {value}")
            label.style().unpolish(label)
            label.style().polish(label)
            self.host.lite_panel.lite_details.addWidget(label, index // 2, index % 2)
            self.host.lite_panel.lite_detail_labels.append(label)

    def _update_live_header_anomaly(
        self, latency_ms: float | None, success: bool, loss_snapshot: PacketLossSnapshot
    ) -> None:
        """Project ping and loss monitor results into the compact header summary."""
        if not success:
            self.host.overview_controller._set_header_anomaly("warning", "Потеря ответа")
            return
        if loss_snapshot.loss_percent >= 20:
            self.host.overview_controller._set_header_anomaly(
                "error", "Потери пакетов: {loss:.0f}%", loss=loss_snapshot.loss_percent
            )
            return
        if loss_snapshot.loss_percent > 0:
            self.host.overview_controller._set_header_anomaly(
                "warning", "Потери пакетов: {loss:.0f}%", loss=loss_snapshot.loss_percent
            )
            return
        episode = self.host._rtt_episode_tracker.active
        if episode is not None and episode.peak >= self.host._thresholds.rtt_peak_ms:
            self.host.overview_controller._set_header_anomaly(
                "error", "Пик пинга > {latency:.0f} мс", latency=episode.peak
            )
            return
        if episode is not None:
            self.host.overview_controller._set_header_anomaly(
                "warning", "Высокий пинг: {latency:.0f} мс", latency=episode.peak
            )
            return
        self.host.overview_controller._set_header_anomaly("good", "Связь стабильна")

    def _update_process_display(self, lite_mode: bool) -> None:
        if not hasattr(
            getattr(self.host, "process_selector_panel", None), "process_connection_selector"
        ):
            return
        self.host.process_selector_panel.process_panel.setVisible(not lite_mode)
        self.host.core_workspace.port_label.setVisible(not lite_mode)
        self.host.core_workspace.port_input.setVisible(not lite_mode)
        self.host.process_selector_panel.connection_title.setVisible(not lite_mode)
        self.host.process_selector_panel.process_connection_selector.setVisible(not lite_mode)
        self.host.process_selector_panel.process_status.setVisible(not lite_mode)
        self.host.process_selector_panel.udp_ports_status.setVisible(not lite_mode)
        for index in range(self.host.process_selector_panel.process_selector.count()):
            process = self.host.process_selector_panel.process_selector.itemData(index)
            if isinstance(process, ProcessNetworkInfo):
                self.host.process_selector_panel.process_selector.setItemText(
                    index, self.host.process_controller._process_display_label(process)
                )

    def _refresh_elided_labels(self) -> None:
        for name in ("udp_ports_status",):
            label = getattr(self.host, name, None)
            if not isinstance(label, QLabel):
                continue
            text = label.property("fullText")
            if isinstance(text, str):
                self.host._set_elided_text(label, text)

    def _refresh_preset_buttons(self) -> None:
        for profile_id in self.host.preset_buttons:
            self.host._update_preset_button(profile_id)

    def _update_tcp_socket_selection(self) -> None:
        row = self.host.tcp_workspace.tcp_sockets_table.currentRow()
        selected = 0 <= row < len(getattr(self.host, "_tcp_socket_records", ()))
        self.host.tcp_workspace.tcp_socket_details_button.setEnabled(selected)
        if selected:
            record = self.host._tcp_socket_records[row]
            self.host.tcp_workspace.tcp_socket_status.setText(
                f"Выбран: {record.process_name} · {record.local_endpoint} → {record.remote_endpoint} · {record.state}"
            )

    def _update_preset_button(self, profile_id: str) -> None:
        button = self.host.preset_buttons[profile_id]
        label, host, port = self.host._preset_profiles[profile_id]
        display_label = self.host._tr(label)
        button.setText(display_label)
        button.setToolTip(
            self.host._translator.format("Проверить профиль: {host}:{port}", host=host, port=port)
        )
        button.setAccessibleName(
            self.host._translator.format("Профиль: {name}", name=display_label)
        )

    def _sync_tray_game_monitor(self, enabled: bool) -> None:
        action = getattr(self.host, "_tray_game_monitor_action", None)
        if action is None or action.isChecked() == enabled:
            return
        action.blockSignals(True)
        action.setChecked(enabled)
        action.blockSignals(False)

    def _sync_rtt_episode_log(self, step: str | None, episode: Episode | None) -> None:
        if step == "opened" and episode is not None:
            self.host._ping_spike_events.append(
                f"[{episode.started_at:%H:%M:%S}] Пик задержки: {episode.peak:.1f} ms · отсчётов: 1"
            )
            self.host._ping_spike_events = self.host._ping_spike_events[-80:]
            self.host._rtt_episode_log_index = len(self.host._ping_spike_events) - 1
        if episode is None or self.host._rtt_episode_log_index is None:
            return
        row_index = self.host._rtt_episode_log_index
        if row_index >= len(self.host._ping_spike_events):
            self.host._rtt_episode_log_index = None
            return
        suffix = " · стабилизировалось" if step == "closed" else ""
        self.host._ping_spike_events[row_index] = (
            f"[{episode.started_at:%H:%M:%S}] Пик задержки: {episode.peak:.1f} ms · отсчётов: {episode.samples_over}{suffix}"
        )
        if step == "closed":
            self.host._rtt_episode_log_index = None

    def _refresh_udp_event_table(self) -> None:
        return self.host.history_controller._refresh_udp_event_table()

    def _refresh_history_view(self) -> None:
        return self.host.history_controller._refresh_history_view()

    def _refresh_loss_workspace(self) -> None:
        self.host._set_loss_snapshot(self.host._loss_analyzer_snapshot())
        events = self.host._loss_analyzer.events
        if events:
            self.host.loss_workspace.loss_events_log.setPlainText(
                "\n".join((f"[{event.observed_at:%H:%M:%S}] {event.message}" for event in events))
            )
            self.host.loss_workspace.loss_detector_status.setText(
                f"Событий в окне: {len(events)} · {events[-1].snapshot.status}"
            )
        elif self.host._loss_analyzer.samples:
            self.host.loss_workspace.loss_detector_status.setText(
                self.host._loss_analyzer_snapshot().status
            )

    def _update_responsive_layout(self) -> None:
        """Compact dense control rows before they can overflow the window."""
        compact = self.host.width() < 1120
        narrow = self.host.width() < 1040
        if hasattr(getattr(self.host, "header_panel", None), "brand_caption"):
            self.host.header_panel.brand_caption.setVisible(not compact)
            self.host.header_panel.header_mode_controls.setVisible(not compact)
            self.host.header_panel.mode_label.setVisible(not compact)
            self.host.header_panel.language_label.setVisible(not narrow)
        if hasattr(getattr(self.host, "header_panel", None), "status_badge"):
            self.host.header_panel.status_badge.setVisible(not narrow)
        if hasattr(getattr(self.host, "header_panel", None), "session_capsule"):
            show_anomaly_text = self.host.width() >= 1180
            self.host.header_panel.session_log_button.setVisible(show_anomaly_text)
            self.host.header_panel.session_capsule.setMaximumWidth(
                520 if show_anomaly_text else 182
            )
            header = self.host.header_panel.session_capsule.parentWidget()
            layout = header.layout()
            margins = layout.contentsMargins()
            available = header.width() - margins.left() - margins.right()

            def required_width() -> int:
                controls = [layout.itemAt(index).widget() for index in range(layout.count())]
                visible = [
                    widget for widget in controls if widget is not None and (not widget.isHidden())
                ]
                return (
                    sum(
                        (
                            (
                                182
                                if widget is self.host.header_panel.session_capsule
                                else max(widget.minimumWidth(), widget.sizeHint().width())
                            )
                            for widget in visible
                        )
                    )
                    + max(0, len(visible) - 1) * layout.spacing()
                )

            for secondary in (
                self.host.header_panel.brand_caption,
                self.host.header_panel.mode_label,
                self.host.header_panel.language_label,
                self.host.header_panel.status_badge,
                self.host.header_panel.header_mode_controls,
            ):
                if required_width() <= available:
                    break
                secondary.hide()
        if hasattr(getattr(self.host, "core_workspace", None), "control_layout"):
            self._reflow_control_bar(compact)
        self.host.state_synchronizer._refresh_elided_labels()

    def _set_status(self, text: str, state: str) -> None:
        self.host._inherited__set_status(text, state)
        if self.host._dashboard_ready and self.host._dashboard_widgets_alive(
            self.host.core_workspace.dashboard_status_pill,
            self.host.core_workspace.dashboard_status_subtitle,
        ):
            self.host.overview_controller._dashboard_apply_health(state, text)

    def _refresh_session_capsule(self) -> None:
        self.host._inherited__refresh_session_capsule()
        if (
            self.host._dashboard_ready
            and self.host._report is not None
            and self.host._dashboard_widgets_alive(self.host.core_workspace.dashboard_status_pill)
        ):
            self.host.overview_controller._dashboard_apply_health(
                self.host._header_anomaly_state,
                self.host._translator.format(
                    self.host._header_anomaly_source, **self.host._header_anomaly_values
                ),
            )

    def _compact_dashboard_tls(self) -> None:
        content = self.host.tls_view.findChild(QWidget, "TlsWorkspaceContent")
        tools = self.host.tls_view.findChild(QFrame, "TlsToolsPanel")
        handshake = self.host.tls_view.findChild(QFrame, "TlsHandshakePanel")
        certificate = self.host.tls_view.findChild(QFrame, "TlsCertificatePanel")
        if not all(
            (
                self.host._qt_object_is_alive(item)
                for item in (content, tools, handshake, certificate)
            )
        ):
            return
        layout = content.layout()
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        overview = self.host.tls_view.findChild(QFrame, "TlsOverviewPanel")
        overview_layout = overview.layout()
        items = [overview_layout.itemAtPosition(0, column).widget() for column in range(6)]
        for column, item in enumerate(items):
            overview_layout.removeWidget(item)
            overview_layout.addWidget(item, column // 3, column % 3)
        title = content.findChild(QLabel, "TlsWorkspaceTitle")
        if self.host._qt_object_is_alive(title):
            title.setWordWrap(True)
            title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        target_row = tools.layout().itemAt(1).layout()
        target_row.removeWidget(self.host.tls_workspace.tls_check_button)
        target_row.removeWidget(self.host.tls_workspace.tls_copy_fingerprint_button)
        target_row.removeWidget(self.host.tls_workspace.tls_refresh_button)
        actions = QHBoxLayout()
        actions.addWidget(self.host.tls_workspace.tls_check_button)
        actions.addWidget(self.host.tls_workspace.tls_refresh_button)
        actions.addStretch(1)
        tools.layout().insertLayout(2, actions)
        actions = QHBoxLayout()
        actions.addWidget(self.host.tls_workspace.tls_copy_fingerprint_button)
        actions.addStretch(1)
        tools.layout().insertLayout(3, actions)
        layout.removeWidget(handshake)
        layout.removeWidget(certificate)
        self.host.tls_workspace.tls_handshake_table.setMinimumHeight(60)
        self.host.tls_workspace.tls_certificate_table.setMinimumHeight(60)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(handshake)
        splitter.addWidget(certificate)
        layout.insertWidget(layout.count() - 1, splitter, 1)

    def _move_udp_test_to_bufferbloat(self) -> None:
        page = self.host.dashboard_quality_tabs.widget(1)
        panel = QFrame()
        panel.setObjectName("DashboardUdpTest")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(4)
        controls = QHBoxLayout()
        self.host._dashboard_udp_labels = []
        for caption in ("UDP-тест", "Цель UDP"):
            label = QLabel(self.host._tr(caption))
            self.host._dashboard_udp_labels.append((label, caption))
            controls.addWidget(label)
        for widget in (
            self.host.loss_workspace.udp_stress_target_input,
            self.host.loss_workspace.udp_stress_port_input,
            self.host.loss_workspace.udp_stress_button,
        ):
            widget.setParent(None)
            controls.addWidget(widget)
            widget.show()
        layout.addLayout(controls)
        metrics = QHBoxLayout()
        for caption, widget in (
            ("Отправлено", self.host.loss_workspace.udp_stress_sent_value),
            ("Получено", self.host.loss_workspace.udp_stress_received_value),
            ("Потери", self.host.loss_workspace.udp_stress_loss_value),
        ):
            label = QLabel(self.host._tr(caption))
            self.host._dashboard_udp_labels.append((label, caption))
            metrics.addWidget(label)
            widget.setParent(None)
            metrics.addWidget(widget)
            widget.show()
        self.host.loss_workspace.udp_stress_status.setParent(None)
        metrics.addWidget(self.host.loss_workspace.udp_stress_status, 1)
        self.host.loss_workspace.udp_stress_status.show()
        layout.addLayout(metrics)
        self.host.loss_workspace.udp_stress_progress.setParent(None)
        layout.addWidget(self.host.loss_workspace.udp_stress_progress)
        page.layout().insertWidget(0, panel)

    def _extract_quality_tabs(self) -> None:
        """Move the quality pages into one visible dashboard subtab control."""
        self.host.dashboard_quality_tabs = QTabWidget()
        self.host.dashboard_quality_tabs.setObjectName("DashboardQualityTabs")
        self.host.dashboard_quality_tabs.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        titles = (
            self.host._tr("Качество интернета"),
            self.host._tr("Bufferbloat"),
            self.host._tr("История проверок"),
        )
        for index, title in reversed(tuple(zip(ui_constants.QUALITY_SOURCE_TABS, titles))):
            page = self.host.workspace_tabs.widget(index)
            if page is None:
                continue
            self.host.workspace_tabs.removeTab(index)
            self.host.dashboard_quality_tabs.insertTab(0, page, title)
            page.show()
        self._move_udp_test_to_bufferbloat()
        if self.host._qt_object_is_alive(self.host.tls_view):
            self.host.tls_view.setParent(None)
            self.host.tls_workspace.tls_back_button.hide()
            self.host.state_synchronizer._compact_dashboard_tls()
            port_tls = self.host.core_workspace._build_dashboard_port_tls()
            self.host.dashboard_quality_tabs.addTab(port_tls, self.host._tr("Порт и TLS"))
            self.host.tls_view.show()
        self.host.dns_workspace.dns_back_button.hide()
        quick_fixes = self.host.dns_view.findChild(QFrame, "QuickFixPanel")
        if quick_fixes is not None:
            quick_fixes.hide()
        self.host.dns_view.layout().setContentsMargins(4, 4, 4, 4)
        self.host.dns_view.layout().setSpacing(4)
        self.host.dashboard_quality_tabs.addTab(self.host.dns_view, "DNS")
        self.host.dashboard_quality_tabs.currentChanged.connect(
            self.host._dashboard_quality_tab_changed
        )

    def _reflow_control_bar(self, compact: bool) -> None:
        if getattr(self.host, "_controls_compact", None) == compact:
            return
        self.host._controls_compact = compact
        while self.host.core_workspace.control_layout.count():
            self.host.core_workspace.control_layout.takeAt(0)
        presets = list(self.host.preset_buttons.values())
        if compact:
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace._control_host_label, 0, 0
            )
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.target_input, 0, 1
            )
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.start_button, 0, 2
            )
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace._control_preset_label, 1, 0
            )
            for column, button in enumerate(presets, start=1):
                self.host.core_workspace.control_layout.addWidget(button, 1, column)
            port_column = len(presets) + 1
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.port_label, 1, port_column
            )
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.port_input, 1, port_column + 1
            )
            self.host.core_workspace.control_layout.setColumnStretch(1, 1)
        else:
            column = 0
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace._control_host_label, 0, column
            )
            column += 1
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.target_input, 0, column
            )
            self.host.core_workspace.control_layout.setColumnStretch(column, 1)
            column += 1
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace._control_preset_label, 0, column
            )
            column += 1
            for button in presets:
                self.host.core_workspace.control_layout.addWidget(button, 0, column)
                column += 1
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.port_label, 0, column
            )
            column += 1
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.port_input, 0, column
            )
            column += 1
            self.host.core_workspace.control_layout.addWidget(
                self.host.core_workspace.start_button, 0, column
            )
        self.host.core_workspace.control_layout.invalidate()

    def _render_tls_audit(self, result: TlsAuditResult) -> None:
        certificate_state = _tls_certificate_state(
            result.certificate_status, result.certificate_valid
        )
        self.host._set_tls_overview_value(
            self.host.tls_workspace.tls_overview_values["tcp_connect"],
            _ms(result.tcp_connect_ms),
            "good" if result.tcp_connect_ms is not None else "bad",
        )
        self.host._set_tls_overview_value(
            self.host.tls_workspace.tls_overview_values["handshake"],
            _ms(result.handshake_ms),
            "good" if result.handshake_ms is not None else "bad",
        )
        self.host._set_tls_overview_value(
            self.host.tls_workspace.tls_overview_values["protocol"],
            result.version or "--",
            certificate_state,
        )
        self.host._set_tls_overview_value(
            self.host.tls_workspace.tls_overview_values["cipher"],
            result.cipher or "--",
            certificate_state,
        )
        self.host._set_tls_overview_value(
            self.host.tls_workspace.tls_overview_values["certificate"],
            result.certificate_status,
            certificate_state,
        )
        leaf = result.chain[0] if result.chain else None
        expiry = (
            "--" if leaf is None or leaf.days_remaining is None else f"{leaf.days_remaining} дн."
        )
        self.host._set_tls_overview_value(
            self.host.tls_workspace.tls_overview_values["expiry"], expiry, certificate_state
        )
        self.host.tls_controller._render_tls_handshake(result)
        self.host._render_tls_chain(result.chain)
        self.host.tls_workspace.tls_copy_fingerprint_button.setEnabled(
            bool(result.fingerprint_sha256)
        )
        details = result.error or "Защищённое соединение проверено"
        self.host.tls_workspace.tls_audit_status.setText(
            f"{result.host}:{result.port} · {result.certificate_status} · {details}"
        )

    def _inherited__refresh_session_capsule(self) -> None:
        """Render the compact session timer and its current anomaly summary."""
        if not hasattr(getattr(self.host, "header_panel", None), "session_timer_button"):
            return
        elapsed = self.host._format_session_elapsed(self.host._session_elapsed_seconds)
        running = self.host._session_timer.isActive()
        self.host.header_panel.session_timer_button.setText(f"⏱  {elapsed}")
        self.host.header_panel.session_timer_button.setProperty("paused", not running)
        self.host.header_panel.session_timer_button.setToolTip(
            self.host._tr(
                "Поставить таймер сессии на паузу" if running else "Продолжить таймер сессии"
            )
        )
        self.host.header_panel.session_timer_button.setAccessibleName(
            self.host._translator.format("Таймер сессии диагностики: {time}", time=elapsed)
        )
        self.host.header_panel.session_reset_button.setToolTip(
            self.host._tr("Сбросить таймер сессии")
        )
        self.host.header_panel.session_reset_button.setAccessibleName(
            self.host._tr("Сбросить таймер сессии")
        )
        icons = ui_constants.DASHBOARD_HEADER_STATE_ICONS
        state = self.host._header_anomaly_state
        message = self.host._translator.format(
            self.host._header_anomaly_source, **self.host._header_anomaly_values
        )
        self.host.header_panel.session_log_button.setText(f"{icons.get(state, 'ℹ')}  {message}")
        self.host.header_panel.session_log_button.setProperty("anomalyState", state)
        self.host.header_panel.session_log_button.setProperty("fullText", message)
        self.host.header_panel.session_log_button.setToolTip(
            self.host._tr("Открыть недавние аномалии")
        )
        self.host.header_panel.session_log_button.setAccessibleName(
            self.host._translator.format(
                "Статус сети: {message}. Открыть недавние аномалии", message=message
            )
        )
        for button in (
            self.host.header_panel.session_timer_button,
            self.host.header_panel.session_log_button,
        ):
            button.style().unpolish(button)
            button.style().polish(button)
