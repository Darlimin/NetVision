import gc
import unittest
from unittest.mock import patch

from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication, QMessageBox, QScrollArea, QSizePolicy

from netvision.core.mtu_optimizer import MtuOptimizerProbe, MtuOptimizerReport
from netvision.core.thresholds import Thresholds
from netvision.core.tls_diagnostics import TlsAuditResult
from netvision.core.udp_stress import UdpStressReport
from netvision.core.traceroute import TracerouteHop
from netvision.core.session_journal import SessionJournal
from netvision.core.system_actions import SystemActionResult, SystemChange
from netvision.ui.controllers.dns_audit import DnsController
from netvision.ui.dashboard_v2 import NetVisionDashboardV2
from netvision.core.process_utils import EndpointChoice
from netvision.core.process_inspector import ProcessConnection


class _MemoryJournalStore:
    """In-memory session storage keeps the MTU rollback test filesystem-free."""

    def __init__(self) -> None:
        self.events: list[object] = []

    def append(self, event: object) -> object:
        self.events.append(event)
        return event

    def load(self) -> list[object]:
        return list(self.events)


class DashboardV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(
            ["NetVision-dashboard-tests", "-platform", "offscreen"]
        )

    def setUp(self) -> None:
        self.journal_record_patch = patch.object(
            NetVisionDashboardV2,
            "_record_journal_event",
            return_value=None,
        )
        self.journal_record_patch.start()
        self.addCleanup(self.journal_record_patch.stop)
        self.local_snapshot_patch = patch.object(
            NetVisionDashboardV2, "_load_local_network_snapshot"
        )
        self.local_snapshot_patch.start()
        self.dns_config_patch = patch.object(DnsController, "_load_dns_configuration")
        self.dns_config_mock = self.dns_config_patch.start()
        self.addCleanup(self.dns_config_patch.stop)
        self.window = NetVisionDashboardV2(bootstrap=False)
        self.addCleanup(self._close_window)

    def _close_window(self) -> None:
        if self.window is not None:
            self.window._quit_requested = True
            self.window.dns_controller.stop()
            self.window._worker_registry.stop_all()
            self.assertTrue(self.window._worker_registry.wait_for_all(10000))
            self.app.processEvents()
            self.window.close()
            self.window.deleteLater()
            self.app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            self.app.processEvents()
        self.local_snapshot_patch.stop()

    def test_log_event_reaches_history_controller(self) -> None:
        with patch.object(self.window, "_append_log") as append_log:
            self.window.event_bus.log_requested.emit("Проверка шины", "INFO")
            self.app.processEvents()
        append_log.assert_called_once_with("Проверка шины")

    def test_timer_registry_preserves_configuration_and_stops_timers(self) -> None:
        registry = self.window.timer_registry
        self.assertIs(registry.parent(), self.window)
        self.assertTrue(registry.responsive_layout.isSingleShot())
        self.assertEqual(registry.task_buttons.interval(), 420)
        self.assertEqual(registry.session.interval(), 1000)
        self.assertIsNone(registry.bootstrap)
        bootstrap = registry.create_bootstrap()
        self.assertTrue(bootstrap.isSingleShot())
        self.assertIs(registry.create_bootstrap(), bootstrap)
        registry.task_buttons.start()
        registry.session.start()
        registry.stop_all()
        self.assertFalse(registry.task_buttons.isActive())
        self.assertFalse(registry.session.isActive())

    def test_menu_and_controllers_remain_owned_during_rebuild(self) -> None:
        menu = self.window._header_anomaly_menu
        self.assertIs(menu.parent(), self.window.header_panel)
        self.assertIs(self.window._worker_registry.parent(), self.window)
        for controller in (
            self.window.overview_controller,
            self.window.dns_controller,
            self.window.mtr_controller,
            self.window.teardown_coordinator,
        ):
            self.assertIs(controller.parent(), self.window)
        for _ in range(10):
            self.window.alarms_controller._populate_header_anomaly_menu()
            gc.collect()
            self.app.processEvents()
            action = self.window._header_anomaly_action
            self.assertIs(action.parent(), menu)
            self.assertIsNotNone(action.defaultWidget())
            self.assertEqual(len(menu.actions()), 1)

    def test_history_event_passes_metrics_to_controller(self) -> None:
        with patch.object(self.window.history_controller, "_record_test_history") as record:
            self.window.event_bus.history_update_requested.emit(
                "Качество интернета", {"ping_ms": 12.5, "download_mbps": None}
            )
            self.app.processEvents()
        record.assert_called_once_with("Качество интернета", ping_ms=12.5, download_mbps=None)

    def test_journal_event_passes_fields_to_controller(self) -> None:
        with patch.object(self.window.history_controller, "_record_journal_event") as record:
            self.window.event_bus.journal_event_requested.emit(
                "probe.failed", {"severity": "warning", "subject": "example"}
            )
            self.app.processEvents()
        record.assert_called_once_with("probe.failed", severity="warning", subject="example")

    def test_starts_neutral_with_dashboard_containers(self) -> None:
        self.assertEqual(
            self.window.core_workspace.dashboard_status_pill.text(), "ОЖИДАНИЕ ПРОВЕРКИ"
        )
        self.assertEqual(
            self.window.core_workspace.dashboard_metric_cards["ping"].value.text(), "— ms"
        )
        self.assertEqual(
            self.window.core_workspace.dashboard_metric_cards["loss"].value.text(), "—"
        )
        self.assertIsNot(self.window._legacy_mode_stack, self.window.mode_stack)
        self.assertIsNot(self.window._legacy_mode_scroll, self.window.mode_scroll)
        self.assertIsNot(self.window._legacy_workspace_tabs, self.window.workspace_tabs)
        self.assertEqual(self.window._legacy_workspace_tabs.count(), 0)
        self.assertEqual(self.window._legacy_mode_stack.count(), 0)

        self.window.show()
        self.app.processEvents()
        self.assertIsNone(self.window._latency_thread)

        self.window.core_workspace.dashboard_nav_buttons["quality"].click()
        self.assertIs(self.window.dashboard_stack.currentWidget(), self.window.dashboard_details)
        self.assertIs(
            self.window.core_workspace.dashboard_details_stack.currentWidget(),
            self.window.dashboard_quality_tabs,
        )
        self.assertEqual(self.window.dashboard_quality_tabs.count(), 5)
        self.assertEqual(self.window.dashboard_quality_tabs.currentIndex(), 0)
        self.window.dashboard_quality_tabs.setCurrentIndex(1)
        self.app.processEvents()
        self.assertTrue(
            self.window.bufferbloat_workspace.bufferbloat_start_button.isVisibleTo(self.window)
        )
        self.window.dashboard_quality_tabs.setCurrentIndex(2)
        self.app.processEvents()
        self.assertTrue(self.window.history_workspace.history_table.isVisibleTo(self.window))

        self.window.dashboard_quality_tabs.setCurrentIndex(3)
        self.app.processEvents()
        self.assertTrue(self.window.tls_workspace.tls_target_input.isVisibleTo(self.window))
        self.assertTrue(self.window.tls_workspace.tls_run_button.isVisibleTo(self.window))
        self.assertFalse(self.window.tls_workspace.tls_back_button.isVisibleTo(self.window))
        self.assertTrue(
            all(
                value.text() == "--"
                for value in self.window.tls_workspace.tls_overview_values.values()
            )
        )

        self.window.core_workspace.dashboard_nav_buttons["overview"].click()
        self.assertIs(self.window.dashboard_stack.currentWidget(), self.window.dashboard_overview)

    def test_tls_target_and_results(self) -> None:
        self.window.core_workspace.dashboard_target_input.setText("example.com")
        self.window.core_workspace.dashboard_port_input.setValue(8443)
        self.assertEqual(self.window.tls_workspace.tls_target_input.text(), "example.com")
        self.assertEqual(self.window.tls_workspace.tls_port_input.value(), 8443)
        result = TlsAuditResult(
            "example.com",
            8443,
            5.0,
            12.0,
            "TLSv1.3",
            "AES",
            None,
            True,
            "Действителен",
            (),
            None,
        )
        with patch.object(self.window.tls_controller, "_inherited_start_tls_audit"):
            self.window.tls_controller.start_tls_audit()
        self.window.tls_controller._on_tls_audit_completed(result)
        self.assertEqual(
            self.window.tls_workspace.tls_overview_values["protocol"].text(), "TLSv1.3"
        )
        self.window.core_workspace.dashboard_target_input.setText("other.example")
        self.assertTrue(
            all(
                value.text() == "--"
                for value in self.window.tls_workspace.tls_overview_values.values()
            )
        )
        self.assertIsNone(self.window._tls_audit_result)
        self.assertFalse(self.window.tls_workspace.tls_copy_fingerprint_button.isEnabled())
        self.window.tls_controller._on_tls_audit_completed(result)
        self.assertEqual(self.window.tls_workspace.tls_overview_values["protocol"].text(), "--")
        self.window.tls_controller._on_tls_audit_failed("outdated error")
        self.assertNotEqual(self.window.tls_workspace.tls_audit_status.text(), "outdated error")
        with patch.object(self.window.tls_controller, "_inherited_start_tls_audit"):
            self.window.tls_controller.start_tls_audit()
        self.window._set_tls_audit_running(True)
        self.window.tls_controller._on_tls_audit_failed("TLS error")
        self.assertEqual(self.window.tls_workspace.tls_audit_status.text(), "TLS error")
        self.assertTrue(self.window.tls_workspace.tls_run_button.isEnabled())
        self.assertTrue(self.window.tls_workspace.tls_check_button.isEnabled())
        self.assertTrue(self.window.tls_workspace.tls_refresh_button.isEnabled())
        error_result = TlsAuditResult(
            "other.example",
            8443,
            None,
            None,
            None,
            None,
            None,
            False,
            "Ошибка",
            (),
            None,
            "Connection refused",
        )
        self.window._set_tls_audit_running(True)
        self.window.tls_controller._on_tls_audit_completed(error_result)
        self.assertIn("Connection refused", self.window.tls_workspace.tls_audit_status.text())
        self.assertTrue(self.window.tls_workspace.tls_run_button.isEnabled())
        self.assertEqual(self.window.tls_workspace.tls_overview_values["protocol"].text(), "--")
        self.window.core_workspace.dashboard_port_input.setValue(443)
        self.assertIsNone(self.window._tls_audit_result)
        self.assertNotIn("Connection refused", self.window.tls_workspace.tls_audit_status.text())

    def test_dns_workspace_is_visible_and_fits(self) -> None:
        self.window.resize(1280, 720)
        self.window.show()
        self.window.core_workspace.dashboard_nav_buttons["quality"].click()
        tabs = self.window.dashboard_quality_tabs
        tabs.setCurrentIndex(tabs.indexOf(self.window.dns_view))
        self.app.processEvents()
        self.assertEqual(self.window.mode_stack.indexOf(self.window.dns_view), -1)
        self.dns_config_mock.assert_called_once_with()
        for widget in (
            self.window.dns_workspace.dns_table,
            self.window.dns_workspace.dns_run_button,
            self.window.dns_workspace.dns_adapter_combo,
            self.window.dns_workspace.dns_apply_button,
            self.window.dns_workspace.dns_flush_button,
            self.window.dns_workspace.dns_geohide_button,
        ):
            self.assertTrue(widget.isVisibleTo(self.window), widget.objectName())
            bottom_right = widget.mapTo(self.window, widget.rect().bottomRight())
            self.assertTrue(self.window.rect().contains(bottom_right), widget.objectName())
        self.window.dns_workspace.dns_geohide_button.click()
        self.assertIsNotNone(self.window._geohide_dialog)
        self.assertTrue(self.window._geohide_dialog.isVisible())
        self.window._geohide_dialog.close()

    def test_udp_test_visible_and_displays_result(self) -> None:
        self.window.resize(1280, 720)
        self.window.show()
        self.window.core_workspace.dashboard_nav_buttons["quality"].click()
        self.window.dashboard_quality_tabs.setCurrentIndex(1)
        self.app.processEvents()
        panel = self.window.loss_workspace.udp_stress_button.parentWidget()
        self.assertEqual(panel.objectName(), "DashboardUdpTest")
        for widget in (
            self.window.loss_workspace.udp_stress_target_input,
            self.window.loss_workspace.udp_stress_port_input,
            self.window.loss_workspace.udp_stress_button,
            self.window.loss_workspace.udp_stress_sent_value,
            self.window.loss_workspace.udp_stress_received_value,
            self.window.loss_workspace.udp_stress_loss_value,
            self.window.bufferbloat_workspace.bufferbloat_start_button,
        ):
            self.assertTrue(widget.isVisibleTo(self.window))
            bottom_right = widget.mapTo(self.window, widget.rect().bottomRight())
            self.assertTrue(self.window.rect().contains(bottom_right))
        report = UdpStressReport("127.0.0.1:53", 10, 8, 2, 20.0, 5.0, "Высокие потери")
        self.window.loss_controller._on_udp_packet_loss_stress_completed(report)
        self.assertEqual(self.window.loss_workspace.udp_stress_sent_value.text(), "10")
        self.assertEqual(self.window.loss_workspace.udp_stress_received_value.text(), "8")
        self.assertEqual(self.window.loss_workspace.udp_stress_loss_value.text(), "20.0%")

    def test_tls_fits_1280_by_720(self) -> None:
        self.window.resize(1280, 720)
        self.window.show()
        self.window.core_workspace.dashboard_nav_buttons["quality"].click()
        self.window.dashboard_quality_tabs.setCurrentIndex(3)
        self.app.processEvents()
        scrolls = [
            scroll
            for scroll in self.window.tls_view.findChildren(QScrollArea)
            if scroll.objectName() == "TlsWorkspaceScroll"
        ]
        self.assertEqual(scrolls, [])

    def test_tcp_and_tls_share_visible_workspace(self) -> None:
        self.window.resize(1280, 720)
        self.window.core_workspace.dashboard_target_input.setText("example.com")
        self.window.core_workspace.dashboard_port_input.setValue(8443)
        self.window.show()
        self.window.core_workspace.dashboard_nav_buttons["quality"].click()
        self.window.dashboard_quality_tabs.setCurrentIndex(3)
        self.app.processEvents()
        self.assertEqual((self.window.width(), self.window.height()), (1280, 720))
        self.assertEqual(self.window.tcp_workspace.tcp_target_input.text(), "example.com")
        self.assertEqual(self.window.tcp_workspace.tcp_ports_input.text(), "8443")
        self.assertEqual(self.window.dashboard_quality_tabs.tabText(3), "Порт и TLS")
        for widget in (
            self.window.tcp_workspace.tcp_target_input,
            self.window.tcp_workspace.tcp_ports_input,
            self.window.tcp_workspace.tcp_ports_table,
            self.window.tcp_workspace.tcp_run_button,
            self.window.tcp_workspace.tcp_handshake_connect,
            self.window.tls_workspace.tls_target_input,
            self.window.tls_workspace.tls_handshake_table,
            self.window.tls_workspace.tls_certificate_table,
            self.window.tls_workspace.tls_run_button,
            self.window.tls_workspace.tls_check_button,
            self.window.tls_workspace.tls_copy_fingerprint_button,
            self.window.tls_workspace.tls_refresh_button,
        ):
            self.assertTrue(widget.isVisibleTo(self.window), widget.objectName())
        self.assertFalse(self.window.tls_view.findChildren(QScrollArea))
        self.assertFalse(self.window.tcp_view.findChildren(QScrollArea))

    def test_migrated_surfaces_do_not_depend_on_legacy_containers(self) -> None:
        self.assertEqual(self.window.mode_stack.indexOf(self.window.dns_view), -1)
        self.assertEqual(self.window.mode_stack.indexOf(self.window.tcp_view), -1)
        self.assertEqual(
            self.window.ping_workspace.ping_tools_splitter.indexOf(
                self.window.mtu_workspace.mtu_optimizer_panel
            ),
            -1,
        )
        self.assertIsNot(self.window.journal_tabs.window(), self.window._legacy_central)
        for widget in (
            self.window.tcp_workspace.tcp_run_button,
            self.window.journal_workspace.journal_layer_filter,
            self.window.loss_workspace.udp_stress_button,
            self.window.core_workspace.dashboard_process_combo,
        ):
            self.assertIsNot(widget.window(), self.window._legacy_central)

    def test_start_button_delegates_to_existing_diagnostic_entry_point(self) -> None:
        self.window.core_workspace.dashboard_target_input.setText("example.com")
        self.window.core_workspace.dashboard_port_input.setValue(443)
        with patch.object(self.window, "start_diagnostic") as start_diagnostic:
            self.window.core_workspace.dashboard_start_button.click()
        start_diagnostic.assert_called_once_with()

    def test_hunt_endpoint_choice_updates_dashboard_target_and_region(self) -> None:
        connection = ProcessConnection("UDP", "NONE", "192.168.1.2", 37000, "8.8.8.8", 27015)
        choice = EndpointChoice(connection, "UDP + игровой порт", 1, 0)
        with (
            patch.object(self.window, "_record_endpoint_choice"),
            patch.object(self.window.ping_controller, "_start_latency_monitor") as start_monitor,
        ):
            self.window._on_endpoint_chosen(choice)

        self.assertEqual(self.window.core_workspace.dashboard_target_input.text(), "8.8.8.8")
        self.assertEqual(self.window.core_workspace.dashboard_port_input.value(), 27015)
        self.assertEqual(
            self.window.region_card.dashboard_region_table.item(0, 1).text(), "8.8.8.8:27015"
        )
        start_monitor.assert_called_once_with("8.8.8.8", 27015, protocol="UDP")

        self.window.ping_controller._on_latency_sample(42.0, True)
        self.assertEqual(
            self.window.region_card.dashboard_region_table.item(0, 4).text(), "Отлично"
        )
        self.window.ping_controller._on_latency_sample(120.0, True)
        self.assertEqual(
            self.window.region_card.dashboard_region_table.item(0, 4).text(), "Внимание"
        )

    def test_dashboard_game_status_uses_shared_thresholds(self) -> None:
        self.window._thresholds = Thresholds(game_good_rtt_ms=40.0, loss_warn_pct=2.0)
        self.window._dashboard_game_metrics = (42.0, 0.0, True)
        self.assertEqual(
            self.window._dashboard_game_status(42.0, 0.0, True),
            ("Стабильно", "good"),
        )
        self.window._dashboard_game_metrics = (42.0, 2.0, True)
        self.assertEqual(
            self.window._dashboard_game_status(42.0, 2.0, True),
            ("Внимание", "error"),
        )

    def test_sidebar_retranslates_with_the_existing_language_service(self) -> None:
        self.window.header_panel.language_combo.setCurrentIndex(
            self.window.header_panel.language_combo.findData("en")
        )
        self.app.processEvents()
        self.assertEqual(
            self.window.core_workspace.dashboard_nav_buttons["overview"].text(),
            "Overview / Diagnosis",
        )
        self.window.header_panel.language_combo.setCurrentIndex(
            self.window.header_panel.language_combo.findData("ru")
        )

    def test_traceroute_hop_history_selects_and_bounds_samples(self) -> None:
        hop = TracerouteHop(6, "80.64.103.52", None, 18.5, "ok", False)
        for sample in range(70):
            self.window.mtr_controller._on_traceroute_hop_found(
                TracerouteHop(6, hop.address, None, float(sample), "ok", False)
            )

        self.assertEqual(self.window._dashboard_selected_hop, 6)
        self.assertEqual(len(self.window._dashboard_hop_histories[6]), 60)
        self.assertIn("80.64.103.52", self.window.core_workspace.dashboard_hop_history_title.text())
        self.assertEqual(self.window.core_workspace.dashboard_hop_history_chart.data[0], 10.0)
        self.assertEqual(self.window.core_workspace.dashboard_hop_history_chart.data[-1], 69.0)

    def test_workspace_sections_restore_visible_content_after_switching(self) -> None:
        self.window.show()
        self.app.processEvents()
        sections = (
            ("overview", self.window.core_workspace.dashboard_latency_chart),
            ("routes", self.window.path_workspace.routes_table),
            ("traceroute", self.window.mtr_workspace.traceroute_mode_tabs),
            ("interfaces", self.window.interfaces_panel.interfaces_table),
            ("quality", self.window.quality_workspace.quality_metrics["download"]),
            ("journal", self.window.journal_tabs),
        )
        for section, target_widget in sections:
            self.window.core_workspace.dashboard_nav_buttons[section].click()
            self.app.processEvents()
            self.assertTrue(target_widget.isVisibleTo(self.window), section)
            self.assertGreater(target_widget.width(), 200, section)

        self.window.core_workspace.dashboard_nav_buttons["overview"].click()
        self.app.processEvents()
        self.assertFalse(self.window.region_card.dashboard_region_table.isVisibleTo(self.window))
        sizes = self.window.core_workspace.dashboard_overview_splitter.sizes()
        self.assertEqual(sizes[1], 0)
        self.assertGreater(sizes[0], 0)
        self.assertGreater(sizes[2], 0)

        self.window.core_workspace.dashboard_nav_buttons["routes"].click()
        self.app.processEvents()
        self.assertTrue(self.window.core_workspace.topology_scroll.isVisibleTo(self.window))
        self.assertGreater(self.window.core_workspace.topology_scroll.width(), 200)
        route_labels = self.window.workspace_tabs.widget(1).findChildren(
            type(self.window.path_workspace.geo_status)
        )
        self.assertTrue(route_labels)
        self.assertTrue(
            all(
                label.sizePolicy().verticalPolicy() == QSizePolicy.Policy.Fixed
                for label in route_labels
                if label.objectName() in {"FieldLabel", "Muted"}
            )
        )

    def test_journal_layer_filter_is_visible_and_filters_events(self) -> None:
        self.window._journal = SessionJournal.create(_MemoryJournalStore())
        kinds = ("udp.port_opened", "vpn.bypass_suspected", "action.target_selected")
        for kind in kinds:
            self.window._journal.record(kind)
        self.window._render_journal()
        self.assertTrue(self.window.history_controller._journal_dirty)
        self.assertEqual(self.window.journal_workspace.journal_table.rowCount(), 0)
        self.window.show()
        self.window.core_workspace.dashboard_nav_buttons["journal"].click()
        self.app.processEvents()

        layer_filter = self.window.journal_workspace.journal_layer_filter
        table = self.window.journal_workspace.journal_table
        self.assertTrue(layer_filter.isVisibleTo(self.window))
        self.assertTrue(layer_filter.isEnabled())
        self.assertEqual(table.rowCount(), 3)
        for layer, kind in zip(("measurement", "inference", "action"), kinds):
            index = layer_filter.findData(layer)
            self.assertGreaterEqual(index, 0)
            layer_filter.setCurrentIndex(index)
            self.assertEqual(table.rowCount(), 1)
            self.assertEqual(table.item(0, 2).text(), kind)
        layer_filter.setCurrentIndex(layer_filter.findData(None))
        self.assertEqual(table.rowCount(), 3)

    def test_dashboard_mtu_pipeline_rolls_back_after_confirmation_timeout(self) -> None:
        self.journal_record_patch.stop()
        self.window._journal = SessionJournal.create(_MemoryJournalStore())
        self.window.show()
        self.window.core_workspace.dashboard_nav_buttons["interfaces"].click()
        self.window.core_workspace.dashboard_target_input.setText("1.1.1.1")
        self.app.processEvents()

        self.assertTrue(self.window.dashboard_mtu_section.isVisibleTo(self.window))
        self.assertEqual(
            self.window.ping_workspace.ping_tools_splitter.indexOf(
                self.window.mtu_workspace.mtu_optimizer_panel
            ),
            -1,
        )
        self.assertTrue(self.window.mtu_workspace.ping_mtu_host_input.isReadOnly())
        self.assertEqual(self.window.mtu_workspace.ping_mtu_host_input.text(), "1.1.1.1")

        report = MtuOptimizerReport(
            "1.1.1.1",
            1500,
            1492,
            (MtuOptimizerProbe(1492, 1464, True, 12.0, outcome="ok"),),
            target_ip="1.1.1.1",
            route_interface="Wi-Fi",
            decision="LOWER",
        )
        with patch.object(
            self.window.mtu_controller,
            "start_mtu_optimizer",
            side_effect=lambda: self.window.mtu_controller._on_mtu_optimizer_completed(report),
        ) as start_optimizer:
            self.window.mtu_workspace.ping_mtu_run_button.click()

        start_optimizer.assert_called_once_with()
        self.assertTrue(self.window.mtu_workspace.mtu_optimizer_apply_button.isEnabled())

        change = SystemChange("mtu", "Wi-Fi", 1500, 1492)

        def run_action(
            label: str,
            action: object,
            button: object,
            status_label: object = None,
        ) -> None:
            self.window._on_system_action_completed(label, button, action())

        with (
            patch(
                "netvision.ui.dashboard_v2.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Yes,
            ),
            patch(
                "netvision.ui.controllers.mtu_optimizer.apply_mtu_trial",
                return_value=SystemActionResult(True, "trial", change),
            ),
            patch(
                "netvision.ui.controllers.mtu_optimizer.rollback_change",
                return_value=SystemActionResult(True, "restored"),
            ),
            patch.object(self.window.mtu_controller, "_start_mtu_control_probe"),
            patch.object(self.window, "_action_confirm_timeout_s", return_value=0.05),
            patch.object(self.window, "_run_system_action", side_effect=run_action),
        ):
            self.window.mtu_workspace.mtu_optimizer_apply_button.click()

        kinds = [event.kind for event in self.window._journal.events()]
        self.assertIn("mtu.measured", kinds)
        self.assertIn("mtu.apply_trial", kinds)
        self.assertIn("mtu.rolled_back", kinds)

    def test_sidebar_theme_toggle_keeps_a_light_dashboard_surface(self) -> None:
        self.window._toggle_theme()
        self.assertEqual(self.window._theme, "light")
        self.assertIn("background-color: #F3F6FA", self.window.styleSheet())
        self.window._toggle_theme()
        self.assertEqual(self.window._theme, "dark")


if __name__ == "__main__":
    unittest.main()
