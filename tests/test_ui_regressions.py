"""Parity and queued-signal regression tests for the dashboard shell."""

from __future__ import annotations

from datetime import datetime
import json
from threading import Event
from types import SimpleNamespace
import ssl
import time
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QEvent, QObject, Qt, Signal
from PySide6.QtGui import QWindowStateChangeEvent
from PySide6.QtWidgets import (
    QApplication,
    QTableWidgetItem,
)

from netvision.core.diagnostics import DiagnosticService
from netvision.core.probes import probe_tls
from netvision.core.target import parse_target
from netvision.core.traceroute import MtrHopStats, MtrSnapshot, TracerouteHop
from netvision.core.nat_diagnostics import NatEndpoint, NatReport
from netvision.core.session_journal import Layer
from netvision.models import (
    DnsResult,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
    TlsResult,
    DiagnosticReport,
)
from netvision.reporting import serialize_support_bundle
from netvision.ui.controllers.dns_audit import DnsController
from netvision.ui.dashboard_v2 import NetVisionDashboardV2
from netvision.ui.components.table_context_menu import create_menu, find_target


class _QuietMtrWorker(QObject):
    snapshot = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, _host: str, **_kwargs: object) -> None:
        super().__init__()
        self._stopped = Event()

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        self._stopped.wait(0.25)
        self.finished.emit()


class UiRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(
            ["NetVision-ui-surface-tests", "-platform", "offscreen"]
        )

    def setUp(self) -> None:
        self._record_patch = patch.object(
            NetVisionDashboardV2, "_record_journal_event", return_value=None
        )
        self._snapshot_patch = patch.object(NetVisionDashboardV2, "_load_local_network_snapshot")
        self._dns_config_patch = patch.object(DnsController, "_load_dns_configuration")
        self._dns_identity_patch = patch.object(DnsController, "_check_network_identity")
        self._record_patch.start()
        self._snapshot_patch.start()
        self._dns_config_patch.start()
        self._dns_identity_patch.start()
        self.window = NetVisionDashboardV2(bootstrap=False)

    def tearDown(self) -> None:
        self.window._quit_requested = True
        self.window.dns_controller.stop()
        self.window._worker_registry.stop_all()
        for thread in tuple(self.window._worker_registry._jobs):
            self.assertTrue(thread.wait(2000))
        self.window.close()
        self.assertTrue(self._wait_until(lambda: not self.window._worker_registry.busy))
        self.window.deleteLater()
        self.app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.app.processEvents()
        self._snapshot_patch.stop()
        self._dns_config_patch.stop()
        self._dns_identity_patch.stop()
        self._record_patch.stop()

    def test_mtr_snapshot_reaches_the_table_through_the_queue(self) -> None:
        worker = _QuietMtrWorker("1.1.1.1")
        self.window._mtr_worker = worker
        worker.snapshot.connect(
            self.window._queue_ui_slot(
                self.window.mtr_controller._on_mtr_snapshot,
                owner=worker,
                active_owner=lambda: self.window._mtr_worker,
            )
        )
        snapshot = self._mtr_snapshot()
        worker.snapshot.emit(snapshot)
        self.assertTrue(
            self._wait_until(lambda: self.window._facts.get("mtr.snapshot") is snapshot)
        )
        self.assertEqual(self.window.mtr_workspace.mtr_table.rowCount(), 0)
        with patch.object(self.window.mtr_workspace.mtr_table, "isVisible", return_value=True):
            self.window.mtr_controller._render_pending_snapshot()
        self.assertTrue(
            self._wait_until(lambda: self.window.mtr_workspace.mtr_table.rowCount() == 1)
        )
        self.assertEqual(self.window.mtr_workspace.mtr_table.item(0, 1).text(), "1.1.1.1")
        self.assertIs(self.window._facts.get("mtr.snapshot"), snapshot)

    def test_context_menus_copy_and_open_target(self) -> None:
        journal = self.window.journal_workspace.journal_table
        udp = self.window.udp_history_workspace.udp_events_table
        mtr = self.window.mtr_workspace.mtr_table
        for table in (journal, udp, mtr):
            self.assertEqual(table.contextMenuPolicy(), Qt.ContextMenuPolicy.CustomContextMenu)
        for table, column, target in (
            (journal, 3, "example.com"),
            (udp, 3, "192.0.2.1"),
            (mtr, 1, "2001:db8::1"),
        ):
            table.setRowCount(1)
            table.setItem(0, column, QTableWidgetItem(target))
            menu = create_menu(self.window, table, 0, (column,), table is not mtr)
            self.assertEqual(len(menu.actions()), 3 if table is not mtr else 2)
            menu.actions()[0].trigger()
            self.assertEqual(self.app.clipboard().text(), target)
            menu.actions()[1].trigger()
            self.assertIn(target, self.app.clipboard().text())
            if table is not mtr:
                menu.actions()[2].trigger()
                self.assertEqual(self.window.mtr_workspace.traceroute_target_input.text(), target)
                self.assertIs(self.window.workspace_tabs.currentWidget(), self.window.mtr_workspace)
                self.assertEqual(self.window.mtr_workspace.traceroute_mode_tabs.currentIndex(), 1)
            menu.deleteLater()
        self.assertIsNone(find_target("UDP-порт 443 появился у PID 123"))
        self.assertEqual(find_target("192.0.2.1:443"), ("192.0.2.1", True))
        self.assertEqual(find_target("[2001:db8::1]:443"), ("2001:db8::1", True))

    def test_traceroute_result_retranslates(self) -> None:
        hop = TracerouteHop(1, "192.0.2.1", None, 2.0, "ok", False)
        self.window.mtr_controller._on_traceroute_completed((hop,))
        self.assertIn("1 узел", self.window.mtr_workspace.traceroute_status.text())
        self.window.header_panel.language_combo.setCurrentIndex(1)
        self.assertIn("1 hop", self.window.mtr_workspace.traceroute_status.text())
        self.window.header_panel.language_combo.setCurrentIndex(0)
        self.assertIn("1 узел", self.window.mtr_workspace.traceroute_status.text())

    def test_restored_journal_flush_is_scheduled_once(self) -> None:
        controller = self.window.history_controller
        controller._journal_dirty = True
        controller._udp_dirty = False
        with (
            patch.object(controller, "_render_journal") as render,
            patch("netvision.ui.controllers.history_controller.QTimer.singleShot") as schedule,
        ):
            controller.flush_visible_tables()
            controller.flush_visible_tables()
            render.assert_not_called()
            schedule.assert_called_once()
            schedule.call_args.args[1]()
            render.assert_called_once()

    def test_deferred_journal_renders_in_batches_and_reuses_items(self) -> None:
        table = self.window.journal_workspace.journal_table
        event = SimpleNamespace(
            at=datetime.now(),
            layer=Layer.MEASUREMENT,
            kind="test",
            subject="example.com",
            template="test",
            values={},
            severity="info",
        )
        with (
            patch.object(self.window, "_journal_events_for_view", return_value=[event] * 250),
            patch.object(table, "isVisible", return_value=True),
            patch("netvision.ui.controllers.history_controller.QTimer.singleShot") as schedule,
        ):
            self.window.history_controller._render_journal(deferred=True)
            self.assertIsNotNone(table.item(99, 0))
            self.assertIsNone(table.item(100, 0))
            first = table.item(0, 0)
            schedule.call_args.args[1]()
            self.assertIsNotNone(table.item(199, 0))
            schedule.call_args.args[1]()
            self.assertIsNotNone(table.item(249, 0))
            self.window.history_controller._render_journal(deferred=True)
            self.assertIs(table.item(0, 0), first)

    def test_theme_change_updates_native_titlebar(self) -> None:
        with patch("netvision.ui.dashboard_v2.apply_titlebar_theme") as apply:
            self.window._toggle_theme()
            apply.assert_called_with(self.window, False)
            self.window._toggle_theme()
            apply.assert_called_with(self.window, True)

    def test_mtr_reuses_cells_and_retains_selection(self) -> None:
        table = self.window.mtr_workspace.mtr_table
        snapshot = self._mtr_snapshot()
        with patch.object(table, "isVisible", return_value=True):
            self.window.mtr_controller._render_mtr_snapshot(snapshot)
            table.selectRow(0)
            original = table.item(0, 1)
            self.window.mtr_controller._render_mtr_snapshot(snapshot)
            self.assertIs(table.item(0, 1), original)
            self.assertEqual(table.currentRow(), 0)

    def test_hidden_mtr_defers_history_until_table_is_shown(self) -> None:
        controller = self.window.mtr_controller
        table = self.window.mtr_workspace.mtr_table
        with patch.object(self.window, "_dashboard_refresh_hop_history") as refresh:
            with patch.object(table, "isVisible", return_value=False):
                controller._render_mtr_snapshot(self._mtr_snapshot())
                refresh.assert_not_called()
                self.assertIsNotNone(controller._pending_snapshot)
            with patch.object(table, "isVisible", return_value=True):
                controller._render_pending_snapshot()
            self.assertIsNone(controller._pending_snapshot)
            self.assertGreaterEqual(refresh.call_count, 1)

    def test_restoring_window_flushes_deferred_views(self) -> None:
        with (
            patch.object(self.window.history_controller, "flush_visible_tables") as history,
            patch.object(self.window.mtr_controller, "_render_pending_snapshot") as mtr,
            patch.object(self.window, "isMinimized", return_value=False),
        ):
            self.window.changeEvent(QWindowStateChangeEvent(Qt.WindowState.WindowMinimized))
            self.assertTrue(self._wait_until(lambda: history.called and mtr.called))

    def test_dns_benchmark_keeps_public_ip_on_failure(self) -> None:
        from netvision.core.internet_quality import PublicIpAddresses

        controller = self.window.dns_controller
        self.window._dns_public_addresses = PublicIpAddresses(ipv4="203.0.113.10")
        with (
            patch("netvision.ui.controllers.dns_audit.QThread") as thread_type,
            patch("netvision.ui.controllers.dns_audit.DnsBenchmarkWorker") as worker_type,
            patch.object(controller.registry, "retain"),
        ):
            thread_type.return_value.isRunning.return_value = False
            controller.start_dns_benchmark()
            controller._on_dns_configuration_failed("temporary timeout")
            self.assertEqual(self.window._dns_public_addresses.ipv4, "203.0.113.10")
            self.window._dns_benchmark_thread = None
            self.window._dns_benchmark_worker = None
            self.assertTrue(worker_type.called)

    def test_dns_stop_discards_late_network_change(self) -> None:
        controller = self.window.dns_controller
        controller._reload_pending = True
        controller.stop()
        self.assertFalse(controller._identity_timer.isActive())
        self.assertFalse(controller._reload_pending)
        with patch.object(controller, "_render_dns_info") as render:
            controller._network_identity_changed(("VPN", "10.0.0.2"))
            render.assert_not_called()
        controller._load_dns_configuration.assert_not_called()

    def test_nat_journal_endpoints_are_readable(self) -> None:
        report = NatReport(
            "ok",
            "eim",
            mapped_endpoints=(NatEndpoint("stun.example:3478", "192.0.2.1", 1234),),
        )
        self.window.diagnostics_coordinator._on_nat_probe_completed(report)
        calls = self.window._record_journal_event.call_args_list
        event = next(call for call in calls if call.args[0] == "nat.measured")
        self.assertEqual(event.kwargs["values"]["endpoints"], "stun.example:3478 -> 192.0.2.1:1234")

    def test_mtr_start_stop_cycle_is_safe(self) -> None:
        with patch("netvision.ui.controllers.mtr_audit.MtrMonitorWorker", _QuietMtrWorker):
            for _ in range(10):
                self.window.mtr_controller.start_mtr_monitor()
                self.assertIsNotNone(self.window._mtr_worker)
                self.window.mtr_controller.stop_mtr_monitor()
                self.assertTrue(self._wait_until(lambda: self.window._mtr_worker is None))
                self.assertTrue(self._wait_until(lambda: not self.window._worker_registry.busy))

    def test_mtr_clear_waits_for_native_thread_cleanup(self) -> None:
        thread = Mock()
        thread.wait.return_value = False
        self.window._mtr_thread = thread
        try:
            with (
                patch("netvision.ui.controllers.mtr_audit.isValid", return_value=True),
                patch("netvision.ui.controllers.mtr_audit.QTimer.singleShot") as retry,
            ):
                self.window.mtr_controller._clear_mtr_worker()
                self.assertIs(self.window._mtr_thread, thread)
                retry.assert_called_once()
        finally:
            self.window._mtr_thread = None

    def test_tls_initialization_failure_preserves_other_probe_results(self) -> None:
        target = parse_target("https://example.com")
        system = SystemSnapshot("test", (), None, (), None, ())
        dns = DnsResult(target.host, (), 1.0, ProbeStatus.SUCCESS)
        tcp = TcpResult(target.host, target.port, None, 2.0, ProbeStatus.SUCCESS)
        ping = PingResult(target.host, 1, 1, 0.0, 3.0, 3.0, 3.0, 0.0, (3.0,), ProbeStatus.SUCCESS)
        with (
            patch("netvision.core.diagnostics.collect_system_snapshot", return_value=system),
            patch("netvision.core.diagnostics.resolve_dns", return_value=dns),
            patch("netvision.core.diagnostics.probe_tcp", return_value=tcp),
            patch("netvision.core.diagnostics.probe_ping", return_value=ping),
            patch("netvision.core.diagnostics.trace_route", return_value=()),
            patch(
                "netvision.core.probes.ssl.create_default_context", side_effect=ssl.SSLError("cert")
            ),
        ):
            report = DiagnosticService().run(target)

        self.assertEqual(report.dns, dns)
        self.assertEqual(report.tcp, tcp)
        self.assertEqual(report.ping, ping)
        self.assertIsNotNone(report.tls)
        self.assertEqual(report.tls.status, ProbeStatus.ERROR)
        self.assertTrue(any(error.startswith("TLS:") for error in report.errors))

    def test_probe_tls_returns_error_when_ssl_context_cannot_start(self) -> None:
        with patch(
            "netvision.core.probes.ssl.create_default_context", side_effect=ssl.SSLError("cert")
        ):
            result = probe_tls(parse_target("https://example.com"))
        self.assertEqual(result.status, ProbeStatus.ERROR)
        self.assertIn("cert", result.error or "")

    def test_ip_tls_mismatch_is_neutral_and_emits_info(self) -> None:
        target = parse_target("140.82.113.26", 443)
        report = DiagnosticReport(
            target,
            SystemSnapshot("test", (), None, (), None, ()),
            DnsResult(target.host, (target.host,), 1.0, ProbeStatus.SUCCESS),
            TcpResult(target.host, 443, target.host, 2.0, ProbeStatus.SUCCESS),
            PingResult(target.host, 1, 1, 0.0, 3.0, 3.0, 3.0, 0.0, (3.0,), ProbeStatus.SUCCESS),
            TlsResult(
                None,
                None,
                None,
                None,
                None,
                None,
                3.0,
                ProbeStatus.ERROR,
                "CERTIFICATE_VERIFY_FAILED: IP address mismatch",
            ),
            (),
            (),
            datetime.now(),
            5.0,
        )
        messages = []
        self.window.event_bus.log_requested.connect(
            lambda message, level: messages.append((message, level))
        )
        with (
            patch.object(self.window, "_start_wifi_monitor"),
            patch.object(self.window, "_dashboard_probe_regions_once"),
        ):
            self.window._on_completed(report)
        self.assertEqual(self.window.expert_view.metrics["tls"].value.text(), "Требует домен")
        self.assertTrue(any(level == "INFO" and "домен" in message for message, level in messages))
        self.assertNotIn(
            "Предупреждение: TLS", self.window.events_card.dashboard_event_output.toPlainText()
        )

    def test_failed_diagnostic_keeps_support_export_available(self) -> None:
        self.window.header_panel.support_bundle_button.setEnabled(False)
        self.window.core_workspace.dashboard_support_button.setEnabled(False)
        with patch("netvision.ui.dashboard_v2.QMessageBox.critical"):
            try:
                try:
                    raise ValueError("initial probe failure")
                except ValueError as context:
                    raise RuntimeError("diagnostic failure") from context
            except RuntimeError as failure:
                self.window._on_failed(failure)

        payload = json.loads(
            serialize_support_bundle(
                None,
                journal=self.window._journal,
                thresholds=self.window._thresholds,
                measurements=self.window._support_bundle_measurements(),
            )
        )
        self.assertTrue(self.window.header_panel.support_bundle_button.isEnabled())
        self.assertTrue(self.window.core_workspace.dashboard_support_button.isEnabled())
        self.assertIsNone(payload["report"])
        self.assertIn("windows_version", payload["meta"])
        self.assertIn("diagnostic failure", payload["measurements"]["diagnostic_failure"])
        self.assertIn("initial probe failure", payload["measurements"]["diagnostic_failure"])

    def _wait_until(self, predicate, timeout_s: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    @staticmethod
    def _mtr_snapshot() -> MtrSnapshot:
        hop = MtrHopStats(
            ttl=1,
            addresses=("1.1.1.1",),
            sent=1,
            recv=1,
            loss_pct=0.0,
            last_ms=10.0,
            avg_ms=10.0,
            best_ms=10.0,
            worst_ms=10.0,
            jitter_ms=0.0,
        )
        return MtrSnapshot("1.1.1.1", datetime.now().astimezone(), (hop,), True, False)


if __name__ == "__main__":
    unittest.main()
