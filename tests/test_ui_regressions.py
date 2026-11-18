"""Parity and queued-signal regression tests for the dashboard shell."""

from __future__ import annotations

from datetime import datetime
import json
from threading import Event
import ssl
import time
import unittest
from unittest.mock import patch

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication,
)

from netvision.core.diagnostics import DiagnosticService
from netvision.core.probes import probe_tls
from netvision.core.target import parse_target
from netvision.core.traceroute import MtrHopStats, MtrSnapshot
from netvision.models import (
    DnsResult,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
)
from netvision.reporting import serialize_support_bundle
from netvision.ui.controllers.dns_audit import DnsController
from netvision.ui.dashboard_v2 import NetVisionDashboardV2


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
        self._record_patch.start()
        self._snapshot_patch.start()
        self._dns_config_patch.start()
        self.window = NetVisionDashboardV2(bootstrap=False)

    def tearDown(self) -> None:
        self.window._quit_requested = True
        self.window._worker_registry.stop_all()
        for thread in tuple(self.window._worker_registry._jobs):
            self.assertTrue(thread.wait(2000))
        self.window.close()
        self.assertTrue(self._wait_until(lambda: not self.window._worker_registry.busy))
        self.window.deleteLater()
        self.app.processEvents()
        self._snapshot_patch.stop()
        self._dns_config_patch.stop()
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
            self._wait_until(lambda: self.window.mtr_workspace.mtr_table.rowCount() == 1)
        )
        self.assertEqual(self.window.mtr_workspace.mtr_table.item(0, 1).text(), "1.1.1.1")
        self.assertIs(self.window._facts.get("mtr.snapshot"), snapshot)

    def test_mtr_start_stop_cycle_is_safe(self) -> None:
        with patch("netvision.ui.controllers.mtr_audit.MtrMonitorWorker", _QuietMtrWorker):
            for _ in range(10):
                self.window.mtr_controller.start_mtr_monitor()
                self.assertIsNotNone(self.window._mtr_worker)
                self.window.mtr_controller.stop_mtr_monitor()
                self.assertTrue(self._wait_until(lambda: self.window._mtr_worker is None))
                self.assertTrue(self._wait_until(lambda: not self.window._worker_registry.busy))

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
