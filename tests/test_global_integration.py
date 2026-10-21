from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from netvision.core import crash_handler, system_actions
from netvision.core.mtu_optimizer import MtuOptimizerProbe, MtuOptimizerReport
from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo, ProcessScanResult
from netvision.core.system_actions import SystemActionResult, SystemChange
from netvision.ui.main_window import MainWindow, PendingAction, RollbackConfirmDialog


class GlobalIntegrationTests(unittest.TestCase):
    """A fully mocked desktop journey that never touches real network settings."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(
            ["NetVision-global-integration", "-platform", "offscreen"]
        )

    def setUp(self) -> None:
        self._temporary_directory = TemporaryDirectory()
        self._journal_path = Path(self._temporary_directory.name) / "event_journal.jsonl"
        self._patches = [
            patch(
                "netvision.core.session_journal.default_journal_path",
                return_value=self._journal_path,
            ),
            patch.object(MainWindow, "_start_latency_monitor"),
            patch.object(MainWindow, "_start_udp_port_monitor"),
            patch("netvision.core.process_inspector.psutil.process_iter", return_value=()),
            patch("netvision.core.process_inspector.psutil.net_connections", return_value=()),
        ]
        for active_patch in self._patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)
        self.window = MainWindow()
        self.window._network_alarm_enabled = False
        self.window.show()
        QTest.qWait(10)
        self.addCleanup(self._close_window)
        self.addCleanup(self._temporary_directory.cleanup)

    def _close_window(self) -> None:
        self.window._background_enabled = False
        self.window._quit_requested = True
        self.window.close()

    def test_full_user_journey_e2e(self) -> None:
        connection = ProcessConnection(
            "UDP", "ESTABLISHED", "192.168.1.20", 40100, "8.8.8.8", 27015
        )
        game = ProcessNetworkInfo(4242, "HuntGame.exe", (connection,))
        self.window._on_process_scan_completed(ProcessScanResult((game,)))
        self.window.process_selector.setCurrentIndex(0)
        self.window._on_connection_selected(0)

        self.assertEqual(self.window._selected_process, game)
        self.assertEqual(self.window.target_input.text(), "8.8.8.8")
        self.assertEqual(self.window.port_input.value(), 27015)

        for latency in (30.0, 32.0, 135.0, 148.0, 121.0, 70.0, 70.0, 70.0):
            self.window._on_latency_sample(latency, True)

        self.assertEqual(len(self.window._ping_spike_events), 1)
        self.assertIn("Пик задержки", self.window.ping_spike_log.toPlainText())
        high_rtt_events = [
            event
            for event in self.window._journal.events()
            if event.kind == "jitter.episode" and "latency" in event.values
        ]
        self.assertEqual(len(high_rtt_events), 1)

        quality_index = next(
            index
            for index in range(self.window.workspace_tabs.count())
            if self.window.workspace_tabs.tabText(index) == "Качество"
        )
        self.window.workspace_tabs.setCurrentIndex(quality_index)
        report = MtuOptimizerReport(
            target="8.8.8.8",
            current_mtu=1500,
            optimal_mtu=1492,
            probes=(MtuOptimizerProbe(1492, 1464, True, 10.0, outcome="ok"),),
            target_ip="8.8.8.8",
            route_interface="Wi-Fi",
            decision="LOWER",
        )
        self.window._on_mtu_optimizer_completed(report)
        self.assertTrue(self.window.mtu_optimizer_apply_button.isEnabled())

        change = SystemChange("mtu", "Wi-Fi", 1500, 1492)
        trial_result = SystemActionResult(True, "Пробный MTU применён", change)
        with patch.object(system_actions.os, "name", "nt"), patch.object(
            system_actions.subprocess,
            "run",
            return_value=CompletedProcess(["netsh"], 0, stdout=b""),
        ) as netsh_run, patch(
            "netvision.ui.main_window.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ), patch(
            "netvision.ui.main_window.apply_mtu_trial",
            return_value=trial_result,
        ), patch.object(
            self.window,
            "_run_system_action",
            side_effect=self._run_system_action_synchronously,
        ), patch.object(
            self.window,
            "_start_mtu_trial_confirmation",
            side_effect=self._reject_mtu_trial,
        ):
            QTest.mouseClick(self.window.mtu_optimizer_apply_button, Qt.MouseButton.LeftButton)

        self.assertEqual(
            netsh_run.call_args.args[0],
            [
                "netsh", "interface", "ipv4", "set", "subinterface", "Wi-Fi",
                "mtu=1500", "store=persistent",
            ],
        )
        event_kinds = [event.kind for event in self.window._journal.events()]
        self.assertIn("action.process_selected", event_kinds)
        self.assertIn("mtu.measured", event_kinds)
        self.assertIn("action.system_rolled_back", event_kinds)
        self.assertIn("mtu.rolled_back", event_kinds)
        self.assertTrue(self._journal_path.exists())

        crash_path = Path(self._temporary_directory.name) / "crash_reports.log"
        with patch.object(crash_handler, "_crash_report_path", return_value=crash_path), patch.object(
            crash_handler, "_queue_error_dialog"
        ):
            try:
                raise RuntimeError("global journey crash reporter")
            except RuntimeError as error:
                crash_handler._handle_exception(
                    type(error), error, error.__traceback__, thread_name="integration"
                )
        self.assertIn("global journey crash reporter", crash_path.read_text(encoding="utf-8"))

    def _run_system_action_synchronously(
        self,
        label: str,
        action: object,
        button: object,
        status_label: object = None,
    ) -> None:
        self.window._on_system_action_completed(label, button, action())

    def _reject_mtu_trial(self, button: object, status_label: object, change: SystemChange) -> None:
        dialog = RollbackConfirmDialog(change, self.window._tr, self.window, seconds=5)
        QTimer.singleShot(
            0,
            lambda: QTest.mouseClick(dialog.rollback_button, Qt.MouseButton.LeftButton),
        )
        self.assertEqual(dialog.exec(), dialog.DialogCode.Rejected)
        rollback_label = "Откат MTU"
        self.window._rollback_actions[rollback_label] = (
            change,
            PendingAction(
                apply=lambda: None,
                rollback=lambda: system_actions.rollback_change(change),
                timeout_s=5.0,
            ),
        )
        self.window._mtu_rollback_reasons[rollback_label] = "user_rejected"
        result = system_actions.rollback_change(change)
        self.window._on_system_action_completed(rollback_label, button, result)


if __name__ == "__main__":
    unittest.main()
