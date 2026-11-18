import json
import unittest
from pathlib import Path
from unittest.mock import patch

from netvision.core.packet_capture import BackendCapture, CaptureState, CapturedUdpPacket
from netvision.core.process_inspector import (
    ProcessConnection,
    ProcessListResult,
    ProcessNetworkInfo,
    ProcessScanResult,
    RunningProcess,
)
from netvision.ui.game_check_worker import GameAutoCheckWorker


class FakeCaptureBackend:
    def __init__(self, capture: BackendCapture | None = None, error: Exception | None = None):
        self.capture_result = capture
        self.error = error
        self.arguments = None

    def capture(self, pid, local_ports, stop_event, timeout_s):
        self.arguments = (pid, tuple(local_ports), stop_event, timeout_s)
        if self.error is not None:
            raise self.error
        return self.capture_result or BackendCapture()


class PacketCaptureWorkerTests(unittest.TestCase):
    def test_unresolved_udp_socket_uses_capture_and_selects_endpoint(self) -> None:
        packets = tuple(
            CapturedUdpPacket("192.168.1.2", 40000, "8.8.8.8", 27015, 1200) for _ in range(8)
        )
        backend = FakeCaptureBackend(BackendCapture(packets, CaptureState.TIMED_OUT))
        worker = GameAutoCheckWorker("HuntGame.exe", backend, capture_timeout_s=0.1)
        results = []
        capture_events = []
        worker.completed.connect(results.append)
        worker.capture_started.connect(capture_events.append)
        process = RunningProcess(700, "HuntGame.exe")
        unresolved = ProcessConnection("UDP", "NONE", "192.168.1.2", 40000, "", 0)

        with (
            patch(
                "netvision.ui.game_check_worker.list_running_processes",
                return_value=ProcessListResult((process,)),
            ),
            patch(
                "netvision.ui.game_check_worker.scan_process",
                return_value=ProcessScanResult(
                    (ProcessNetworkInfo(process.pid, process.name, (unresolved,)),)
                ),
            ),
            patch("netvision.ui.game_check_worker.probe_ping", return_value=object()),
        ):
            worker.run()

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].capture_state, CaptureState.ENDPOINT_FOUND)
        self.assertEqual(results[0].selected_connection.remote_endpoint, "8.8.8.8:27015")
        self.assertEqual(results[0].selection_reason, "Перехват UDP-заголовков")
        self.assertEqual(
            capture_events,
            [{"pid": 700, "process": "HuntGame.exe", "ports": (40000,)}],
        )
        self.assertEqual(backend.arguments[0:2], (700, (40000,)))

    def test_permission_denied_is_returned_as_honest_capture_status(self) -> None:
        backend = FakeCaptureBackend(error=PermissionError("administrator required"))
        worker = GameAutoCheckWorker("HuntGame.exe", backend)
        results = []
        worker.completed.connect(results.append)
        process = RunningProcess(700, "HuntGame.exe")
        unresolved = ProcessConnection("UDP", "NONE", "192.168.1.2", 40000, "", 0)

        with (
            patch(
                "netvision.ui.game_check_worker.list_running_processes",
                return_value=ProcessListResult((process,)),
            ),
            patch(
                "netvision.ui.game_check_worker.scan_process",
                return_value=ProcessScanResult(
                    (ProcessNetworkInfo(process.pid, process.name, (unresolved,)),)
                ),
            ),
        ):
            worker.run()

        self.assertEqual(results[0].capture_state, CaptureState.PERMISSION_DENIED)
        self.assertIn("Администратора", results[0].warning or "")

    def test_new_packet_capture_localization_keys_are_synchronized(self) -> None:
        root = Path(__file__).resolve().parents[1] / "netvision" / "ui"
        ru = json.loads((root / "ru-ru.json").read_text(encoding="utf-8-sig"))
        en = json.loads((root / "en-en.json").read_text(encoding="utf-8-sig"))

        self.assertEqual(set(ru), set(en))
        for key in (
            "Перехват UDP-заголовков",
            "Перехват UDP-заголовков запущен для PID {pid} по портам {ports}",
            "Игровой UDP endpoint обнаружен перехватом: {endpoint}",
            "Перезапустить как Администратор",
        ):
            self.assertIn(key, ru)
            self.assertIn(key, en)


if __name__ == "__main__":
    unittest.main()
