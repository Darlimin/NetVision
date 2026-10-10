import socket
import unittest
from unittest.mock import patch

from netvision.core import network_boost
from netvision.core.network_boost import BackgroundTrafficCandidate


class FakeConnection:
    def __init__(self, pid, connection_type, status="", local_address=("192.168.1.5", 50000)) -> None:
        self.pid = pid
        self.type = connection_type
        self.status = status
        self.laddr = local_address


class FakeProcess:
    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self._name = name
        self.terminated = False

    def name(self) -> str:
        return self._name

    def create_time(self) -> float:
        return 1000.0

    def is_running(self) -> bool:
        return True

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float) -> None:
        if not self.terminated:
            raise AssertionError(f"process {self.pid} was not terminated")


class NetworkBoostTests(unittest.TestCase):
    @patch.object(network_boost.psutil, "Process")
    @patch.object(network_boost.psutil, "net_connections")
    def test_scanner_only_returns_known_non_system_background_apps(self, connections_mock, process_mock) -> None:
        connections_mock.return_value = [
            FakeConnection(101, socket.SOCK_STREAM, "ESTABLISHED"),
            FakeConnection(101, socket.SOCK_STREAM, "SYN_SENT"),
            FakeConnection(202, socket.SOCK_DGRAM, "NONE"),
            FakeConnection(303, socket.SOCK_STREAM, "ESTABLISHED"),
            FakeConnection(404, socket.SOCK_STREAM, "ESTABLISHED"),
            FakeConnection(505, socket.SOCK_STREAM, "LISTEN"),
        ]
        process_mock.side_effect = lambda pid: FakeProcess(
            pid,
            {
                101: "qBittorrent.exe",
                202: "OneDrive.exe",
                303: "svchost.exe",
                404: "chrome.exe",
                505: "steam.exe",
            }[pid],
        )

        result = network_boost.scan_background_traffic_candidates()

        self.assertIsNone(result.warning)
        self.assertEqual([candidate.pid for candidate in result.candidates], [101, 202])
        self.assertEqual(result.candidates[0].category, "Торрент-клиент")
        self.assertEqual(result.candidates[0].active_connection_count, 2)
        self.assertEqual(result.candidates[1].display_name, "Microsoft OneDrive")

    def test_protected_processes_and_current_netvision_process_are_never_allowed(self) -> None:
        self.assertTrue(network_boost.is_protected_process("svchost.exe"))
        self.assertTrue(network_boost.is_protected_process("explorer.exe"))
        self.assertTrue(network_boost.is_protected_process("NetVision.exe"))
        self.assertTrue(network_boost.is_protected_process("qBittorrent.exe", network_boost.os.getpid()))
        self.assertFalse(network_boost.is_protected_process("qBittorrent.exe", 12345))

    @patch.object(network_boost.psutil, "Process")
    def test_termination_revalidates_identity_before_terminate(self, process_mock) -> None:
        process = FakeProcess(101, "qBittorrent.exe")
        process_mock.return_value = process
        candidate = BackgroundTrafficCandidate(101, "qBittorrent.exe", "qBittorrent", "Торрент-клиент", 3, 1000.0)

        result = network_boost.terminate_background_candidates((candidate,))

        self.assertTrue(process.terminated)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].success)
        self.assertEqual(result[0].message, "Процесс завершён")

    @patch.object(network_boost.psutil, "Process")
    def test_termination_refuses_pid_reused_by_another_process(self, process_mock) -> None:
        process = FakeProcess(101, "steam.exe")
        process_mock.return_value = process
        candidate = BackgroundTrafficCandidate(101, "qBittorrent.exe", "qBittorrent", "Торрент-клиент", 1, 1000.0)

        result = network_boost.terminate_background_candidates((candidate,))

        self.assertFalse(process.terminated)
        self.assertFalse(result[0].success)
        self.assertIn("другому процессу", result[0].message)

    @patch.object(network_boost.psutil, "Process")
    def test_invalid_and_reserved_pids_never_reach_psutil(self, process_mock) -> None:
        for pid in (0, 4, -1, True, "123", network_boost.os.getpid(), network_boost.os.getppid()):
            candidate = BackgroundTrafficCandidate(pid, "steam.exe", "Steam", "Launcher", 1, 1000.0)
            self.assertFalse(network_boost.terminate_background_candidates((candidate,))[0].success)
        process_mock.assert_not_called()

    @patch.object(network_boost.psutil, "Process")
    def test_protected_names_and_unknown_apps_never_reach_psutil(self, process_mock) -> None:
        for name in (*network_boost.PROTECTED_PROCESS_NAMES, "unknown.exe"):
            candidate = BackgroundTrafficCandidate(12345, name.upper(), name, "", 1, 1000.0)
            self.assertFalse(network_boost.terminate_background_candidates((candidate,))[0].success)
        process_mock.assert_not_called()

    @patch.object(network_boost.psutil, "Process")
    def test_missing_identity_fails_closed(self, process_mock) -> None:
        candidate = BackgroundTrafficCandidate(12345, "steam.exe", "Steam", "", 1)
        self.assertFalse(network_boost.terminate_background_candidates((candidate,))[0].success)
        process_mock.assert_not_called()

    @patch.object(network_boost.psutil, "Process")
    def test_same_name_recycled_pid_is_not_terminated(self, process_mock) -> None:
        process = process_mock.return_value
        process.name.return_value = "steam.exe"
        process.create_time.return_value = 2000.0
        candidate = BackgroundTrafficCandidate(12345, "steam.exe", "Steam", "", 1, 1000.0)
        self.assertFalse(network_boost.terminate_background_candidates((candidate,))[0].success)
        process.terminate.assert_not_called()

    @patch.object(network_boost.psutil, "Process")
    def test_timeout_never_escalates_and_duplicates_terminate_once(self, process_mock) -> None:
        process = process_mock.return_value
        process.name.return_value = "steam.exe"
        process.create_time.return_value = 1000.0
        process.wait.side_effect = network_boost.psutil.TimeoutExpired(0.01)
        candidate = BackgroundTrafficCandidate(12345, "steam.exe", "Steam", "", 1, 1000.0)
        results = network_boost.terminate_background_candidates((candidate, candidate), timeout_s=0.01)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].success)
        process.terminate.assert_called_once()
        process.kill.assert_not_called()

    @patch.object(network_boost.psutil, "Process")
    def test_disappeared_and_access_denied_processes_are_reported(self, process_mock) -> None:
        candidate = BackgroundTrafficCandidate(12345, "steam.exe", "Steam", "", 1, 1000.0)
        for error, success in ((network_boost.psutil.NoSuchProcess(12345), True),
                               (network_boost.psutil.AccessDenied(12345), False)):
            process_mock.side_effect = error
            self.assertEqual(network_boost.terminate_background_candidates((candidate,))[0].success, success)

    @patch.object(network_boost.psutil, "Process")
    @patch.object(network_boost.psutil, "net_connections")
    def test_scanning_empty_inaccessible_and_disappeared_processes(self, connections_mock, process_mock) -> None:
        connections_mock.return_value = []
        self.assertEqual(network_boost.scan_background_traffic_candidates().candidates, ())
        process_mock.assert_not_called()
        connections_mock.return_value = [FakeConnection(12345, socket.SOCK_STREAM, "ESTABLISHED")]
        process_mock.side_effect = network_boost.psutil.NoSuchProcess(12345)
        self.assertEqual(network_boost.scan_background_traffic_candidates().candidates, ())
        connections_mock.side_effect = network_boost.psutil.AccessDenied()
        self.assertIsNotNone(network_boost.scan_background_traffic_candidates().warning)


if __name__ == "__main__":
    unittest.main()
