import socket
import unittest
from unittest.mock import patch

from netvision.core import process_inspector


class FakeConnection:
    def __init__(self, pid, laddr, raddr, status, connection_type=socket.SOCK_STREAM):
        self.pid = pid
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.type = connection_type


class FakeProcess:
    def __init__(self, name: str, connections=()):
        self._name = name
        self._connections = connections

    def name(self) -> str:
        return self._name

    def net_connections(self, kind: str):
        assert kind == "inet"
        return self._connections


class ProcessInspectorTests(unittest.TestCase):
    @patch.object(process_inspector.psutil, "Process")
    @patch.object(process_inspector.psutil, "net_connections")
    def test_groups_active_tcp_and_udp_connections_by_process(self, connections_mock, process_mock) -> None:
        connections_mock.return_value = [
            FakeConnection(101, ("192.168.1.4", 52000), ("203.0.113.10", 443), "ESTABLISHED"),
            FakeConnection(101, ("192.168.1.4", 52001), ("203.0.113.20", 27015), "NONE", socket.SOCK_DGRAM),
            FakeConnection(101, ("192.168.1.4", 52003), (), "NONE", socket.SOCK_DGRAM),
            FakeConnection(101, ("192.168.1.4", 52002), ("203.0.113.30", 80), "LISTEN"),
            FakeConnection(202, ("192.168.1.4", 53000), ("198.51.100.5", 443), "SYN_SENT"),
            FakeConnection(404, ("192.168.1.4", 55000), ("198.51.100.10", 443), "ESTABLISHED"),
            FakeConnection(505, ("192.168.1.4", 56000), ("198.51.100.11", 443), "ESTABLISHED"),
        ]
        process_mock.side_effect = lambda pid: FakeProcess(
            {
                101: "game.exe",
                202: "discord.exe",
                404: "AppleMobileDeviceService.exe",
                505: "svchost.exe",
            }[pid]
        )

        result = process_inspector.scan_processes()

        self.assertIsNone(result.warning)
        self.assertEqual([item.name for item in result.processes], ["discord.exe", "game.exe"])
        game = next(item for item in result.processes if item.pid == 101)
        self.assertEqual(len(game.connections), 3)
        self.assertEqual(game.connections[0].remote_endpoint, "203.0.113.10:443")
        self.assertEqual(game.connections[1].protocol, "UDP")
        self.assertEqual(game.connections[2].remote_endpoint, "локальный UDP-порт 52003")

    def test_identifies_ignored_services_case_insensitively(self) -> None:
        self.assertTrue(process_inspector.is_ignored_process("AppleMobileDeviceService.exe"))
        self.assertTrue(process_inspector.is_ignored_process("SVCHOST.EXE"))
        self.assertTrue(process_inspector.is_ignored_process("mDNSResponder.exe"))
        self.assertFalse(process_inspector.is_ignored_process("telegram.exe"))

    @patch.object(process_inspector.psutil, "net_connections", side_effect=process_inspector.psutil.AccessDenied())
    def test_reports_access_denied(self, _connections_mock) -> None:
        result = process_inspector.scan_processes()

        self.assertEqual(result.processes, ())
        self.assertIn("не разрешила", result.warning or "")

    @patch.object(process_inspector.psutil, "Process")
    @patch.object(process_inspector.psutil, "net_connections")
    def test_scans_one_process_without_global_socket_enumeration(
        self,
        global_connections_mock,
        process_mock,
    ) -> None:
        process_mock.return_value = FakeProcess(
            "huntgame.exe",
            [
                FakeConnection(
                    777,
                    ("192.168.1.4", 52100),
                    ("203.0.113.42", 27015),
                    "ESTABLISHED",
                )
            ],
        )

        result = process_inspector.scan_process(777)

        global_connections_mock.assert_not_called()
        self.assertIsNone(result.warning)
        self.assertEqual(len(result.processes), 1)
        self.assertEqual(result.processes[0].pid, 777)
        self.assertEqual(result.processes[0].connections[0].remote_endpoint, "203.0.113.42:27015")


if __name__ == "__main__":
    unittest.main()
