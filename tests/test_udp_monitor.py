import socket
from datetime import datetime, timezone
from threading import Event
import unittest
from unittest.mock import patch

from netvision.core import udp_monitor


class UdpPortMonitorTests(unittest.TestCase):
    @patch.object(udp_monitor.os, "name", "nt")
    @patch.object(udp_monitor, "_read_windows_udp_rows")
    def test_returns_sorted_unique_ports_for_the_requested_pid(self, rows_mock) -> None:
        rows_mock.return_value = (
            udp_monitor._MibUdpRowOwnerPid(0, socket.htons(27015), 101),
            udp_monitor._MibUdpRowOwnerPid(0, socket.htons(27016), 101),
            udp_monitor._MibUdpRowOwnerPid(0, socket.htons(27015), 101),
            udp_monitor._MibUdpRowOwnerPid(0, socket.htons(443), 202),
        )

        snapshot = udp_monitor.get_process_udp_ports(101)

        self.assertEqual(snapshot.pid, 101)
        self.assertEqual(snapshot.ports, (27015, 27016))
        self.assertIsNone(snapshot.warning)

    @patch.object(udp_monitor.os, "name", "nt")
    @patch.object(udp_monitor, "_read_windows_udp_rows", side_effect=OSError(5, "access denied"))
    def test_returns_warning_when_windows_rejects_the_table_read(self, _rows_mock) -> None:
        snapshot = udp_monitor.get_process_udp_ports(101)

        self.assertEqual(snapshot.ports, ())
        self.assertIn("таблицу UDP", snapshot.warning or "")

    def test_rejects_invalid_pid_without_touching_windows_api(self) -> None:
        snapshot = udp_monitor.get_process_udp_ports(0)

        self.assertEqual(snapshot.ports, ())
        self.assertIn("Некорректный PID", snapshot.warning or "")

    def test_history_reports_opened_closed_and_complete_port_rotation(self) -> None:
        history = udp_monitor.UdpPortHistory()
        timestamp = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)

        first = history.observe(udp_monitor.UdpPortSnapshot(101, (27015, 27016)), timestamp)
        rotation = history.observe(udp_monitor.UdpPortSnapshot(101, (27017,)), timestamp)

        self.assertEqual(first.opened_ports, ())
        self.assertEqual(rotation.opened_ports, (27017,))
        self.assertEqual(rotation.closed_ports, (27015, 27016))
        self.assertEqual(rotation.anomaly, udp_monitor.UdpPortAnomaly.FULL_PORT_ROTATION)
        self.assertTrue(rotation.potential_disconnect)

    def test_history_marks_full_port_loss_but_not_an_access_error(self) -> None:
        history = udp_monitor.UdpPortHistory()
        history.observe(udp_monitor.UdpPortSnapshot(101, (27015,)))
        warning = history.observe(udp_monitor.UdpPortSnapshot(101, (), "access denied"))
        loss = history.observe(udp_monitor.UdpPortSnapshot(101, ()))

        self.assertIsNone(warning.anomaly)
        self.assertEqual(loss.closed_ports, (27015,))
        self.assertEqual(loss.anomaly, udp_monitor.UdpPortAnomaly.ALL_PORTS_LOST)

    def test_manager_polls_on_a_background_thread_and_can_stop(self) -> None:
        callback_called = Event()
        snapshots = iter(
            (
                udp_monitor.UdpPortSnapshot(101, (27015,)),
                udp_monitor.UdpPortSnapshot(101, ()),
            )
        )

        def reader(pid: int) -> udp_monitor.UdpPortSnapshot:
            return next(snapshots, udp_monitor.UdpPortSnapshot(pid, ()))

        manager = udp_monitor.UdpPortMonitorManager(
            pid=101,
            interval_s=0.01,
            reader=reader,
            on_activity=lambda _activity: callback_called.set(),
        )
        manager.start()
        self.assertTrue(callback_called.wait(0.5))
        manager.stop()

        self.assertFalse(manager.is_running)
        self.assertGreaterEqual(len(manager.history), 1)

    @patch.object(udp_monitor.os, "name", "posix")
    @patch.object(udp_monitor.psutil, "net_connections")
    def test_uses_psutil_fallback_outside_windows(self, connections_mock) -> None:
        class Connection:
            pid = 101
            laddr = ("192.168.1.4", 27015)

        connections_mock.return_value = [Connection()]

        snapshot = udp_monitor.get_process_udp_ports(101)

        self.assertEqual(snapshot.ports, (27015,))
        self.assertIsNone(snapshot.warning)
        connections_mock.assert_called_once_with(kind="udp")


if __name__ == "__main__":
    unittest.main()
