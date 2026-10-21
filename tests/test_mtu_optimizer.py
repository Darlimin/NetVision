from subprocess import CompletedProcess
import unittest
from unittest.mock import patch

from netvision.core import mtu_optimizer
from netvision.models import NetworkInterface, SystemSnapshot


def _snapshot() -> SystemSnapshot:
    return SystemSnapshot(
        hostname="test-host",
        interfaces=(NetworkInterface("Wi-Fi", "Wi-Fi", True, 1000, ipv4=("192.168.1.10",)),),
        gateway=None,
        dns_servers=(),
        external_ip=None,
        proxies=(),
    )


class MtuOptimizerTests(unittest.TestCase):
    def _run(self, run_mock, *, minimum=576, maximum=1500):
        with patch.object(mtu_optimizer.socket, "getaddrinfo", return_value=[(2, 0, 0, "", ("8.8.8.8", 0))]), patch.object(
            mtu_optimizer, "_route_local_ipv4", return_value="192.168.1.10"
        ), patch.object(mtu_optimizer.os, "name", "nt"):
            return mtu_optimizer.run_mtu_optimizer(
                "target.example", minimum=minimum, maximum=maximum, snapshot=_snapshot()
            )

    @patch.object(mtu_optimizer.subprocess, "run")
    def test_all_timeouts_stop_after_three_barrier_probes(self, run_mock) -> None:
        def side_effect(command, **_kwargs):
            if command[0] == "netsh":
                return CompletedProcess(command, 0, stdout=b"1500 0 0 0 Wi-Fi\n")
            return CompletedProcess(command, 1, stdout=b"Request timed out.\n")

        run_mock.side_effect = side_effect
        report = self._run(run_mock)

        ping_calls = [call for call in run_mock.call_args_list if call.args[0][0] == "ping"]
        self.assertIsNone(report.optimal_mtu)
        self.assertEqual(report.error_code, "icmp_no_reply")
        self.assertEqual(len(ping_calls), 3)

    @patch.object(mtu_optimizer.subprocess, "run")
    def test_fragmentation_above_1492_returns_1492(self, run_mock) -> None:
        def side_effect(command, **_kwargs):
            if command[0] == "netsh":
                return CompletedProcess(command, 0, stdout=b"1500 0 0 0 Wi-Fi\n")
            mtu = int(command[-2]) + 28
            output = b"Reply from 8.8.8.8: bytes=32 time=10ms\n" if mtu <= 1492 else b"Packet needs to be fragmented but DF set.\n"
            return CompletedProcess(command, 0 if mtu <= 1492 else 1, stdout=output)

        run_mock.side_effect = side_effect
        report = self._run(run_mock)

        self.assertEqual(report.optimal_mtu, 1492)
        self.assertEqual(report.decision, "LOWER")

    @patch.object(mtu_optimizer.subprocess, "run")
    def test_one_timeout_does_not_lower_a_successful_retry(self, run_mock) -> None:
        calls_for_1486 = 0

        def side_effect(command, **_kwargs):
            nonlocal calls_for_1486
            if command[0] == "netsh":
                return CompletedProcess(command, 0, stdout=b"1500 0 0 0 Wi-Fi\n")
            mtu = int(command[-2]) + 28
            if mtu == 1486 and calls_for_1486 == 0:
                calls_for_1486 += 1
                return CompletedProcess(command, 1, stdout=b"Request timed out.\n")
            if mtu == 1486:
                calls_for_1486 += 1
            output = b"Reply from 8.8.8.8: bytes=32 time=10ms\n" if mtu <= 1492 else b"Packet needs to be fragmented but DF set.\n"
            return CompletedProcess(command, 0 if mtu <= 1492 else 1, stdout=output)

        run_mock.side_effect = side_effect
        report = self._run(run_mock, minimum=1480, maximum=1492)

        self.assertEqual(report.optimal_mtu, 1492)
        self.assertGreaterEqual(calls_for_1486, 2)

    @patch.object(mtu_optimizer.os, "name", "nt")
    @patch.object(mtu_optimizer.subprocess, "run")
    def test_route_interface_uses_matching_vpn_mtu(self, run_mock) -> None:
        run_mock.return_value = CompletedProcess(
            ["netsh"],
            0,
            stdout=b"1500 0 0 0 Wi-Fi\n1420 0 0 0 VPN\n",
        )

        current = mtu_optimizer.detect_system_mtu("VPN")

        self.assertEqual(current, 1420)
        self.assertEqual(mtu_optimizer._mtu_decision(current, 1420, mtu_optimizer.DEFAULT_THRESHOLDS), "NO_CHANGE")


if __name__ == "__main__":
    unittest.main()
