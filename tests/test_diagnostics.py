import threading
import unittest
from unittest.mock import patch

from netvision.core import diagnostics
from netvision.core.diagnostics import DiagnosticService, _public_route_addresses
from netvision.core.target import parse_target
from netvision.models import (
    DnsResult,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
)


class DiagnosticParallelismTests(unittest.TestCase):
    def test_independent_probes_are_started_concurrently(self) -> None:
        target = parse_target("example.test", 80)
        barrier = threading.Barrier(5)

        def concurrent_result(value):
            def operation(*_args):
                barrier.wait(timeout=1.0)
                return value

            return operation

        snapshot = SystemSnapshot("test-pc", (), None, (), None, ())
        dns = DnsResult(target.host, ("192.0.2.1",), 2.0, ProbeStatus.SUCCESS)
        tcp = TcpResult(target.host, target.port, "192.0.2.1", 3.0, ProbeStatus.SUCCESS)
        ping = PingResult(target.host, 5, 5, 0.0, 4.0, 2.0, 6.0, 1.0, (2, 3, 4, 5, 6), ProbeStatus.SUCCESS)

        with (
            patch.object(diagnostics, "collect_system_snapshot", concurrent_result(snapshot)),
            patch.object(diagnostics, "resolve_dns", concurrent_result(dns)),
            patch.object(diagnostics, "probe_tcp", concurrent_result(tcp)),
            patch.object(diagnostics, "probe_ping", concurrent_result(ping)),
            patch.object(diagnostics, "trace_route", concurrent_result(())),
        ):
            report = DiagnosticService().run(target)

        self.assertEqual(report.dns.status, ProbeStatus.SUCCESS)
        self.assertEqual(report.tcp.status, ProbeStatus.SUCCESS)
        self.assertEqual(report.ping.jitter_ms, 1.0)


class PublicRouteAddressTests(unittest.TestCase):
    def test_excludes_private_and_duplicate_addresses(self) -> None:
        addresses = _public_route_addresses(
            ("192.168.1.1", "8.8.8.8", "8.8.8.8"),
            "1.1.1.1",
            (),
        )
        self.assertEqual(addresses, ("8.8.8.8", "1.1.1.1"))


if __name__ == "__main__":
    unittest.main()

