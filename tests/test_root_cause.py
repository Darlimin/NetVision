import unittest
from datetime import datetime

from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo
from netvision.core.root_cause import CauseSeverity, analyze_report
from netvision.models import (
    DefaultRoute,
    DiagnosticReport,
    DnsResult,
    HopResult,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    Target,
    TcpResult,
)


def make_report(**changes: object) -> DiagnosticReport:
    target = Target("game.example", "game.example", 443, "https")
    values: dict[str, object] = {
        "target": target,
        "system": SystemSnapshot("pc", (), None, (), None, (), ()),
        "dns": DnsResult(target.host, ("203.0.113.10",), 4.0, ProbeStatus.SUCCESS),
        "tcp": TcpResult(target.host, target.port, "203.0.113.10", 12.0, ProbeStatus.SUCCESS),
        "ping": PingResult(target.host, 5, 5, 0.0, 30.0, 28.0, 32.0, 3.0, (28, 30, 32, 30, 30), ProbeStatus.SUCCESS),
        "tls": None,
        "hops": (),
        "geolocation": (),
        "started_at": datetime(2026, 10, 8, 12, 0, 0),
        "total_ms": 100.0,
        "errors": (),
    }
    values.update(changes)
    return DiagnosticReport(**values)


class RootCauseTests(unittest.TestCase):
    def test_high_latency_and_vpn_loss_produce_specific_findings(self) -> None:
        report = make_report(
            system=SystemSnapshot(
                "pc", (), None, (), None, (),
                default_routes=(DefaultRoute("10.0.0.1", "VPN", "10.0.0.2", 1, True),),
            ),
            ping=PingResult("game.example", 5, 4, 20.0, 140.0, 130.0, 150.0, 35.0, (130, 150, 140, 140), ProbeStatus.WARNING),
        )

        analysis = analyze_report(report, ProcessNetworkInfo(99, "game.exe", ()))
        titles = {finding.title for finding in analysis.findings}

        self.assertIn("Высокая задержка или Jitter", titles)
        self.assertIn("Нестабильный VPN-маршрут", titles)
        self.assertEqual(analysis.subject, "game.exe")

    def test_tcp_failure_points_to_firewall_or_antivirus(self) -> None:
        report = make_report(
            tcp=TcpResult("game.example", 443, None, 900.0, ProbeStatus.ERROR, "timeout")
        )

        analysis = analyze_report(report)

        self.assertEqual(analysis.findings[0].severity, CauseSeverity.ERROR)
        self.assertEqual(analysis.findings[0].title, "Порт недоступен")
        self.assertIn("Брандмауэром Windows", analysis.findings[0].explanation)

    def test_timeout_on_later_route_hop_points_to_transit_provider(self) -> None:
        report = make_report(
            hops=(HopResult(1, "192.0.2.1", 10.0), HopResult(5, None, None, True)),
        )

        analysis = analyze_report(report)

        self.assertTrue(any("магистрального провайдера" in item.explanation for item in analysis.findings))

    def test_udp_target_does_not_mislabel_tcp_as_firewall_failure(self) -> None:
        report = make_report(
            tcp=TcpResult("game.example", 27015, None, 900.0, ProbeStatus.ERROR, "TCP is not the game protocol"),
        )
        connection = ProcessConnection("UDP", "NONE", "192.168.1.4", 50000, "203.0.113.10", 27015)

        analysis = analyze_report(report, ProcessNetworkInfo(99, "game.exe", (connection,)), connection)
        titles = {finding.title for finding in analysis.findings}

        self.assertIn("Выбран UDP-endpoint", titles)
        self.assertNotIn("Порт недоступен", titles)


if __name__ == "__main__":
    unittest.main()
