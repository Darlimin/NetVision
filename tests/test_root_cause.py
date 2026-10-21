import unittest
from datetime import datetime

from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo
from netvision.core.root_cause import CauseSeverity, analyze_report, vpn_bypass_connections
from netvision.core.traceroute import MtrHopStats, MtrSnapshot
from netvision.models import (
    DefaultRoute,
    DiagnosticReport,
    DnsResult,
    HopResult,
    NetworkInterface,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    Target,
    TcpResult,
    WifiSnapshot,
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
    def test_low_wifi_signal_is_in_latency_evidence(self) -> None:
        report = make_report(
            ping=PingResult("game.example", 5, 5, 0.0, 140.0, 130.0, 150.0, 35.0, (130, 150, 140, 140), ProbeStatus.WARNING),
        )
        analysis = analyze_report(
            report,
            wifi=WifiSnapshot("Wi-Fi", "Home", "aa", "802.11ac", "5 GHz", "36", 35, 300.0, 200.0),
        )

        finding = next(item for item in analysis.findings if item.title == "Высокая задержка или Jitter")
        self.assertIn("сигнал Wi-Fi 35%", finding.evidence)

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

    def test_mtr_clean_destination_suppresses_timeout_based_route_warning(self) -> None:
        report = make_report(
            hops=(HopResult(1, "192.0.2.1", 10.0), HopResult(3, None, None, True)),
        )
        mtr = MtrSnapshot(
            "8.8.8.8",
            datetime.now().astimezone(),
            (
                MtrHopStats(1, ("192.0.2.1",), 10, 10, 0.0, 10.0, 10.0, 10.0, 10.0, 0.0),
                MtrHopStats(3, (), 10, 5, 50.0, None, None, None, None, None, icmp_limited=True),
                MtrHopStats(4, ("8.8.8.8",), 10, 10, 0.0, 12.0, 12.0, 12.0, 12.0, 0.0),
            ),
            True,
            False,
        )

        analysis = analyze_report(report, mtr=mtr)

        self.assertFalse(any(item.title == "Потери на промежуточном узле" for item in analysis.findings))
        self.assertFalse(any(item.title == "Сквозные потери по маршруту" for item in analysis.findings))

    def test_udp_target_does_not_mislabel_tcp_as_firewall_failure(self) -> None:
        report = make_report(
            tcp=TcpResult("game.example", 27015, None, 900.0, ProbeStatus.ERROR, "TCP is not the game protocol"),
        )
        connection = ProcessConnection("UDP", "NONE", "192.168.1.4", 50000, "203.0.113.10", 27015)

        analysis = analyze_report(report, ProcessNetworkInfo(99, "game.exe", (connection,)), connection)
        titles = {finding.title for finding in analysis.findings}

        self.assertIn("Выбран UDP-endpoint", titles)
        self.assertNotIn("Порт недоступен", titles)

    def test_global_process_socket_on_physical_interface_warns_about_vpn_bypass(self) -> None:
        report = make_report(
            system=SystemSnapshot(
                "pc",
                (
                    NetworkInterface("WireGuard", "VPN", True, 1000, ipv4=("10.8.0.2",)),
                    NetworkInterface("Ethernet", "Ethernet", True, 1000, ipv4=("192.168.1.25",)),
                ),
                None,
                (),
                None,
                (),
                default_routes=(DefaultRoute("10.8.0.1", "WireGuard", "10.8.0.2", 1, True),),
            ),
        )
        process = ProcessNetworkInfo(
            99,
            "HuntGame.exe",
            (ProcessConnection("UDP", "ESTABLISHED", "192.168.1.25", 50000, "8.8.8.8", 27015),),
        )

        finding = vpn_bypass_connections(report, process)
        analysis = analyze_report(report, process)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, CauseSeverity.WARNING)
        self.assertIn("192.168.1.25 -> 8.8.8.8 (Ethernet)", finding.evidence)
        self.assertEqual(analysis.headline, "Возможный обход VPN")

    def test_vpn_client_and_vpn_bound_socket_do_not_report_bypass(self) -> None:
        report = make_report(
            system=SystemSnapshot(
                "pc",
                (
                    NetworkInterface("WireGuard", "VPN", True, 1000, ipv4=("10.8.0.2",)),
                    NetworkInterface("Ethernet", "Ethernet", True, 1000, ipv4=("192.168.1.25",)),
                ),
                None,
                (),
                None,
                (),
                default_routes=(DefaultRoute("10.8.0.1", "WireGuard", "10.8.0.2", 1, True),),
            ),
        )
        vpn_client = ProcessNetworkInfo(
            100,
            "openvpn.exe",
            (ProcessConnection("UDP", "ESTABLISHED", "10.8.0.2", 50000, "8.8.8.8", 1194),),
        )
        game_on_vpn = ProcessNetworkInfo(
            99,
            "HuntGame.exe",
            (ProcessConnection("UDP", "ESTABLISHED", "10.8.0.2", 50000, "8.8.8.8", 27015),),
        )

        self.assertIsNone(vpn_bypass_connections(report, vpn_client))
        self.assertIsNone(vpn_bypass_connections(report, game_on_vpn))


if __name__ == "__main__":
    unittest.main()
