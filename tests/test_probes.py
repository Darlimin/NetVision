import unittest
import subprocess
from unittest.mock import patch

from netvision.core import probes
from netvision.core.probes import parse_geo_payload, parse_ping_samples, parse_tracert_output
from netvision.core.target import parse_target
from netvision.core.system import (
    normalize_dns_server_values,
    parse_default_routes_output,
    parse_route_print_output,
)
from netvision.models import NetworkInterface, ProbeStatus
from netvision.reporting import _redact_proxy_credentials


class TracertParserTests(unittest.TestCase):
    def test_parses_hops_and_average_latency(self) -> None:
        output = """
          1    <1 ms     1 ms     2 ms  192.168.1.1
          2     *        *        *     Request timed out.
          3    14 ms    15 ms    16 ms  203.0.113.10
        """
        hops = parse_tracert_output(output)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0].address, "192.168.1.1")
        self.assertEqual(hops[0].latency_ms, 1.3)
        self.assertTrue(hops[1].timed_out)
        self.assertEqual(hops[2].latency_ms, 15.0)

    def test_parses_russian_tracert_units_and_decimal_comma(self) -> None:
        output = "  1    <1 мс     2,5 мс    3 мс  192.168.1.1"

        hops = parse_tracert_output(output)

        self.assertEqual(hops[0].latency_ms, 2.2)

    @patch.object(probes.subprocess, "run")
    @patch.object(probes, "_oem_encoding", return_value="cp866")
    def test_trace_route_uses_oem_encoding(self, _encoding_mock, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=["tracert"],
            returncode=0,
            stdout="  1    5 мс  192.168.1.1",
            stderr="",
        )

        probes.trace_route(parse_target("example.com"))

        self.assertEqual(run_mock.call_args.kwargs["encoding"], "cp866")


class PingParserTests(unittest.TestCase):
    def test_parses_english_and_russian_ping_responses(self) -> None:
        output = "Reply time=12ms\nОтвет время<1мс\ntime=15.5 ms"
        self.assertEqual(parse_ping_samples(output), (12.0, 0.5, 15.5))

    def test_parses_russian_response_before_ttl_marker(self) -> None:
        output = "Ответ от 192.168.1.1: число байт=32 время<1мс TTL=128\n"
        output += "Ответ от 192.168.1.1: число байт=32 время=12,5мс TTL=128\n"

        self.assertEqual(parse_ping_samples(output), (0.5, 12.5))

    @patch.object(probes.subprocess, "run")
    @patch.object(probes, "_oem_encoding", return_value="cp866")
    def test_ping_uses_oem_encoding(self, _encoding_mock, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=["ping"],
            returncode=0,
            stdout="Ответ от 192.168.1.1: число байт=32 время=12мс TTL=128",
            stderr="",
        )

        result = probes.probe_ping("192.168.1.1", count=1)

        self.assertEqual(run_mock.call_args.kwargs["encoding"], "cp866")
        self.assertEqual(result.received, 1)
        self.assertEqual(result.average_ms, 12.0)

    def test_oem_encoding_falls_back_to_cp866_without_windows_api(self) -> None:
        self.assertEqual(probes._oem_encoding(), "cp866")


class GeoPayloadParserTests(unittest.TestCase):
    def test_reads_location_and_asn_fields(self) -> None:
        result = parse_geo_payload(
            "203.0.113.1",
            {
                "success": True,
                "ip": "203.0.113.1",
                "country": "Example",
                "region": "Region",
                "city": "City",
                "connection": {"asn": 64500, "org": "Example Net", "isp": "Example ISP"},
            },
        )
        self.assertEqual(result.status, ProbeStatus.SUCCESS)
        self.assertEqual(result.asn, "64500")
        self.assertEqual(result.isp, "Example ISP")
        self.assertEqual(result.city, "City")


class ReportPrivacyTests(unittest.TestCase):
    def test_redacts_proxy_username_and_password(self) -> None:
        sanitized = _redact_proxy_credentials("http://user:secret@proxy.example:8080")
        self.assertEqual(sanitized, "http://proxy.example:8080")


class RoutePrintParserTests(unittest.TestCase):
    def test_uses_lowest_metric_default_route(self) -> None:
        output = """
              0.0.0.0          0.0.0.0     192.168.31.1   192.168.31.100     30
              0.0.0.0          0.0.0.0         On-link        172.19.0.1      0
        """
        interfaces = (
            NetworkInterface("Wi-Fi", "Wi-Fi", True, 866, ipv4=("192.168.31.100",)),
            NetworkInterface("Happ Tunnel", "VPN", True, 0, ipv4=("172.19.0.1",)),
        )
        gateway = parse_route_print_output(output, interfaces)
        self.assertIsNotNone(gateway)
        assert gateway is not None
        self.assertEqual(gateway.address, "172.19.0.1")
        self.assertEqual(gateway.interface, "Happ Tunnel")
        self.assertEqual(gateway.metric, 0)

    def test_keeps_vpn_and_physical_default_routes_for_comparison(self) -> None:
        output = """
              0.0.0.0          0.0.0.0     192.168.31.1   192.168.31.100     30
              0.0.0.0          0.0.0.0         On-link        172.19.0.1      0
        """
        interfaces = (
            NetworkInterface("Wi-Fi", "Wi-Fi", True, 866, ipv4=("192.168.31.100",)),
            NetworkInterface("happ-xray", "Network", True, 0, ipv4=("172.19.0.1",)),
        )
        routes = parse_default_routes_output(output, interfaces)
        self.assertEqual(len(routes), 2)
        self.assertTrue(routes[0].is_vpn)
        self.assertEqual(routes[0].interface, "happ-xray")
        self.assertFalse(routes[1].is_vpn)

    def test_replaces_unspecified_next_hop_with_interface_address(self) -> None:
        output = """
              0.0.0.0          0.0.0.0         0.0.0.0        172.19.0.1      0
        """
        gateway = parse_route_print_output(output)
        self.assertIsNotNone(gateway)
        assert gateway is not None
        self.assertEqual(gateway.address, "172.19.0.1")


class DnsServerNormalizerTests(unittest.TestCase):
    def test_removes_windows_site_local_placeholders(self) -> None:
        servers = normalize_dns_server_values(
            ["172.19.0.2", "fec0:0:0:ffff::1", "2001:4860:4860::8888"]
        )
        self.assertEqual(servers, ("172.19.0.2", "2001:4860:4860::8888"))


if __name__ == "__main__":
    unittest.main()

