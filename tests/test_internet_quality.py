import json
import socket
import unittest
from io import BytesIO
from unittest.mock import patch

from netvision.core.internet_quality import (
    DOWNLOAD_BYTES,
    InternetQualityReport,
    LocalNetworkContext,
    PublicNetworkInfo,
    SpeedtestResult,
    build_smart_report,
    collect_local_network_context,
    fetch_public_network_info,
    measure_download,
    measure_tcp_latency,
    parse_public_network_json,
)
from netvision.models import NetworkInterface, SystemSnapshot


class InternetQualityTests(unittest.TestCase):
    def test_download_speed_uses_http_bytes_and_browser_headers(self) -> None:
        body = b"x" * DOWNLOAD_BYTES
        response = BytesIO(body)
        response.__enter__ = lambda: response
        response.__exit__ = lambda *_args: None

        with patch("netvision.core.internet_quality.urllib.request.urlopen", return_value=response) as open_url, patch(
            "netvision.core.internet_quality.time.perf_counter", side_effect=[10.0, 12.0]
        ):
            result = measure_download(urls=("https://cdn.example/test",), timeout=4)

        self.assertEqual(result.download_mbps, 40.0)
        request = open_url.call_args.args[0]
        self.assertIn("Mozilla/5.0", request.get_header("User-agent"))
        self.assertEqual(open_url.call_args.kwargs["timeout"], 4)

    @patch("netvision.core.internet_quality.socket.create_connection")
    def test_tcp_latency_uses_dns_port_and_returns_average(self, create_connection: object) -> None:
        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        create_connection.return_value = Connection()
        with patch(
            "netvision.core.internet_quality.time.perf_counter",
            side_effect=[1.0, 1.012, 2.0, 2.020, 3.0, 3.016],
        ):
            result = measure_tcp_latency(targets=(("Test DNS", "1.1.1.1", 53),), attempts=3)

        self.assertAlmostEqual(result.ping_ms or 0, 16.0, places=2)
        self.assertEqual(create_connection.call_args.args, (("1.1.1.1", 53),))

    def test_parses_ip_api_json(self) -> None:
        result = parse_public_network_json(
            {
                "query": "203.0.113.30",
                "isp": "Example ISP",
                "regionName": "Moscow",
                "city": "Moscow",
                "hosting": True,
            },
            "ip-api.com",
        )

        self.assertEqual(result.ipv4, "203.0.113.30")
        self.assertEqual(result.isp, "Example ISP")
        self.assertEqual(result.region, "Moscow")
        self.assertTrue(result.vpn_detected)

    def test_parses_ipwho_json(self) -> None:
        result = parse_public_network_json(
            {
                "ip": "2001:db8::30",
                "connection": {"isp": "Example IPv6 ISP"},
                "location": {"region": "Example Region", "city": "Example City"},
            },
            "ipwho.is",
        )

        self.assertEqual(result.ipv6, "2001:db8::30")
        self.assertEqual(result.isp, "Example IPv6 ISP")
        self.assertEqual(result.city, "Example City")

    @patch("netvision.core.internet_quality.urllib.request.urlopen")
    def test_fetches_two_public_geo_apis_and_merges_fields(self, open_url: object) -> None:
        first = BytesIO(b'{"query":"203.0.113.31","isp":"Example ISP"}')
        second = BytesIO(b'{"ip":"203.0.113.31","location":{"city":"Moscow","region":"Moscow"}}')
        first.__enter__ = lambda: first
        first.__exit__ = lambda *_args: None
        second.__enter__ = lambda: second
        second.__exit__ = lambda *_args: None
        open_url.side_effect = [first, second]

        result = fetch_public_network_info(timeout=5)

        self.assertEqual(result.ipv4, "203.0.113.31")
        self.assertEqual(result.isp, "Example ISP")
        self.assertEqual(result.city, "Moscow")
        self.assertEqual(open_url.call_count, 2)

    @patch("netvision.core.internet_quality.urllib.request.build_opener")
    @patch("netvision.core.internet_quality.urllib.request.urlopen", side_effect=OSError("proxy refused"))
    def test_http_request_retries_without_system_proxy(self, _open_url: object, build_opener: object) -> None:
        response = BytesIO(b"x" * DOWNLOAD_BYTES)
        response.__enter__ = lambda: response
        response.__exit__ = lambda *_args: None
        direct_opener = build_opener.return_value
        direct_opener.open.return_value = response

        with patch("netvision.core.internet_quality.time.perf_counter", side_effect=[1.0, 3.0]):
            result = measure_download(urls=("https://cdn.example/test",))

        self.assertEqual(result.download_mbps, 40.0)
        direct_opener.open.assert_called_once()

    def test_filters_local_addresses_to_primary_and_vpn_ipv4(self) -> None:
        snapshot = SystemSnapshot(
            hostname="pc",
            interfaces=(
                NetworkInterface("Wi-Fi", "Wi-Fi", True, 866, ipv4=("169.254.53.164", "192.168.31.100"), ipv6=("fe80::1",)),
                NetworkInterface("happ-xray", "VPN", True, 4294, ipv4=("172.19.0.1",)),
            ),
            gateway=None,
            dns_servers=(),
            external_ip=None,
            proxies=(),
        )

        result = collect_local_network_context(snapshot)

        self.assertEqual(result.local_ipv4, ("192.168.31.100", "172.19.0.1"))
        self.assertEqual(result.local_ipv6, ())
        self.assertIn("169.254.53.164", result.local_ip_tooltip or "")

    def test_smart_report_describes_autonomous_measurements(self) -> None:
        report = InternetQualityReport(
            speedtest=SpeedtestResult(download_mbps=80.0, ping_ms=18.0, server_name="Cloudflare DNS"),
            network=PublicNetworkInfo(ipv4="198.51.100.40", isp="Example ISP", city="Москва"),
            local=LocalNetworkContext(adapter_name="Wi-Fi", adapter_speed_mbps=866, local_ipv4=("192.168.1.20",)),
        )

        summary = build_smart_report(report)

        self.assertIn("80.0 Мбит/с", summary)
        self.assertIn("Example ISP", summary)
        self.assertIn("TCP-пинг", summary)
        self.assertIn("192.168.1.20", summary)


if __name__ == "__main__":
    unittest.main()
