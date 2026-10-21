import json
import unittest
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
import csv

from netvision.core.target import parse_target
from netvision.models import (
    DiagnosticReport,
    DnsResult,
    GeoResult,
    HopResult,
    NetworkInterface,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
    WifiSnapshot,
)
from netvision.reporting import (
    serialize_report,
    serialize_support_bundle,
    serialize_udp_events_csv,
    serialize_udp_events_json,
)


@dataclass(frozen=True)
class UdpEvent:
    observed_at: datetime
    event_type: str
    port: int | None
    details: str
    is_anomaly: bool = False
    pid: int | None = None


class ReportSerializationTests(unittest.TestCase):
    def test_serializes_report_and_redacts_proxy_credentials(self) -> None:
        target = parse_target("example.test", 80)
        report = DiagnosticReport(
            target=target,
            system=SystemSnapshot(
                "test-pc", (), None, (), None, (("http", "http://user:secret@proxy.example:8080"),)
            ),
            dns=DnsResult(target.host, (), None, ProbeStatus.WARNING),
            tcp=TcpResult(target.host, target.port, None, None, ProbeStatus.WARNING),
            ping=PingResult(target.host, 5, 0, 100, None, None, None, None, (), ProbeStatus.WARNING),
            tls=None,
            hops=(),
            geolocation=(),
            started_at=datetime(2026, 10, 7, 12, 0, 0),
            total_ms=10.0,
        )

        payload = json.loads(serialize_report(report))

        self.assertEqual(payload["target"]["host"], "example.test")
        self.assertEqual(payload["schema_version"], "1.1")
        self.assertEqual(payload["started_at"], "2026-10-07T12:00:00")
        self.assertEqual(payload["system"]["proxies"][0][1], "http://proxy.example:8080")
        self.assertEqual(payload["udp_activity"], {"event_count": 0, "events": []})
        self.assertNotIn("secret", serialize_report(report))

    def test_serializes_udp_event_history_to_json_and_csv(self) -> None:
        events = (
            UdpEvent(
                datetime(2026, 10, 8, 15, 30, 0),
                "Порт открыт",
                27015,
                "UDP-порт появился",
                pid=321,
            ),
            UdpEvent(
                datetime(2026, 10, 8, 15, 31, 0),
                "Возможный обрыв",
                None,
                "Все порты исчезли",
                is_anomaly=True,
                pid=321,
            ),
        )

        json_payload = json.loads(serialize_udp_events_json(events))
        csv_rows = list(csv.DictReader(StringIO(serialize_udp_events_csv(events))))

        self.assertEqual(json_payload["udp_activity"]["event_count"], 2)
        self.assertTrue(json_payload["udp_activity"]["events"][1]["is_anomaly"])
        self.assertEqual(json_payload["udp_activity"]["events"][0]["pid"], 321)
        self.assertEqual(csv_rows[0]["event_type"], "Порт открыт")
        self.assertEqual(csv_rows[0]["port"], "27015")
        self.assertEqual(csv_rows[1]["is_anomaly"], "True")

    def test_support_bundle_schema_and_consistent_redaction(self) -> None:
        report = self._support_report()
        payload = json.loads(
            serialize_support_bundle(
                report,
                measurements={
                    "wifi": WifiSnapshot(
                        "Wi-Fi",
                        "Home Secret Network",
                        "AA:BB:CC:DD:EE:FF",
                        "802.11ax",
                        "5 GHz",
                        "36",
                        75,
                        300.0,
                        200.0,
                    )
                },
                journal_events=(
                    {
                        "subject": "8.8.8.8:27015",
                        "values": {"peer": "8.8.8.8"},
                    },
                ),
                process={
                    "name": "HuntGame.exe",
                    "pid": 321,
                    "connections": ({"remote_address": "8.8.8.8", "remote_port": 27015},),
                },
            )
        )
        rendered = json.dumps(payload, ensure_ascii=False)

        self.assertEqual(payload["schema_version"], "1.2")
        self.assertEqual(payload["report"]["schema_version"], "1.1")
        for secret in (
            "support-pc",
            "00:11:22:33:44:55",
            "Home Secret Network",
            "AA:BB:CC:DD:EE:FF",
            "8.8.8.8",
        ):
            self.assertNotIn(secret, rendered)
        token = payload["report"]["system"]["external_ip"]
        self.assertRegex(token, r"^ip-\d+$")
        self.assertEqual(token, payload["report"]["hops"][0]["address"])
        self.assertEqual(token, payload["process"]["endpoints"][0]["remote_address"])
        self.assertRegex(payload["measurements"]["wifi"]["ssid"], r"^ssid-\d+$")
        self.assertRegex(payload["measurements"]["wifi"]["bssid"], r"^bssid-\d+$")

    def test_support_bundle_uses_new_tokens_for_each_export(self) -> None:
        report = self._support_report()
        first = json.loads(serialize_support_bundle(report))
        second = json.loads(serialize_support_bundle(report))

        self.assertNotEqual(
            first["report"]["system"]["external_ip"],
            second["report"]["system"]["external_ip"],
        )

    def test_support_bundle_can_keep_original_values_when_redaction_is_disabled(self) -> None:
        report = self._support_report()
        rendered = serialize_support_bundle(
            report,
            measurements={
                "wifi": WifiSnapshot(
                    "Wi-Fi", "Home Secret Network", "AA:BB:CC:DD:EE:FF",
                    None, None, None, None, None, None,
                )
            },
            redact=False,
        )

        for value in ("support-pc", "00:11:22:33:44:55", "8.8.8.8", "Home Secret Network"):
            self.assertIn(value, rendered)
        self.assertEqual(json.loads(serialize_report(report))["schema_version"], "1.1")

    @staticmethod
    def _support_report() -> DiagnosticReport:
        target = parse_target("8.8.8.8", 443)
        return DiagnosticReport(
            target=target,
            system=SystemSnapshot(
                "support-pc",
                (NetworkInterface("Wi-Fi", "Wi-Fi", True, 866, "00:11:22:33:44:55", ("192.168.1.50",)),),
                None,
                ("1.1.1.1",),
                "8.8.8.8",
                (),
            ),
            dns=DnsResult(target.host, ("8.8.8.8",), 10.0, ProbeStatus.SUCCESS),
            tcp=TcpResult(target.host, target.port, "8.8.8.8", 12.0, ProbeStatus.SUCCESS),
            ping=PingResult(target.host, 3, 3, 0.0, 12.0, 10.0, 15.0, 1.0, (10.0, 12.0, 15.0), ProbeStatus.SUCCESS),
            tls=None,
            hops=(HopResult(1, "8.8.8.8", 12.0),),
            geolocation=(GeoResult("8.8.8.8", "US", None, None, "AS15169", "Google", "Google", ProbeStatus.SUCCESS),),
            started_at=datetime(2026, 10, 21, 12, 0, 0),
            total_ms=12.0,
        )


if __name__ == "__main__":
    unittest.main()

