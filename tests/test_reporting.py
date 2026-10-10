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
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
)
from netvision.reporting import serialize_report, serialize_udp_events_csv, serialize_udp_events_json


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


if __name__ == "__main__":
    unittest.main()

