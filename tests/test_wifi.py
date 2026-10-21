import unittest

from netvision.core.system import parse_wifi_interfaces_output
from netvision.models import WifiSnapshot
from netvision.ui.monitor_workers import WifiSignalTracker
from netvision.ui.main_window import _wifi_correlation_evidence


EN_OUTPUT = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Home
    BSSID                  : 11:22:33:44:55:66
    Radio type             : 802.11ac
    Band                   : 5 GHz
    Channel                : 36
    Signal                 : 82%
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 433.3
"""

RU_OUTPUT = """
    Имя                    : Wi-Fi
    Состояние              : подключено
    SSID                   : Дом
    BSSID                  : AA:BB:CC:DD:EE:FF
    Тип радиосети          : 802.11ax
    Диапазон               : 2.4 ГГц
    Канал                  : 6
    Сигнал                 : 59%
    Скорость приёма (Мбит/с) : 144.4
    Скорость передачи (Мбит/с) : 72.2
"""


class WifiParsingTests(unittest.TestCase):
    def test_parse_english_output(self) -> None:
        snapshots = parse_wifi_interfaces_output(EN_OUTPUT)

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].interface_name, "Wi-Fi")
        self.assertEqual(snapshots[0].signal_pct, 82)
        self.assertEqual(snapshots[0].rx_mbps, 866.7)

    def test_parse_russian_output_keeps_signal_as_percent(self) -> None:
        snapshots = parse_wifi_interfaces_output(RU_OUTPUT)

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].signal_pct, 59)
        self.assertEqual(snapshots[0].band, "2.4 ГГц")

    def test_disconnected_and_unknown_locale_are_ignored(self) -> None:
        disconnected = EN_OUTPUT.replace("connected", "disconnected")
        unknown = "Name: Wi-Fi\nStatus: connected\nSignal: 80%"

        self.assertEqual(parse_wifi_interfaces_output(disconnected), [])
        self.assertEqual(parse_wifi_interfaces_output(unknown), [])

    def test_multiple_adapters_are_parsed(self) -> None:
        output = EN_OUTPUT + EN_OUTPUT.replace("Wi-Fi", "Wi-Fi 2").replace("Home", "Guest")

        snapshots = parse_wifi_interfaces_output(output)

        self.assertEqual([item.interface_name for item in snapshots], ["Wi-Fi", "Wi-Fi 2"])


class WifiSignalTrackerTests(unittest.TestCase):
    def test_signal_hysteresis(self) -> None:
        tracker = WifiSignalTracker()

        self.assertEqual(tracker.update(60, 60, 5), "entered")
        self.assertIsNone(tracker.update(62, 60, 5))
        self.assertEqual(tracker.update(65, 60, 5), "cleared")

    def test_recent_wifi_events_correlate_with_network_spike(self) -> None:
        confirmed, evidence = _wifi_correlation_evidence(
            WifiSnapshot("Wi-Fi", "Home", "aa", "802.11ac", "5 GHz", "36", 62, 300.0, 200.0, 300.0),
            False,
            {"wifi.roam"},
        )

        self.assertTrue(confirmed)
        self.assertIn("roaming", evidence)
        self.assertIn("шлюз 300.0 мс", evidence)


class WifiModelTests(unittest.TestCase):
    def test_snapshot_shape_is_explicit(self) -> None:
        snapshot = WifiSnapshot("Wi-Fi", "Home", None, "802.11ac", "5 GHz", "36", 80, 100.0, 50.0)

        self.assertEqual(snapshot.signal_pct, 80)
        self.assertIsNone(snapshot.gateway_rtt_ms)
