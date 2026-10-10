import json
import unittest
from dataclasses import replace
from datetime import datetime
from unittest.mock import patch

from PySide6.QtCore import QEventLoop, QPoint, QRect, QTimer, Qt, qInstallMessageHandler
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
)

from netvision.core.target import parse_target
from netvision.core.dns_benchmark import DnsBenchmarkResult, DnsResolverProfile
from netvision.core.ping_benchmark import MtuProbeResult, RegionalPingResult, RegionalPingTarget
from netvision.core.packet_loss import HopLossResult, StressTestResult
from netvision.core.tcp_diagnostics import TcpConnectMeasurement, TcpSocketRecord
from netvision.core.tls_diagnostics import CertificateRecord, TlsAuditResult
from netvision.core.internet_quality import (
    InternetQualityReport,
    LocalNetworkContext,
    PublicNetworkInfo,
    SpeedtestResult,
)
from netvision.ui.main_window import InternetQualityWorker, NetworkBoostDialog
from netvision.core.network_boost import BackgroundTrafficCandidate, ProcessTerminationResult
from netvision.core.system_actions import SystemActionResult, open_network_adapters
from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo, ProcessScanResult
from netvision.core.udp_monitor import UdpPortActivity, UdpPortAnomaly, UdpPortSnapshot
from netvision.ui.main_window import METRIC_TOOLTIPS
from netvision.ui.widgets import JitterChart, LatencyChart, MetricTile, TopologyWidget
from netvision.models import (
    DefaultRoute,
    DiagnosticReport,
    DnsResult,
    GatewayInfo,
    GeoResult,
    HopResult,
    NetworkInterface,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
)
from netvision.ui.main_window import MainWindow
from netvision.ui.theme import APP_STYLE, LIGHT_STYLE


class MainWindowReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(["NetVision-tests", "-platform", "offscreen"])

    def setUp(self) -> None:
        # UI layout tests must not depend on external DNS or leave live probes
        # behind. Real QThread lifetime is covered in test_monitor_workers.py.
        monitor_patch = patch.object(MainWindow, "_start_latency_monitor")
        monitor_patch.start()
        self.addCleanup(monitor_patch.stop)

    def test_displays_new_results_and_exports_json(self) -> None:
        target = parse_target("example.test", 443)
        system = SystemSnapshot(
            hostname="test-pc",
            interfaces=(NetworkInterface("happ-xray", "VPN", True, 0, ipv4=("172.19.0.1",)),),
            gateway=GatewayInfo("192.168.1.1", "Ethernet", 1),
            dns_servers=("1.1.1.1",),
            external_ip="198.51.100.2",
            proxies=(("https", "https://user:secret@proxy.example:8080"),),
            default_routes=(
                DefaultRoute("172.19.0.1", "happ-xray", "172.19.0.1", 0, True, True),
                DefaultRoute("192.168.1.1", "Wi-Fi", "192.168.1.10", 30, False),
            ),
        )
        report = DiagnosticReport(
            target=target,
            system=system,
            dns=DnsResult(target.host, ("203.0.113.1",), 9.0, ProbeStatus.SUCCESS),
            tcp=TcpResult(target.host, target.port, "203.0.113.1", 12.0, ProbeStatus.SUCCESS),
            ping=PingResult(target.host, 5, 4, 20.0, 10.0, 8.0, 12.0, 2.0, (8, 10, 12, 10), ProbeStatus.WARNING),
            tls=None,
            hops=(HopResult(1, "203.0.113.1", 12.0),),
            geolocation=(GeoResult("203.0.113.1", "Example", "Region", "City", "64500", "Example Org", "Example ISP", ProbeStatus.SUCCESS),),
            started_at=datetime(2026, 10, 7, 12, 0, 0),
            total_ms=100.0,
        )

        window = MainWindow()
        window._on_completed(report)
        self.assertEqual(window.routes_table.rowCount(), 2)
        self.assertEqual(window.geo_table.rowCount(), 1)
        self.assertEqual(window.metrics["loss"].value.text(), "20%")
        self.assertEqual(window.metrics["ping"].hint.text(), "Отлично для игр и звонков")
        self.assertEqual(window.metrics["loss"].hint.text(), "Возможны фризы и задержки")
        self.assertEqual(window.metrics["dns"].value.property("metricState"), "good")
        self.assertEqual(window.metrics["dns"].value.text(), "9.0 ms")
        self.assertNotIn("DNS", window.metrics["dns"].value.text())
        self.assertEqual(window.metrics["dns"].hint.text(), "Имя сайта найдено")
        self.assertEqual(window.metrics["loss"].value.property("metricState"), "bad")
        self.assertEqual(window.metrics["tls"].value.property("metricState"), "neutral")
        self.assertTrue(window.export_button.isEnabled())

        class MemorySaveFile:
            def __init__(self, path: str) -> None:
                self.path = path
                self.payload = b""

            def open(self, _mode: object) -> bool:
                return True

            def write(self, data: bytes) -> int:
                self.payload = data
                return len(data)

            def commit(self) -> bool:
                return True

            def errorString(self) -> str:
                return ""

        save_files: list[MemorySaveFile] = []

        def make_save_file(path: str) -> MemorySaveFile:
            result = MemorySaveFile(path)
            save_files.append(result)
            return result

        export_path = "report.json"
        with (
            patch(
                "netvision.ui.main_window.QFileDialog.getSaveFileName",
                return_value=(export_path, "JSON (*.json)"),
            ),
            patch("netvision.ui.main_window.QSaveFile", side_effect=make_save_file),
            patch("netvision.ui.main_window.QMessageBox.critical") as error_dialog,
        ):
            window._export_report()
            error_dialog.assert_not_called()

        self.assertEqual(save_files[0].path, export_path)
        payload = save_files[0].payload.decode("utf-8")
        parsed = json.loads(payload)
        self.assertEqual(parsed["system"]["proxies"][0][1], "https://proxy.example:8080")
        self.assertNotIn("secret", payload)
        window.close()

    def test_metric_tile_uses_neutral_state_without_glow(self) -> None:
        tile = MetricTile("Ping")
        tile.set_metric("--", "ожидание")

        self.assertEqual(tile.value.property("metricState"), "neutral")
        effect = tile.value.graphicsEffect()
        self.assertIsNotNone(effect)
        self.assertEqual(effect.blurRadius(), 0.0)
        tile.deleteLater()

    def test_latency_chart_keeps_last_sixty_samples(self) -> None:
        chart = LatencyChart()
        for index in range(65):
            chart.add_sample(float(index), index % 7 != 0)

        self.assertEqual(len(chart.samples), 60)
        self.assertEqual(chart.samples[0].latency_ms, 5.0)
        self.assertTrue(any(not sample.success for sample in chart.samples))
        chart.deleteLater()

    def test_latency_chart_auto_scales_and_uses_hover_markers(self) -> None:
        lower, upper = LatencyChart._axis_range([10.0, 20.0])
        self.assertLess(lower, 10.0)
        self.assertGreater(upper, 20.0)
        self.assertEqual(LatencyChart._axis_range([]), (0.0, 100.0))

        chart = LatencyChart()
        self.assertTrue(chart.hasMouseTracking())
        self.assertFalse(chart.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents))
        chart.deleteLater()

    def test_jitter_chart_keeps_live_deviation_samples(self) -> None:
        chart = JitterChart()
        for index in range(65):
            chart.add_sample(float(index))

        self.assertEqual(len(chart.samples), 60)
        self.assertEqual(chart.samples[0], 5.0)
        self.assertTrue(chart.minimumHeight() >= 210)
        chart.deleteLater()

    def test_network_boost_buttons_are_available_in_loss_and_jitter_workspaces(self) -> None:
        window = MainWindow()

        self.assertEqual(window.loss_network_boost_button.objectName(), "NetworkBoostButton")
        self.assertEqual(window.jitter_network_boost_button.objectName(), "NetworkBoostButton")
        self.assertEqual(len(window._network_boost_buttons), 2)
        self.assertTrue(window.loss_network_boost_button.isEnabled())
        self.assertTrue(window.jitter_network_boost_button.isEnabled())
        window.close()

    def test_network_boost_dialog_requires_explicit_selection_and_displays_result(self) -> None:
        candidate = BackgroundTrafficCandidate(456, "qBittorrent.exe", "qBittorrent", "Торрент-клиент", 2)
        dialog = NetworkBoostDialog((candidate,))

        self.assertFalse(dialog.terminate_button.isEnabled())
        checkbox = next(iter(dialog._candidate_checkboxes.values()))
        checkbox.setChecked(True)
        self.assertTrue(dialog.terminate_button.isEnabled())

        dialog.apply_termination_results(
            (ProcessTerminationResult(456, "qBittorrent.exe", True, "Процесс завершён"),)
        )

        self.assertFalse(checkbox.isEnabled())
        self.assertIn("Завершено процессов: 1", dialog.status_label.text())
        dialog.close()

    def test_network_boost_confirmation_and_busy_close_guard(self) -> None:
        candidate = BackgroundTrafficCandidate(456, "steam.exe", "Steam", "Игровой лаунчер", 1, 1000.0)
        dialog = NetworkBoostDialog((candidate,))
        dialog.show()
        checkbox = next(iter(dialog._candidate_checkboxes.values()))
        checkbox.setChecked(True)
        requests = []
        dialog.terminate_requested.connect(requests.append)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No):
            dialog.terminate_button.click()
        self.assertEqual(requests, [])
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            dialog.terminate_button.click()
        self.assertEqual(requests, [(candidate,)])
        dialog.set_busy(True)
        dialog.reject()
        dialog.close()
        self.assertTrue(dialog.isVisible())
        self.assertFalse(dialog.terminate_button.isEnabled())
        dialog.set_busy(False)
        dialog.reject()
        self.assertFalse(dialog.isVisible())

    def test_main_metric_cards_have_icons_and_waiting_prompt(self) -> None:
        window = MainWindow()
        expected_icons = {
            "dns": "🌐",
            "ping": "⚡",
            "loss": "📉",
            "jitter": "📊",
            "tcp": "🔒",
            "tls": "🔒",
        }

        for metric, icon in expected_icons.items():
            tile = window.metrics[metric]
            self.assertEqual(tile.icon_label.text(), icon)
            self.assertEqual(tile.value.text(), "--")
            self.assertEqual(tile.hint.text(), "Нажмите для проверки")
            self.assertTrue(tile.hint.property("waiting"))

        window.close()

    def test_dns_metric_opens_deep_dive_and_back_returns_to_dashboard(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()
        with patch.object(MainWindow, "_load_dns_configuration"):
            QTest.mouseClick(window.metrics["dns"], Qt.MouseButton.LeftButton)
            self.app.processEvents()
            self.assertIs(window.mode_stack.currentWidget(), window.dns_view)
            self.assertTrue(window.dns_table.rowCount() >= 6)
            window.dns_back_button.click()
            self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        window.close()

    def test_dns_workspace_adds_custom_profile_and_highlights_best_result(self) -> None:
        window = MainWindow()
        initial_count = len(window._dns_profiles)
        window.dns_custom_input.setText("10.0.0.53")
        window._add_custom_dns_profile()
        self.assertEqual(len(window._dns_profiles), initial_count + 1)
        self.assertEqual(window._dns_profiles[-1].addresses, ("10.0.0.53",))

        fast_profile = DnsResolverProfile("Fast", ("10.0.0.1",))
        slow_profile = DnsResolverProfile("Slow", ("10.0.0.2",))
        window._dns_profiles = [fast_profile, slow_profile]
        window._render_dns_profiles()
        window._on_dns_benchmark_completed(
            (
                DnsBenchmarkResult(fast_profile, "10.0.0.1", 4.2),
                DnsBenchmarkResult(slow_profile, "10.0.0.2", 18.7),
            )
        )
        self.assertEqual(window.dns_table.item(0, 4).text(), "Лучший")
        self.assertEqual(window.dns_table.item(1, 4).text(), "Доступен")
        self.assertIn("Fast", window.dns_status.text())
        window.close()

    def test_ping_metric_opens_deep_dive_and_back_returns_to_dashboard(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()

        QTest.mouseClick(window.metrics["ping"], Qt.MouseButton.LeftButton)
        self.app.processEvents()

        self.assertIs(window.mode_stack.currentWidget(), window.ping_view)
        self.assertEqual(window.ping_matrix_table.rowCount(), 5)
        self.assertEqual(window.ping_mtu_table.rowCount(), 3)
        window.ping_back_button.click()
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        window.close()

    def test_ping_workspace_renders_results_and_live_spike(self) -> None:
        window = MainWindow()
        target = RegionalPingTarget("Frankfurt", "fra.example", "Reference")
        fast_ping = PingResult(
            "fra.example", 3, 3, 0.0, 8.0, 9.0, 10.0, 1.0, (8.0, 9.0, 10.0), ProbeStatus.SUCCESS
        )
        regional = (RegionalPingResult(target, fast_ping),)
        mtu = (MtuProbeResult(1472, 0, 2, 100.0, None, "Пакет требует фрагментации"),)

        window._on_ping_benchmark_completed(regional, mtu)
        window._on_latency_sample(120.0, True)

        self.assertEqual(window.ping_matrix_table.item(0, 4).text(), "Лучший")
        self.assertIn("8.0", window.ping_matrix_table.item(0, 2).text())
        self.assertIn("фрагментации", window.ping_mtu_table.item(0, 3).text())
        self.assertIn("Пик задержки", window.ping_spike_log.toPlainText())
        self.assertEqual(window.ping_stat_max.text(), "120.0 ms")
        window.close()

    def test_loss_metric_opens_deep_dive_and_back_returns_to_dashboard(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()

        QTest.mouseClick(window.metrics["loss"], Qt.MouseButton.LeftButton)
        self.app.processEvents()

        self.assertIs(window.mode_stack.currentWidget(), window.loss_view)
        self.assertEqual(window.loss_stress_table.rowCount(), 2)
        self.assertTrue(window.metrics["loss"].property("clickable"))
        window.loss_back_button.click()
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        window.close()

    def test_jitter_metric_opens_deep_dive_and_back_returns_to_dashboard(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()

        QTest.mouseClick(window.metrics["jitter"], Qt.MouseButton.LeftButton)
        self.app.processEvents()

        self.assertIs(window.mode_stack.currentWidget(), window.jitter_view)
        self.assertTrue(window.metrics["jitter"].property("clickable"))
        self.assertEqual(window.jitter_events_table.columnCount(), 4)
        window.jitter_back_button.click()
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        window.close()

    def test_jitter_workspace_logs_spikes_and_rates_voice_and_gaming_impact(self) -> None:
        window = MainWindow()
        window._open_jitter_workspace()
        window._on_latency_sample(20.0, True)
        window._on_latency_sample(42.0, True)
        window._on_latency_sample(None, False)

        self.assertEqual(window.jitter_events_table.rowCount(), 2)
        self.assertEqual(window.jitter_impact_values["current"].text(), "--")
        self.assertEqual(window.jitter_impact_values["voice"].text(), "N/A")
        self.assertEqual(window.jitter_impact_values["stability"].text(), "Нестабильно")
        self.assertEqual(window.jitter_events_table.item(0, 1).text(), "timeout")
        window.close()

    def test_loss_workspace_renders_hops_and_stress_results(self) -> None:
        window = MainWindow()
        hops = (
            HopLossResult(1, "192.0.2.1", 3, 3, 0.0, 5.0, "Стабильно"),
            HopLossResult(2, "198.51.100.1", 3, 1, 66.7, 20.0, "Есть потери"),
        )
        results = (
            StressTestResult("ICMP", "example.test", 10, 8, 20.0, 12.0, "Есть потери"),
            StressTestResult(
                "UDP", "example.test:443", 20, 20, None, 0.2, "Отправка успешна",
                "UDP не подтверждает доставку без ACK приложения; учтены только локальные sendto.",
            ),
        )

        window._on_packet_loss_analysis_completed(hops, results[0], results[1])
        window._on_latency_sample(None, False)
        window._on_latency_sample(None, False)

        self.assertIn("67%", window.loss_hops_table.item(1, 3).text())
        self.assertEqual(window.loss_stress_table.item(0, 3).text(), "20%")
        self.assertEqual(window.loss_stress_table.item(1, 3).text(), "не подтверждается")
        self.assertEqual(window.loss_stat_longest_burst.text(), "2")
        self.assertIn("подряд: 2", window.loss_events_log.toPlainText())
        window.close()

    def test_tcp_metric_opens_deep_dive_and_back_returns_to_dashboard(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()

        QTest.mouseClick(window.metrics["tcp"], Qt.MouseButton.LeftButton)
        self.app.processEvents()

        self.assertIs(window.mode_stack.currentWidget(), window.tcp_view)
        self.assertEqual(window.tcp_ports_table.rowCount(), 3)
        self.assertTrue(window.metrics["tcp"].property("clickable"))
        window.tcp_back_button.click()
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        window.close()

    def test_tcp_workspace_renders_ports_and_sockets(self) -> None:
        window = MainWindow()
        primary = TcpConnectMeasurement("example.test", 443, 12.5, "Открыт")
        ports = (
            primary,
            TcpConnectMeasurement("example.test", 80, None, "Закрыт", "Удалённый узел отклонил TCP-соединение"),
        )
        sockets = (
            TcpSocketRecord(42, "game.exe", "192.168.1.20:50000", "203.0.113.10:443", "ESTABLISHED"),
        )

        window._on_tcp_diagnostics_completed(sockets, primary, ports)
        window.tcp_sockets_table.selectRow(0)

        self.assertEqual(window.tcp_handshake_connect.text(), "12.5 ms")
        self.assertEqual(window.tcp_ports_table.item(1, 1).text(), "Закрыт")
        self.assertIn("game.exe", window.tcp_sockets_table.item(0, 0).text())
        self.assertTrue(window.tcp_socket_details_button.isEnabled())
        window.close()

    def test_tls_metric_opens_security_workspace_and_returns_to_dashboard(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()

        QTest.mouseClick(window.metrics["tls"], Qt.MouseButton.LeftButton)
        self.app.processEvents()

        self.assertIs(window.mode_stack.currentWidget(), window.tls_view)
        self.assertTrue(window.metrics["tls"].property("clickable"))
        self.assertEqual(window.tls_handshake_table.rowCount(), 4)
        window.tls_back_button.click()
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        window.close()

    def test_tls_workspace_renders_certificate_audit(self) -> None:
        window = MainWindow()
        certificate = CertificateRecord(
            position=0,
            subject="commonName=example.test",
            issuer="commonName=NetVision Test CA",
            serial_number="01AB",
            valid_from=datetime(2026, 1, 1),
            valid_to=datetime(2027, 1, 1),
            days_remaining=84,
            fingerprint_sha256="AA:BB:CC",
            status="Действителен",
        )
        result = TlsAuditResult(
            host="example.test",
            port=443,
            tcp_connect_ms=8.2,
            handshake_ms=15.6,
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            alpn="h2",
            certificate_valid=True,
            certificate_status="Действителен",
            chain=(certificate,),
            fingerprint_sha256="AA:BB:CC",
        )

        window._on_tls_audit_completed(result)

        self.assertEqual(window.tls_overview_values["protocol"].text(), "TLSv1.3")
        self.assertEqual(window.tls_overview_values["handshake"].text(), "15.6 ms")
        self.assertEqual(window.tls_certificate_table.item(0, 1).text(), "commonName=example.test")
        self.assertEqual(window.tls_certificate_table.item(0, 7).text(), "AA:BB:CC")
        self.assertTrue(window.tls_copy_fingerprint_button.isEnabled())
        window.close()

    def test_deep_dive_workspaces_include_quick_fix_action_bars(self) -> None:
        window = MainWindow()

        self.assertEqual(set(window.quick_fix_status), {"dns", "ping", "loss", "tcp"})
        for context in ("dns", "ping", "loss", "tcp"):
            self.assertEqual(len(window.quick_fix_buttons[context]), 4)
            self.assertEqual(window.quick_fix_status[context].text(), "Готово к применению")
            self.assertTrue(all(button.minimumHeight() >= 34 for button in window.quick_fix_buttons[context]))

        self.assertEqual(window.findChildren(QFrame, "QuickFixPanel").__len__(), 4)
        window.close()

    def test_dns_adapter_properties_button_is_below_selector_and_opens_windows_connections(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(1280, 820)
        # The layout is prebuilt; switch views directly so this geometry test
        # does not start the asynchronous DNS configuration worker.
        window.mode_stack.setCurrentWidget(window.dns_view)
        self.app.processEvents()

        button = window.dns_adapter_properties_button
        combo = window.dns_adapter_combo
        self.assertEqual(button.objectName(), "DnsAdapterPropertiesButton")
        self.assertEqual(button.parentWidget(), combo.parentWidget())
        self.assertEqual(button.pos().x(), combo.pos().x())
        self.assertGreater(button.geometry().top(), combo.geometry().bottom())
        self.assertEqual(button.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Maximum)

        with patch.object(window, "_run_system_action") as run_action:
            button.click()

        run_action.assert_called_once_with(
            "Открыть свойства адаптера",
            open_network_adapters,
            button,
            window.dns_status,
        )
        window.close()

    def test_quick_fix_requires_confirmation_for_tcp_stack_reset(self) -> None:
        window = MainWindow()
        window.dns_adapter_combo.addItem("Ethernet", "Ethernet")
        button = window.quick_fix_buttons["loss"][2]
        status = window.quick_fix_status["loss"]

        with patch("netvision.ui.main_window.QMessageBox.question", return_value=QMessageBox.StandardButton.No):
            window._trigger_quick_fix("stack", button, status)

        self.assertEqual(status.text(), "Действие отменено")
        self.assertTrue(button.isEnabled())
        window.close()

    def test_all_tables_support_interactive_resizing_and_responsive_last_column(self) -> None:
        window = MainWindow()
        tables = (
            window.dns_table,
            window.ping_matrix_table,
            window.ping_mtu_table,
            window.loss_stress_table,
            window.loss_hops_table,
            window.tcp_ports_table,
            window.tcp_sockets_table,
            window.tls_handshake_table,
            window.tls_certificate_table,
            window.jitter_events_table,
            window.routes_table,
            window.geo_table,
            window.interfaces_table,
            window.udp_events_table,
        )

        for table in tables:
            header = table.horizontalHeader()
            self.assertEqual(header.sectionResizeMode(0), QHeaderView.ResizeMode.Interactive)
            self.assertTrue(header.stretchLastSection())
            self.assertTrue(header.sectionsClickable())
            self.assertEqual(
                table.selectionBehavior(),
                QAbstractItemView.SelectionBehavior.SelectRows,
            )
            self.assertEqual(
                table.horizontalScrollBarPolicy(),
                Qt.ScrollBarPolicy.ScrollBarAsNeeded,
            )
            first_width = header.sectionSize(0)
            header.resizeSection(0, first_width + 24)
            self.assertEqual(header.sectionSize(0), first_width + 24)
        window.close()

    def test_quick_action_buttons_are_available(self) -> None:
        window = MainWindow()

        self.assertEqual(window.flush_dns_button.text(), "🔄  Сброс DNS")
        self.assertEqual(window.flush_dns_button.objectName(), "QuickActionPrimary")
        self.assertEqual(window.adapters_button.text(), "🖥️  Сетевые адаптеры")
        self.assertEqual(window.proxy_settings_button.text(), "⚙️  Параметры прокси")
        self.assertEqual(window.firewall_button.text(), "🛡️  Брандмауэр")
        self.assertTrue(window.flush_dns_button.icon().isNull())
        self.assertTrue(window.adapters_button.icon().isNull())
        self.assertTrue(window.proxy_settings_button.icon().isNull())
        self.assertTrue(window.firewall_button.icon().isNull())

        window.close()

    def test_process_dropdown_is_embedded_and_closes_before_mode_switch(self) -> None:
        window = MainWindow()
        window.show()
        self.app.processEvents()
        combo = window.process_selector
        combo.showPopup()
        self.app.processEvents()

        self.assertTrue(window.embedded_dropdown.isVisible())
        self.assertIs(window.embedded_dropdown.parentWidget(), window.process_panel)
        self.assertIsNone(window.embedded_dropdown.window().parentWidget())
        self.assertFalse(window.embedded_dropdown.windowFlags() & Qt.WindowType.Popup)
        window._set_interface_mode("lite")
        self.app.processEvents()

        self.assertIs(window.mode_stack.currentWidget(), window.lite_view)
        self.assertFalse(window.embedded_dropdown.isVisible())
        window.close()

    def test_expert_mode_prioritizes_workspace_and_compacts_metrics(self) -> None:
        window = MainWindow()

        self.assertTrue(window.expert_view.isAncestorOf(window.quick_actions_panel))
        self.assertGreaterEqual(window.latency_chart.minimumHeight(), 180)
        self.assertEqual(
            window.latency_chart.sizePolicy().verticalPolicy(),
            QSizePolicy.Policy.Expanding,
        )
        self.assertEqual(window.metrics["ping"].minimumHeight(), 82)
        self.assertEqual(
            window.metrics["ping"].sizePolicy().verticalPolicy(),
            QSizePolicy.Policy.Preferred,
        )
        self.assertTrue(window.process_status.isHidden())
        self.assertTrue(window.metrics["jitter"].icon_label.text())

        window.close()

    def test_responsive_layout_reflows_metric_cards_and_preserves_scroll_access(self) -> None:
        window = MainWindow()
        window.show()

        self.assertIsInstance(window.mode_scroll, QScrollArea)
        self.assertIs(window.mode_scroll.widget(), window.mode_stack)

        observed_columns: list[int] = []
        for width, height in ((960, 680), (1024, 768), (1280, 820), (1920, 1080)):
            window.resize(width, height)
            self.app.processEvents()
            observed_columns.append(window.metric_grid.columns)
            self.assertGreaterEqual(window.metric_grid.columns, 1)
            self.assertLessEqual(window.metric_grid.columns, 6)
            self.assertEqual(window.mode_scroll.verticalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            self.assertEqual(window.mode_scroll.horizontalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.assertGreater(observed_columns[-1], observed_columns[0])
        self.assertTrue(window.topology.sizePolicy().horizontalPolicy() == QSizePolicy.Policy.Expanding)
        self.assertEqual(window.topology.sizePolicy().verticalPolicy(), QSizePolicy.Policy.Preferred)
        window.close()

    def test_responsive_status_labels_keep_full_text_in_tooltips(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(960, 680)
        self.app.processEvents()

        window._set_status("WARNING", "warning")
        expected_health = "🟡  Есть задержки / Высокий пинг"
        self.assertEqual(window.status_badge.property("fullText"), expected_health)
        self.assertEqual(window.status_badge.toolTip(), expected_health)

        window._udp_monitor_pid = 42
        window._on_udp_port_snapshot(UdpPortSnapshot(42, tuple(range(27000, 27020))))
        self.assertEqual(window.udp_ports_status.property("fullText"), window.udp_ports_status.toolTip())
        window.close()

    def test_network_health_badge_reserves_room_for_full_status_message(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(1280, 820)
        self.app.processEvents()

        window._set_status("READY", "success")
        expected = "🟢  Сеть работает отлично"
        self.assertEqual(window.status_badge.text(), expected)
        required_width = window.status_badge.fontMetrics().horizontalAdvance(expected) + 34
        self.assertGreaterEqual(
            window.status_badge.width(),
            required_width,
        )
        self.assertEqual(window.status_badge.maximumWidth(), window.status_badge.minimumWidth())
        self.assertEqual(window.status_badge.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Fixed)
        window.close()

    def test_header_controls_compact_without_overlap_and_topology_has_no_horizontal_scrollbar(self) -> None:
        window = MainWindow()
        window.show()

        for width in (960, 1040, 1120, 1280):
            window.resize(width, 820)
            self.app.processEvents()
            controls = [
                control
                for control in (window.export_button, window.language_combo, window.theme_button)
                if control.isVisible()
            ]
            for index, first in enumerate(controls):
                for second in controls[index + 1 :]:
                    first_rect = QRect(first.mapTo(window, QPoint(0, 0)), first.size())
                    second_rect = QRect(second.mapTo(window, QPoint(0, 0)), second.size())
                    self.assertFalse(first_rect.intersects(second_rect))

        self.assertTrue(window.header_settings.rect().contains(window.language_combo.geometry()))
        self.assertTrue(window.header_settings.rect().contains(window.theme_button.geometry()))

        self.assertEqual(window.topology.minimumWidth(), 0)
        self.assertEqual(
            window.topology_scroll.horizontalScrollBarPolicy(),
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
        )
        self.assertEqual(
            window.details_scroll.horizontalScrollBarPolicy(),
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
        )
        window._toggle_theme()
        self.app.processEvents()
        self.assertEqual(window._theme, "light")
        self.assertTrue(window.language_combo.isVisible())
        self.assertTrue(window.theme_button.isVisible())
        window.close()

    def test_session_capsule_compacts_without_hiding_timer(self) -> None:
        window = MainWindow()
        window.show()

        window.resize(1280, 820)
        self.app.processEvents()
        self.assertTrue(window.session_capsule.isVisible())
        self.assertTrue(window.session_timer_button.isVisible())
        self.assertTrue(window.session_log_button.isVisible())

        window.resize(960, 820)
        self.app.processEvents()
        self.assertTrue(window.session_timer_button.isVisible())
        self.assertFalse(window.session_log_button.isVisible())
        self.assertEqual(window.session_capsule.maximumWidth(), 182)
        window.close()

    def test_session_capsule_tracks_anomalies_and_opens_log(self) -> None:
        window = MainWindow()
        window.show()

        window._start_diagnostic_session()
        self.assertTrue(window._session_timer.isActive())
        self.assertIn("Диагностика", window.session_log_button.text())

        window._session_elapsed_seconds = 62
        window._refresh_session_capsule()
        self.assertEqual(window.session_timer_button.text(), "⏱  01:02")
        window.session_timer_button.click()
        self.assertFalse(window._session_timer.isActive())
        window.session_timer_button.click()
        self.assertTrue(window._session_timer.isActive())
        window.session_reset_button.click()
        self.assertFalse(window._session_timer.isActive())
        self.assertEqual(window.session_timer_button.text(), "⏱  00:00")

        window._on_latency_sample(175.0, True)
        self.assertEqual(window.session_log_button.property("anomalyState"), "error")
        self.assertIn("Пик пинга", window.session_log_button.text())

        window.lite_mode_button.setChecked(True)
        window._open_log_from_header()
        self.assertTrue(window.expert_mode_button.isChecked())
        self.assertIs(window.workspace_tabs.currentWidget(), window.log_tab)
        window.close()

    def test_session_anomaly_menu_shows_recent_events_and_opens_full_log(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(1280, 820)

        window._set_header_anomaly("warning", "Высокий пинг: {latency:.0f} мс", latency=112)
        window._set_header_anomaly("warning", "Высокий пинг: {latency:.0f} мс", latency=148)
        self.assertEqual(len(window._header_anomaly_history), 1)

        window._set_header_anomaly("good", "Связь стабильна")
        window._set_header_anomaly("error", "Пик пинга > {latency:.0f} мс", latency=180)
        self.assertEqual(len(window._header_anomaly_history), 2)

        menu = window._header_anomaly_menu
        assert menu is not None
        # The offscreen Qt platform does not keep QMenu popups visible. Verify
        # the dynamically rendered contents here; the desktop smoke check
        # exercises the actual popup visibility.
        window._populate_header_anomaly_menu()
        events = menu.findChildren(QLabel, "SessionAnomalyItem")
        self.assertEqual(len(events), 2)
        self.assertIn("Пик пинга > 180 мс", events[0].text())
        self.assertRegex(events[0].text(), r"^\d{2}:\d{2}:\d{2}  -  ")

        open_log_button = menu.findChild(QPushButton, "SessionAnomalyOpenLogButton")
        self.assertIsNotNone(open_log_button)
        assert open_log_button is not None
        open_log_button.click()
        self.assertIs(window.workspace_tabs.currentWidget(), window.log_tab)
        window.close()

    def test_session_anomaly_menu_limits_history_and_has_empty_state(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(1280, 820)

        menu = window._header_anomaly_menu
        assert menu is not None
        window._populate_header_anomaly_menu()
        empty_state = menu.findChild(QLabel, "SessionAnomalyEmptyState")
        self.assertIsNotNone(empty_state)

        for index in range(6):
            window._set_header_anomaly("warning", f"Событие {index}")
            window._set_header_anomaly("good", "Связь стабильна")
        self.assertEqual(len(window._header_anomaly_history), 5)
        self.assertEqual(window._header_anomaly_history[0].source, "Событие 1")
        window.close()

    def test_network_health_badge_only_uses_the_width_needed_by_long_status(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(1920, 1080)
        self.app.processEvents()

        window._set_status("WARNING", "warning")
        text = window.status_badge.text()
        required_width = window.status_badge.fontMetrics().horizontalAdvance(text) + 34
        self.assertIn("Высокий пинг", text)
        self.assertEqual(window.status_badge.width(), required_width)
        self.assertEqual(window.status_badge.minimumWidth(), required_width)
        self.assertEqual(window.status_badge.maximumWidth(), required_width)
        window.close()

    def test_dns_metric_card_uses_the_same_compact_contract_as_other_cards(self) -> None:
        window = MainWindow()
        window.show()
        window.resize(1280, 820)
        self.app.processEvents()

        dns_tile = window.metrics["dns"]
        ping_tile = window.metrics["ping"]
        self.assertEqual(dns_tile.minimumWidth(), ping_tile.minimumWidth())
        self.assertEqual(dns_tile.minimumHeight(), ping_tile.minimumHeight())
        self.assertEqual(dns_tile.hint.minimumHeight(), ping_tile.hint.minimumHeight())
        self.assertEqual(dns_tile.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Expanding)
        self.assertEqual(dns_tile.property("metricRole"), None)
        self.assertEqual(window.metric_grid.columns, 6)
        window.close()

    def test_dns_metric_removes_repeated_title_from_value(self) -> None:
        window = MainWindow()
        window.metrics["dns"].set_metric("DNS 5.3 ms - 203.0.113.1", "IP: 203.0.113.1", "good")

        self.assertEqual(window.metrics["dns"].value.text(), "5.3 ms - 203.0.113.1")
        self.assertFalse(window.metrics["dns"].value.text().startswith("DNS"))
        window.close()

    def test_topology_starts_neutral_and_colors_connections_from_report(self) -> None:
        topology = TopologyWidget()
        self.assertTrue(all(node.status == ProbeStatus.PENDING for node in topology._nodes))
        self.assertTrue(all(status == ProbeStatus.PENDING for status in topology._connection_statuses))

        target = parse_target("example.test", 443)
        system = SystemSnapshot(
            hostname="test-pc",
            interfaces=(NetworkInterface("Ethernet", "Ethernet", True, 0, ipv4=("192.168.1.10",)),),
            gateway=GatewayInfo("192.168.1.1", "Ethernet", 1),
            dns_servers=("1.1.1.1",),
            external_ip=None,
            proxies=(),
        )
        report = DiagnosticReport(
            target=target,
            system=system,
            dns=DnsResult(target.host, ("203.0.113.1",), 5.0, ProbeStatus.SUCCESS),
            tcp=TcpResult(target.host, target.port, "203.0.113.1", 9.0, ProbeStatus.SUCCESS),
            ping=PingResult(target.host, 5, 5, 0.0, 20.0, 18.0, 22.0, 2.0, (18, 20, 22), ProbeStatus.SUCCESS),
            tls=None,
            hops=(),
            geolocation=(),
            started_at=datetime(2026, 10, 8, 12, 0, 0),
            total_ms=100.0,
        )
        topology.set_report(report)
        self.assertTrue(all(status == ProbeStatus.SUCCESS for status in topology._connection_statuses))
        self.assertEqual(topology._dns_label, "5.0 ms  ·  203.0.113.1")
        self.assertFalse(topology._dns_label.startswith("DNS"))

        topology.set_report(replace(report, ping=replace(report.ping, loss_percent=20.0, received=4)))
        self.assertEqual(topology._connection_statuses[-1], ProbeStatus.WARNING)

        topology.set_report(replace(report, tcp=replace(report.tcp, status=ProbeStatus.ERROR)))
        self.assertEqual(topology._connection_statuses[-1], ProbeStatus.ERROR)
        topology.deleteLater()

    def test_target_presets_fill_the_ready_diagnostic_profile(self) -> None:
        window = MainWindow()

        expected_profiles = {
            "Google": "google.com",
            "Telegram": "t.me",
            "Яндекс": "yandex.ru",
            "Игровой сервер": "steamcommunity.com",
        }
        self.assertEqual(set(window.preset_buttons), set(expected_profiles))
        for name, host in expected_profiles.items():
            window.preset_buttons[name].click()
            self.assertEqual(window.target_input.text(), host)
            self.assertEqual(window.port_input.value(), 443)
            self.assertEqual(window._active_preset, name)
            self.assertTrue(window.preset_buttons[name].isChecked())

        window.close()

    def test_main_port_input_explains_its_valid_range_and_default(self) -> None:
        window = MainWindow()

        self.assertEqual(window.port_input.minimum(), 1)
        self.assertEqual(window.port_input.maximum(), 65535)
        self.assertEqual(window.port_input.value(), 443)
        self.assertEqual(
            window.port_input.toolTip(),
            "Сетевой порт целевого узла.\n"
            "• 443 — для защищенных HTTPS-соединений и большинства веб-серверов\n"
            "• 80 — для обычных HTTP-соединений\n"
            "Оставьте стандартное значение, если не уверены.",
        )

        window.language_combo.setCurrentIndex(1)
        self.assertIn("Target host network port.", window.port_input.toolTip())
        self.assertIn("Keep the default value", window.port_input.toolTip())
        window.close()

    def test_network_health_indicator_uses_clear_user_facing_states(self) -> None:
        window = MainWindow()

        window._set_status("READY", "success")
        self.assertIn("Сеть работает отлично", window.status_badge.text())
        window._set_status("WARNING", "warning")
        self.assertIn("Есть задержки / Высокий пинг", window.status_badge.text())
        window._set_status("ERROR", "error")
        self.assertIn("Нет подключения", window.status_badge.text())

        window.close()

    def test_header_language_selector_updates_primary_controls(self) -> None:
        window = MainWindow()

        self.assertEqual(window.language_combo.currentData(), "ru")
        window.language_combo.setCurrentIndex(1)

        self.assertEqual(window._language, "en")
        self.assertEqual(window.language_label.text(), "LANGUAGE")
        self.assertEqual(window.mode_label.text(), "MODE")
        self.assertEqual(window.expert_mode_button.text(), "Expert")
        self.assertEqual(window.lite_mode_button.text(), "Simple mode")
        window.close()

    def test_language_selector_retranslates_existing_dashboard_and_open_dialog(self) -> None:
        window = MainWindow()
        candidate = BackgroundTrafficCandidate(
            456,
            "qBittorrent.exe",
            "qBittorrent",
            "Торрент-клиент",
            2,
        )
        dialog = NetworkBoostDialog((candidate,), window, window._tr)
        window._network_boost_dialog = dialog

        window.language_combo.setCurrentIndex(1)

        self.assertEqual(window.start_button.text(), "Run diagnostics")
        self.assertEqual(window.metrics["loss"].title_label.text(), "PACKET LOSS")
        self.assertEqual(window.dns_back_button.text(), "←  Back")
        self.assertEqual(window.dns_adapter_properties_button.text(), "Open Adapter Properties")
        self.assertEqual(window.dns_table.horizontalHeaderItem(0).text(), "Provider")
        self.assertEqual(window.findChildren(QTabWidget)[0].tabText(0), "Overview")
        self.assertEqual(window.flush_dns_button.text(), "🔄  Flush DNS")
        self.assertEqual(window.tls_run_button.text(), "▶  Check certificate")
        self.assertEqual(window.jitter_event_status.text(), "Critical threshold: Δ RTT > 15 ms · events: 0")
        self.assertEqual(window.latency_chart._translate("60с назад"), "60s ago")
        self.assertEqual(dialog.windowTitle(), "Background process optimization")
        self.assertIn("Torrent client", next(iter(dialog._candidate_checkboxes.values())).text())
        self.assertEqual(dialog.cancel_button.text(), "Cancel")

        window.language_combo.setCurrentIndex(0)

        self.assertEqual(window.start_button.text(), "Запустить диагностику")
        self.assertEqual(window.metrics["loss"].title_label.text(), "ПОТЕРИ")
        self.assertEqual(window.dns_adapter_properties_button.text(), "Открыть свойства адаптера")
        self.assertEqual(window.dns_table.horizontalHeaderItem(0).text(), "Провайдер")
        self.assertEqual(window.flush_dns_button.text(), "🔄  Сброс DNS")
        self.assertEqual(dialog.windowTitle(), "Оптимизация фоновых процессов")
        self.assertIn("Торрент-клиент", next(iter(dialog._candidate_checkboxes.values())).text())
        dialog.close()
        window.close()

    def test_header_theme_toggle_applies_light_and_dark_styles(self) -> None:
        window = MainWindow()
        app = QApplication.instance()
        assert app is not None

        window._toggle_theme()
        self.assertEqual(window._theme, "light")
        self.assertEqual(window.theme_button.text(), "☀")
        self.assertEqual(app.styleSheet(), LIGHT_STYLE)

        window._toggle_theme()
        self.assertEqual(window._theme, "dark")
        self.assertEqual(window.theme_button.text(), "☾")
        self.assertEqual(app.styleSheet(), APP_STYLE)
        window.close()

    def test_theme_language_resize_stress_keeps_controls_and_canvases_consistent(self) -> None:
        window = MainWindow()
        messages = []
        old_handler = qInstallMessageHandler(lambda _kind, _context, message: messages.append(message))
        self.app.setStyleSheet(APP_STYLE)
        window.show()
        try:
            for iteration in range(8):
                window._toggle_theme()
                window.language_combo.setCurrentIndex(iteration % 2)
                for width, height in ((960, 680), (1120, 768), (1280, 820), (1920, 1080)):
                    window.resize(width, height)
                    for _ in range(3):
                        self.app.processEvents()
                    controls = [widget for widget in (
                        window.status_badge, window.session_capsule, window.header_mode_controls,
                        window.export_button, window.header_settings,
                    ) if widget.isVisible()]
                    for first, second in zip(controls, controls[1:]):
                        self.assertFalse(first.geometry().intersects(second.geometry()))
                    for widget in (window.language_combo, window.theme_button):
                        self.assertTrue(window.header_settings.rect().contains(widget.geometry()))
                    for scroll in (window.topology_scroll, window.details_scroll):
                        self.assertEqual(scroll.horizontalScrollBar().maximum(), 0)
                for canvas in (window.topology, window.latency_chart, window.jitter_chart):
                    canvas.ensurePolished()
                    # Inspect painted pixels, not only the stylesheet string.
                    image = canvas.grab().toImage()
                    self.assertEqual(image.pixelColor(4, 40).name(),
                                     "#ffffff" if window._theme == "light" else "#161b22")
            self.assertFalse({message for message in messages if
                              "Unknown property" in message or "Could not parse" in message})
        finally:
            qInstallMessageHandler(old_handler)
            window.close()
            self.app.setStyleSheet(APP_STYLE)

    def test_process_selector_fills_diagnostic_target(self) -> None:
        window = MainWindow()
        connection = ProcessConnection("TCP", "ESTABLISHED", "192.168.1.20", 52000, "203.0.113.10", 443)
        process = ProcessNetworkInfo(321, "game.exe", (connection,))

        window._on_process_scan_completed(ProcessScanResult((process,)))
        self.assertEqual(window.process_selector.count(), 1)
        window.process_selector.setCurrentIndex(0)
        window.process_connection_selector.setCurrentIndex(0)

        self.assertEqual(window.target_input.text(), "203.0.113.10")
        self.assertEqual(window.port_input.value(), 443)
        self.assertIn("game.exe", window.process_status.text())
        window.close()

    def test_udp_monitor_status_shows_selected_process_ports(self) -> None:
        window = MainWindow()
        window._udp_monitor_pid = 321

        window._on_udp_port_snapshot(UdpPortSnapshot(321, (27015, 27016)))
        self.assertEqual(window.udp_ports_status.text(), "UDP-порты PID 321: 27015, 27016")

        window._on_udp_port_snapshot(UdpPortSnapshot(321, ()))
        self.assertEqual(window.udp_ports_status.text(), "UDP: локальные порты не обнаружены")

        window._on_udp_port_snapshot(UdpPortSnapshot(999, (443,)))
        self.assertEqual(window.udp_ports_status.text(), "UDP: локальные порты не обнаружены")
        window.close()

    def test_udp_events_table_records_transitions_and_filters_anomalies(self) -> None:
        window = MainWindow()
        window._udp_monitor_pid = 321
        timestamp = datetime(2026, 10, 8, 15, 30, 0)
        opened = UdpPortActivity(
            UdpPortSnapshot(321, (27015,)),
            timestamp,
            opened_ports=(27015,),
        )
        loss = UdpPortActivity(
            UdpPortSnapshot(321, ()),
            timestamp,
            closed_ports=(27015,),
            anomaly=UdpPortAnomaly.ALL_PORTS_LOST,
        )

        window._on_udp_port_activity(opened)
        window._on_udp_port_activity(loss)

        self.assertEqual(window.udp_events_table.rowCount(), 3)
        self.assertEqual(window.udp_events_table.item(0, 1).text(), "Порт открыт")
        self.assertEqual(window.udp_events_table.item(1, 1).text(), "Порт закрыт")
        self.assertEqual(window.udp_events_table.item(2, 1).text(), "Возможный обрыв")
        self.assertTrue(window.export_udp_json_button.isEnabled())
        self.assertTrue(window.export_udp_csv_button.isEnabled())

        window.udp_anomaly_filter.setChecked(True)
        self.assertEqual(window.udp_events_table.rowCount(), 1)
        self.assertEqual(window.udp_events_table.item(0, 1).text(), "Возможный обрыв")
        self.assertIn("Показано аномалий: 1", window.udp_event_status.text())
        window.close()

    def test_udp_csv_export_uses_save_dialog_and_writes_event_rows(self) -> None:
        window = MainWindow()
        window._udp_monitor_pid = 321
        activity = UdpPortActivity(
            UdpPortSnapshot(321, (27015,)),
            datetime(2026, 10, 8, 15, 30, 0),
            opened_ports=(27015,),
        )
        window._on_udp_port_activity(activity)

        class MemorySaveFile:
            payload = b""

            def __init__(self, _path: str) -> None:
                pass

            def open(self, _mode: object) -> bool:
                return True

            def write(self, data: bytes) -> int:
                self.payload = data
                return len(data)

            def commit(self) -> bool:
                return True

            def errorString(self) -> str:
                return ""

        saved_files: list[MemorySaveFile] = []

        def make_save_file(path: str) -> MemorySaveFile:
            result = MemorySaveFile(path)
            saved_files.append(result)
            return result

        with (
            patch("netvision.ui.main_window.QFileDialog.getSaveFileName", return_value=("udp-events", "CSV (*.csv)")),
            patch("netvision.ui.main_window.QSaveFile", side_effect=make_save_file),
        ):
            window._export_udp_events_csv()

        self.assertIn("event_type", saved_files[0].payload.decode("utf-8"))
        self.assertIn("Порт открыт", saved_files[0].payload.decode("utf-8"))
        self.assertIn("UDP-события сохранены в CSV", window.log_output.toPlainText())
        window.close()

    def test_local_udp_socket_does_not_replace_the_diagnostic_target(self) -> None:
        window = MainWindow()
        window.target_input.setText("example.com")
        window.port_input.setValue(443)
        local_udp = ProcessConnection("UDP", "NONE", "192.168.1.20", 27015, "", 0)
        process = ProcessNetworkInfo(321, "huntgame.exe", (local_udp,))

        window._on_process_scan_completed(ProcessScanResult((process,)))
        window._on_connection_selected(0)

        self.assertEqual(window.target_input.text(), "example.com")
        self.assertEqual(window.port_input.value(), 443)
        self.assertIn("локальный UDP-порт 27015", window.process_status.text())
        window.close()

    def test_lite_mode_hides_process_technical_details_and_uses_friendly_name(self) -> None:
        window = MainWindow()
        connection = ProcessConnection("TCP", "ESTABLISHED", "192.168.1.20", 52000, "203.0.113.10", 443)
        process = ProcessNetworkInfo(321, "discord.exe", (connection,))
        window._on_process_scan_completed(ProcessScanResult((process,)))

        self.assertIn("PID 321", window.process_selector.itemText(0))
        window.lite_mode_button.setChecked(True)

        self.assertEqual(window.process_selector.itemText(0), "💬 Discord")
        self.assertTrue(window.process_connection_selector.isHidden())
        self.assertTrue(window.process_status.isHidden())

        window.expert_mode_button.setChecked(True)
        self.assertIn("PID 321", window.process_selector.itemText(0))
        self.assertFalse(window.process_connection_selector.isHidden())
        window.close()

    def test_metric_help_tooltips_and_interface_mode_switch(self) -> None:
        window = MainWindow()

        for metric, tooltip in METRIC_TOOLTIPS.items():
            self.assertEqual(window.metrics[metric].help_button.toolTip(), tooltip)
        self.assertTrue(window.expert_mode_button.isChecked())
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)

        window.lite_mode_button.setChecked(True)
        self.assertIs(window.mode_stack.currentWidget(), window.lite_view)
        self.assertFalse(window.expert_view.isVisible())
        self.assertTrue(window.lite_mode_button.isChecked())
        self.assertTrue(window.process_panel.isHidden())
        self.assertTrue(window.port_label.isHidden())
        self.assertTrue(window.port_input.isHidden())

        window.expert_mode_button.setChecked(True)
        self.assertIs(window.mode_stack.currentWidget(), window.expert_view)
        self.assertFalse(window.process_panel.isHidden())
        self.assertFalse(window.port_label.isHidden())
        self.assertFalse(window.port_input.isHidden())
        window.close()

    def test_lite_summary_reflects_diagnostic_severity(self) -> None:
        target = parse_target("example.test", 443)
        base_report = DiagnosticReport(
            target=target,
            system=SystemSnapshot(
                hostname="test-pc",
                interfaces=(),
                gateway=None,
                dns_servers=("1.1.1.1",),
                external_ip=None,
                proxies=(),
                default_routes=(DefaultRoute("10.0.0.1", "Test VPN", "10.0.0.2", 1, True),),
            ),
            dns=DnsResult(target.host, ("203.0.113.1",), 4.0, ProbeStatus.SUCCESS),
            tcp=TcpResult(target.host, target.port, "203.0.113.1", 8.0, ProbeStatus.SUCCESS),
            ping=PingResult(target.host, 5, 5, 0.0, 21.0, 20.0, 22.0, 2.0, (20, 22, 21, 20, 22), ProbeStatus.SUCCESS),
            tls=None,
            hops=(),
            geolocation=(),
            started_at=datetime(2026, 10, 8, 12, 0, 0),
            total_ms=100.0,
        )
        window = MainWindow()

        window._update_lite_summary(base_report)
        self.assertEqual(window.lite_title.text(), "Сайт полностью доступен")
        card_texts = [item.text() for item in window.lite_detail_labels]
        self.assertIn("🌐 DNS\n4.0 мс (Быстрый отклик)", card_texts)
        self.assertIn("🔓 Порт 443\nОткрыт", card_texts)
        self.assertIn("📉 Потери\n0% (Связь стабильная)", card_texts)
        self.assertIn("🛡️ Маршрут\nVPN активен", card_texts)
        self.assertEqual(window.lite_status_indicator.text(), "🟢")

        warning_report = replace(
            base_report,
            ping=PingResult(target.host, 5, 0, 100.0, None, None, None, None, (), ProbeStatus.WARNING),
        )
        window._update_lite_summary(warning_report)
        self.assertEqual(window.lite_title.text(), "Сайт доступен, но есть предупреждения")
        self.assertEqual(window.lite_status_indicator.styleSheet().count("#FFB800"), 1)
        self.assertTrue(
            any("100% (Обрыв связи)" in item.text() for item in window.lite_detail_labels)
        )
        self.assertEqual(window.lite_status_indicator.text(), "⚠️")

        error_report = replace(
            base_report,
            dns=DnsResult(target.host, (), None, ProbeStatus.ERROR, "DNS failed"),
        )
        window._update_lite_summary(error_report)
        self.assertEqual(window.lite_title.text(), "Нет связи с узлом")
        self.assertEqual(window.lite_status_indicator.styleSheet().count("#FF4757"), 1)
        self.assertIn("🌐 DNS\nНет ответа", [item.text() for item in window.lite_detail_labels])
        self.assertEqual(window.lite_status_indicator.text(), "🔴")
        window.close()

    def test_system_action_runs_asynchronously_and_reports_result(self) -> None:
        window = MainWindow()
        event_loop = QEventLoop()
        timer = QTimer()
        timer.setInterval(10)
        timer.timeout.connect(
            lambda: event_loop.quit()
            if window.flush_dns_button.isEnabled() and not window._system_action_threads
            else None
        )
        timer.start()
        QTimer.singleShot(1000, event_loop.quit)

        window._run_system_action(
            "Тестовое действие",
            lambda: SystemActionResult(True, "выполнено"),
            window.flush_dns_button,
        )
        self.assertFalse(window.flush_dns_button.isEnabled())
        event_loop.exec()
        timer.stop()

        self.assertTrue(window.flush_dns_button.isEnabled())
        self.assertIn("Тестовое действие: выполнено", window.log_output.toPlainText())
        self.assertEqual(window.statusBar().currentMessage(), "Тестовое действие: выполнено")
        window.close()

    def test_internet_quality_tab_displays_partial_results(self) -> None:
        window = MainWindow()
        report = InternetQualityReport(
            speedtest=SpeedtestResult(download_mbps=120.0, ping_ms=15.0, server_name="Cloudflare DNS"),
            network=PublicNetworkInfo(ipv4="198.51.100.50", isp="Example ISP", city="Москва"),
            local=LocalNetworkContext(
                adapter_name="Ethernet",
                adapter_speed_mbps=1000,
                local_ipv4=("192.168.1.20", "172.19.0.1"),
                local_ip_tooltip="Все обнаруженные адреса: 192.168.1.20, 172.19.0.1, fe80::1",
            ),
            errors=("Speedtest warning",),
        )

        window._on_quality_completed(report)

        self.assertEqual(window.quality_metrics["download"].value.text(), "120.0 Мбит/с")
        self.assertEqual(window.quality_metrics["loaded_ping"].value.text(), "N/A")
        self.assertEqual(window.quality_details["isp"].text(), "Example ISP")
        self.assertEqual(window.quality_details["local_ip"].text(), "192.168.1.20, 172.19.0.1")
        self.assertIn("fe80::1", window.quality_details["local_ip"].toolTip())
        self.assertIn("частично", window.quality_status.text())
        self.assertIn("Speedtest warning", window.quality_report_output.toPlainText())
        window.close()

    def test_internet_quality_check_runs_in_background(self) -> None:
        window = MainWindow()
        result = InternetQualityReport(
            speedtest=SpeedtestResult(download_mbps=80.0),
            network=PublicNetworkInfo(ipv4="198.51.100.60"),
            local=LocalNetworkContext(),
        )
        event_loop = QEventLoop()
        timer = QTimer()
        timer.setInterval(10)
        timer.timeout.connect(
            lambda: event_loop.quit()
            if window.quality_test_button.isEnabled() and window._quality_thread is None
            else None
        )
        timer.start()
        QTimer.singleShot(1500, event_loop.quit)

        with patch("netvision.ui.main_window.run_internet_quality_check", return_value=result):
            window.start_quality_check()
            self.assertFalse(window.quality_test_button.isEnabled())
            event_loop.exec()

        timer.stop()
        self.assertTrue(window.quality_test_button.isEnabled())
        self.assertEqual(window.quality_metrics["download"].value.text(), "80.0 Мбит/с")
        window.close()


if __name__ == "__main__":
    unittest.main()

