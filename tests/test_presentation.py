import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock

from netvision.core.process_inspector import ProcessConnection
from netvision.core.process_inspector import ProcessListResult, RunningProcess
from netvision.ui.game_check_worker import GameAutoCheckWorker
from netvision.ui.presentation import (
    AMBER,
    GREEN,
    GREY,
    RED,
    metric_assessment,
    nat_description,
    smart_verdict,
    socket_label,
    socket_priority,
    target_mode,
    traceroute_completed_text,
)


@pytest.mark.parametrize(
    "count,word",
    [(1, "узел"), (2, "узла"), (5, "узлов"), (11, "узлов"), (21, "узел"), (24, "узла")],
)
def test_traceroute_pluralization(count, word):
    assert traceroute_completed_text(count, "ru").endswith(f"{count} {word}")
    assert traceroute_completed_text(count, "en").endswith(
        f"{count} {'hop' if count == 1 else 'hops'}"
    )


@pytest.mark.parametrize(
    "key,value,color",
    [
        ("dns", 24.9, GREEN),
        ("dns", 25, AMBER),
        ("dns", 80, AMBER),
        ("dns", 80.1, RED),
        ("ping", 45, AMBER),
        ("ping", 95, AMBER),
        ("loss", 0, GREEN),
        ("loss", 1.5, AMBER),
        ("loss", 1.6, RED),
        ("jitter", 5, AMBER),
        ("jitter", 15, AMBER),
        ("tcp", 120, AMBER),
    ],
)
def test_metric_boundaries(key, value, color):
    assert metric_assessment(key, value).color == color


def test_live_metrics_refresh_colors_and_verdict():
    from netvision.ui.controllers.overview_controller import OverviewController

    cards = {key: MagicMock() for key in ("loss", "jitter", "ping")}
    controller = SimpleNamespace(
        workspace=SimpleNamespace(dashboard_metric_cards=cards),
        host=SimpleNamespace(_tr=lambda text: text, _report=object()),
        _update_dashboard_verdict=MagicMock(),
    )
    OverviewController.update_live_assessments(controller, 12.0, 6.7, 20.0)
    cards["loss"].caption.setText.assert_called_with("Потеря пакетов")
    cards["jitter"].caption.setText.assert_called_with("Умеренно")
    cards["loss"].value.setStyleSheet.assert_called_with(f"color: {RED};")
    cards["jitter"].value.setStyleSheet.assert_called_with(f"color: {AMBER};")
    controller._update_dashboard_verdict.assert_called_once_with(
        controller.host._report, loss=12.0, jitter=6.7, ping=20.0
    )
    assert "Потери" in smart_verdict(None, None, False, 12.0, 6.7, 20.0, True)


def test_neutral_vpn_and_udp():
    assert metric_assessment("dns", 0.5, vpn=True).color == GREY
    assert metric_assessment("tls", None, udp=True, error=True).text == "Не для UDP"
    assert metric_assessment("tls", 1, expires_days=13).color == AMBER


def test_socket_order_and_nat():
    udp = ProcessConnection("UDP", "NONE", "10.0.0.1", 5000, "1.1.1.1", 53)
    tcp = ProcessConnection("TCP", "ESTABLISHED", "10.0.0.1", 5001, "1.1.1.1", 443)
    local = ProcessConnection("TCP", "ESTABLISHED", "127.0.0.1", 5002, "127.0.0.1", 443)
    assert sorted([local, tcp, udp], key=socket_priority) == [udp, tcp, local]
    assert "Локальный" in socket_label(local)
    assert "Строгий" in nat_description("edm")
    assert nat_description("undetermined") == "Не определён"


def test_verdict_respects_priority_and_unknown_gateway():
    assert "локально" in smart_verdict(20, 0, True, 5, 30, 150)
    assert "VPN" in smart_verdict(1, 0, True, 5, 30, 150)
    assert "провайдера" in smart_verdict(1, 0, False, 5, 30, 150)
    assert "не проверено" in smart_verdict(None, None, False, 0, 1, 10)


def test_game_check_excludes_unrelated_processes():
    worker = GameAutoCheckWorker()
    result = ProcessListResult((RunningProcess(1, "chrome.exe"), RunningProcess(2, "CS2.EXE")))
    assert [process.pid for process in worker._candidate_processes(result)] == [2]


def test_target_mode_identifies_ip_and_udp():
    assert "по IP" in target_mode("2001:db8::1", "TCP")
    assert "по IP" in target_mode("140.82.113.26", "TCP")
    assert "доступность порта" in target_mode("example.com", "TCP")
    assert "Режим UDP" in target_mode("example.com", "UDP")
