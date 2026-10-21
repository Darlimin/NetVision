from unittest.mock import patch

from netvision.core.packet_loss import (
    LossSample,
    PacketLossAnalyzer,
    run_hop_loss_breakdown,
    run_udp_stress_test,
    summarize_loss,
)
from netvision.models import HopResult, PingResult, ProbeStatus


def _ping(host: str, loss_percent: float, average_ms: float | None) -> PingResult:
    received = 3 - round(loss_percent * 3 / 100)
    return PingResult(
        host,
        3,
        received,
        loss_percent,
        average_ms,
        average_ms,
        average_ms,
        0.0,
        (average_ms,) if average_ms is not None else (),
        ProbeStatus.SUCCESS if loss_percent == 0 else ProbeStatus.WARNING,
    )


def test_summarize_loss_detects_bursts_and_jitter_drops() -> None:
    samples = (
        LossSample(True, 10.0),
        LossSample(False),
        LossSample(False),
        LossSample(True, 50.0),
    )

    snapshot = summarize_loss(samples)

    assert snapshot.sent == 4
    assert snapshot.received == 2
    assert snapshot.loss_percent == 50.0
    assert snapshot.burst_count == 1
    assert snapshot.longest_burst == 2
    assert snapshot.jitter_drops == 1
    assert snapshot.status == "Критическая потеря"


def test_packet_loss_analyzer_emits_event_and_keeps_bounded_window() -> None:
    analyzer = PacketLossAnalyzer(max_samples=3)

    analyzer.observe(True, 10.0)
    analyzer.observe(False)
    _, event = analyzer.observe(False)
    analyzer.observe(True, 12.0)

    assert event is not None
    assert event.kind == "burst"
    assert len(analyzer.samples) == 3
    assert [item.kind for item in analyzer.events] == ["drop", "burst"]


def test_packet_loss_analyzer_closes_burst_after_three_successes() -> None:
    analyzer = PacketLossAnalyzer()

    analyzer.observe(False)
    analyzer.observe(False)
    analyzer.observe(True, 10.0)
    analyzer.observe(True, 10.0)
    _, event = analyzer.observe(True, 10.0)

    assert event is not None
    assert event.kind == "burst_end"
    assert event.lost == 2
    assert [item.kind for item in analyzer.events] == ["drop", "burst", "burst_end"]


def test_hop_breakdown_preserves_order_and_marks_first_loss() -> None:
    hops = (HopResult(1, "192.0.2.1", 5.0), HopResult(2, "198.51.100.1", 20.0))

    with patch(
        "netvision.core.packet_loss.probe_ping",
        side_effect=lambda host, _count, _wait: _ping(host, 0.0 if host.endswith("2.1") else 33.3, 8.0),
    ):
        results = run_hop_loss_breakdown(hops)

    assert [result.hop for result in results] == [1, 2]
    assert results[0].loss_percent == 0.0
    assert results[1].loss_percent == 33.3


def test_udp_stress_reports_local_send_count_without_claiming_delivery() -> None:
    with patch("netvision.core.packet_loss.socket.socket") as socket_factory:
        socket_instance = socket_factory.return_value.__enter__.return_value
        result = run_udp_stress_test("127.0.0.1", 443, count=4)

    assert result.sent == 4
    assert result.received == 4
    assert result.loss_percent is None
    assert result.protocol == "UDP"
    assert "ACK" in (result.note or "")
