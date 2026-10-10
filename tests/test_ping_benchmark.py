import subprocess
from unittest.mock import patch

from netvision.core.ping_benchmark import (
    RegionalPingTarget,
    benchmark_regional_targets,
    latency_statistics,
    run_mtu_stress_test,
)
from netvision.models import PingResult, ProbeStatus


def _ping(host: str, latency_ms: float | None) -> PingResult:
    return PingResult(
        host=host,
        sent=3,
        received=3 if latency_ms is not None else 0,
        loss_percent=0.0 if latency_ms is not None else 100.0,
        minimum_ms=latency_ms,
        average_ms=latency_ms,
        maximum_ms=latency_ms,
        jitter_ms=0.0 if latency_ms is not None else None,
        samples_ms=(latency_ms,) if latency_ms is not None else (),
        status=ProbeStatus.SUCCESS if latency_ms is not None else ProbeStatus.ERROR,
    )


def test_regional_benchmark_keeps_configured_order_and_isolates_failure() -> None:
    targets = (
        RegionalPingTarget("First", "first.example", "first"),
        RegionalPingTarget("Second", "second.example", "second"),
    )

    def probe(host: str, _count: int, _wait_ms: int) -> PingResult:
        if host == "second.example":
            raise OSError("unreachable")
        return _ping(host, 14.2)

    with patch("netvision.core.ping_benchmark.probe_ping", side_effect=probe):
        results = benchmark_regional_targets(targets)

    assert [result.target.host for result in results] == ["first.example", "second.example"]
    assert results[0].success
    assert not results[1].success
    assert results[1].ping.error == "unreachable"


def test_latency_statistics_calculates_rtt_jitter_loss_and_stability() -> None:
    statistics = latency_statistics((10.0, 20.0, 30.0), sent=4)

    assert statistics.minimum_ms == 10.0
    assert statistics.maximum_ms == 30.0
    assert statistics.average_ms == 20.0
    assert statistics.jitter_ms == 10.0
    assert statistics.loss_percent == 25.0
    assert statistics.stability == "Есть потери"


def test_mtu_probe_uses_oem_output_and_parses_russian_ping() -> None:
    completed = subprocess.CompletedProcess(
        args=["ping"],
        returncode=0,
        stdout="Ответ от 1.1.1.1: число байт=32 время=12мс TTL=128",
        stderr="",
    )
    with (
        patch("netvision.core.ping_benchmark.subprocess.run", return_value=completed) as run_mock,
        patch("netvision.core.ping_benchmark._oem_encoding", return_value="cp866"),
    ):
        results = run_mtu_stress_test("1.1.1.1", payload_sizes=(32,), count=1)

    assert results[0].success
    assert results[0].average_ms == 12.0
    assert run_mock.call_args.kwargs["encoding"] == "cp866"
