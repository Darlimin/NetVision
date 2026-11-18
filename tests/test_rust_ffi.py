"""Exercise the optional native extension after it has been compiled."""

import importlib.util

import pytest

spec = importlib.util.find_spec("netvision_rs")
if spec is None or spec.origin is None:
    pytest.skip("netvision_rs extension has not been compiled", allow_module_level=True)

import netvision_rs  # noqa: E402


def test_network_score() -> None:
    assert netvision_rs.calculate_network_score(50.0, 10.0, 2.0) == pytest.approx(89.0)
    assert netvision_rs.calculate_network_score(0.0, 0.0, 0.0) == 100.0
    assert netvision_rs.calculate_network_score(2000.0, 0.0, 0.0) == 0.0


def test_parse_ping_output() -> None:
    if not hasattr(netvision_rs, "parse_ping_output"):
        pytest.skip("rebuild netvision_rs to enable the ping parser")
    raw = "Reply time=12ms\nОтвет время<1мс\nОтвет время=12,5мс TTL=128"
    assert netvision_rs.parse_ping_output(raw) == pytest.approx([12.0, 0.5, 12.5])


@pytest.mark.parametrize(
    "raw",
    [
        " 1 <1 ms 1 ms 2 ms 192.168.1.1\n 2 * * * Request timed out.",
        "  7 1,5 мс 2 мс 2001:db8::1\n  8  *  4 ms example.org",
        "Header\n 3 5 ms [192.0.2.1]\n 9 * * * 203.0.113.1",
        " 1 1.0 ms 1.1 ms 2001:0DB8::1\r\n 2 4 ms invalid.ip",
    ],
)
def test_tracert_rust_matches_python_fallback(raw: str) -> None:
    if not hasattr(netvision_rs, "parse_tracert_rows"):
        pytest.skip("rebuild netvision_rs to enable the tracert parser")
    from netvision.core.probes import _parse_tracert_output_python, parse_tracert_output

    assert parse_tracert_output(raw) == _parse_tracert_output_python(raw)


@pytest.mark.parametrize("values", [(-1.0, 0.0, 0.0), (0.0, float("nan"), 0.0), (0.0, 0.0, 101.0)])
def test_network_score_rejects_invalid_measurements(values: tuple[float, float, float]) -> None:
    with pytest.raises(ValueError):
        netvision_rs.calculate_network_score(*values)
