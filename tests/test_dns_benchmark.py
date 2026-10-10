from unittest.mock import patch

import pytest

from netvision.core.dns_benchmark import (
    DnsResolverProfile,
    benchmark_resolvers,
    custom_dns_profile,
)


def test_benchmark_selects_fastest_endpoint_for_each_profile() -> None:
    cloudflare = DnsResolverProfile("Cloudflare", ("1.1.1.1", "1.0.0.1"))
    google = DnsResolverProfile("Google", ("8.8.8.8",))
    measurements = {
        "1.1.1.1": (18.5, None),
        "1.0.0.1": (9.1, None),
        "8.8.8.8": (None, "Connection timed out"),
    }

    with patch(
        "netvision.core.dns_benchmark._probe_dns_port",
        side_effect=lambda address, _timeout: measurements[address],
    ):
        results = benchmark_resolvers((cloudflare, google))

    assert results[0].address == "1.0.0.1"
    assert results[0].latency_ms == 9.1
    assert results[0].success
    assert results[1].address is None
    assert not results[1].success
    assert "timed out" in (results[1].error or "")


def test_custom_dns_profile_validates_addresses() -> None:
    profile = custom_dns_profile(" 10.0.0.53 ")

    assert profile.addresses == ("10.0.0.53",)
    assert profile.is_custom
    with pytest.raises(ValueError):
        custom_dns_profile("not-an-ip")
