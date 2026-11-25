from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch
import socket

import pytest

from netvision.core.diagnostics import _run_tls_probe
from netvision.core.internet_quality import PublicIpAddresses
from netvision.core.judgement import header_anomaly
from netvision.core.system import DnsConfiguration
from netvision.core.target import parse_target
from netvision.core.thresholds import DEFAULT_THRESHOLDS
from netvision.models import (
    DiagnosticReport,
    DnsResult,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    TcpResult,
    TlsResult,
)
from netvision.ui.controllers.dns_audit import DnsController
from netvision.ui.lite_mode import LiteStatus, summarize_report
from netvision.core.system import active_network_identity_fast
from netvision.models import DefaultRoute


@pytest.mark.parametrize("host", ["140.82.113.26", "2001:db8::1", "example.com"])
def test_tls_certificate_failure_classification(host):
    target = parse_target(f"[{host}]" if ":" in host else host, 443)
    tcp = TcpResult(target.host, 443, host, 2.0, ProbeStatus.SUCCESS)
    tls = TlsResult(
        None,
        None,
        None,
        None,
        None,
        None,
        3.0,
        ProbeStatus.ERROR,
        "CERTIFICATE_VERIFY_FAILED: IP address mismatch",
    )
    errors = []
    progress = Mock()
    with patch("netvision.core.diagnostics.probe_tls", return_value=tls):
        assert _run_tls_probe(target, tcp, progress, errors) is tls
    report = DiagnosticReport(
        target,
        SystemSnapshot("pc", (), None, (), None, ()),
        DnsResult(host, (host,), 1.0, ProbeStatus.SUCCESS),
        tcp,
        PingResult(host, 1, 1, 0.0, 3.0, 3.0, 3.0, 0.0, (3.0,), ProbeStatus.SUCCESS),
        tls,
        (),
        (),
        datetime.now(),
        5.0,
        tuple(errors),
    )
    expected = host != "example.com"
    assert (not errors) is expected
    assert (summarize_report(report).status == LiteStatus.SUCCESS) is expected
    assert (header_anomaly(report, DEFAULT_THRESHOLDS)[0] == "good") is expected
    if expected:
        assert "доменное имя" in progress.call_args.args[1]


def test_dns_network_change_invalidates_cache_and_deduplicates():
    host = SimpleNamespace(
        _dns_public_addresses=PublicIpAddresses(ipv4="203.0.113.10"), _dns_config_thread=None
    )
    controller = SimpleNamespace(
        host=host,
        _network_identity=("LAN", "192.168.1.2"),
        _measured_identity=("LAN", "192.168.1.2"),
        _reload_pending=False,
        _shutting_down=False,
        _render_dns_info=Mock(),
        _load_dns_configuration=Mock(),
    )
    DnsController._network_identity_changed(controller, ("VPN", "10.0.0.2"))
    assert host._dns_public_addresses.ipv4 is None
    controller._load_dns_configuration.assert_called_once()
    host._dns_config_thread = object()
    DnsController._network_identity_changed(controller, ("LAN", "192.168.1.3"))
    assert controller._reload_pending
    controller._load_dns_configuration.assert_called_once()


def test_dns_result_from_changed_route_is_discarded():
    host = SimpleNamespace(_dns_public_addresses=PublicIpAddresses())
    controller = SimpleNamespace(
        host=host,
        _network_identity=("VPN", "10.0.0.2"),
        _request_identity=("LAN", "192.168.1.2"),
        _reload_pending=False,
        _shutting_down=False,
    )
    DnsController._on_dns_configuration_completed(
        controller,
        DnsConfiguration(("LAN",), ("1.1.1.1",)),
        PublicIpAddresses(ipv4="203.0.113.10"),
        ("LAN", "192.168.1.2"),
        ("LAN", "192.168.1.2"),
    )
    assert host._dns_public_addresses.ipv4 is None
    assert controller._reload_pending


def test_fast_identity_tracks_vpn_and_avoids_full_snapshot():
    routes = (
        DefaultRoute("192.168.1.1", None, "192.168.1.2", 10, False),
        DefaultRoute("10.0.0.1", None, "10.0.0.2", 10, False),
    )
    entries = {
        "Ethernet": [SimpleNamespace(family=socket.AF_INET, address="192.168.1.2")],
        "happ-xray": [SimpleNamespace(family=socket.AF_INET, address="10.0.0.2")],
    }
    with (
        patch("netvision.core.system._collect_default_routes", return_value=routes),
        patch("netvision.core.system.psutil.net_if_addrs", return_value=entries),
        patch("netvision.core.system.active_network_identity") as full,
    ):
        assert active_network_identity_fast() == ("happ-xray", "10.0.0.2")
        full.assert_not_called()


def test_identity_poll_does_not_overlap_existing_workers():
    host = SimpleNamespace(_dashboard_closing=False, _dns_config_thread=object())
    controller = SimpleNamespace(
        _shutting_down=False, _identity_thread=None, host=host, registry=Mock()
    )
    DnsController._check_network_identity(controller)
    controller.registry.start.assert_not_called()
    host._dns_config_thread = None
    controller._identity_thread = object()
    DnsController._check_network_identity(controller)
    controller.registry.start.assert_not_called()


def test_unchanged_identity_preserves_public_ip_without_redraw():
    host = SimpleNamespace(_dns_public_addresses=PublicIpAddresses(ipv4="203.0.113.10"))
    controller = SimpleNamespace(
        host=host,
        _network_identity=("happ-xray", "10.0.0.2"),
        _shutting_down=False,
        _render_dns_info=Mock(),
        _load_dns_configuration=Mock(),
    )
    DnsController._network_identity_changed(controller, ("happ-xray", "10.0.0.2"))
    controller._render_dns_info.assert_not_called()
    controller._load_dns_configuration.assert_not_called()
    assert host._dns_public_addresses.ipv4 == "203.0.113.10"
