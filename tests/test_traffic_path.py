from netvision.core.traffic_path import (
    _sanitize_url,
    _egress,
    format_traffic_path_summary,
    collect_traffic_path_snapshot,
    SystemProxyInfo,
    DnsPolicyInfo,
)
from unittest.mock import patch


def test_winhttp_only_egress_and_cancellation():
    from concurrent.futures import CancelledError
    from threading import Event
    import pytest

    event = Event()
    event.set()
    with patch("netvision.core.traffic_path._collect_interfaces") as collect:
        with pytest.raises(CancelledError):
            collect_traffic_path_snapshot(cancel_event=event)
        collect.assert_not_called()
    with (
        patch("netvision.core.traffic_path._collect_interfaces", return_value=()),
        patch("netvision.core.traffic_path._collect_default_routes", return_value=()),
        patch(
            "netvision.core.traffic_path._proxy_info",
            return_value=SystemProxyInfo(winhttp="http://proxy:8080"),
        ),
        patch("netvision.core.traffic_path._raw_proxy", return_value=""),
        patch("netvision.core.traffic_path._read_winhttp_proxy", return_value="proxy:8080"),
        patch("netvision.core.traffic_path._channels", return_value=()),
        patch("netvision.core.traffic_path._dns_policy", return_value=DnsPolicyInfo()),
        patch(
            "netvision.core.traffic_path._egress",
            side_effect=[("1.1.1.1", None, None, None, None), ("8.8.8.8", None, None, None, None)],
        ) as egress,
    ):
        snapshot = collect_traffic_path_snapshot()
    assert snapshot.egress.proxy_ip == "8.8.8.8"
    assert egress.call_args.args[0] == "proxy:8080"


def test_summary_localizes_errors_and_unknown_dns():
    from datetime import datetime, timezone
    from netvision.core.traffic_path import TrafficPathSnapshot, KernelRouteInfo, EgressPathInfo

    for error, expected in (
        ("Proxy authentication required (HTTP 407)", "Требуется авторизация"),
        ("PAC evaluation unavailable", "Вычисление PAC"),
        ("SOCKS proxy unsupported", "через SOCKS"),
    ):
        snapshot = TrafficPathSnapshot(
            datetime.now(timezone.utc),
            KernelRouteInfo(metric=7),
            SystemProxyInfo(enabled=True),
            DnsPolicyInfo(),
            EgressPathInfo(proxy_error=error),
        )
        ru = format_traffic_path_summary(snapshot, "ru")
        en = format_traffic_path_summary(snapshot, "en")
        assert expected in ru and error in en and "Метрика 7" in ru and "Metric 7" in en
        assert "DoH: недоступно" in ru and "NRPT: недоступно" in ru
        assert "DoH: unavailable" in en and "NRPT: unavailable" in en
    snapshot = TrafficPathSnapshot(
        datetime.now(timezone.utc),
        KernelRouteInfo(),
        SystemProxyInfo(),
        DnsPolicyInfo(doh_enabled=False, nrpt_rules=0),
        EgressPathInfo(),
    )
    assert "DoH: не обнаружен · NRPT: нет правил" in format_traffic_path_summary(snapshot)


def test_missing_and_inaccessible_registry_are_distinct():
    import pytest
    from netvision.core.traffic_path import _dns_policy

    pytest.importorskip("winreg")
    with patch(
        "netvision.core.traffic_path.collect_dns_configuration",
        return_value=type("Dns", (), {"servers": ()})(),
    ):
        with patch("winreg.OpenKey", side_effect=FileNotFoundError()):
            dns = _dns_policy()
            assert dns.doh_enabled is False and dns.nrpt_rules == 0
        with patch("winreg.OpenKey", side_effect=PermissionError()):
            dns = _dns_policy()
            assert dns.doh_enabled is None and dns.nrpt_rules is None


def test_proxy_credentials_removed():
    assert _sanitize_url("http://user:secret@example.com:8080") == "http://example.com:8080"


def test_egress_failure_is_reported():
    with patch("urllib.request.build_opener") as build:
        build.return_value.open.side_effect = OSError("offline")
        assert "OSError" in _egress(None, 1)[4]


def test_snapshot_without_external_request():
    with (
        patch("netvision.core.traffic_path._collect_interfaces", return_value=()),
        patch("netvision.core.traffic_path._collect_default_routes", return_value=()),
        patch("netvision.core.traffic_path._proxy_info", return_value=SystemProxyInfo()) as proxy,
        patch("netvision.core.traffic_path._dns_policy", return_value=DnsPolicyInfo()) as dns,
        patch("netvision.core.traffic_path._channels", return_value=()),
        patch("netvision.core.traffic_path._egress") as request,
    ):
        snapshot = collect_traffic_path_snapshot(False)
        request.assert_not_called()
        assert "Route:" in format_traffic_path_summary(snapshot, "en")
        assert proxy.called and dns.called


def test_proxy_multischeme_and_socks():
    from netvision.core.traffic_path import _proxy_entries

    chosen, visible = _proxy_entries(
        "http=127.0.0.1:8080;https=user:secret@127.0.0.1:8443;socks=127.0.0.1:1080"
    )
    assert chosen == "user:secret@127.0.0.1:8443"
    assert "secret" not in visible and "user" not in visible
    assert _proxy_entries("socks=127.0.0.1:1080")[0] == "socks5://127.0.0.1:1080"


def test_authentication_error_does_not_expose_credentials():
    from urllib.error import HTTPError

    with patch("urllib.request.build_opener") as build:
        build.return_value.open.side_effect = HTTPError(
            "http://user:secret@proxy", 407, "auth", {}, None
        )
        error = _egress("http://user:secret@proxy:80", 1)[4]
    assert "407" in error and "secret" not in error and "user" not in error
    with patch("urllib.request.build_opener") as build:
        build.return_value.open.side_effect = OSError("Tunnel failed: 407 user:secret")
        error = _egress("http://user:secret@proxy:80", 1)[4]
    assert "407" in error and "secret" not in error and "user" not in error


def test_route_index_matches_interface():
    from types import SimpleNamespace
    from netvision.core.traffic_path import _route_by_index
    from netvision.core.windows_routes import _ForwardRow, _AddressRow
    from netvision.models import NetworkInterface
    import socket

    row = _ForwardRow(
        index=7,
        next_hop=int.from_bytes(socket.inet_aton("192.168.1.1"), "little"),
        kind=4,
        metric=10,
    )
    address = _AddressRow(
        index=7, address=int.from_bytes(socket.inet_aton("192.168.1.9"), "little")
    )
    interface = NetworkInterface("LAN", "Ethernet", True, 100, None, ("192.168.1.9",), ())
    with (
        patch(
            "netvision.core.traffic_path.ctypes.WinDLL",
            return_value=SimpleNamespace(GetIpAddrTable=object()),
        ),
        patch("netvision.core.traffic_path._configure_api"),
        patch("netvision.core.traffic_path._read_table", return_value=[address]),
    ):
        result = _route_by_index(row, (interface,), ())
    assert result.interface == "LAN" and result.local_address == "192.168.1.9"


def test_pac_and_socks_egress_are_explicit():
    from netvision.core.traffic_path import SystemProxyInfo

    for proxy, raw, expected in (
        (SystemProxyInfo(pac_active=True), "", "PAC"),
        (
            SystemProxyInfo(enabled=True, server="socks=socks5://127.0.0.1:1080"),
            "socks=127.0.0.1:1080",
            "SOCKS",
        ),
    ):
        with (
            patch("netvision.core.traffic_path._collect_interfaces", return_value=()),
            patch("netvision.core.traffic_path._collect_default_routes", return_value=()),
            patch("netvision.core.traffic_path._proxy_info", return_value=proxy),
            patch("netvision.core.traffic_path._raw_proxy", return_value=raw),
            patch("netvision.core.traffic_path._dns_policy", return_value=DnsPolicyInfo()),
            patch("netvision.core.traffic_path._channels", return_value=()),
            patch(
                "netvision.core.traffic_path._egress",
                return_value=("1.1.1.1", None, None, None, None),
            ),
        ):
            assert expected in collect_traffic_path_snapshot().egress.proxy_error


def test_route_modes_and_egress_comparison():
    from types import SimpleNamespace
    from netvision.core.traffic_path import SocketChannelSummary

    physical = SimpleNamespace(kind="Ethernet", is_up=True)
    vpn = SimpleNamespace(kind="VPN", is_up=True)
    direct = SimpleNamespace(
        interface="LAN", local_address="10.0.0.2", gateway="10.0.0.1", metric=1, is_vpn=False
    )
    tunnel = SimpleNamespace(
        interface="VPN", local_address="10.1.0.2", gateway="10.1.0.1", metric=2, is_vpn=True
    )
    scenarios = [
        (direct, (physical,), (), SystemProxyInfo(), "direct"),
        (tunnel, (physical, vpn), ("vpn_tun",), SystemProxyInfo(), "vpn_tun"),
        (tunnel, (physical, vpn), ("physical",), SystemProxyInfo(), "split_tunnel"),
        (tunnel, (physical, vpn), ("physical", "vpn_tun"), SystemProxyInfo(), "split_tunnel"),
        (
            direct,
            (physical,),
            (),
            SystemProxyInfo(enabled=True, is_local_proxy=True),
            "split_tunnel",
        ),
        (None, (), (), SystemProxyInfo(), "unknown"),
    ]
    for selected, interfaces, active, proxy, expected in scenarios:
        channels = tuple(SocketChannelSummary(name, None, None, 1) for name in active)
        with (
            patch("netvision.core.traffic_path._collect_interfaces", return_value=interfaces),
            patch("netvision.core.traffic_path._collect_default_routes", return_value=()),
            patch("netvision.core.traffic_path._best_route", return_value=object()),
            patch("netvision.core.traffic_path._route_by_index", return_value=selected),
            patch("netvision.core.traffic_path._proxy_info", return_value=proxy),
            patch("netvision.core.traffic_path._dns_policy", return_value=DnsPolicyInfo()),
            patch("netvision.core.traffic_path._channels", return_value=channels),
        ):
            assert collect_traffic_path_snapshot(False).route.mode == expected

    with (
        patch("netvision.core.traffic_path._collect_interfaces", return_value=()),
        patch("netvision.core.traffic_path._collect_default_routes", return_value=()),
        patch(
            "netvision.core.traffic_path._proxy_info", return_value=SystemProxyInfo(enabled=True)
        ),
        patch("netvision.core.traffic_path._raw_proxy", return_value="http=proxy:8080"),
        patch("netvision.core.traffic_path._dns_policy", return_value=DnsPolicyInfo()),
        patch("netvision.core.traffic_path._channels", return_value=()),
        patch(
            "netvision.core.traffic_path._egress",
            side_effect=[("1.1.1.1", None, None, None, None), ("8.8.8.8", None, None, None, None)],
        ),
    ):
        assert collect_traffic_path_snapshot().egress.differs_from_direct is True


def test_best_route_declares_windows_abi():
    import ctypes
    from unittest.mock import MagicMock
    from netvision.core.traffic_path import _best_route
    from netvision.core.windows_routes import _ForwardRow

    function = MagicMock(return_value=0)
    with (
        patch("netvision.core.traffic_path.sys.platform", "win32"),
        patch("netvision.core.traffic_path.ctypes.WinDLL") as dll,
    ):
        dll.return_value.GetBestRoute = function
        _best_route()
    assert function.argtypes[2] == ctypes.POINTER(_ForwardRow)
    assert function.restype == ctypes.wintypes.DWORD


def test_channels_group_by_local_interface_and_proxy():
    from types import SimpleNamespace
    from netvision.core.traffic_path import _channels

    interfaces = [
        SimpleNamespace(name="LAN", kind="Ethernet", ipv4=("10.0.0.2",), ipv6=()),
        SimpleNamespace(name="VPN", kind="VPN", ipv4=("10.1.0.2",), ipv6=()),
    ]
    connections = [
        SimpleNamespace(local_address=local, remote_address=remote, remote_port=port)
        for local, remote, port in [
            ("10.0.0.2", "8.8.8.8", 443),
            ("10.1.0.2", "8.8.4.4", 443),
            ("127.0.0.1", "127.0.0.1", 8080),
            ("10.2.0.2", "1.1.1.1", 443),
        ]
    ]
    observed = [SimpleNamespace(pid=123, connection=connection) for connection in connections]
    with (
        patch("netvision.core.traffic_path.psutil.net_connections", return_value=[]),
        patch("netvision.core.traffic_path._collect_inet_connections", return_value=observed),
        patch("netvision.core.traffic_path._process_name", return_value="app"),
    ):
        channels = _channels(
            interfaces, SystemProxyInfo(enabled=True, is_local_proxy=True, port=8080)
        )
    assert {channel.channel for channel in channels} == {
        "physical",
        "vpn_tun",
        "local_proxy",
        "other",
    }


def test_local_noise_and_vpn_transport_are_excluded_from_bypass():
    from types import SimpleNamespace
    from netvision.core.traffic_path import _channels

    interface = SimpleNamespace(name="LAN", kind="Ethernet", ipv4=("10.0.0.2",), ipv6=())
    addresses = [("8.8.8.8", 443), ("192.168.1.1", 80), ("127.0.0.1", 5000), ("127.0.0.1", 8080)]
    observed = [
        SimpleNamespace(
            pid=1,
            connection=SimpleNamespace(
                local_address="10.0.0.2", remote_address=ip, remote_port=port
            ),
        )
        for ip, port in addresses
    ]
    with (
        patch("netvision.core.traffic_path.psutil.net_connections", return_value=[]),
        patch("netvision.core.traffic_path._collect_inet_connections", return_value=observed),
        patch("netvision.core.traffic_path._process_name", return_value="xray.exe"),
    ):
        channels = _channels(
            [interface], SystemProxyInfo(enabled=True, is_local_proxy=True, port=8080)
        )
    assert sum(c.count for c in channels) == 2
    assert next(c for c in channels if c.channel == "physical").application_count == 0
    assert any(c.channel == "local_proxy" for c in channels)


def test_summary_has_no_raw_keys_or_empty_proxy_block():
    from datetime import datetime, timezone
    from netvision.core.traffic_path import TrafficPathSnapshot, KernelRouteInfo, EgressPathInfo

    snapshot = TrafficPathSnapshot(
        datetime.now(timezone.utc),
        KernelRouteInfo(mode="vpn_tun"),
        SystemProxyInfo(),
        DnsPolicyInfo(),
        EgressPathInfo(direct_ip="1.1.1.1"),
    )
    for lang in ("ru", "en"):
        text = format_traffic_path_summary(snapshot, lang)
        assert "None" not in text and "vpn_tun" not in text and "differs:" not in text
        assert "1.1.1.1 /" not in text
        assert "не настроен" in text.lower() if lang == "ru" else "not configured" in text.lower()


def test_winhttp_abi_and_registry_fallback():
    import ctypes
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from netvision.core.traffic_path import _dns_policy, _winhttp_proxy

    get_config = MagicMock(return_value=0)
    free = MagicMock()
    libraries = {
        "winhttp": SimpleNamespace(WinHttpGetDefaultProxyConfiguration=get_config),
        "kernel32": SimpleNamespace(GlobalFree=free),
    }
    with (
        patch("netvision.core.traffic_path.sys.platform", "win32"),
        patch(
            "netvision.core.traffic_path.ctypes.WinDLL",
            side_effect=lambda name, **kwargs: libraries[name],
        ),
    ):
        assert _winhttp_proxy() is None
    assert len(get_config.argtypes) == 1
    assert get_config.restype == ctypes.wintypes.BOOL
    assert free.argtypes == (ctypes.c_void_p,)
    assert free.restype == ctypes.c_void_p
    proxy_buffer = ctypes.create_unicode_buffer("http://user:secret@proxy:8080")

    def populate(pointer):
        pointer._obj.proxy = ctypes.addressof(proxy_buffer)
        return 1

    get_config.side_effect = populate
    with (
        patch("netvision.core.traffic_path.sys.platform", "win32"),
        patch(
            "netvision.core.traffic_path.ctypes.WinDLL",
            side_effect=lambda name, **kwargs: libraries[name],
        ),
    ):
        assert _winhttp_proxy() == "http://proxy:8080"
    free.assert_called_once_with(ctypes.addressof(proxy_buffer))
    with (
        patch(
            "netvision.core.traffic_path.collect_dns_configuration",
            side_effect=OSError("unavailable"),
        ),
        patch("netvision.core.traffic_path._registry_policy", return_value=None),
        patch("winreg.OpenKey", side_effect=PermissionError("denied")),
    ):
        dns = _dns_policy()
    assert dns.servers == () and dns.doh_enabled is None and dns.nrpt_rules is None


def test_proxy_port_owner_and_pac_are_sanitized():
    from types import SimpleNamespace
    from netvision.core.traffic_path import _proxy_info

    values = {
        "ProxyEnable": 1,
        "ProxyServer": "socks=user:secret@127.0.0.1:1080",
        "AutoConfigURL": "https://user:secret@example.org/config.pac",
    }
    listener = SimpleNamespace(status="LISTEN", laddr=SimpleNamespace(port=1080), pid=123)
    with (
        patch(
            "netvision.core.traffic_path._registry_value",
            side_effect=lambda root, path, name: values.get(name),
        ),
        patch("netvision.core.traffic_path._winhttp_proxy", return_value=None),
        patch("netvision.core.traffic_path.psutil.net_connections", return_value=[listener]),
        patch("netvision.core.traffic_path.psutil.Process") as process,
    ):
        process.return_value.name.return_value = "proxy.exe"
        proxy = _proxy_info()
    assert proxy.is_local_proxy and proxy.port == 1080
    assert proxy.owner_pid == 123 and proxy.owner_name == "proxy.exe"
    assert proxy.pac_active and "secret" not in repr(proxy) and "user" not in repr(proxy)


def test_dns_doh_nrpt_and_bilingual_summary():
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    import pytest
    from netvision.core.traffic_path import _dns_policy

    winreg = pytest.importorskip("winreg")
    with (
        patch(
            "netvision.core.traffic_path.collect_dns_configuration",
            return_value=SimpleNamespace(servers=("1.1.1.1",)),
        ),
        patch("netvision.core.traffic_path._registry_policy", return_value=2),
        patch.object(winreg, "OpenKey", return_value=MagicMock()),
        patch.object(winreg, "QueryInfoKey", return_value=(3, 0, 0)),
    ):
        dns = _dns_policy()
    assert dns.servers == ("1.1.1.1",) and dns.doh_enabled and dns.nrpt_rules == 3
    with (
        patch("netvision.core.traffic_path._collect_interfaces", return_value=()),
        patch("netvision.core.traffic_path._collect_default_routes", return_value=()),
        patch(
            "netvision.core.traffic_path._proxy_info",
            return_value=SystemProxyInfo(enabled=True, server="http://user:secret@proxy:80"),
        ),
        patch("netvision.core.traffic_path._raw_proxy", return_value="proxy:80"),
        patch("netvision.core.traffic_path._dns_policy", return_value=dns),
        patch("netvision.core.traffic_path._channels", return_value=()),
        patch(
            "netvision.core.traffic_path._egress", return_value=("1.1.1.1", None, None, None, None)
        ),
    ):
        snapshot = collect_traffic_path_snapshot()
    assert snapshot.egress.differs_from_direct is False
    for lang, label in (("ru", "Маршрут"), ("en", "Route")):
        summary = format_traffic_path_summary(snapshot, lang)
        assert label in summary and "NRPT: 3" in summary
        assert "user" not in summary and "secret" not in summary
