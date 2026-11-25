import socket
import ctypes
from unittest.mock import patch
from types import SimpleNamespace
from ctypes import wintypes

import pytest

from netvision.core.system import _collect_default_routes
from netvision.core.windows_routes import _ForwardRow, _configure_api, convert_default_routes
from netvision.models import NetworkInterface


def _number(address):
    return int.from_bytes(socket.inet_aton(address), "little")


def test_native_route_conversion_selects_vpn_and_direct_gateway():
    lan = _ForwardRow(
        destination=0, mask=0, next_hop=_number("192.168.1.1"), index=1, kind=4, metric=30
    )
    vpn = _ForwardRow(destination=0, mask=0, next_hop=0, index=2, kind=3, metric=1)
    interfaces = (
        NetworkInterface("Ethernet", "Ethernet", True, 100, None, ("192.168.1.2",), ()),
        NetworkInterface("happ-xray", "VPN", True, 100, None, ("10.0.0.2",), ()),
    )
    routes = convert_default_routes(
        [lan, vpn],
        {1: [("192.168.1.2", "255.255.255.0")], 2: [("10.0.0.2", "255.255.255.0")]},
        interfaces,
    )
    assert (routes[0].interface, routes[0].gateway, routes[0].metric, routes[0].is_vpn) == (
        "happ-xray",
        "10.0.0.2",
        1,
        True,
    )
    assert (routes[1].gateway, routes[1].metric, routes[1].on_link) == ("192.168.1.1", 30, False)


def test_route_command_used_if_native_api_fails():
    result = SimpleNamespace(returncode=0, stdout="0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.2 30")
    with (
        patch(
            "netvision.core.system.collect_windows_default_routes", side_effect=OSError("failed")
        ),
        patch("netvision.core.system.subprocess.run", return_value=result) as run,
    ):
        routes = _collect_default_routes(())
    assert routes[0].gateway == "192.168.1.1"
    assert run.call_args.args[0] == ["route", "print", "-4"]


def test_api_signatures_are_declared():
    api = SimpleNamespace(GetIpForwardTable=SimpleNamespace(), GetIpAddrTable=SimpleNamespace())
    _configure_api(api)
    for function in (api.GetIpForwardTable, api.GetIpAddrTable):
        assert function.argtypes == (ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL)
        assert function.restype is wintypes.DWORD


def test_multiple_addresses_select_gateway_subnet():
    row = _ForwardRow(
        destination=0, mask=0, next_hop=_number("192.168.1.1"), index=3, kind=4, metric=5
    )
    addresses = {3: [("169.254.1.2", "255.255.0.0"), ("192.168.1.9", "255.255.255.0")]}
    assert convert_default_routes([row], addresses, ())[0].local_address == "192.168.1.9"
    with pytest.raises(OSError, match="no IPv4"):
        convert_default_routes([row], {}, ())
