"""Read IPv4 default routes from the Windows IP Helper API."""

import ctypes
import ipaddress
import socket
import sys
from ctypes import wintypes

from netvision.models import DefaultRoute, NetworkInterface


class _ForwardRow(ctypes.Structure):
    _fields_ = [
        (name, wintypes.DWORD)
        for name in (
            "destination",
            "mask",
            "policy",
            "next_hop",
            "index",
            "kind",
            "protocol",
            "age",
            "next_hop_as",
            "metric",
            "metric2",
            "metric3",
            "metric4",
            "metric5",
        )
    ]


class _AddressRow(ctypes.Structure):
    _fields_ = [
        (name, wintypes.DWORD) for name in ("address", "index", "mask", "broadcast", "reassembly")
    ] + [("unused", ctypes.c_ushort), ("kind", ctypes.c_ushort)]


def _read_table(function, row_type):
    size = wintypes.ULONG(0)
    status = function(None, ctypes.byref(size), False)
    if status not in (0, 122) or size.value < ctypes.sizeof(wintypes.DWORD):
        raise OSError(status, "IP Helper table sizing failed")
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        status = function(buffer, ctypes.byref(size), False)
        if status != 122:
            break
    if status:
        raise OSError(status, "IP Helper table read failed")
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    offset = ctypes.sizeof(wintypes.DWORD)
    if offset + count * ctypes.sizeof(row_type) > len(buffer):
        raise OSError("Invalid IP Helper table length")
    return list((row_type * count).from_buffer_copy(buffer, offset))


def _ipv4(value: int) -> str:
    return socket.inet_ntoa(value.to_bytes(4, byteorder="little"))


def _configure_api(api) -> None:
    for function in (api.GetIpForwardTable, api.GetIpAddrTable):
        function.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL)
        function.restype = wintypes.DWORD


def _select_address(candidates, gateway: str) -> str:
    gateway_ip = ipaddress.IPv4Address(gateway)

    def rank(candidate):
        address, mask = candidate
        ip = ipaddress.IPv4Address(address)
        network = ipaddress.IPv4Network((address, mask), strict=False)
        matches = not gateway_ip.is_unspecified and gateway_ip in network
        return (not matches, ip.is_link_local, ip.is_loopback, -network.prefixlen)

    try:
        ranked = [(rank(candidate), candidate[0]) for candidate in candidates]
        best = min(item[0] for item in ranked)
        addresses = {address for priority, address in ranked if priority == best}
        if len(addresses) != 1:
            raise OSError("Ambiguous IPv4 source address")
        return addresses.pop()
    except (ValueError, TypeError) as exc:
        raise OSError("Invalid interface address or mask") from exc


def convert_default_routes(rows, addresses, interfaces: tuple[NetworkInterface, ...]):
    result = []
    for row in rows:
        if row.destination or row.mask or row.kind == 2:
            continue
        candidates = addresses.get(row.index)
        if not candidates:
            raise OSError("Default route has no IPv4 interface address")
        gateway = _ipv4(row.next_hop)
        local = _select_address(candidates, gateway)
        interface = next((item for item in interfaces if local in item.ipv4), None)
        on_link = row.kind == 3 or gateway == "0.0.0.0"
        if on_link:
            gateway = local
        result.append(
            DefaultRoute(
                gateway=gateway,
                interface=interface.name if interface else None,
                local_address=local,
                metric=row.metric,
                is_vpn=bool(interface and interface.kind == "VPN"),
                on_link=on_link,
            )
        )
    return tuple(sorted(result, key=lambda route: (route.metric, not route.is_vpn)))


def collect_windows_default_routes(
    interfaces: tuple[NetworkInterface, ...],
) -> tuple[DefaultRoute, ...]:
    if sys.platform != "win32":
        raise OSError("Windows IP Helper API unavailable")
    api = ctypes.WinDLL("iphlpapi")
    _configure_api(api)
    rows = _read_table(api.GetIpForwardTable, _ForwardRow)
    address_rows = _read_table(api.GetIpAddrTable, _AddressRow)
    addresses = {}
    route_indexes = {
        row.index for row in rows if not row.destination and not row.mask and row.kind != 2
    }
    for row in address_rows:
        if row.index not in route_indexes:
            continue
        addresses.setdefault(row.index, []).append((_ipv4(row.address), _ipv4(row.mask)))
    return convert_default_routes(rows, addresses, interfaces)
