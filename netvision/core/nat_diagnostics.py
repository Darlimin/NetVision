"""Small, dependency-free STUN probes for NAT diagnostics."""

from __future__ import annotations

import os
import socket
import struct


DEFAULT_STUN_SERVERS = (
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
)

_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_MAPPED_ADDRESS = 0x0001
_XOR_MAPPED_ADDRESS = 0x0020
_MAGIC_COOKIE = 0x2112A442


class NatEndpoint:
    """A public endpoint reported by one STUN server."""

    __slots__ = ("server", "mapped_ip", "mapped_port")

    def __init__(self, server: str, mapped_ip: str, mapped_port: int) -> None:
        self.server = server
        self.mapped_ip = mapped_ip
        self.mapped_port = mapped_port

    @property
    def display(self) -> str:
        return f"{self.server} -> {self.mapped_ip}:{self.mapped_port}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NatEndpoint):
            return NotImplemented
        return (
            self.server,
            self.mapped_ip,
            self.mapped_port,
        ) == (
            other.server,
            other.mapped_ip,
            other.mapped_port,
        )


class NatReport:
    """Evidence-based NAT classification; filtering is intentionally unknown."""

    __slots__ = (
        "status",
        "nat_type",
        "filtering",
        "mapped_endpoints",
        "local_ip",
        "cgnat_likely",
        "double_nat_likely",
        "udp_egress_differs",
    )

    def __init__(
        self,
        status: str,
        nat_type: str | None,
        *,
        mapped_endpoints: tuple[NatEndpoint, ...] = (),
        local_ip: str | None = None,
        cgnat_likely: bool = False,
        double_nat_likely: bool = False,
        udp_egress_differs: bool = False,
    ) -> None:
        self.status = status
        self.nat_type = nat_type
        self.filtering = "unknown"
        self.mapped_endpoints = mapped_endpoints
        self.local_ip = local_ip
        self.cgnat_likely = cgnat_likely
        self.double_nat_likely = double_nat_likely
        self.udp_egress_differs = udp_egress_differs


def probe_nat(
    servers: tuple[tuple[str, int], ...] = DEFAULT_STUN_SERVERS,
    timeout_s: float = 1.5,
    retries: int = 2,
    external_ip: str | None = None,
    hops: tuple[object, ...] = (),
    cgnat_hop_limit: int = 4,
) -> NatReport:
    """Probe STUN mappings without overstating what public STUN can prove."""
    cgnat_likely, double_nat_likely = _route_heuristics(hops, cgnat_hop_limit)
    resolved = _resolve_servers(servers)
    if not resolved:
        return NatReport(
            "no_servers",
            None,
            cgnat_likely=cgnat_likely,
            double_nat_likely=double_nat_likely,
        )

    local_ip = _route_local_ip(resolved[0][1])
    endpoints: list[NatEndpoint] = []
    attempts = max(1, retries)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_socket:
        probe_socket.bind(("", 0))
        probe_socket.settimeout(max(0.01, timeout_s))
        for server_name, address in resolved:
            endpoint = _probe_server(probe_socket, server_name, address, attempts)
            if endpoint is not None:
                endpoints.append(endpoint)

    mapped = tuple(endpoints)
    nat_type = _classify(mapped, local_ip)
    return NatReport(
        "ok" if mapped else "udp_blocked",
        nat_type,
        mapped_endpoints=mapped,
        local_ip=local_ip,
        cgnat_likely=cgnat_likely,
        double_nat_likely=double_nat_likely,
        udp_egress_differs=bool(
            external_ip
            and any(endpoint.mapped_ip != external_ip for endpoint in mapped)
        ),
    )


def _resolve_servers(
    servers: tuple[tuple[str, int], ...],
) -> list[tuple[str, tuple[str, int]]]:
    resolved: list[tuple[str, tuple[str, int]]] = []
    for host, port in servers:
        try:
            info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        except OSError:
            continue
        if not info:
            continue
        address = (str(info[0][4][0]), int(info[0][4][1]))
        resolved.append((f"{host}:{port}", address))
    return resolved


def _route_local_ip(address: tuple[str, int]) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
            route_socket.connect(address)
            return str(route_socket.getsockname()[0])
    except OSError:
        return None


def _probe_server(
    probe_socket: socket.socket,
    server_name: str,
    address: tuple[str, int],
    attempts: int,
) -> NatEndpoint | None:
    for _attempt in range(attempts):
        transaction_id = os.urandom(12)
        request = struct.pack("!HHI12s", _BINDING_REQUEST, 0, _MAGIC_COOKIE, transaction_id)
        try:
            probe_socket.sendto(request, address)
            while True:
                response, _peer = probe_socket.recvfrom(2048)
                endpoint = _parse_stun_response(response, transaction_id)
                if endpoint is not None:
                    return NatEndpoint(server_name, endpoint[0], endpoint[1])
        except (OSError, TimeoutError):
            continue
    return None


def _parse_stun_response(
    payload: bytes,
    transaction_id: bytes,
) -> tuple[str, int] | None:
    if len(payload) < 20:
        return None
    message_type, message_length, cookie = struct.unpack("!HHI", payload[:8])
    if (
        message_type != _BINDING_SUCCESS
        or cookie != _MAGIC_COOKIE
        or payload[8:20] != transaction_id
        or len(payload) < 20 + message_length
    ):
        return None
    offset = 20
    end = 20 + message_length
    mapped: tuple[str, int] | None = None
    while offset + 4 <= end:
        attribute_type, attribute_length = struct.unpack("!HH", payload[offset : offset + 4])
        value_start = offset + 4
        value_end = value_start + attribute_length
        if value_end > end:
            return None
        value = payload[value_start:value_end]
        if attribute_type == _XOR_MAPPED_ADDRESS:
            mapped = _parse_mapped_address(value, xor=True)
            if mapped is not None:
                return mapped
        elif attribute_type == _MAPPED_ADDRESS and mapped is None:
            mapped = _parse_mapped_address(value, xor=False)
        offset = value_start + ((attribute_length + 3) // 4) * 4
    return mapped


def _parse_mapped_address(value: bytes, *, xor: bool) -> tuple[str, int] | None:
    if len(value) < 8 or value[1] != 0x01:
        return None
    port = struct.unpack("!H", value[2:4])[0]
    packed_ip = struct.unpack("!I", value[4:8])[0]
    if xor:
        port ^= _MAGIC_COOKIE >> 16
        packed_ip ^= _MAGIC_COOKIE
    return socket.inet_ntoa(struct.pack("!I", packed_ip)), port


def _classify(endpoints: tuple[NatEndpoint, ...], local_ip: str | None) -> str | None:
    if not endpoints:
        return None
    if local_ip and all(endpoint.mapped_ip == local_ip for endpoint in endpoints):
        return "no_nat"
    if len(endpoints) == 1:
        return "undetermined"
    mappings = {(endpoint.mapped_ip, endpoint.mapped_port) for endpoint in endpoints}
    return "eim" if len(mappings) == 1 else "apdm"


def _route_heuristics(hops: tuple[object, ...], hop_limit: int) -> tuple[bool, bool]:
    first_hops = tuple(hops)[: max(0, hop_limit)]
    cgnat_likely = any(_in_network(_hop_address(hop), "100.64.0.0", 10) for hop in first_hops)
    double_nat_likely = any(
        2 <= int(getattr(hop, "index", 0)) <= hop_limit
        and _is_private_ipv4(_hop_address(hop))
        for hop in first_hops
    )
    return cgnat_likely, double_nat_likely


def _hop_address(hop: object) -> str | None:
    address = getattr(hop, "address", None)
    return address if isinstance(address, str) else None


def _is_private_ipv4(address: str | None) -> bool:
    return (
        _in_network(address, "10.0.0.0", 8)
        or _in_network(address, "172.16.0.0", 12)
        or _in_network(address, "192.168.0.0", 16)
    )


def _in_network(address: str | None, network: str, prefix: int) -> bool:
    if not address:
        return False
    try:
        address_value = struct.unpack("!I", socket.inet_aton(address))[0]
        network_value = struct.unpack("!I", socket.inet_aton(network))[0]
    except OSError:
        return False
    mask = ((1 << prefix) - 1) << (32 - prefix)
    return (address_value & mask) == (network_value & mask)
