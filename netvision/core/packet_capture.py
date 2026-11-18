"""Native, header-only UDP endpoint capture for selected processes.

The Windows backend uses the built-in WinSock raw receive path. It is opt-in,
requires administrator rights on Windows, and keeps only normalized UDP
headers. The public functions are platform-neutral so tests never need a live
network or elevated privileges.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from enum import Enum
import ipaddress
import socket
import struct
import sys
import threading
import time
from typing import Protocol

from netvision.core.process_inspector import ProcessConnection


class CaptureState(str, Enum):
    NOT_STARTED = "not_started"
    ENDPOINT_FOUND = "endpoint_found"
    PERMISSION_DENIED = "permission_denied"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    TIMED_OUT = "timed_out"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CapturedUdpPacket:
    """A UDP header normalized to the process-local direction."""

    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    byte_count: int = 0


@dataclass(frozen=True, slots=True)
class EndpointCandidate:
    connection: ProcessConnection
    packet_count: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class BackendCapture:
    packets: tuple[CapturedUdpPacket, ...] = ()
    state: CaptureState = CaptureState.TIMED_OUT
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class PacketCaptureResult:
    pid: int
    state: CaptureState
    connection: ProcessConnection | None = None
    candidates: tuple[EndpointCandidate, ...] = ()
    packets_seen: int = 0
    bytes_seen: int = 0
    reason: str | None = None


class PacketCaptureBackend(Protocol):
    """Blocking backend contract, intended to be called from a worker thread."""

    def capture(
        self,
        pid: int,
        local_ports: Collection[int],
        stop_event: threading.Event,
        timeout_s: float,
    ) -> BackendCapture: ...


_SERVICE_PORTS = frozenset({53, 1900, 5353})
_MIN_CONFIRMATION_PACKETS = 8
_RAW_SOCKET_POLL_S = 0.2
_SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
_RCVALL_ON = getattr(socket, "RCVALL_ON", 1)
_RCVALL_OFF = getattr(socket, "RCVALL_OFF", 0)


def capture_udp_endpoint(
    backend: PacketCaptureBackend,
    pid: int,
    local_ports: Collection[int],
    stop_event: threading.Event | None = None,
    timeout_s: float = 10.0,
) -> PacketCaptureResult:
    """Run one backend capture and convert its best endpoint to ProcessConnection."""
    event = stop_event or threading.Event()
    if event.is_set():
        return PacketCaptureResult(pid, CaptureState.STOPPED, reason="stop_requested")
    normalized_ports = _normalize_ports(local_ports)
    if not normalized_ports:
        return PacketCaptureResult(
            pid,
            CaptureState.BACKEND_UNAVAILABLE,
            reason="no_local_udp_ports",
        )
    try:
        capture = backend.capture(pid, normalized_ports, event, timeout_s)
    except PermissionError as exc:
        return PacketCaptureResult(pid, CaptureState.PERMISSION_DENIED, reason=str(exc))
    except NotImplementedError as exc:
        return PacketCaptureResult(pid, CaptureState.BACKEND_UNAVAILABLE, reason=str(exc))
    except OSError as exc:
        state = CaptureState.PERMISSION_DENIED if _is_permission_error(exc) else CaptureState.FAILED
        return PacketCaptureResult(pid, state, reason=str(exc))
    return _result_from_capture(pid, capture, normalized_ports, event)


def filter_udp_packets(
    packets: Iterable[CapturedUdpPacket], local_ports: Collection[int]
) -> tuple[CapturedUdpPacket, ...]:
    """Keep only public, non-service UDP peers for the selected local ports."""
    ports = _normalize_ports(local_ports)
    return tuple(packet for packet in packets if _is_relevant_packet(packet, ports))


def rank_udp_candidates(
    packets: Iterable[CapturedUdpPacket],
    local_ports: Collection[int],
    min_packets: int = _MIN_CONFIRMATION_PACKETS,
) -> tuple[EndpointCandidate, ...]:
    """Rank public peers by packet count, bytes, and stable endpoint text."""
    if min_packets < 1:
        return ()
    counters: dict[tuple[str, int, str, int], list[int]] = {}
    for packet in filter_udp_packets(packets, local_ports):
        key = (
            packet.local_address,
            packet.local_port,
            packet.remote_address,
            packet.remote_port,
        )
        stats = counters.setdefault(key, [0, 0])
        stats[0] += 1
        stats[1] += max(0, packet.byte_count)
    candidates = [
        _candidate_from_stats(key, stats)
        for key, stats in counters.items()
        if stats[0] >= min_packets
    ]
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                -item.packet_count,
                -item.byte_count,
                item.connection.remote_address,
                item.connection.remote_port,
            ),
        )
    )


class WindowsRawUdpBackend:
    """Capture IPv4 UDP headers through native Windows raw sockets.

    Windows supplies no PID in the raw packet. The caller scopes capture to
    local UDP ports obtained from psutil, so packets are correlated by the
    selected process' socket set rather than by untrusted payload data.
    """

    def capture(
        self,
        pid: int,
        local_ports: Collection[int],
        stop_event: threading.Event,
        timeout_s: float,
    ) -> BackendCapture:
        if sys.platform != "win32":
            return BackendCapture(state=CaptureState.BACKEND_UNAVAILABLE, reason="windows_only")
        if not local_ports:
            return BackendCapture(
                state=CaptureState.BACKEND_UNAVAILABLE, reason="no_local_udp_ports"
            )
        if stop_event.is_set():
            return BackendCapture(state=CaptureState.STOPPED, reason="stop_requested")
        return self._capture_windows(local_ports, stop_event, timeout_s)

    def _capture_windows(
        self,
        local_ports: Collection[int],
        stop_event: threading.Event,
        timeout_s: float,
    ) -> BackendCapture:
        raw_socket = None
        receiver_enabled = False
        try:
            local_address = _local_ipv4_address()
            if local_address is None:
                return BackendCapture(
                    state=CaptureState.BACKEND_UNAVAILABLE,
                    reason="local_ipv4_unavailable",
                )
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            raw_socket.bind((local_address, 0))
            raw_socket.ioctl(_SIO_RCVALL, _RCVALL_ON)
            receiver_enabled = True
            packets, state = self._receive(raw_socket, local_ports, stop_event, timeout_s)
            return BackendCapture(tuple(packets), state)
        except PermissionError:
            raise
        except OSError as exc:
            if _is_permission_error(exc):
                raise PermissionError(
                    "Для перехвата UDP-заголовков нужны права администратора"
                ) from exc
            return BackendCapture(
                state=CaptureState.BACKEND_UNAVAILABLE,
                reason=_winsock_error_reason(exc),
            )
        finally:
            if raw_socket is not None:
                if receiver_enabled:
                    try:
                        raw_socket.ioctl(_SIO_RCVALL, _RCVALL_OFF)
                    except OSError:
                        pass
                raw_socket.close()

    def _receive(
        self,
        raw_socket: socket.socket,
        local_ports: Collection[int],
        stop_event: threading.Event,
        timeout_s: float,
    ) -> tuple[list[CapturedUdpPacket], CaptureState]:
        packets: list[CapturedUdpPacket] = []
        ports = _normalize_ports(local_ports)
        deadline = time.monotonic() + max(0.0, timeout_s)
        while not stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return packets, CaptureState.TIMED_OUT
            raw_socket.settimeout(min(_RAW_SOCKET_POLL_S, remaining))
            try:
                payload = raw_socket.recv(65535)
            except TimeoutError:
                continue
            packet = _decode_ipv4_udp(payload, ports)
            if packet is not None:
                packets.append(packet)
        return packets, CaptureState.STOPPED


def _result_from_capture(
    pid: int,
    capture: BackendCapture,
    local_ports: Collection[int],
    stop_event: threading.Event,
) -> PacketCaptureResult:
    candidates = rank_udp_candidates(capture.packets, local_ports)
    packets_seen = len(capture.packets)
    bytes_seen = sum(max(0, packet.byte_count) for packet in capture.packets)
    if stop_event.is_set() or capture.state == CaptureState.STOPPED:
        state = CaptureState.STOPPED
    elif candidates:
        state = CaptureState.ENDPOINT_FOUND
    else:
        state = capture.state
    return PacketCaptureResult(
        pid=pid,
        state=state,
        connection=candidates[0].connection if candidates else None,
        candidates=candidates,
        packets_seen=packets_seen,
        bytes_seen=bytes_seen,
        reason=capture.reason,
    )


def _candidate_from_stats(key: tuple[str, int, str, int], stats: list[int]) -> EndpointCandidate:
    local_address, local_port, remote_address, remote_port = key
    connection = ProcessConnection(
        protocol="UDP",
        status="NONE",
        local_address=local_address,
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
    )
    return EndpointCandidate(connection, stats[0], stats[1])


def _is_relevant_packet(packet: CapturedUdpPacket, local_ports: Collection[int]) -> bool:
    return (
        packet.local_port in local_ports
        and packet.remote_port > 0
        and packet.local_port not in _SERVICE_PORTS
        and packet.remote_port not in _SERVICE_PORTS
        and _is_public_ip(packet.remote_address)
    )


def _normalize_ports(ports: Collection[int]) -> frozenset[int]:
    return frozenset(port for port in ports if isinstance(port, int) and 1 <= port <= 65535)


def _is_public_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except (TypeError, ValueError):
        return False


def _decode_ipv4_udp(payload: bytes, local_ports: Collection[int]) -> CapturedUdpPacket | None:
    if len(payload) < 28 or payload[0] >> 4 != 4:
        return None
    header_length = (payload[0] & 0x0F) * 4
    if header_length < 20 or len(payload) < header_length + 8 or payload[9] != socket.IPPROTO_UDP:
        return None
    source_port, destination_port = struct.unpack_from("!HH", payload, header_length)
    source_address = socket.inet_ntoa(payload[12:16])
    destination_address = socket.inet_ntoa(payload[16:20])
    if source_port in local_ports:
        return CapturedUdpPacket(
            source_address,
            source_port,
            destination_address,
            destination_port,
            len(payload),
        )
    if destination_port in local_ports:
        return CapturedUdpPacket(
            destination_address,
            destination_port,
            source_address,
            source_port,
            len(payload),
        )
    return None


def _is_permission_error(error: OSError) -> bool:
    return getattr(error, "winerror", None) in {5, 10013} or getattr(error, "errno", None) in {
        1,
        13,
    }


def _local_ipv4_address() -> str | None:
    """Resolve the local IPv4 used for the default outbound interface."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 80))
        address = probe.getsockname()[0]
        return address if _is_valid_ipv4(address) else None
    except OSError:
        return None
    finally:
        probe.close()


def _is_valid_ipv4(address: object) -> bool:
    if not isinstance(address, str):
        return False
    try:
        return ipaddress.ip_address(address).version == 4
    except ValueError:
        return False


def _winsock_error_reason(error: OSError) -> str:
    code = getattr(error, "winerror", None) or getattr(error, "errno", None)
    return f"winsock_{code}: {error}" if code is not None else str(error)
