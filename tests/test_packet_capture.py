import threading

from netvision.core.packet_capture import (
    BackendCapture,
    CaptureState,
    CapturedUdpPacket,
    capture_udp_endpoint,
    rank_udp_candidates,
)
from netvision.core.process_inspector import (
    ProcessConnection,
    has_unresolved_udp_socket,
    unresolved_udp_ports,
)


class FakePacketCaptureBackend:
    def __init__(self, capture: BackendCapture | None = None, error: Exception | None = None):
        self.capture_result = capture
        self.error = error
        self.called = False

    def capture(self, pid, local_ports, stop_event, timeout_s):
        self.called = True
        if self.error is not None:
            raise self.error
        return self.capture_result or BackendCapture()


def _packet(remote_address: str, remote_port: int, byte_count: int = 1200) -> CapturedUdpPacket:
    return CapturedUdpPacket("192.168.1.20", 41000, remote_address, remote_port, byte_count)


def test_selects_public_game_endpoint_and_filters_network_noise() -> None:
    packets = (
        _packet("8.8.8.8", 27015, 1400),
        _packet("8.8.8.8", 27015, 1500),
        _packet("8.8.8.8", 27015, 1600),
        _packet("8.8.8.8", 27015, 1400),
        _packet("8.8.8.8", 27015, 1500),
        _packet("8.8.8.8", 27015, 1600),
        _packet("8.8.8.8", 27015, 1400),
        _packet("8.8.8.8", 27015, 1500),
        _packet("192.168.1.1", 27015, 10000),
        _packet("1.1.1.1", 53, 10000),
        _packet("224.0.0.251", 5353, 10000),
        _packet("239.255.255.250", 1900, 10000),
    )

    candidates = rank_udp_candidates(packets, {41000})

    assert len(candidates) == 1
    assert candidates[0].connection == ProcessConnection(
        "UDP", "NONE", "192.168.1.20", 41000, "8.8.8.8", 27015
    )
    assert candidates[0].packet_count == 8


def test_short_beacon_burst_is_not_confirmed_as_game_endpoint() -> None:
    candidates = rank_udp_candidates(
        tuple(_packet("178.162.218.236", 29457) for _ in range(4)),
        {41000},
    )

    assert candidates == ()


def test_capture_maps_permission_denied_to_explicit_state() -> None:
    backend = FakePacketCaptureBackend(error=PermissionError("administrator required"))

    result = capture_udp_endpoint(backend, 123, {41000}, threading.Event())

    assert result.state is CaptureState.PERMISSION_DENIED
    assert result.connection is None


def test_winsock_access_denied_is_not_reported_as_unavailable() -> None:
    class WinSockAccessDenied(OSError):
        winerror = 10013

    backend = FakePacketCaptureBackend(error=WinSockAccessDenied("access denied"))

    result = capture_udp_endpoint(backend, 123, {41000}, threading.Event())

    assert result.state is CaptureState.PERMISSION_DENIED
    assert result.reason == "access denied"


def test_capture_maps_unavailable_backend_without_network_access() -> None:
    backend = FakePacketCaptureBackend(
        BackendCapture(state=CaptureState.BACKEND_UNAVAILABLE, reason="windows_only")
    )

    result = capture_udp_endpoint(backend, 123, {41000}, threading.Event())

    assert result.state is CaptureState.BACKEND_UNAVAILABLE
    assert result.reason == "windows_only"


def test_capture_stops_before_backend_when_stop_event_is_set() -> None:
    backend = FakePacketCaptureBackend()
    stop_event = threading.Event()
    stop_event.set()

    result = capture_udp_endpoint(backend, 123, {41000}, stop_event)

    assert result.state is CaptureState.STOPPED
    assert backend.called is False


def test_unresolved_udp_ports_define_capture_scope() -> None:
    connections = (
        ProcessConnection("UDP", "NONE", "192.168.1.20", 41000, "", 0),
        ProcessConnection("UDP", "NONE", "192.168.1.20", 41001, "8.8.8.8", 27015),
        ProcessConnection("TCP", "ESTABLISHED", "192.168.1.20", 41002, "8.8.8.8", 443),
    )

    assert unresolved_udp_ports(connections) == (41000,)
    assert has_unresolved_udp_socket(connections)
