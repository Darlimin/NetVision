import socket
import struct
import threading
import time
import unittest

from netvision.core.nat_diagnostics import _MAGIC_COOKIE, probe_nat
from netvision.models import HopResult


def _stun_response(transaction_id: bytes, mapped_ip: str, mapped_port: int) -> bytes:
    encoded_port = mapped_port ^ (_MAGIC_COOKIE >> 16)
    encoded_ip = struct.unpack("!I", socket.inet_aton(mapped_ip))[0] ^ _MAGIC_COOKIE
    attribute = struct.pack(
        "!HHBBHI",
        0x0020,
        8,
        0,
        1,
        encoded_port,
        encoded_ip,
    )
    return struct.pack("!HHI12s", 0x0101, len(attribute), _MAGIC_COOKIE, transaction_id) + attribute


class _StunResponder:
    def __init__(self, mapped_port: int, *, foreign_first: bool = False) -> None:
        self._mapped_port = mapped_port
        self._foreign_first = foreign_first
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return int(self._socket.getsockname()[1])

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                request, peer = self._socket.recvfrom(2048)
            except TimeoutError:
                continue
            if len(request) < 20:
                continue
            transaction_id = request[8:20]
            if self._foreign_first:
                self._socket.sendto(
                    _stun_response(b"x" * 12, "203.0.113.25", self._mapped_port),
                    peer,
                )
            self._socket.sendto(
                _stun_response(transaction_id, "203.0.113.25", self._mapped_port),
                peer,
            )


class NatDiagnosticsTests(unittest.TestCase):
    def _probe_with_servers(
        self,
        first_port: int,
        second_port: int,
        *,
        foreign_first: bool = False,
    ):
        first = _StunResponder(first_port, foreign_first=foreign_first)
        second = _StunResponder(second_port)
        first.start()
        second.start()
        try:
            return probe_nat(
                (("127.0.0.1", first.port), ("127.0.0.1", second.port)),
                timeout_s=0.1,
                retries=1,
            )
        finally:
            first.close()
            second.close()

    def test_same_mapping_from_two_servers_is_eim(self) -> None:
        report = self._probe_with_servers(42000, 42000)

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.nat_type, "eim")

    def test_different_mapping_from_two_servers_is_apdm(self) -> None:
        report = self._probe_with_servers(42000, 42001)

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.nat_type, "apdm")

    def test_foreign_transaction_id_is_ignored(self) -> None:
        report = self._probe_with_servers(42000, 42000, foreign_first=True)

        self.assertEqual(report.nat_type, "eim")
        self.assertTrue(all(endpoint.mapped_port == 42000 for endpoint in report.mapped_endpoints))

    def test_no_stun_answers_marks_udp_blocked_within_budget(self) -> None:
        unused = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        unused.bind(("127.0.0.1", 0))
        port = int(unused.getsockname()[1])
        unused.close()
        started = time.monotonic()

        report = probe_nat((("127.0.0.1", port),), timeout_s=0.03, retries=1)

        self.assertEqual(report.status, "udp_blocked")
        self.assertLess(time.monotonic() - started, 0.5)

    def test_cgnat_and_double_nat_heuristics_use_route_hops(self) -> None:
        report = probe_nat(
            (),
            hops=(
                HopResult(1, "192.168.1.1", 1.0),
                HopResult(2, "100.64.0.1", 4.0),
                HopResult(3, "10.0.0.1", 5.0),
            ),
        )

        self.assertEqual(report.status, "no_servers")
        self.assertTrue(report.cgnat_likely)
        self.assertTrue(report.double_nat_likely)
