"""Measured UDP packet-loss checks using DNS request/response packets."""

from __future__ import annotations

from dataclasses import dataclass
import socket
import struct
import time


@dataclass(frozen=True, slots=True)
class UdpStressReport:
    """Result of a UDP request/response stress test."""

    target: str
    sent: int
    received: int
    lost: int
    loss_percent: float
    average_ms: float | None
    status: str
    error: str | None = None


def _dns_query(transaction_id: int) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"\x08netvision\x05local\x00" + struct.pack("!HH", 1, 1)
    return header + question


def run_udp_packet_loss_stress(
    host: str,
    port: int = 53,
    *,
    count: int = 30,
    timeout: float = 1.0,
    interval: float = 0.05,
) -> UdpStressReport:
    """Send DNS-over-UDP requests and calculate response loss and RTT.

    This deliberately uses a request/response protocol. Arbitrary UDP datagrams
    cannot prove delivery because most public endpoints do not send ACKs.
    """
    host = host.strip()
    if not host:
        raise ValueError("UDP target is empty")
    if not 1 <= port <= 65535:
        raise ValueError("UDP port must be between 1 and 65535")
    if count < 1:
        raise ValueError("UDP packet count must be positive")
    if timeout <= 0:
        raise ValueError("UDP timeout must be positive")

    sent = 0
    received = 0
    timings: list[float] = []
    last_error: str | None = None

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(timeout)
        for sequence in range(count):
            transaction_id = (int(time.monotonic_ns()) + sequence) & 0xFFFF
            payload = _dns_query(transaction_id)
            started = time.perf_counter()
            try:
                connection.sendto(payload, (host, port))
                sent += 1
                response, _ = connection.recvfrom(2048)
                if len(response) >= 2 and struct.unpack("!H", response[:2])[0] == transaction_id:
                    received += 1
                    timings.append((time.perf_counter() - started) * 1000)
            except socket.timeout:
                last_error = "UDP response timeout"
            except OSError as exc:
                last_error = str(exc)
            if interval > 0 and sequence + 1 < count:
                time.sleep(interval)

    lost = sent - received
    loss_percent = round((lost / sent) * 100, 1) if sent else 100.0
    average_ms = round(sum(timings) / len(timings), 1) if timings else None
    if received == sent and sent:
        status = "Стабильно"
    elif loss_percent < 3:
        status = "Есть потери"
    else:
        status = "Высокие потери"
    return UdpStressReport(
        target=f"{host}:{port}",
        sent=sent,
        received=received,
        lost=lost,
        loss_percent=loss_percent,
        average_ms=average_ms,
        status=status,
        error=last_error,
    )
