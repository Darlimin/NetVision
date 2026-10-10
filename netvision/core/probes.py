from __future__ import annotations

import ipaddress
import ctypes
import json
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime
from urllib.error import URLError
from urllib.request import Request, urlopen

from netvision.models import (
    DnsResult,
    GeoResult,
    HopResult,
    PingResult,
    ProbeStatus,
    Target,
    TcpResult,
    TlsResult,
)


def resolve_dns(target: Target) -> DnsResult:
    started = time.perf_counter()
    try:
        records = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
        addresses = tuple(dict.fromkeys(record[4][0] for record in records))
        elapsed = _elapsed_ms(started)
        if not addresses:
            return DnsResult(target.host, (), elapsed, ProbeStatus.WARNING, "DNS не вернул адреса")
        return DnsResult(target.host, addresses, elapsed, ProbeStatus.SUCCESS)
    except OSError as exc:
        return DnsResult(target.host, (), _elapsed_ms(started), ProbeStatus.ERROR, str(exc))


def probe_tcp(target: Target, timeout: float = 4.0) -> TcpResult:
    started = time.perf_counter()
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as connection:
            peer = connection.getpeername()[0]
        return TcpResult(
            target.host,
            target.port,
            peer,
            _elapsed_ms(started),
            ProbeStatus.SUCCESS,
        )
    except TimeoutError:
        return TcpResult(
            target.host,
            target.port,
            None,
            _elapsed_ms(started),
            ProbeStatus.WARNING,
            "Превышено время ожидания TCP-соединения",
        )
    except OSError as exc:
        return TcpResult(
            target.host,
            target.port,
            None,
            _elapsed_ms(started),
            ProbeStatus.ERROR,
            str(exc),
        )


def probe_ping(host: str, count: int = 5, wait_ms: int = 900) -> PingResult:
    if count < 1 or wait_ms < 1:
        raise ValueError("Количество ping и ожидание должны быть положительными")
    command = ["ping", "-n", str(count), "-w", str(wait_ms), host]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=_oem_encoding(),
            errors="replace",
            timeout=count * (wait_ms / 1000) + 5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PingResult(
            host, count, 0, 100.0, None, None, None, None, (), ProbeStatus.ERROR, str(exc)
        )

    samples = parse_ping_samples(completed.stdout + "\n" + completed.stderr)
    received = min(len(samples), count)
    loss = round((count - received) * 100 / count, 1) if count else 0.0
    average = round(sum(samples) / received, 1) if received else None
    jitter = (
        round(sum(abs(right - left) for left, right in zip(samples, samples[1:])) / (received - 1), 1)
        if received > 1
        else None
    )
    status = ProbeStatus.SUCCESS if received == count else ProbeStatus.WARNING
    error = None
    if received < count:
        error = "ICMP-ответы получены не на все запросы; узел или сеть могут фильтровать ping"
    if completed.returncode != 0 and not received:
        error = "ICMP-ответы не получены; проверьте фильтрацию ping или доступность узла"
    return PingResult(
        host=host,
        sent=count,
        received=received,
        loss_percent=loss,
        average_ms=average,
        minimum_ms=min(samples) if samples else None,
        maximum_ms=max(samples) if samples else None,
        jitter_ms=jitter,
        samples_ms=samples,
        status=status,
        error=error,
    )


def parse_ping_samples(output: str) -> tuple[float, ...]:
    samples: list[float] = []
    ttl_pattern = re.compile(r"TTL\s*=", flags=re.IGNORECASE)
    value_pattern = re.compile(r"([=<])\s*(\d+(?:[.,]\d+)?)")
    legacy_pattern = re.compile(
        r"(?:time|время)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)",
        flags=re.IGNORECASE,
    )

    for line in output.splitlines():
        ttl = ttl_pattern.search(line)
        matches = value_pattern.findall(line[: ttl.start()] if ttl else "")
        if not matches:
            matches = legacy_pattern.findall(line)
        if not matches:
            continue
        operator, value = matches[-1]
        samples.append(0.5 if operator == "<" else float(value.replace(",", ".")))
    return tuple(samples)


def lookup_geo(address: str, timeout: float = 4.0) -> GeoResult:
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        return _geo_error(address, str(exc))
    if not parsed_address.is_global:
        return _geo_error(address, "Для частного IP GeoIP не запрашивается", ProbeStatus.WARNING)

    url = f"https://ipwho.is/{parsed_address}?fields=success,ip,country,region,city,connection"
    request = Request(url, headers={"User-Agent": "NetVision/0.2"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except (OSError, URLError, json.JSONDecodeError, TimeoutError, UnicodeError) as exc:
        return _geo_error(address, str(exc))

    return parse_geo_payload(str(parsed_address), payload)


def parse_geo_payload(address: str, payload: object) -> GeoResult:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        message = payload.get("message") if isinstance(payload, dict) else None
        return _geo_error(address, str(message or "GeoIP-сервис вернул некорректный ответ"))

    connection = payload.get("connection")
    if not isinstance(connection, dict):
        connection = {}
    return GeoResult(
        address=str(payload.get("ip") or address),
        country=_optional_text(payload.get("country")),
        region=_optional_text(payload.get("region")),
        city=_optional_text(payload.get("city")),
        asn=_optional_text(connection.get("asn")),
        organization=_optional_text(connection.get("org")),
        isp=_optional_text(connection.get("isp")),
        status=ProbeStatus.SUCCESS,
    )


def _geo_error(address: str, message: str, status: ProbeStatus = ProbeStatus.ERROR) -> GeoResult:
    return GeoResult(address, None, None, None, None, None, None, status, message)


def _optional_text(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def probe_tls(target: Target, timeout: float = 5.0) -> TlsResult:
    started = time.perf_counter()
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=target.host) as secure:
                certificate = secure.getpeercert()
                cipher = secure.cipher()
                expires_at = _parse_certificate_date(certificate.get("notAfter"))
                return TlsResult(
                    version=secure.version(),
                    cipher=cipher[0] if cipher else None,
                    alpn=secure.selected_alpn_protocol(),
                    subject=_certificate_name(certificate.get("subject", ())),
                    issuer=_certificate_name(certificate.get("issuer", ())),
                    expires_at=expires_at,
                    latency_ms=_elapsed_ms(started),
                    status=ProbeStatus.SUCCESS,
                )
    except (OSError, ssl.SSLError) as exc:
        return TlsResult(
            version=None,
            cipher=None,
            alpn=None,
            subject=None,
            issuer=None,
            expires_at=None,
            latency_ms=_elapsed_ms(started),
            status=ProbeStatus.ERROR,
            error=str(exc),
        )


def trace_route(target: Target, max_hops: int = 10, wait_ms: int = 650) -> tuple[HopResult, ...]:
    command = ["tracert", "-d", "-w", str(wait_ms), "-h", str(max_hops), target.host]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=_oem_encoding(),
            errors="replace",
            timeout=max_hops * 3 * (wait_ms / 1000) + 6,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    return parse_tracert_output(completed.stdout)


def parse_tracert_output(output: str) -> tuple[HopResult, ...]:
    hops: list[HopResult] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match:
            continue
        index = int(match.group(1))
        body = match.group(2)
        address = _trailing_ip_address(body)
        latency_values = [
            float(value.replace(",", "."))
            for value in re.findall(r"<?(\d+(?:[.,]\d+)?)\s*(?:ms|мс)", body, re.IGNORECASE)
        ]
        latency = round(sum(latency_values) / len(latency_values), 1) if latency_values else None
        timed_out = address is None and "*" in body
        hops.append(HopResult(index=index, address=address, latency_ms=latency, timed_out=timed_out))
    return tuple(hops)


def _trailing_ip_address(value: str) -> str | None:
    candidate = value.rsplit(maxsplit=1)[-1] if value.split() else ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


def _oem_encoding() -> str:
    """Return the active Windows console encoding used by ping/tracert."""

    try:
        code_page = int(ctypes.windll.kernel32.GetOEMCP())
        if code_page > 0:
            return f"cp{code_page}"
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return "cp866"


def _certificate_name(parts: object) -> str | None:
    if not isinstance(parts, tuple):
        return None
    values: list[str] = []
    for group in parts:
        if not isinstance(group, tuple):
            continue
        for item in group:
            if isinstance(item, tuple) and len(item) == 2 and item[0] in {"commonName", "organizationName"}:
                values.append(str(item[1]))
    return " / ".join(dict.fromkeys(values)) or None


def _parse_certificate_date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value))
    except (ValueError, OverflowError):
        return None

