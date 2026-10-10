from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import socket
import ssl
from time import perf_counter


@dataclass(frozen=True, slots=True)
class CertificateRecord:
    """Certificate metadata exposed by Python's standard SSL API."""

    position: int
    subject: str
    issuer: str
    serial_number: str
    valid_from: datetime | None
    valid_to: datetime | None
    days_remaining: int | None
    fingerprint_sha256: str | None
    status: str


@dataclass(frozen=True, slots=True)
class TlsAuditResult:
    host: str
    port: int
    tcp_connect_ms: float | None
    handshake_ms: float | None
    version: str | None
    cipher: str | None
    alpn: str | None
    certificate_valid: bool
    certificate_status: str
    chain: tuple[CertificateRecord, ...]
    fingerprint_sha256: str | None
    error: str | None = None


def audit_tls_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> TlsAuditResult:
    """Audit one TLS endpoint without sending application data.

    A verified connection is always attempted first. If certificate validation
    fails, a second read-only unverified handshake is used only to collect the
    leaf certificate details; the returned result remains explicitly invalid.
    """
    normalized_host = host.strip()
    if not normalized_host or not 1 <= port <= 65535 or timeout <= 0:
        raise ValueError("Параметры TLS-проверки некорректны")

    try:
        return _run_handshake(
            normalized_host,
            port,
            timeout,
            ssl.create_default_context(),
            certificate_valid=True,
            certificate_status="Действителен",
        )
    except ssl.SSLCertVerificationError as exc:
        validation_error = _format_ssl_error(exc)
        try:
            return _run_handshake(
                normalized_host,
                port,
                timeout,
                ssl._create_unverified_context(),
                certificate_valid=False,
                certificate_status=f"Ошибка проверки: {validation_error}",
                error=validation_error,
            )
        except (OSError, ssl.SSLError) as fallback_exc:
            return _error_result(
                normalized_host,
                port,
                f"Сертификат не прошёл проверку: {validation_error}; {fallback_exc}",
            )
    except (OSError, ssl.SSLError) as exc:
        return _error_result(normalized_host, port, str(exc))


def _run_handshake(
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    *,
    certificate_valid: bool,
    certificate_status: str,
    error: str | None = None,
) -> TlsAuditResult:
    tcp_started = perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        tcp_connect_ms = round((perf_counter() - tcp_started) * 1000, 1)
        context.set_alpn_protocols(["h2", "http/1.1"])
        handshake_started = perf_counter()
        with context.wrap_socket(raw_socket, server_hostname=host) as secure_socket:
            handshake_ms = round((perf_counter() - handshake_started) * 1000, 1)
            certificate = secure_socket.getpeercert() or {}
            certificate_der = secure_socket.getpeercert(binary_form=True)
            record = _certificate_record(
                certificate,
                certificate_der,
                position=0,
                forced_status=certificate_status if not certificate_valid else None,
            )
            cipher_info = secure_socket.cipher()
            return TlsAuditResult(
                host=host,
                port=port,
                tcp_connect_ms=tcp_connect_ms,
                handshake_ms=handshake_ms,
                version=secure_socket.version(),
                cipher=cipher_info[0] if cipher_info else None,
                alpn=secure_socket.selected_alpn_protocol(),
                # A certificate may be currently valid but close to expiry.
                # The UI renders that distinction as a warning instead of an error.
                certificate_valid=certificate_valid,
                certificate_status=record.status,
                chain=(record,),
                fingerprint_sha256=record.fingerprint_sha256,
                error=error,
            )


def _certificate_record(
    certificate: dict[str, object],
    certificate_der: bytes | None,
    *,
    position: int,
    forced_status: str | None = None,
) -> CertificateRecord:
    valid_from = _parse_cert_datetime(certificate.get("notBefore"))
    valid_to = _parse_cert_datetime(certificate.get("notAfter"))
    days_remaining = None
    if valid_to is not None:
        days_remaining = (valid_to - datetime.now(timezone.utc)).days

    if forced_status:
        status = forced_status
    elif valid_to is None:
        status = "Дата окончания не указана"
    elif days_remaining < 0:
        status = "Просрочен"
    elif days_remaining <= 30:
        status = "Истекает скоро"
    else:
        status = "Действителен"

    return CertificateRecord(
        position=position,
        subject=_certificate_name(certificate.get("subject")),
        issuer=_certificate_name(certificate.get("issuer")),
        serial_number=str(certificate.get("serialNumber") or "--"),
        valid_from=valid_from,
        valid_to=valid_to,
        days_remaining=days_remaining,
        fingerprint_sha256=_fingerprint(certificate_der),
        status=status,
    )


def _parse_cert_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _certificate_name(value: object) -> str:
    if not isinstance(value, tuple):
        return "--"
    parts: list[str] = []
    for group in value:
        if not isinstance(group, tuple):
            continue
        for pair in group:
            if isinstance(pair, tuple) and len(pair) == 2:
                parts.append(f"{pair[0]}={pair[1]}")
    return ", ".join(parts) or "--"


def _fingerprint(certificate_der: bytes | None) -> str | None:
    if not certificate_der:
        return None
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def _format_ssl_error(error: ssl.SSLCertVerificationError) -> str:
    return error.verify_message or str(error)


def _error_result(host: str, port: int, message: str) -> TlsAuditResult:
    return TlsAuditResult(
        host=host,
        port=port,
        tcp_connect_ms=None,
        handshake_ms=None,
        version=None,
        cipher=None,
        alpn=None,
        certificate_valid=False,
        certificate_status="Проверка не выполнена",
        chain=(),
        fingerprint_sha256=None,
        error=message,
    )
