from __future__ import annotations

from unittest.mock import patch

from netvision.core import tls_diagnostics


class _RawSocket:
    def __enter__(self) -> _RawSocket:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None


class _SecureSocket:
    def __enter__(self) -> _SecureSocket:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def getpeercert(self, binary_form: bool = False) -> dict[str, object] | bytes:
        if binary_form:
            return b"test-certificate"
        return {
            "subject": ((('commonName', 'example.test'),),),
            "issuer": ((('commonName', 'NetVision Test CA'),),),
            "serialNumber": "01AB",
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2099 GMT",
        }

    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def selected_alpn_protocol(self) -> str:
        return "h2"


class _TlsContext:
    def __init__(self) -> None:
        self.alpn_protocols: list[str] = []

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        self.alpn_protocols = protocols

    def wrap_socket(self, _raw: _RawSocket, *, server_hostname: str) -> _SecureSocket:
        assert server_hostname == "example.test"
        return _SecureSocket()


def test_audit_tls_endpoint_collects_certificate_and_fingerprint() -> None:
    context = _TlsContext()
    with (
        patch.object(tls_diagnostics.ssl, "create_default_context", return_value=context),
        patch.object(tls_diagnostics.socket, "create_connection", return_value=_RawSocket()),
    ):
        result = tls_diagnostics.audit_tls_endpoint("example.test", 443)

    assert result.certificate_valid
    assert result.version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.alpn == "h2"
    assert result.chain[0].subject == "commonName=example.test"
    assert result.chain[0].issuer == "commonName=NetVision Test CA"
    assert result.chain[0].serial_number == "01AB"
    assert result.fingerprint_sha256
    assert context.alpn_protocols == ["h2", "http/1.1"]


def test_certificate_record_marks_expired_certificate() -> None:
    record = tls_diagnostics._certificate_record(
        {
            "subject": ((('commonName', 'expired.test'),),),
            "issuer": ((('commonName', 'Test CA'),),),
            "notAfter": "Jan  1 00:00:00 2020 GMT",
        },
        b"expired-certificate",
        position=0,
    )

    assert record.status == "Просрочен"
    assert record.days_remaining is not None and record.days_remaining < 0
    assert record.fingerprint_sha256
