from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from netvision.models import Target


def parse_target(value: str, port: int | None = None) -> Target:
    """Normalize a hostname, IP address, or URL into a diagnostic target."""
    raw = value.strip()
    if not raw:
        raise ValueError("Укажите адрес или имя хоста.")

    candidate = raw if "://" in raw else f"//{raw}"
    parsed = urlsplit(candidate)
    host = parsed.hostname
    if not host:
        raise ValueError("Не удалось определить имя хоста.")

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Порт должен быть числом от 1 до 65535.") from exc

    selected_port = port or parsed_port
    if selected_port is None:
        selected_port = 443 if scheme == "https" else 80
    if not 1 <= selected_port <= 65535:
        raise ValueError("Порт должен быть числом от 1 до 65535.")

    if not scheme:
        scheme = "https" if selected_port in {443, 8443} else "tcp"

    normalized_host = _normalize_host(host)
    return Target(original=raw, host=normalized_host, port=selected_port, scheme=scheme)


def _normalize_host(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        normalized = host.rstrip(".").lower()
        if not normalized or " " in normalized:
            raise ValueError("Имя хоста содержит недопустимые символы.")
        try:
            normalized.encode("idna")
        except UnicodeError as exc:
            raise ValueError("Имя хоста содержит недопустимые символы.") from exc
        return normalized

