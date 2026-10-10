"""GeoHide DNS page retrieval without coupling the core to Qt."""

from __future__ import annotations

from dataclasses import dataclass
import html
import ipaddress
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


GEOHIDE_URL = "https://geohide.ru/"
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_BLOCK_RE = re.compile(r"<(?:li|p|tr|td|code|pre)[^>]*>(.*?)</(?:li|p|tr|td|code|pre)>", re.I | re.S)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_DNS_TERMS = re.compile(r"dns|udp|порт|port|сервер|server", re.I)
_SERVER_TERMS = re.compile(r"dns[- ]?over[- ]?(?:udp|tcp)|dns[- ]?сервер|nameserver", re.I)
_REGION_TERMS = (
    ("RU", re.compile(r"\b(?:ru|russia|россия|российск)\b", re.I)),
    ("EU", re.compile(r"\b(?:eu|europe|европа|европейск)\b", re.I)),
    ("US", re.compile(r"\b(?:us|usa|united states|сша|америк)\b", re.I)),
)


@dataclass(frozen=True, slots=True)
class GeoHideServer:
    address: str
    region: str
    server_type: str = "DNS-over-UDP"


GEOHIDE_FALLBACK_SERVERS = (
    GeoHideServer("159.194.200.33", "EU"),
    GeoHideServer("193.233.112.67", "RU"),
    GeoHideServer("193.233.112.88", "RU"),
    GeoHideServer("37.230.192.51", "RU"),
    GeoHideServer("46.8.158.6", "RU"),
    GeoHideServer("193.233.112.68", "RU"),
)


@dataclass(frozen=True, slots=True)
class GeoHideResult:
    servers: tuple[GeoHideServer, ...]
    parameters: tuple[str, ...]
    source: str = GEOHIDE_URL
    used_fallback: bool = False

    @property
    def addresses(self) -> tuple[str, ...]:
        return tuple(server.address for server in self.servers)


def _public_addresses(value: str) -> tuple[str, ...]:
    result: list[str] = []
    for candidate in _IPV4_RE.findall(value):
        if _is_public_ipv4(candidate):
            if candidate not in result:
                result.append(candidate)
    return tuple(result)


def _is_public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and not address.is_private and not address.is_loopback


def _region_for_text(value: str) -> str:
    for region, pattern in _REGION_TERMS:
        if pattern.search(value):
            return region
    return "Global"


def _region_context(payload: str, start: int, end: int) -> str:
    """Use the closest region marker when an IP is outside a table cell."""
    window_start = max(0, start - 180)
    window_end = min(len(payload), end + 180)
    return _region_for_text(payload[window_start:window_end])


def _server_type_for_text(value: str) -> str:
    lowered = value.lower()
    if "tcp" in lowered and "udp" not in lowered:
        return "DNS-over-TCP"
    return "DNS-over-UDP"


def _fallback_result() -> GeoHideResult:
    return GeoHideResult(
        servers=GEOHIDE_FALLBACK_SERVERS,
        parameters=("DNS-over-UDP · резервный список GeoHide",),
        used_fallback=True,
    )


def parse_geohide_page(payload: str) -> GeoHideResult:
    """Extract public IPv4 addresses and DNS/UDP-related text from the page."""
    blocks: list[str] = []
    for match in _BLOCK_RE.finditer(payload):
        text = html.unescape(_HTML_TAG_RE.sub(" ", match.group(1)))
        text = " ".join(text.split())
        if text:
            blocks.append(text)

    servers: list[GeoHideServer] = []
    seen_addresses: set[str] = set()
    parameters: list[str] = []
    for block in blocks:
        found = _public_addresses(block)
        if not found or not _DNS_TERMS.search(block):
            continue
        region = _region_for_text(block)
        server_type = _server_type_for_text(block)
        for address in found:
            if address in seen_addresses:
                continue
            server = GeoHideServer(address, region, server_type)
            servers.append(server)
            seen_addresses.add(address)
        if block not in parameters and len(block) <= 240:
            parameters.append(block)

    # Some versions of the page render the server list in scripts or cards
    # that are not covered by the block expression. Scan the complete text
    # and keep every public address, using nearby RU/EU/US context.
    for match in _IPV4_RE.finditer(payload):
        address = match.group(0)
        if address in seen_addresses or not _is_public_ipv4(address):
            continue
        context = html.unescape(_HTML_TAG_RE.sub(" ", payload[max(0, match.start() - 240):match.end() + 240]))
        if not (
            _DNS_TERMS.search(context)
            or _SERVER_TERMS.search(context)
            or _region_for_text(context) != "Global"
        ):
            continue
        server = GeoHideServer(
            address,
            _region_context(payload, match.start(), match.end()),
            _server_type_for_text(context),
        )
        servers.append(server)
        seen_addresses.add(address)

    if not servers:
        for address in _public_addresses(payload):
            if address not in seen_addresses:
                servers.append(
                    GeoHideServer(address, _region_for_text(payload), _server_type_for_text(payload))
                )
                seen_addresses.add(address)

    return GeoHideResult(
        servers=tuple(servers),
        parameters=tuple(parameters[:30]),
    )


def fetch_geohide_dns(timeout: float = 12.0) -> GeoHideResult:
    request = Request(
        GEOHIDE_URL,
        headers={
            "User-Agent": "NetVision/0.8.0 (Windows; network diagnostics)",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(2_000_000).decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError):
        return _fallback_result()
    result = parse_geohide_page(payload)
    return result if result.servers else _fallback_result()
