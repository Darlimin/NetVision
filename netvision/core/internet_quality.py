from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

import psutil

from netvision.models import NetworkInterface, SystemSnapshot


DOWNLOAD_URLS = (
    "https://speed.cloudflare.com/__down?bytes=10000000",
    "https://proof.ovh.net/files/10Mb.dat",
)
PUBLIC_INFO_URLS = ("http://ip-api.com/json/", "https://ipwho.is/")
PUBLIC_IP_URLS = (
    (4, "https://api4.ipify.org"),
    (6, "https://api6.ipify.org"),
)
DOWNLOAD_BYTES = 10_000_000
DOWNLOAD_TIMEOUT = 60
TCP_TIMEOUT = 3
TCP_TARGETS = (
    ("Cloudflare DNS", "1.1.1.1", 53),
    ("Google DNS", "8.8.8.8", 53),
)
REQUEST_HEADERS = {
    "Accept": "application/json,text/plain,*/*",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
}


@dataclass(frozen=True, slots=True)
class SpeedtestResult:
    download_mbps: float | None = None
    upload_mbps: float | None = None
    ping_ms: float | None = None
    loaded_ping_ms: float | None = None
    server_name: str | None = None
    server_location: str | None = None
    isp: str | None = None
    external_ip: str | None = None
    tool: str = "Python HTTP CDN"
    error: str | None = None

    @property
    def is_success(self) -> bool:
        return self.error is None and (
            self.download_mbps is not None or self.ping_ms is not None
        )


@dataclass(frozen=True, slots=True)
class PublicNetworkInfo:
    ipv4: str | None = None
    ipv6: str | None = None
    isp: str | None = None
    region: str | None = None
    city: str | None = None
    vpn_detected: bool | None = None
    proxy_detected: bool | None = None
    source: str = "публичные Geo API"
    error: str | None = None

    @property
    def is_success(self) -> bool:
        return self.error is None and bool(self.ipv4 or self.ipv6 or self.isp)


@dataclass(frozen=True, slots=True)
class PublicIpAddresses:
    """Public addresses read directly from lightweight IP endpoints."""

    ipv4: str | None = None
    ipv6: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class LocalNetworkContext:
    adapter_name: str | None = None
    adapter_kind: str | None = None
    adapter_speed_mbps: int | None = None
    local_ipv4: tuple[str, ...] = ()
    local_ipv6: tuple[str, ...] = ()
    local_ip_tooltip: str | None = None
    known_external_ip: str | None = None
    vpn_detected: bool = False
    proxy_detected: bool = False


@dataclass(frozen=True, slots=True)
class InternetQualityReport:
    speedtest: SpeedtestResult
    network: PublicNetworkInfo
    local: LocalNetworkContext
    errors: tuple[str, ...] = ()

    @property
    def is_partial(self) -> bool:
        return bool(self.errors) or not (self.speedtest.is_success and self.network.is_success)


def measure_download(
    progress: Callable[[str], None] | None = None,
    urls: Sequence[str] = DOWNLOAD_URLS,
    timeout: int = DOWNLOAD_TIMEOUT,
) -> SpeedtestResult:
    """Download a bounded test file without keeping it in memory."""
    errors: list[str] = []
    for url in urls:
        _emit(progress, f"Загрузка тестового файла через {_host(url)}")
        request = urllib.request.Request(url, headers=REQUEST_HEADERS)
        started = time.perf_counter()
        received = 0
        try:
            with _open_request(request, timeout) as response:
                while received < DOWNLOAD_BYTES:
                    chunk = response.read(min(64 * 1024, DOWNLOAD_BYTES - received))
                    if not chunk:
                        break
                    received += len(chunk)
        except (OSError, TimeoutError, UnicodeError) as exc:
            errors.append(f"{_host(url)}: {exc}")
            continue
        elapsed = time.perf_counter() - started
        if received <= 0 or elapsed <= 0:
            errors.append(f"{_host(url)}: CDN не вернул тестовые байты")
            continue
        speed_mbps = received * 8 / elapsed / 1_000_000
        return SpeedtestResult(download_mbps=speed_mbps, tool=f"Python HTTP CDN ({_host(url)})")
    return SpeedtestResult(
        tool="Python HTTP CDN",
        error="Не удалось загрузить тестовый файл: " + " | ".join(errors),
    )


def measure_tcp_latency(
    progress: Callable[[str], None] | None = None,
    targets: Sequence[tuple[str, str, int]] = TCP_TARGETS,
    attempts: int = 3,
    timeout: int = TCP_TIMEOUT,
) -> SpeedtestResult:
    """Measure TCP connect latency to public DNS service ports."""
    errors: list[str] = []
    for target_name, host, port in targets:
        _emit(progress, f"Измеряем TCP-пинг: {target_name} {host}:{port}")
        samples: list[float] = []
        for _ in range(attempts):
            started = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    samples.append((time.perf_counter() - started) * 1000)
            except (OSError, TimeoutError) as exc:
                errors.append(f"{host}:{port}: {exc}")
        if samples:
            return SpeedtestResult(
                ping_ms=sum(samples) / len(samples),
                server_name=target_name,
                tool="Python TCP connect",
            )
    return SpeedtestResult(tool="Python TCP connect", error="Не удалось измерить TCP-пинг: " + " | ".join(errors))


def fetch_public_network_info(
    progress: Callable[[str], None] | None = None,
    urls: Sequence[str] = PUBLIC_INFO_URLS,
    timeout: int = 8,
) -> PublicNetworkInfo:
    """Read public IP, ISP and location from JSON-only Geo APIs."""
    results: list[PublicNetworkInfo] = []
    errors: list[str] = []
    for url in urls:
        _emit(progress, f"Запрашиваем внешний IP и Geo API: {_host(url)}")
        request = urllib.request.Request(url, headers=REQUEST_HEADERS)
        try:
            with _open_request(request, timeout) as response:
                payload = json.loads(response.read(512_000).decode("utf-8", errors="replace"))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{_host(url)}: {exc}")
            continue
        parsed = parse_public_network_json(payload, _host(url))
        if parsed.is_success:
            results.append(parsed)
        elif parsed.error:
            errors.append(parsed.error)

    merged = _merge_network_info(results)
    if merged.is_success:
        return merged
    return PublicNetworkInfo(
        source="публичные Geo API",
        error="Не удалось определить внешний IP и провайдера: " + " | ".join(errors),
    )


def fetch_public_ip_addresses(timeout: int = 5) -> PublicIpAddresses:
    """Resolve public IPv4 and IPv6 independently without Geo API parsing."""
    values: dict[int, str] = {}
    errors: list[str] = []
    for version, url in PUBLIC_IP_URLS:
        request = urllib.request.Request(url, headers=REQUEST_HEADERS)
        try:
            with _open_request(request, timeout) as response:
                candidate = response.read(128).decode("utf-8", errors="replace").strip()
        except (OSError, TimeoutError, UnicodeError) as exc:
            errors.append(f"IPv{version}: {exc}")
            continue
        address = _ip_version(candidate, version)
        if address is None:
            errors.append(f"IPv{version}: сервис вернул некорректный адрес")
            continue
        values[version] = address
    return PublicIpAddresses(
        ipv4=values.get(4),
        ipv6=values.get(6),
        error=" | ".join(errors) if errors and not values else None,
    )


def parse_public_network_json(payload: object, source: str = "Geo API") -> PublicNetworkInfo:
    if not isinstance(payload, dict):
        return PublicNetworkInfo(source=source, error="Geo API вернул не JSON-объект")
    if payload.get("success") is False or payload.get("status") == "fail":
        return PublicNetworkInfo(source=source, error=_text(payload.get("message")) or "Geo API отклонил запрос")

    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
    address = payload.get("query") or payload.get("ip")
    return PublicNetworkInfo(
        ipv4=_ip_version(address, 4),
        ipv6=_ip_version(address, 6),
        isp=(
            _text(payload.get("isp"))
            or _text(payload.get("org"))
            or _text(payload.get("organization"))
            or _text(connection.get("isp"))
            or _text(connection.get("org"))
        ),
        region=(
            _text(payload.get("regionName"))
            or _text(payload.get("region_name"))
            or _text(payload.get("region"))
            or _text(location.get("region"))
        ),
        city=_text(payload.get("city")) or _text(location.get("city")),
        vpn_detected=_optional_bool(payload.get("hosting")),
        proxy_detected=_optional_bool(payload.get("proxy")),
        source=source,
    )


def collect_local_network_context(snapshot: SystemSnapshot | None = None) -> LocalNetworkContext:
    if snapshot is not None:
        interfaces = snapshot.interfaces
        proxy_detected = bool(snapshot.proxies)
    else:
        interfaces = _collect_interfaces()
        proxy_detected = bool(urllib.request.getproxies())

    candidates = [
        interface
        for interface in interfaces
        if interface.is_up and interface.ipv4 and interface.kind != "Loopback"
    ]
    physical = [interface for interface in candidates if interface.kind != "VPN"]
    active = physical[0] if physical else (candidates[0] if candidates else None)
    primary_ipv4 = _pick_ipv4(active.ipv4 if active else ())
    vpn_ipv4 = _pick_vpn_ipv4(
        address
        for interface in candidates
        if interface.kind == "VPN"
        for address in interface.ipv4
    )
    visible_ipv4 = tuple(dict.fromkeys(address for address in (primary_ipv4, vpn_ipv4) if address))
    all_ipv4 = tuple(address for interface in interfaces for address in interface.ipv4)
    all_ipv6 = tuple(address for interface in interfaces for address in interface.ipv6)
    hidden = tuple(address for address in (*all_ipv4, *all_ipv6) if address not in visible_ipv4)
    tooltip = "Все обнаруженные адреса:\n" + ", ".join((*visible_ipv4, *hidden)) if hidden else None
    vpn_detected = any(interface.is_up and interface.kind == "VPN" for interface in interfaces)
    if snapshot is not None:
        vpn_detected = vpn_detected or any(route.is_vpn for route in snapshot.default_routes)

    return LocalNetworkContext(
        adapter_name=active.name if active else None,
        adapter_kind=active.kind if active else None,
        adapter_speed_mbps=active.speed_mbps if active and active.speed_mbps > 0 else None,
        local_ipv4=visible_ipv4,
        local_ip_tooltip=tooltip,
        known_external_ip=snapshot.external_ip if snapshot else None,
        vpn_detected=vpn_detected,
        proxy_detected=proxy_detected,
    )


def run_internet_quality_check(
    snapshot: SystemSnapshot | None = None,
    progress: Callable[[str], None] | None = None,
) -> InternetQualityReport:
    local = collect_local_network_context(snapshot)
    _emit(progress, "Запускаем автономный HTTP-тест скорости")
    download = measure_download(progress)
    _emit(progress, "Измеряем задержку TCP")
    latency = measure_tcp_latency(progress)
    _emit(progress, "Получаем внешний IP и данные провайдера")
    network = fetch_public_network_info(progress)
    speedtest = SpeedtestResult(
        download_mbps=download.download_mbps,
        ping_ms=latency.ping_ms,
        server_name=latency.server_name,
        tool=f"{download.tool}; {latency.tool}",
        error=" | ".join(error for error in (download.error, latency.error) if error) or None,
    )
    errors = tuple(error for error in (speedtest.error, network.error) if error)
    return InternetQualityReport(speedtest=speedtest, network=network, local=local, errors=errors)


def build_smart_report(report: InternetQualityReport) -> str:
    speed = report.speedtest
    network = report.network
    local = report.local
    location = ", ".join(value for value in (network.city, network.region) if value) or "не определён"
    if local.vpn_detected or local.proxy_detected or network.vpn_detected is True or network.proxy_detected is True:
        vpn_proxy = "обнаружен VPN/прокси"
    elif network.vpn_detected is False and network.proxy_detected is False:
        vpn_proxy = "не обнаружен"
    else:
        vpn_proxy = "не определён"
    lines = [
        f"Скорость скачивания: {_format_speed(speed.download_mbps)}.",
        f"Публичный IP: {network.ipv4 or network.ipv6 or 'не определён'}; провайдер: {network.isp or 'не определён'}; регион: {location}.",
        f"Локальный адаптер: {local.adapter_name or 'не определён'} ({_format_speed(local.adapter_speed_mbps)}).",
        f"Локальный IP: {', '.join(local.local_ipv4) or 'не определён'}.",
        f"VPN/прокси: {vpn_proxy}.",
    ]
    if speed.ping_ms is not None:
        lines.append(f"TCP-пинг: {speed.ping_ms:.1f} мс до {speed.server_name or 'DNS-сервиса'}.")
    if report.errors:
        lines.append("Неполные источники: " + " | ".join(report.errors))
    return "\n".join(lines)


def _merge_network_info(results: Sequence[PublicNetworkInfo]) -> PublicNetworkInfo:
    if not results:
        return PublicNetworkInfo(error="Ответы Geo API отсутствуют")
    return PublicNetworkInfo(
        ipv4=next((item.ipv4 for item in results if item.ipv4), None),
        ipv6=next((item.ipv6 for item in results if item.ipv6), None),
        isp=next((item.isp for item in results if item.isp), None),
        region=next((item.region for item in results if item.region), None),
        city=next((item.city for item in results if item.city), None),
        vpn_detected=next((item.vpn_detected for item in results if item.vpn_detected is not None), None),
        proxy_detected=next((item.proxy_detected for item in results if item.proxy_detected is not None), None),
        source=" + ".join(dict.fromkeys(item.source for item in results)),
    )


def _collect_interfaces() -> tuple[NetworkInterface, ...]:
    addresses_by_name = psutil.net_if_addrs()
    statistics = psutil.net_if_stats()
    result: list[NetworkInterface] = []
    for name, addresses in addresses_by_name.items():
        ipv4 = tuple(address.address for address in addresses if address.family == socket.AF_INET)
        ipv6 = tuple(address.address.split("%", 1)[0] for address in addresses if address.family == socket.AF_INET6)
        stats = statistics.get(name)
        result.append(
            NetworkInterface(
                name=name,
                kind=_interface_kind(name),
                is_up=bool(stats and stats.isup),
                speed_mbps=max(0, int(stats.speed)) if stats else 0,
                ipv4=ipv4,
                ipv6=ipv6,
            )
        )
    return tuple(result)


def _interface_kind(name: str) -> str:
    normalized = name.casefold()
    if any(token in normalized for token in ("wi-fi", "wifi", "wireless", "wlan")):
        return "Wi-Fi"
    if any(token in normalized for token in ("vpn", "tap", "tun", "wireguard", "wintun", "happ", "xray", "clash", "tailscale", "zerotier", "nordlynx")):
        return "VPN"
    if any(token in normalized for token in ("ethernet", "lan")):
        return "Ethernet"
    if "loopback" in normalized:
        return "Loopback"
    return "Network"


def _pick_ipv4(addresses: Iterable[str]) -> str | None:
    usable = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv4Address) and not (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast):
            usable.append(str(address))
    return min(usable, key=_ipv4_preference) if usable else None


def _pick_vpn_ipv4(addresses: Iterable[str]) -> str | None:
    usable = tuple(address for address in addresses if _pick_ipv4((address,)) == address)
    if not usable:
        return None
    vpn = [value for value in usable if ipaddress.ip_address(value) in ipaddress.ip_network("172.16.0.0/12")]
    return vpn[0] if vpn else usable[0]


def _ipv4_preference(value: str) -> tuple[int, str]:
    address = ipaddress.ip_address(value)
    if address in ipaddress.ip_network("192.168.0.0/16"):
        return 0, value
    if address in ipaddress.ip_network("10.0.0.0/8"):
        return 1, value
    if address in ipaddress.ip_network("172.16.0.0/12"):
        return 2, value
    return 3, value


def _ip_version(value: object, version: int) -> str | None:
    try:
        address = ipaddress.ip_address(str(value))
    except (ValueError, TypeError):
        return None
    return str(address) if address.version == version else None


def _optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.casefold() in {"true", "yes", "1"}:
            return True
        if value.casefold() in {"false", "no", "0"}:
            return False
    return None


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _format_speed(value: float | int | None) -> str:
    return "не измерена" if value is None else f"{value:.1f} Мбит/с"


def _host(url: str) -> str:
    return url.split("/", 3)[2]


def _open_request(request: urllib.request.Request, timeout: int):
    """Retry directly when a configured local proxy rejects the connection."""
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except (OSError, TimeoutError):
        direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return direct_opener.open(request, timeout=timeout)


def _emit(callback: Callable[[str], None] | None, message: str) -> None:
    if callback:
        callback(message)
