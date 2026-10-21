from __future__ import annotations

import json
import ipaddress
import re
import socket
import subprocess
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass

import psutil

from netvision.core.probes import _oem_encoding
from netvision.models import DefaultRoute, GatewayInfo, NetworkInterface, SystemSnapshot, WifiSnapshot


@dataclass(frozen=True, slots=True)
class DnsConfiguration:
    adapter_names: tuple[str, ...]
    servers: tuple[str, ...]


def collect_dns_configuration() -> DnsConfiguration:
    """Read active adapter names and configured resolvers without external network calls."""
    interfaces = _collect_interfaces()
    adapters = tuple(
        interface.name
        for interface in interfaces
        if interface.is_up and interface.kind != "Loopback"
    )
    return DnsConfiguration(adapters, _collect_dns_servers())


def parse_wifi_interfaces_output(text: str) -> list[WifiSnapshot]:
    """Parse ``netsh wlan show interfaces`` in English and Russian Windows locales."""
    snapshots: list[WifiSnapshot] = []
    current: dict[str, str] = {}
    aliases = {
        "name": "interface_name",
        "имя": "interface_name",
        "state": "state",
        "состояние": "state",
        "ssid": "ssid",
        "bssid": "bssid",
        "radio type": "radio_type",
        "тип радиосети": "radio_type",
        "band": "band",
        "диапазон": "band",
        "channel": "channel",
        "канал": "channel",
        "signal": "signal_pct",
        "сигнал": "signal_pct",
        "receive rate (mbps)": "rx_mbps",
        "скорость приёма (мбит/с)": "rx_mbps",
        "скорость приема (мбит/с)": "rx_mbps",
        "transmit rate (mbps)": "tx_mbps",
        "скорость передачи (мбит/с)": "tx_mbps",
    }

    def flush() -> None:
        if current.get("state", "").casefold() not in {"connected", "подключено"}:
            current.clear()
            return
        interface_name = current.get("interface_name")
        if not interface_name:
            current.clear()
            return
        snapshots.append(
            WifiSnapshot(
                interface_name=interface_name,
                ssid=_optional_text(current.get("ssid")),
                bssid=_optional_text(current.get("bssid")),
                radio_type=_optional_text(current.get("radio_type")),
                band=_optional_text(current.get("band")),
                channel=_optional_text(current.get("channel")),
                signal_pct=_parse_percent(current.get("signal_pct")),
                rx_mbps=_parse_rate_mbps(current.get("rx_mbps")),
                tx_mbps=_parse_rate_mbps(current.get("tx_mbps")),
            )
        )
        current.clear()

    for line in text.splitlines():
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if match is None:
            continue
        key, value = match.groups()
        field = aliases.get(key.casefold())
        if field is None:
            continue
        if field == "interface_name":
            flush()
        current[field] = value.strip()
    flush()
    return snapshots


def collect_wifi_snapshot(route_interface: str | None) -> WifiSnapshot | None:
    """Return Wi-Fi data only when it belongs to the active route interface."""
    if not route_interface:
        return None
    completed = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=False,
        timeout=8,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if completed.returncode != 0:
        message = _decode_oem_output(completed.stderr).strip()
        raise OSError(message or "netsh wlan недоступен")
    snapshots = parse_wifi_interfaces_output(_decode_oem_output(completed.stdout))
    return next(
        (snapshot for snapshot in snapshots if snapshot.interface_name == route_interface),
        None,
    )


def collect_system_snapshot() -> SystemSnapshot:
    warnings: list[str] = []
    interfaces = _collect_interfaces()

    default_routes: tuple[DefaultRoute, ...] = ()
    try:
        default_routes = _collect_default_routes(interfaces)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        warnings.append(f"Не удалось определить основной шлюз: {exc}")
    gateway = None
    if default_routes:
        selected_route = default_routes[0]
        gateway = GatewayInfo(
            address=selected_route.gateway,
            interface=selected_route.interface,
            metric=selected_route.metric,
        )

    dns_servers: tuple[str, ...] = ()
    try:
        dns_servers = _collect_dns_servers()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        warnings.append(f"Не удалось определить DNS-серверы: {exc}")

    external_ip = None
    try:
        external_ip = _collect_external_ip()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        warnings.append(f"Не удалось определить внешний IP: {exc}")

    proxies = tuple(sorted(urllib.request.getproxies().items()))
    return SystemSnapshot(
        hostname=socket.gethostname(),
        interfaces=interfaces,
        gateway=gateway,
        dns_servers=dns_servers,
        external_ip=external_ip,
        proxies=proxies,
        warnings=tuple(warnings),
        default_routes=default_routes,
    )


def _collect_interfaces() -> tuple[NetworkInterface, ...]:
    addresses_by_name = psutil.net_if_addrs()
    statistics = psutil.net_if_stats()
    interfaces: list[NetworkInterface] = []
    for name, addresses in addresses_by_name.items():
        ipv4: list[str] = []
        ipv6: list[str] = []
        mac = None
        for address in addresses:
            if address.family == socket.AF_INET:
                ipv4.append(address.address)
            elif address.family == socket.AF_INET6:
                ipv6.append(address.address.split("%", 1)[0])
            elif address.family == getattr(psutil, "AF_LINK", object()):
                mac = address.address or None
        stats = statistics.get(name)
        interfaces.append(
            NetworkInterface(
                name=name,
                kind=_interface_kind(name),
                is_up=bool(stats and stats.isup),
                speed_mbps=max(0, int(stats.speed)) if stats else 0,
                mac=mac,
                ipv4=tuple(ipv4),
                ipv6=tuple(ipv6),
            )
        )
    return tuple(sorted(interfaces, key=lambda item: (not item.is_up, item.name.lower())))


def _collect_default_routes(interfaces: tuple[NetworkInterface, ...]) -> tuple[DefaultRoute, ...]:
    completed = subprocess.run(
        ["route", "print", "-4"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=8,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if completed.returncode != 0:
        raise OSError("не удалось прочитать таблицу IPv4-маршрутов")
    return parse_default_routes_output(completed.stdout, interfaces)


def _collect_dns_servers() -> tuple[str, ...]:
    script = (
        "Get-DnsClientServerAddress "
        "| Where-Object { $_.ServerAddresses.Count -gt 0 } "
        "| Select-Object -ExpandProperty ServerAddresses "
        "| ConvertTo-Json -Compress"
    )
    try:
        payload = _run_powershell_json(script)
        if isinstance(payload, str):
            values: Iterable[object] = (payload,)
        elif isinstance(payload, list):
            values = payload
        else:
            values = ()
        servers = normalize_dns_server_values(values)
        if servers:
            return servers
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return _collect_dns_from_registry()


def parse_default_routes_output(
    output: str,
    interfaces: tuple[NetworkInterface, ...] = (),
) -> tuple[DefaultRoute, ...]:
    candidates: list[DefaultRoute] = []
    pattern = re.compile(
        r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        gateway_text, local_address, metric_text = match.groups()
        try:
            ipaddress.ip_address(local_address)
        except ValueError:
            continue
        on_link = gateway_text.casefold() == "on-link"
        try:
            gateway = str(ipaddress.ip_address(gateway_text))
        except ValueError:
            gateway = local_address
            on_link = True
        if gateway in {"0.0.0.0", "::"}:
            gateway = local_address
            on_link = True
        interface_name = next(
            (interface.name for interface in interfaces if local_address in interface.ipv4),
            None,
        )
        interface = next((item for item in interfaces if item.name == interface_name), None)
        is_vpn = bool(interface and interface.kind == "VPN") or _is_vpn_name(interface_name or "")
        candidates.append(
            DefaultRoute(
                gateway=gateway,
                interface=interface_name,
                local_address=local_address,
                metric=int(metric_text),
                is_vpn=is_vpn,
                on_link=on_link,
            )
        )

    ordered = sorted(candidates, key=lambda route: (route.metric, not route.is_vpn))
    return tuple(ordered)


def parse_route_print_output(
    output: str,
    interfaces: tuple[NetworkInterface, ...] = (),
) -> GatewayInfo | None:
    routes = parse_default_routes_output(output, interfaces)
    if not routes:
        return None
    route = routes[0]
    return GatewayInfo(address=route.gateway, interface=route.interface, metric=route.metric)


def _collect_dns_from_registry() -> tuple[str, ...]:
    try:
        import winreg
    except ImportError as exc:
        raise OSError("реестр Windows недоступен") from exc

    paths = (
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
    )
    servers: list[str] = []
    for path in paths:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        except OSError:
            continue
        with root:
            subkey_count = winreg.QueryInfoKey(root)[0]
            for index in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(root, index)
                    interface_key = winreg.OpenKey(root, subkey_name)
                except OSError:
                    continue
                with interface_key:
                    configured = _registry_text(interface_key, "NameServer")
                    discovered = configured or _registry_text(interface_key, "DhcpNameServer")
                    servers.extend(_split_ip_values(discovered))
    return tuple(dict.fromkeys(servers))


def normalize_dns_server_values(values: Iterable[object]) -> tuple[str, ...]:
    servers: list[str] = []
    for value in values:
        if value:
            servers.extend(_split_ip_values(str(value)))
    return tuple(dict.fromkeys(servers))


def _registry_text(key: object, name: str) -> str:
    try:
        import winreg

        value, _value_type = winreg.QueryValueEx(key, name)
    except (OSError, TypeError):
        return ""
    return value if isinstance(value, str) else ""


def _split_ip_values(value: str) -> list[str]:
    result: list[str] = []
    for candidate in re.split(r"[\s,;]+", value.strip()):
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
            if address.is_unspecified or address.is_loopback or address.is_multicast:
                continue
            if isinstance(address, ipaddress.IPv6Address) and address.is_site_local:
                continue
            result.append(str(address))
        except ValueError:
            continue
    return result


def _collect_external_ip() -> str:
    services = (
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
    )
    last_error: OSError | ValueError | None = None
    for url in services:
        request = urllib.request.Request(url, headers={"User-Agent": "NetVision/0.2"})
        try:
            with urllib.request.urlopen(request, timeout=4) as response:
                address = response.read(128).decode("ascii", errors="strict").strip()
            return str(ipaddress.ip_address(address))
        except (OSError, ValueError, UnicodeError) as exc:
            last_error = exc
    raise OSError(f"публичные сервисы IP недоступны: {last_error}")


def _run_powershell_json(script: str) -> object:
    completed = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=8,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr.strip() or "PowerShell завершился с ошибкой")
    text = completed.stdout.strip().lstrip("\ufeff")
    return json.loads(text) if text else None


def _interface_kind(name: str) -> str:
    normalized = name.lower()
    if any(token in normalized for token in ("wi-fi", "wifi", "wireless", "wlan")):
        return "Wi-Fi"
    if _is_vpn_name(normalized):
        return "VPN"
    if any(token in normalized for token in ("ethernet", "lan")):
        return "Ethernet"
    if "loopback" in normalized:
        return "Loopback"
    return "Network"


def _is_vpn_name(name: str) -> bool:
    normalized = name.casefold()
    return any(
        token in normalized
        for token in (
            "vpn",
            "tap",
            "tun",
            "wireguard",
            "wintun",
            "tunnel",
            "happ",
            "xray",
            "clash",
            "sing-box",
            "tailscale",
            "zerotier",
            "openvpn",
            "nordlynx",
        )
    )


def _optional_text(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _parse_percent(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(r"\d+", value)
    if match is None:
        return None
    return max(0, min(100, int(match.group())))


def _parse_rate_mbps(value: str | None) -> float | None:
    if not value:
        return None
    match = re.search(r"\d+(?:[.,]\d+)?", value)
    return float(match.group().replace(",", ".")) if match else None


def _decode_oem_output(value: bytes | str | None) -> str:
    if isinstance(value, str):
        return value
    return (value or b"").decode(_oem_encoding(), errors="replace")

