"""Evidence-based traffic path snapshot; unknown values remain explicit."""

import ctypes
import ipaddress
import json
import socket
import sys
import urllib.request
import urllib.error
from ctypes import wintypes
from urllib.parse import urlsplit, urlunsplit
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from collections import Counter

from netvision.core.system import (
    _collect_default_routes,
    _collect_interfaces,
    collect_dns_configuration,
    _is_vpn_name,
)
from netvision.core.windows_routes import (
    _ForwardRow,
    _AddressRow,
    _read_table,
    _ipv4,
    _configure_api,
    _select_address,
)
from netvision.core.process_inspector import (
    _collect_inet_connections,
    _process_name,
    is_public_address,
)
import psutil


@dataclass(frozen=True, slots=True)
class KernelRouteInfo:
    adapter: str | None = None
    local_ip: str | None = None
    gateway: str | None = None
    metric: int | None = None
    mode: str = "unknown"
    source: str = "fallback"
    secondary_physical_route: bool = False


@dataclass(frozen=True, slots=True)
class SystemProxyInfo:
    enabled: bool | None = None
    server: str | None = None
    bypass: str | None = None
    pac_url: str | None = None
    pac_active: bool = False
    winhttp: str | None = None
    is_local_proxy: bool = False
    host: str | None = None
    port: int | None = None
    owner_pid: int | None = None
    owner_name: str | None = None


@dataclass(frozen=True, slots=True)
class DnsPolicyInfo:
    servers: tuple[str, ...] = ()
    doh_enabled: bool | None = None
    nrpt_rules: int | None = None


@dataclass(frozen=True, slots=True)
class EgressPathInfo:
    direct_ip: str | None = None
    direct_asn: str | None = None
    direct_provider: str | None = None
    direct_country: str | None = None
    direct_error: str | None = None
    proxy_ip: str | None = None
    proxy_asn: str | None = None
    proxy_provider: str | None = None
    proxy_country: str | None = None
    proxy_error: str | None = None
    differs_from_direct: bool | None = None


@dataclass(frozen=True, slots=True)
class SocketChannelSummary:
    channel: str
    interface: str | None
    address: str | None
    count: int
    top_processes: tuple[str, ...] = ()
    application_count: int | None = None


@dataclass(frozen=True, slots=True)
class TrafficPathSnapshot:
    collected_at: datetime
    route: KernelRouteInfo
    proxy: SystemProxyInfo
    dns: DnsPolicyInfo
    egress: EgressPathInfo
    channels: tuple[SocketChannelSummary, ...] = ()


def _best_route() -> _ForwardRow:
    if sys.platform != "win32":
        raise OSError("Windows IP Helper unavailable")
    function = ctypes.WinDLL("iphlpapi").GetBestRoute
    function.argtypes = (wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_ForwardRow))
    function.restype = wintypes.DWORD
    row = _ForwardRow()
    destination = int.from_bytes(socket.inet_aton("1.1.1.1"), "little")
    status = function(destination, 0, ctypes.byref(row))
    if status:
        raise OSError(status, "GetBestRoute failed")
    return row


def _registry_value(root, path: str, name: str):
    try:
        import winreg

        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except (ImportError, OSError):
        return None


def _sanitize_url(value: str) -> str:
    try:
        raw = value if "://" in value else "http://" + value
        parsed = urlsplit(raw)
        host = parsed.hostname
        if not host:
            return "<proxy configured>"
        host = f"[{host}]" if ":" in host else host
        return urlunsplit(
            (parsed.scheme, host + (f":{parsed.port}" if parsed.port else ""), "", "", "")
        )
    except ValueError:
        return "<proxy configured>"


def _sanitize_pac(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if not host:
            return "<PAC configured>"
        host = f"[{host}]" if ":" in host else host
        return urlunsplit(
            (parsed.scheme, host + (f":{parsed.port}" if parsed.port else ""), parsed.path, "", "")
        )
    except ValueError:
        return "<PAC configured>"


def _winhttp_proxy() -> str | None:
    if sys.platform != "win32":
        return None

    class ProxyConfig(ctypes.Structure):
        _fields_ = [
            ("access", wintypes.DWORD),
            ("proxy", ctypes.c_void_p),
            ("bypass", ctypes.c_void_p),
        ]

    try:
        api = ctypes.WinDLL("winhttp", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_config = api.WinHttpGetDefaultProxyConfiguration
        get_config.argtypes = (ctypes.POINTER(ProxyConfig),)
        get_config.restype = wintypes.BOOL
        free = kernel.GlobalFree
        free.argtypes = (ctypes.c_void_p,)
        free.restype = ctypes.c_void_p
        config = ProxyConfig()
        if not get_config(ctypes.byref(config)):
            return None
        try:
            value = ctypes.wstring_at(config.proxy) if config.proxy else None
            return _sanitize_url(value) if value else None
        finally:
            if config.proxy:
                free(config.proxy)
            if config.bypass:
                free(config.bypass)
    except (OSError, AttributeError, ValueError):
        return None


def _proxy_entries(value: str) -> tuple[str | None, str | None]:
    entries = {}
    for part in value.split(";"):
        if not part.strip():
            continue
        key, sep, target = part.partition("=")
        entries[key.strip().lower() if sep else "default"] = target.strip() if sep else key.strip()
    preferred = next(
        (entries[key] for key in ("https", "http", "socks", "default") if key in entries), None
    )
    display = ";".join(
        (f"{key}=" if key != "default" else "") + _sanitize_url(target)
        for key, target in entries.items()
    )
    if (
        preferred
        and "socks" in entries
        and preferred == entries["socks"]
        and "://" not in preferred
    ):
        preferred = "socks5://" + preferred
    return preferred, display or None


def _raw_proxy() -> str:
    try:
        import winreg

        return str(
            _registry_value(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "ProxyServer",
            )
            or ""
        )
    except ImportError:
        return ""


def _proxy_info() -> SystemProxyInfo:
    try:
        import winreg
    except ImportError:
        return SystemProxyInfo()
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    enabled = _registry_value(winreg.HKEY_CURRENT_USER, path, "ProxyEnable")
    raw = _registry_value(winreg.HKEY_CURRENT_USER, path, "ProxyServer")
    bypass = _registry_value(winreg.HKEY_CURRENT_USER, path, "ProxyOverride")
    pac = _registry_value(winreg.HKEY_CURRENT_USER, path, "AutoConfigURL")
    preferred, sanitized = _proxy_entries(str(raw or ""))
    parsed = urlsplit(_sanitize_url(preferred)) if preferred else None
    host = parsed.hostname if parsed else None
    port = parsed.port if parsed else None
    local = host is not None and host.casefold() in {"localhost", "127.0.0.1", "::1"}
    pid = None
    name = None
    if local and port:
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == "LISTEN" and conn.laddr and conn.laddr.port == port and conn.pid:
                    pid = conn.pid
                    try:
                        name = psutil.Process(pid).name()
                    except (psutil.Error, OSError):
                        pass
                    break
        except (psutil.Error, OSError):
            pass
    return SystemProxyInfo(
        enabled=bool(enabled) if enabled is not None else None,
        server=sanitized or None,
        bypass=str(bypass) if bypass else None,
        pac_url=_sanitize_pac(str(pac)) if pac else None,
        pac_active=bool(pac),
        winhttp=_winhttp_proxy(),
        is_local_proxy=local,
        host=host,
        port=port,
        owner_pid=pid,
        owner_name=name,
    )


def _dns_policy() -> DnsPolicyInfo:
    try:
        servers = collect_dns_configuration().servers
    except (OSError, ValueError):
        servers = ()
    try:
        import winreg

        doh = _registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "EnableAutoDoh",
        )
        path = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                count = winreg.QueryInfoKey(key)[0]
        except OSError:
            count = None
        return DnsPolicyInfo(servers, bool(doh) if doh is not None else None, count)
    except ImportError:
        return DnsPolicyInfo(servers)


def _egress(proxy: str | None, timeout: float) -> tuple:
    if proxy and "://" not in proxy:
        proxy = "http://" + proxy
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})
    )
    try:
        with opener.open("https://ipwho.is/", timeout=timeout) as response:
            payload = json.loads(response.read(65536))
        ip = str(ipaddress.ip_address(payload["ip"]))
        connection = payload.get("connection") or {}
        return (
            ip,
            str(connection.get("asn") or "") or None,
            connection.get("isp"),
            payload.get("country"),
            None,
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 407:
            return None, None, None, None, "Proxy authentication required (HTTP 407)"
        return None, None, None, None, f"HTTP {exc.code}"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if proxy and "407" in str(exc):
            return None, None, None, None, "Proxy authentication required (HTTP 407)"
        return None, None, None, None, f"{type(exc).__name__}: request failed"


def _channels(interfaces, proxy: SystemProxyInfo) -> tuple[SocketChannelSummary, ...]:
    groups = {}
    applications = Counter()
    try:
        observed = _collect_inet_connections(psutil.net_connections(kind="inet"))
    except (psutil.Error, OSError):
        return ()
    names = {}
    for item in observed:
        connection = item.connection
        if item.pid not in names:
            names[item.pid] = _process_name(item.pid) if item.pid is not None else "Unknown"
        name = names[item.pid]
        if connection.remote_address and connection.remote_port:
            if not connection.remote_address or not connection.remote_port:
                continue
            local = connection.local_address
            interface = next((i for i in interfaces if local in (*i.ipv4, *i.ipv6)), None)
            if (
                proxy.enabled
                and proxy.is_local_proxy
                and connection.remote_address in {"127.0.0.1", "::1"}
                and connection.remote_port == proxy.port
            ):
                channel = "local_proxy"
            elif (
                not is_public_address(connection.remote_address)
                or ipaddress.ip_address(connection.remote_address).is_multicast
            ):
                continue
            elif interface and interface.kind == "VPN":
                channel = "vpn_tun"
            elif interface and interface.kind != "Loopback":
                channel = "physical"
            else:
                channel = "other"
            key = (channel, interface.name if interface else None, local)
            groups.setdefault(key, []).append(name)
            if not _is_vpn_name(name) and name.casefold() not in {
                "xray.exe",
                "happd.exe",
                "sing-box.exe",
                "v2ray.exe",
                "openvpn.exe",
                "wireguard.exe",
            }:
                applications[key] += 1
    return tuple(
        SocketChannelSummary(
            *key,
            len(names),
            tuple(name for name, _ in Counter(names).most_common(5)),
            applications[key],
        )
        for key, names in groups.items()
    )


def _route_by_index(best, interfaces, routes):
    api = ctypes.WinDLL("iphlpapi")
    _configure_api(api)
    rows = _read_table(api.GetIpAddrTable, _AddressRow)
    address_rows = [row for row in rows if row.index == best.index]
    addresses = {_ipv4(row.address) for row in address_rows}
    candidates = [interface for interface in interfaces if addresses.intersection(interface.ipv4)]
    if len(candidates) != 1:
        gateway = _ipv4(best.next_hop)
        matches = [route for route in routes if route.gateway == gateway]
        if addresses:
            exact = [route for route in matches if route.local_address in addresses]
            if exact:
                matches = exact
            else:
                try:
                    networks = [
                        ipaddress.IPv4Network((_ipv4(row.address), _ipv4(row.mask)), strict=False)
                        for row in address_rows
                    ]
                    matches = [
                        route
                        for route in matches
                        if route.local_address
                        and any(ipaddress.IPv4Address(route.local_address) in n for n in networks)
                    ]
                except ValueError:
                    return None
        return matches[0] if len(matches) == 1 else None
    interface = candidates[0]
    local = next(
        (
            route.local_address
            for route in routes
            if route.interface == interface.name and route.local_address in addresses
        ),
        None,
    )
    if local is None:
        candidates = [
            (_ipv4(row.address), _ipv4(row.mask))
            for row in address_rows
            if _ipv4(row.address) in interface.ipv4
        ]
        if candidates:
            try:
                local = _select_address(candidates, _ipv4(best.next_hop))
            except OSError:
                return None
    if local is None:
        return None
    from netvision.models import DefaultRoute

    gateway = _ipv4(best.next_hop)
    on_link = best.kind == 3 or gateway == "0.0.0.0"
    return DefaultRoute(
        local if on_link else gateway,
        interface.name,
        local,
        best.metric,
        interface.kind == "VPN",
        on_link,
    )


def _has_vpn_route(interfaces) -> bool:
    """Look for any usable IPv4 route on an active VPN interface, not only defaults."""
    if sys.platform != "win32":
        return False
    try:
        api = ctypes.WinDLL("iphlpapi")
        _configure_api(api)
        addresses = _read_table(api.GetIpAddrTable, _AddressRow)
        vpn_addresses = {
            address
            for interface in interfaces
            if interface.kind == "VPN" and interface.is_up
            for address in interface.ipv4
        }
        indexes = {row.index for row in addresses if _ipv4(row.address) in vpn_addresses}
        return any(
            row.index in indexes and row.kind != 2
            for row in _read_table(api.GetIpForwardTable, _ForwardRow)
        )
    except (OSError, AttributeError):
        return False


def collect_traffic_path_snapshot(
    include_egress: bool = True, timeout: float = 4.0
) -> TrafficPathSnapshot:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    interfaces = ()
    routes = ()
    try:
        interfaces = _collect_interfaces()
        routes = _collect_default_routes(interfaces)
        try:
            best = _best_route()
            selected = _route_by_index(best, interfaces, routes)
            if selected is None:
                selected = routes[0] if routes else None
                source = "fallback"
            else:
                source = "windows_api"
        except (OSError, AttributeError):
            selected = routes[0] if routes else None
            source = "fallback"
        route = KernelRouteInfo(
            adapter=selected.interface if selected else None,
            local_ip=selected.local_address if selected else None,
            gateway=selected.gateway if selected else None,
            metric=selected.metric if selected else None,
            mode=("vpn_tun" if selected.is_vpn else "direct") if selected else "unknown",
            source=source,
            secondary_physical_route=bool(
                selected and selected.is_vpn and any(not r.is_vpn for r in routes)
            ),
        )
    except (OSError, ValueError):
        route = KernelRouteInfo()
    proxy = _proxy_info()
    channels = _channels(interfaces, proxy)
    active_channels = {channel.channel for channel in channels if channel.count}
    vpn_active = any(interface.kind == "VPN" and interface.is_up for interface in interfaces)
    physical_apps = any(
        c.channel == "physical"
        and (c.application_count if c.application_count is not None else c.count) > 0
        for c in channels
    )
    if route.mode == "vpn_tun" and physical_apps:
        route = replace(route, mode="split_tunnel")
    elif route.mode == "direct" and (
        (
            vpn_active
            and (
                "vpn_tun" in active_channels
                or any(r.is_vpn for r in routes)
                or _has_vpn_route(interfaces)
            )
        )
        or (proxy.enabled and proxy.is_local_proxy)
    ):
        route = replace(route, mode="split_tunnel")
    if include_egress:
        direct = _egress(None, timeout)
        selected_proxy, _ = _proxy_entries(_raw_proxy())
        if proxy.pac_active and not selected_proxy:
            proxied = (None, None, None, None, "PAC evaluation unavailable")
        elif proxy.enabled and selected_proxy:
            if selected_proxy.startswith("socks"):
                proxied = (None, None, None, None, "SOCKS proxy unsupported")
            else:
                proxied = _egress(selected_proxy, timeout)
        else:
            proxied = (None, None, None, None, None)
        egress = EgressPathInfo(
            *direct,
            *proxied,
            differs_from_direct=(direct[0] != proxied[0] if direct[0] and proxied[0] else None),
        )
    else:
        egress = EgressPathInfo()
    return TrafficPathSnapshot(
        datetime.now(timezone.utc),
        route,
        proxy,
        _dns_policy(),
        egress,
        channels,
    )


def format_traffic_path_summary(snapshot: TrafficPathSnapshot, lang: str = "ru") -> str:
    en = lang == "en"
    unknown = "Unknown" if en else "Не определён"
    labels = (
        ("Route", "Proxy", "DNS", "Egress", "Sockets")
        if en
        else ("Маршрут", "Прокси", "DNS", "Выход", "Сокеты")
    )
    proxy = snapshot.proxy
    # Values can come from persisted snapshots; redact again at the presentation boundary.
    _, server = _proxy_entries(proxy.server or "")
    modes = {
        "direct": "Direct" if en else "Прямой",
        "vpn_tun": "VPN (TUN)",
        "split_tunnel": "Split-tunnel" if en else "Split-tunnel (раздельный маршрут)",
        "unknown": unknown,
    }
    channel_names = {
        "vpn_tun": "VPN (TUN)",
        "local_proxy": "Local proxy" if en else "Локальный прокси",
        "physical": "Physical adapter" if en else "Физический адаптер",
        "other": "Other" if en else "Другое",
    }
    channel_text = (
        "; ".join(
            f"{channel_names.get(c.channel, unknown)}: {c.count} · {c.interface or unknown} · {c.address or unknown} ({', '.join(c.top_processes)})"
            for c in snapshot.channels
        )
        or unknown
    )
    safe_errors = {
        "Proxy authentication required (HTTP 407)",
        "PAC evaluation unavailable",
        "SOCKS proxy unsupported",
    }

    def endpoint(ip, asn, provider, country, error):
        details = ", ".join(str(v) for v in (asn, provider, country) if v)
        value = ip or unknown
        if details:
            value += f" ({details})"
        if error:
            value += " · " + (
                error if error in safe_errors else ("Request failed" if en else "Ошибка запроса")
            )
        return value

    proxy_parts = [
        v
        for v in (
            server,
            _sanitize_url(proxy.winhttp) if proxy.winhttp else None,
            _sanitize_pac(proxy.pac_url) if proxy.pac_url else None,
        )
        if v
    ]
    proxy_text = " · ".join(proxy_parts) or ("not configured" if en else "не настроен")
    if proxy.owner_pid:
        proxy_text += f" · PID {proxy.owner_pid}"
    if proxy.owner_name:
        proxy_text += f" · {proxy.owner_name}"
    dns = snapshot.dns
    doh = (
        ("enabled" if en else "включён")
        if dns.doh_enabled
        else ("not detected" if en else "не обнаружен")
    )
    nrpt = str(dns.nrpt_rules) if dns.nrpt_rules else ("no rules" if en else "нет правил")
    e = snapshot.egress
    egress = endpoint(
        e.direct_ip, e.direct_asn, e.direct_provider, e.direct_country, e.direct_error
    )
    if proxy.enabled or proxy.pac_active or proxy.winhttp:
        egress += " / " + endpoint(
            e.proxy_ip, e.proxy_asn, e.proxy_provider, e.proxy_country, e.proxy_error
        )
        if e.differs_from_direct is not None:
            egress += " · " + (
                ("different" if en else "различаются")
                if e.differs_from_direct
                else ("same" if en else "совпадают")
            )
    return "\n".join(
        (
            f"{labels[0]}: {modes.get(snapshot.route.mode, unknown)} · {snapshot.route.adapter or unknown} · {snapshot.route.local_ip or unknown} · {snapshot.route.gateway or unknown}"
            + (f" · metric {snapshot.route.metric}" if snapshot.route.metric is not None else ""),
            f"{labels[1]}: {proxy_text}",
            f"{labels[2]}: {', '.join(dns.servers) or unknown} · DoH: {doh} · NRPT: {nrpt}",
            f"{labels[3]}: {egress}",
            f"{labels[4]}: {channel_text}",
        )
    )
