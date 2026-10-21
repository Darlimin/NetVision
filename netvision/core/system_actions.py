from __future__ import annotations

from dataclasses import dataclass
import locale
import os
import re
import socket
import subprocess
import time
import ipaddress
from typing import Sequence

import psutil


@dataclass(frozen=True, slots=True)
class SystemChange:
    """A reversible DNS or MTU change captured before it was applied."""

    kind: str
    adapter: str
    before: object
    after: object


@dataclass(frozen=True)
class SystemActionResult:
    success: bool
    message: str
    change: SystemChange | None = None


@dataclass(frozen=True, slots=True)
class DnsAdapterState:
    """Registry-backed DNS state needed to restore an adapter exactly."""

    adapter_name: str
    interface_guid: str
    dhcp_enabled: bool
    name_server: str
    dhcp_name_server: str


_DNS_SNAPSHOTS: dict[str, DnsAdapterState] = {}
def flush_dns_cache() -> SystemActionResult:
    """Flush the Windows DNS resolver cache without opening a console window."""
    if os.name != "nt":
        return SystemActionResult(False, "Очистка DNS доступна только в Windows")

    try:
        completed = subprocess.run(
            ["ipconfig", "/flushdns"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return SystemActionResult(False, f"Не удалось очистить кэш DNS: {exc}")

    output = _decode_output(completed.stdout).strip()
    if completed.returncode == 0:
        return SystemActionResult(True, "Кэш DNS успешно очищен")

    details = output or f"код завершения {completed.returncode}"
    return SystemActionResult(False, f"Очистка DNS не выполнена: {details}")


def apply_dns_servers(adapter_name: str, servers: Sequence[str]) -> SystemActionResult:
    """Set IPv4 DNS servers for an adapter only after an explicit user action."""
    if os.name != "nt":
        return SystemActionResult(False, "Настройка DNS доступна только в Windows")
    if not adapter_name.strip():
        return SystemActionResult(False, "Выберите активный сетевой адаптер")
    if not servers:
        return SystemActionResult(False, "Не выбран DNS-профиль")

    normalized: list[str] = []
    try:
        for server in servers:
            address = ipaddress.ip_address(server)
            if address.version != 4:
                return SystemActionResult(False, "Автонастройка поддерживает только IPv4 DNS-профили")
            normalized.append(str(address))
    except ValueError:
        return SystemActionResult(False, "DNS-профиль содержит некорректный IP-адрес")

    snapshot = capture_dns_state(adapter_name)
    if snapshot is None:
        return SystemActionResult(
            False,
            "Не удалось сохранить текущие DNS-настройки для безопасного отката",
        )
    _DNS_SNAPSHOTS[adapter_name.casefold()] = snapshot

    commands = [
        [
            "netsh", "interface", "ipv4", "set", "dnsservers",
            f"name={adapter_name}", "source=static", f"address={normalized[0]}", "validate=no",
        ],
        *(
            [
                "netsh", "interface", "ipv4", "add", "dnsservers",
                f"name={adapter_name}", f"address={server}", f"index={index}", "validate=no",
            ]
            for index, server in enumerate(normalized[1:], start=2)
        ),
    ]
    try:
        for command in commands:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
            if completed.returncode != 0:
                details = _decode_output(completed.stdout).strip() or f"код завершения {completed.returncode}"
                restore_dns_state(snapshot)
                return SystemActionResult(
                    False,
                    f"Не удалось применить DNS: {details}. Возможно, нужны права администратора.",
                )
    except (OSError, subprocess.SubprocessError) as exc:
        restore_dns_state(snapshot)
        return SystemActionResult(False, f"Не удалось применить DNS: {exc}")
    return SystemActionResult(
        True,
        f"DNS для «{adapter_name}» обновлён: {', '.join(normalized)}",
        SystemChange("dns", adapter_name, snapshot, tuple(normalized)),
    )


def optimize_mtu(
    adapter_name: str,
    mtu: int | None = None,
    *,
    target_host: str | None = None,
) -> SystemActionResult:
    """Apply an explicit MTU trial; discovery belongs to ``mtu_optimizer``."""
    if os.name != "nt":
        return SystemActionResult(False, "Настройка MTU доступна только в Windows")
    if not adapter_name.strip():
        return SystemActionResult(False, "Не удалось определить активный сетевой адаптер")
    if mtu is None:
        return SystemActionResult(False, "Сначала выполните проверку MTU для выбранной цели")
    return apply_mtu_trial(adapter_name, mtu)


def apply_mtu_trial(
    adapter_name: str,
    mtu: int,
    *,
    before: int | None = None,
) -> SystemActionResult:
    """Apply MTU for the active session only, retaining state for rollback."""
    if os.name != "nt":
        return SystemActionResult(False, "Настройка MTU доступна только в Windows")
    if not adapter_name.strip() or not 576 <= mtu <= 9000:
        return SystemActionResult(False, "MTU должен быть в диапазоне от 576 до 9000")
    captured = capture_mtu_state(adapter_name) if before is None else before
    if captured is None:
        return SystemActionResult(False, "Не удалось определить текущий MTU для безопасного отката")
    result = _run_hidden_command(
        [
            "netsh", "interface", "ipv4", "set", "subinterface", adapter_name,
            f"mtu={mtu}", "store=active",
        ],
        "Не удалось применить пробный MTU",
    )
    if not result.success:
        return result
    return SystemActionResult(
        True,
        f"Пробный MTU {mtu} применён для «{adapter_name}»",
        SystemChange("mtu", adapter_name, captured, mtu),
    )


def persist_mtu(adapter_name: str, mtu: int) -> SystemActionResult:
    """Persist a previously verified MTU after the user confirms it."""
    if os.name != "nt":
        return SystemActionResult(False, "Настройка MTU доступна только в Windows")
    if not adapter_name.strip() or not 576 <= mtu <= 9000:
        return SystemActionResult(False, "MTU должен быть в диапазоне от 576 до 9000")
    result = _run_hidden_command(
        [
            "netsh", "interface", "ipv4", "set", "subinterface", adapter_name,
            f"mtu={mtu}", "store=persistent",
        ],
        "Не удалось сохранить MTU",
    )
    if result.success:
        return SystemActionResult(True, f"MTU {mtu} сохранён для «{adapter_name}»")
    return result


def capture_mtu_state(adapter_name: str) -> int | None:
    """Read the current IPv4 MTU for one Windows adapter."""
    if os.name != "nt" or not adapter_name.strip():
        return None
    try:
        completed = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    for line in _decode_output(completed.stdout).splitlines():
        match = re.match(r"^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+(.+?)\s*$", line)
        if match is None or match.group(2).casefold() != adapter_name.strip().casefold():
            continue
        mtu = int(match.group(1))
        return mtu if 576 <= mtu <= 9000 else None
    return None


def restore_mtu_state(adapter_name: str, mtu: int) -> SystemActionResult:
    """Restore a previously captured IPv4 MTU value."""
    if os.name != "nt":
        return SystemActionResult(False, "Восстановление MTU доступно только в Windows")
    if not adapter_name.strip() or not 576 <= mtu <= 9000:
        return SystemActionResult(False, "Недопустимое состояние MTU для отката")
    result = _run_hidden_command(
        [
            "netsh", "interface", "ipv4", "set", "subinterface", adapter_name,
            f"mtu={mtu}", "store=persistent",
        ],
        "Не удалось восстановить MTU",
    )
    if result.success:
        return SystemActionResult(True, f"MTU {mtu} восстановлен для «{adapter_name}»")
    return result


def restore_mtu(adapter_name: str, mtu: int) -> SystemActionResult:
    """Backward-compatible alias for restoring an MTU snapshot."""
    return restore_mtu_state(adapter_name, mtu)


def rollback_change(change: SystemChange) -> SystemActionResult:
    """Restore a change only when its captured state has the expected type."""
    if change.kind == "dns" and isinstance(change.before, DnsAdapterState):
        return restore_dns_state(change.before)
    if change.kind == "mtu" and isinstance(change.before, int):
        return restore_mtu_state(change.adapter, change.before)
    return SystemActionResult(False, "Сохранённое состояние для отката недоступно")


def capture_dns_state(adapter_name: str) -> DnsAdapterState | None:
    """Read static/DHCP DNS values from the adapter's Windows registry key."""
    if os.name != "nt" or not adapter_name.strip():
        return None
    try:
        import winreg

        interface_guid = _find_interface_guid(winreg, adapter_name)
        if not interface_guid:
            return None
        key_path = (
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
            + interface_guid
        )
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            enable_dhcp = int(_registry_value(winreg, key, "EnableDHCP", 0)) == 1
            name_server = str(_registry_value(winreg, key, "NameServer", "") or "")
            dhcp_name_server = str(_registry_value(winreg, key, "DhcpNameServer", "") or "")
        return DnsAdapterState(
            adapter_name=adapter_name,
            interface_guid=interface_guid,
            dhcp_enabled=enable_dhcp,
            name_server=name_server,
            dhcp_name_server=dhcp_name_server,
        )
    except (OSError, ImportError, ValueError, TypeError):
        return None


def restore_dns_state(state: DnsAdapterState) -> SystemActionResult:
    """Restore the exact DHCP/static mode captured before a DNS change."""
    if os.name != "nt":
        return SystemActionResult(False, "Восстановление DNS доступно только в Windows")
    if state.dhcp_enabled:
        return _run_hidden_command(
            [
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={state.adapter_name}", "source=dhcp",
            ],
            "Не удалось восстановить DHCP-DNS",
        )

    if not state.name_server.strip():
        return _run_hidden_command(
            [
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={state.adapter_name}", "source=static", "address=none",
            ],
            "Не удалось восстановить пустой статический DNS",
        )

    servers = [item for item in re.split(r"[,\s]+", state.name_server) if item]
    if not servers:
        return SystemActionResult(False, "В сохранённом состоянии DNS нет адресов")
    commands = [
        [
            "netsh", "interface", "ipv4", "set", "dnsservers",
            f"name={state.adapter_name}", "source=static", f"address={servers[0]}", "validate=no",
        ],
        *(
            [
                "netsh", "interface", "ipv4", "add", "dnsservers",
                f"name={state.adapter_name}", f"address={server}", f"index={index}", "validate=no",
            ]
            for index, server in enumerate(servers[1:], start=2)
        ),
    ]
    for command in commands:
        result = _run_hidden_command(command, "Не удалось восстановить статический DNS")
        if not result.success:
            return result
    return SystemActionResult(True, f"DNS для «{state.adapter_name}» восстановлен")


def restore_dns_for_adapter(adapter_name: str) -> SystemActionResult:
    state = _DNS_SNAPSHOTS.get(adapter_name.casefold())
    if state is None:
        return SystemActionResult(False, "Сохраненное состояние DNS для адаптера не найдено")
    return restore_dns_state(state)


def _find_interface_guid(winreg: object, adapter_name: str) -> str | None:
    control_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, control_path) as root:
            index = 0
            while True:
                try:
                    interface_guid = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                connection_path = f"{interface_guid}\\Connection"
                try:
                    with winreg.OpenKey(root, connection_path) as connection_key:
                        value, _ = winreg.QueryValueEx(connection_key, "Name")
                    if str(value).casefold() == adapter_name.casefold():
                        return interface_guid
                except OSError:
                    continue
    except OSError:
        return None
    return None


def _registry_value(winreg: object, key: object, name: str, default: object) -> object:
    try:
        value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return default
    return value


def reset_tcpip_stack() -> SystemActionResult:
    """Reset TCP/IP and Winsock; Windows requires a restart to finish applying it."""
    if os.name != "nt":
        return SystemActionResult(False, "Сброс TCP/IP доступен только в Windows")
    commands = (
        (["netsh", "int", "ip", "reset"], "Не удалось сбросить стек TCP/IP"),
        (["netsh", "winsock", "reset"], "Не удалось сбросить Winsock"),
    )
    for command, failure_prefix in commands:
        result = _run_hidden_command(command, failure_prefix)
        if not result.success:
            return result
    return SystemActionResult(True, "TCP/IP и Winsock сброшены. Перезагрузите Windows, чтобы завершить применение.")


def restart_network_adapter(adapter_name: str) -> SystemActionResult:
    """Disable and re-enable the selected adapter, temporarily dropping its connection."""
    if os.name != "nt":
        return SystemActionResult(False, "Перезапуск адаптера доступен только в Windows")
    if not adapter_name.strip():
        return SystemActionResult(False, "Не удалось определить активный сетевой адаптер")
    disabled = _run_hidden_command(
        ["netsh", "interface", "set", "interface", f"name={adapter_name}", "admin=disabled"],
        "Не удалось отключить адаптер",
    )
    if not disabled.success:
        return disabled
    enabled: SystemActionResult | None = None
    for attempt in range(3):
        enabled = _run_hidden_command(
            ["netsh", "interface", "set", "interface", f"name={adapter_name}", "admin=enabled"],
            "Не удалось включить адаптер",
        )
        if enabled.success:
            break
        if attempt < 2:
            time.sleep(0.5 * (attempt + 1))
    if enabled is None or not enabled.success:
        return enabled or SystemActionResult(False, "Не удалось включить адаптер")
    return SystemActionResult(True, f"Адаптер «{adapter_name}» перезапущен")


def restart_adapter_verified(adapter_name: str, timeout: float = 15.0) -> SystemActionResult:
    """Restart an adapter and wait until it is up with a usable IPv4 address."""
    if timeout <= 0:
        return SystemActionResult(False, "Время ожидания перезапуска адаптера должно быть положительным")
    result = restart_network_adapter(adapter_name)
    if not result.success:
        return result

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _adapter_has_usable_ipv4(adapter_name):
            return SystemActionResult(True, f"Адаптер «{adapter_name}» перезапущен и подключён")
        time.sleep(0.5)
    return SystemActionResult(
        False,
        f"Адаптер «{adapter_name}» включён, но не получил рабочий IPv4 за {timeout:.0f} с",
    )


def _adapter_has_usable_ipv4(adapter_name: str) -> bool:
    stats = psutil.net_if_stats().get(adapter_name)
    if stats is None or not stats.isup:
        return False
    for address in psutil.net_if_addrs().get(adapter_name, ()):
        if address.family != socket.AF_INET:
            continue
        try:
            candidate = ipaddress.ip_address(address.address)
        except ValueError:
            continue
        if not (candidate.is_loopback or candidate.is_link_local or candidate.is_unspecified):
            return True
    return False


def open_network_adapters() -> SystemActionResult:
    return _open_control_panel("ncpa.cpl", "Настройки адаптеров")


def open_network_proxy_settings() -> SystemActionResult:
    if os.name != "nt":
        return SystemActionResult(False, "Параметры сети доступны только в Windows")
    return _open_process(
        ["explorer.exe", "ms-settings:network-proxy"],
        "Параметры сети и прокси",
    )


def open_windows_firewall() -> SystemActionResult:
    return _open_control_panel("firewall.cpl", "Брандмауэр Windows")


def _open_control_panel(control_file: str, label: str) -> SystemActionResult:
    if os.name != "nt":
        return SystemActionResult(False, f"{label} доступны только в Windows")
    return _open_process(["control.exe", control_file], label)


def _run_hidden_command(command: Sequence[str], failure_prefix: str) -> SystemActionResult:
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return SystemActionResult(False, f"{failure_prefix}: {exc}")
    if completed.returncode == 0:
        return SystemActionResult(True, "Команда выполнена")
    details = _decode_output(completed.stdout).strip() or f"код завершения {completed.returncode}"
    return SystemActionResult(False, f"{failure_prefix}: {details}. Возможно, нужны права администратора.")


def _open_process(command: Sequence[str], label: str) -> SystemActionResult:
    try:
        subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return SystemActionResult(False, f"Не удалось открыть «{label}»: {exc}")
    return SystemActionResult(True, f"Открыто: {label}")


def _decode_output(value: bytes | str | None) -> str:
    if isinstance(value, str):
        return value
    if not value:
        return ""
    encoding = _oem_encoding()
    return value.decode(encoding, errors="replace")


def _oem_encoding() -> str:
    """Return the active Windows console OEM code page for command output."""
    if os.name != "nt":
        return locale.getpreferredencoding(False) or "utf-8"
    try:
        import ctypes

        code_page = int(ctypes.windll.kernel32.GetOEMCP())
        return f"cp{code_page}" if code_page else "cp866"
    except (AttributeError, OSError, ValueError):
        return "cp866"
