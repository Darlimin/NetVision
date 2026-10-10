from __future__ import annotations

from dataclasses import dataclass
import locale
import os
import subprocess
import ipaddress
from typing import Sequence


@dataclass(frozen=True)
class SystemActionResult:
    success: bool
    message: str


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
                return SystemActionResult(
                    False,
                    f"Не удалось применить DNS: {details}. Возможно, нужны права администратора.",
                )
    except (OSError, subprocess.SubprocessError) as exc:
        return SystemActionResult(False, f"Не удалось применить DNS: {exc}")
    return SystemActionResult(True, f"DNS для «{adapter_name}» обновлён: {', '.join(normalized)}")


def optimize_mtu(adapter_name: str, mtu: int = 1500) -> SystemActionResult:
    """Apply a conservative Ethernet MTU to a named adapter on explicit request."""
    if os.name != "nt":
        return SystemActionResult(False, "Настройка MTU доступна только в Windows")
    if not adapter_name.strip():
        return SystemActionResult(False, "Не удалось определить активный сетевой адаптер")
    if not 576 <= mtu <= 9000:
        return SystemActionResult(False, "MTU должен быть в диапазоне от 576 до 9000")
    result = _run_hidden_command(
        ["netsh", "interface", "ipv4", "set", "subinterface", adapter_name, f"mtu={mtu}", "store=persistent"],
        "Не удалось применить MTU",
    )
    if result.success:
        return SystemActionResult(True, f"MTU {mtu} применён для «{adapter_name}»")
    return result


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
    for admin, failure_prefix in (("disabled", "Не удалось отключить адаптер"), ("enabled", "Не удалось включить адаптер")):
        result = _run_hidden_command(
            ["netsh", "interface", "set", "interface", f"name={adapter_name}", f"admin={admin}"],
            failure_prefix,
        )
        if not result.success:
            return result
    return SystemActionResult(True, f"Адаптер «{adapter_name}» перезапущен")


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
    encoding = locale.getpreferredencoding(False) or "utf-8"
    return value.decode(encoding, errors="replace")
