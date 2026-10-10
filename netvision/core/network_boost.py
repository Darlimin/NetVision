from __future__ import annotations

from dataclasses import dataclass
import logging
import math
import os
import socket
from typing import Iterable

import psutil


logger = logging.getLogger("NetVision.NetworkBoost")
PROTECTED_PIDS = frozenset({0, 4})


# These are Windows processes which must never be presented as a candidate.
# Kernel drivers are not user-mode psutil processes, so they cannot be selected
# or terminated through this module in the first place.
PROTECTED_PROCESS_NAMES = frozenset(
    {
        "system idle process",
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "explorer.exe",
        "sihost.exe",
        "shellexperiencehost.exe",
        "startmenuexperiencehost.exe",
        "searchhost.exe",
        "searchindexer.exe",
        "runtimebroker.exe",
        "applicationframehost.exe",
        "taskhostw.exe",
        "taskmgr.exe",
        "conhost.exe",
        "dllhost.exe",
        "wudfhost.exe",
        "wmiprvse.exe",
        "spoolsv.exe",
        "audiodg.exe",
        "ctfmon.exe",
        "msmpeng.exe",
        "nisrv.exe",
        "securityhealthservice.exe",
        "securityhealthsystray.exe",
        "applemobiledeviceservice.exe",
        "mdnsresponder.exe",
        "netvision.exe",
        "netvision",
        "python.exe",
        "pythonw.exe",
        "python",
        "python3",
    }
)

# Only explicitly recognised user applications are candidates. Browsers and
# unknown executables are deliberately excluded: NetVision cannot determine
# from psutil alone whether they are intentionally being used by the person.
TRAFFIC_APP_CATALOG: dict[str, tuple[str, str]] = {
    "qbittorrent.exe": ("Торрент-клиент", "qBittorrent"),
    "utorrent.exe": ("Торрент-клиент", "uTorrent"),
    "bittorrent.exe": ("Торрент-клиент", "BitTorrent"),
    "transmission-qt.exe": ("Торрент-клиент", "Transmission"),
    "deluge.exe": ("Торрент-клиент", "Deluge"),
    "vuze.exe": ("Торрент-клиент", "Vuze"),
    "onedrive.exe": ("Облачная синхронизация", "Microsoft OneDrive"),
    "googledrivefs.exe": ("Облачная синхронизация", "Google Drive"),
    "googledrive.exe": ("Облачная синхронизация", "Google Drive"),
    "yandexdisk.exe": ("Облачная синхронизация", "Яндекс Диск"),
    "dropbox.exe": ("Облачная синхронизация", "Dropbox"),
    "megasync.exe": ("Облачная синхронизация", "MEGA Sync"),
    "steam.exe": ("Игровой лаунчер", "Steam"),
    "steamwebhelper.exe": ("Игровой лаунчер", "Steam Client WebHelper"),
    "epicgameslauncher.exe": ("Игровой лаунчер", "Epic Games Launcher"),
    "epicwebhelper.exe": ("Игровой лаунчер", "Epic Web Helper"),
    "battle.net.exe": ("Игровой лаунчер", "Battle.net"),
    "riotclientservices.exe": ("Игровой лаунчер", "Riot Client"),
    "ubisoftconnect.exe": ("Игровой лаунчер", "Ubisoft Connect"),
    "eadesktop.exe": ("Игровой лаунчер", "EA app"),
    "origin.exe": ("Игровой лаунчер", "EA Origin"),
    "obs64.exe": ("Стриминг", "OBS Studio"),
    "obs.exe": ("Стриминг", "OBS Studio"),
    "streamlabs.exe": ("Стриминг", "Streamlabs"),
    "xsplit.core.exe": ("Стриминг", "XSplit"),
    "spotify.exe": ("Потоковое аудио", "Spotify"),
    "discord.exe": ("Фоновая связь", "Discord"),
}

_ACTIVE_TCP_STATUSES = frozenset({"ESTABLISHED", "SYN_SENT", "SYN_RECV"})


@dataclass(frozen=True, slots=True)
class BackgroundTrafficCandidate:
    pid: int
    name: str
    display_name: str
    category: str
    active_connection_count: int
    # A PID can be recycled even for an executable with the same name.
    create_time: float | None = None

    @property
    def label(self) -> str:
        suffix = "сокет" if self.active_connection_count == 1 else "сокетов"
        return f"{self.display_name} · {self.category} · PID {self.pid} · {self.active_connection_count} {suffix}"


@dataclass(frozen=True, slots=True)
class NetworkBoostScanResult:
    candidates: tuple[BackgroundTrafficCandidate, ...]
    warning: str | None = None


@dataclass(frozen=True, slots=True)
class ProcessTerminationResult:
    pid: int
    name: str
    success: bool
    message: str


def is_protected_process(name: str, pid: int | None = None) -> bool:
    """Return whether the process is protected from Network Boost actions."""
    normalized = (name or "").strip().casefold()
    return (
        (pid is not None and (type(pid) is not int or pid <= 0))
        or pid in PROTECTED_PIDS
        or pid in {os.getpid(), os.getppid()}
        or normalized in PROTECTED_PROCESS_NAMES
        or normalized.startswith("netvision")
    )


def scan_background_traffic_candidates() -> NetworkBoostScanResult:
    """Find recognised background apps which currently hold active network sockets."""
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return NetworkBoostScanResult(
            (),
            "Windows не разрешила прочитать системные сетевые сокеты. Запустите NetVision с нужными правами.",
        )
    except OSError as exc:
        return NetworkBoostScanResult((), f"Не удалось получить сетевые соединения: {exc}")

    connection_counts: dict[int, int] = {}
    for connection in connections:
        pid = getattr(connection, "pid", None)
        if type(pid) is not int or is_protected_process("", pid) or not _is_active_socket(connection):
            continue
        connection_counts[pid] = connection_counts.get(pid, 0) + 1

    candidates: list[BackgroundTrafficCandidate] = []
    for pid, count in connection_counts.items():
        try:
            process = psutil.Process(pid)
            name = process.name() or ""
            create_time = process.create_time()
            if not process.is_running():
                continue
        except (psutil.Error, OSError):
            continue
        if not name or is_protected_process(name, pid):
            continue
        profile = TRAFFIC_APP_CATALOG.get(name.strip().casefold())
        if profile is None:
            continue
        category, display_name = profile
        candidates.append(
            BackgroundTrafficCandidate(
                pid=pid,
                name=name,
                display_name=display_name,
                category=category,
                active_connection_count=count,
                create_time=create_time,
            )
        )

    return NetworkBoostScanResult(
        tuple(sorted(candidates, key=lambda item: (-item.active_connection_count, item.display_name.casefold(), item.pid)))
    )


def terminate_background_candidates(
    candidates: Iterable[BackgroundTrafficCandidate],
    *,
    timeout_s: float = 3.0,
) -> tuple[ProcessTerminationResult, ...]:
    """Terminate explicitly selected processes; Windows termination is forceful.

    Never escalate to kill on timeout. Process identity must match the scan.
    """
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("timeout_s must be finite and positive")
    results: list[ProcessTerminationResult] = []
    handled_pids: set[int] = set()
    for candidate in candidates:
        if candidate.pid in handled_pids:
            continue
        handled_pids.add(candidate.pid)
        result = _terminate_candidate(candidate, timeout_s)
        logger.log(logging.INFO if result.success else logging.WARNING,
                   "PID %s (%s): %s", result.pid, result.name, result.message)
        results.append(result)
    return tuple(results)


def _terminate_candidate(candidate: BackgroundTrafficCandidate, timeout_s: float) -> ProcessTerminationResult:
    if is_protected_process(candidate.name, candidate.pid):
        return ProcessTerminationResult(candidate.pid, candidate.name, False, "Процесс защищён и не может быть завершён")
    if candidate.name.strip().casefold() not in TRAFFIC_APP_CATALOG:
        return ProcessTerminationResult(candidate.pid, candidate.name, False, "Процесс не входит в разрешённый список Network Boost")
    if candidate.create_time is None or not math.isfinite(candidate.create_time):
        return ProcessTerminationResult(candidate.pid, candidate.name, False, "Нет данных о времени создания процесса. Повторите сканирование.")

    try:
        process = psutil.Process(candidate.pid)
        current_name = process.name() or ""
        current_create_time = process.create_time()
    except psutil.NoSuchProcess:
        return ProcessTerminationResult(candidate.pid, candidate.name, True, "Процесс уже завершился")
    except psutil.AccessDenied:
        return ProcessTerminationResult(candidate.pid, candidate.name, False, "Нет прав для завершения процесса")
    except OSError as exc:
        return ProcessTerminationResult(candidate.pid, candidate.name, False, f"Не удалось открыть процесс: {exc}")

    if (current_name.strip().casefold() != candidate.name.strip().casefold()
            or current_create_time != candidate.create_time):
        return ProcessTerminationResult(candidate.pid, candidate.name, False, "PID уже принадлежит другому процессу")
    if is_protected_process(current_name, candidate.pid):
        return ProcessTerminationResult(candidate.pid, current_name, False, "Процесс защищён и не может быть завершён")

    try:
        process.terminate()
        process.wait(timeout=timeout_s)
    except psutil.NoSuchProcess:
        return ProcessTerminationResult(candidate.pid, current_name, True, "Процесс завершён")
    except psutil.TimeoutExpired:
        return ProcessTerminationResult(
            candidate.pid,
            current_name,
            False,
            "Завершение не подтверждено за отведённое время; повторный kill не применяется",
        )
    except psutil.AccessDenied:
        return ProcessTerminationResult(candidate.pid, current_name, False, "Нет прав для завершения процесса")
    except OSError as exc:
        return ProcessTerminationResult(candidate.pid, current_name, False, f"Не удалось завершить процесс: {exc}")
    return ProcessTerminationResult(candidate.pid, current_name, True, "Процесс завершён")


def _is_active_socket(connection: object) -> bool:
    connection_type = getattr(connection, "type", None)
    if connection_type == socket.SOCK_DGRAM:
        return bool(getattr(connection, "laddr", None))
    if connection_type != socket.SOCK_STREAM:
        return False
    return str(getattr(connection, "status", "")).upper() in _ACTIVE_TCP_STATUSES


