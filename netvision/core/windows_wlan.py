"""Read connected WLAN interfaces using the Windows Native Wifi API."""

import ctypes
import sys
import uuid
from ctypes import wintypes

from netvision.models import WifiSnapshot


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _Interface(ctypes.Structure):
    _fields_ = [("guid", _Guid), ("description", wintypes.WCHAR * 256), ("state", wintypes.DWORD)]


class _InterfaceList(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD), ("index", wintypes.DWORD), ("items", _Interface * 1)]


class _Ssid(ctypes.Structure):
    _fields_ = [("length", wintypes.ULONG), ("bytes", ctypes.c_ubyte * 32)]


class _Association(ctypes.Structure):
    _fields_ = [
        ("ssid", _Ssid),
        ("bss_type", wintypes.DWORD),
        ("bssid", ctypes.c_ubyte * 6),
        ("phy", wintypes.DWORD),
        ("phy_index", wintypes.ULONG),
        ("signal", wintypes.ULONG),
        ("rx", wintypes.ULONG),
        ("tx", wintypes.ULONG),
    ]


class _Security(ctypes.Structure):
    _fields_ = [
        ("enabled", wintypes.BOOL),
        ("one_x", wintypes.BOOL),
        ("authentication", wintypes.DWORD),
        ("cipher", wintypes.DWORD),
    ]


class _Connection(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("mode", wintypes.DWORD),
        ("profile", wintypes.WCHAR * 256),
        ("association", _Association),
        ("security", _Security),
    ]


def _configure(api):
    api.WlanOpenHandle.argtypes = (
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE),
    )
    api.WlanOpenHandle.restype = wintypes.DWORD
    api.WlanEnumInterfaces.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    api.WlanEnumInterfaces.restype = wintypes.DWORD
    api.WlanQueryInterface.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_Guid),
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    api.WlanQueryInterface.restype = wintypes.DWORD
    api.WlanFreeMemory.argtypes = (ctypes.c_void_p,)
    api.WlanFreeMemory.restype = None
    api.WlanCloseHandle.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
    api.WlanCloseHandle.restype = wintypes.DWORD


def _interface_name(guid):
    import winreg

    value = str(uuid.UUID(bytes_le=bytes(guid))).upper()
    path = rf"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{{{value}}}\Connection"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
        return winreg.QueryValueEx(key, "Name")[0]


def _query(api, handle, guid, opcode, result_type, required=False):
    size = wintypes.DWORD()
    data = ctypes.c_void_p()
    try:
        status = api.WlanQueryInterface(
            handle, ctypes.byref(guid), opcode, None, ctypes.byref(size), ctypes.byref(data), None
        )
        if status or not data.value or size.value < ctypes.sizeof(result_type):
            if required:
                raise OSError(status, "WlanQueryInterface failed")
            return None
        return result_type.from_buffer_copy(ctypes.string_at(data, ctypes.sizeof(result_type)))
    finally:
        if data.value:
            api.WlanFreeMemory(data)


def collect_windows_wifi() -> list[WifiSnapshot] | None:
    """Return connected interfaces, or None when Native Wifi is unavailable."""
    if sys.platform != "win32":
        return None
    handle = wintypes.HANDLE()
    interfaces = ctypes.c_void_p()
    opened = False
    try:
        api = ctypes.WinDLL("wlanapi")
        _configure(api)
        version = wintypes.DWORD()
        if api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)):
            return None
        opened = True
        if api.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces)) or not interfaces.value:
            return None
        count = ctypes.cast(interfaces, ctypes.POINTER(_InterfaceList)).contents.count
        if count > 1024:
            return None
        address = interfaces.value + _InterfaceList.items.offset
        snapshots = []
        for info in (_Interface * count).from_address(address):
            if info.state != 1:
                continue
            connection = _query(api, handle, info.guid, 7, _Connection, required=True)
            channel = _query(api, handle, info.guid, 8, wintypes.ULONG)
            rssi = _query(api, handle, info.guid, 0x10000102, ctypes.c_long)
            try:
                name = _interface_name(info.guid)
            except (ImportError, OSError, ValueError):
                return None
            assoc = connection.association
            if assoc.ssid.length > 32:
                return None
            number = channel.value if channel else None
            snapshots.append(
                WifiSnapshot(
                    interface_name=name,
                    ssid=bytes(assoc.ssid.bytes[: assoc.ssid.length]).decode("utf-8", "replace")
                    or None,
                    bssid=":".join(f"{part:02x}" for part in assoc.bssid),
                    radio_type={
                        4: "802.11a",
                        5: "802.11b",
                        6: "802.11g",
                        7: "802.11n",
                        8: "802.11ac",
                        9: "802.11ad",
                        10: "802.11ax",
                        11: "802.11be",
                    }.get(assoc.phy),
                    band=None,
                    channel=str(number) if number else None,
                    signal_pct=min(100, assoc.signal),
                    rx_mbps=assoc.rx / 1000,
                    tx_mbps=assoc.tx / 1000,
                    rssi_dbm=rssi.value if rssi else None,
                    profile=connection.profile or None,
                    authentication=str(connection.security.authentication),
                )
            )
        return snapshots
    except (OSError, AttributeError, ValueError):
        return None
    finally:
        if interfaces.value:
            api.WlanFreeMemory(interfaces)
        if opened:
            api.WlanCloseHandle(handle, None)
