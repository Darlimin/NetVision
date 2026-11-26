import ctypes
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from netvision.core import windows_wlan as wlan
from netvision.core.system import collect_wifi_snapshot


def test_signatures():
    api = SimpleNamespace(
        **{
            name: MagicMock()
            for name in (
                "WlanOpenHandle",
                "WlanEnumInterfaces",
                "WlanQueryInterface",
                "WlanFreeMemory",
                "WlanCloseHandle",
            )
        }
    )
    wlan._configure(api)
    for name in (
        "WlanOpenHandle",
        "WlanEnumInterfaces",
        "WlanQueryInterface",
        "WlanFreeMemory",
        "WlanCloseHandle",
    ):
        function = getattr(api, name)
        assert function.argtypes is not None
        assert function.restype is (None if name == "WlanFreeMemory" else ctypes.wintypes.DWORD)


def test_connected_interface_and_resource_cleanup():
    api = SimpleNamespace(
        **{
            name: MagicMock(return_value=0)
            for name in (
                "WlanOpenHandle",
                "WlanEnumInterfaces",
                "WlanQueryInterface",
                "WlanFreeMemory",
                "WlanCloseHandle",
            )
        }
    )
    interfaces = wlan._InterfaceList()
    interfaces.count = 1
    interfaces.items[0].state = 1
    connection = wlan._Connection()
    raw = "Сеть".encode()
    connection.association.ssid.length = len(raw)
    connection.association.ssid.bytes[: len(raw)] = raw
    connection.association.bssid[:] = (0, 1, 2, 3, 4, 5)
    connection.association.phy = 10
    connection.association.signal = 85
    connection.association.rx = 433300
    connection.association.tx = 144400
    connection.profile = "WiFi"
    buffer = ctypes.pointer(interfaces)

    def enumerate_interfaces(handle, reserved, out):
        out._obj.value = ctypes.addressof(interfaces)
        return 0

    api.WlanEnumInterfaces.side_effect = enumerate_interfaces
    with (
        patch.object(wlan.sys, "platform", "win32"),
        patch.object(wlan.ctypes, "WinDLL", return_value=api),
        patch.object(wlan, "_interface_name", return_value="Wi-Fi"),
        patch.object(
            wlan, "_query", side_effect=[connection, ctypes.wintypes.ULONG(36), ctypes.c_long(-55)]
        ),
    ):
        result = wlan.collect_windows_wifi()
    assert buffer and result[0].ssid == "Сеть" and result[0].bssid == "00:01:02:03:04:05"
    assert (
        result[0].channel,
        result[0].radio_type,
        result[0].signal_pct,
        result[0].rx_mbps,
        result[0].rssi_dbm,
    ) == ("36", "802.11ax", 85, 433.3, -55)
    api.WlanFreeMemory.assert_called_once()
    api.WlanCloseHandle.assert_called_once()


def test_query_error_frees_buffer_and_closes_handle():
    api = SimpleNamespace(
        **{
            name: MagicMock(return_value=0)
            for name in (
                "WlanOpenHandle",
                "WlanEnumInterfaces",
                "WlanQueryInterface",
                "WlanFreeMemory",
                "WlanCloseHandle",
            )
        }
    )
    interfaces = wlan._InterfaceList()
    interfaces.count = 1
    interfaces.items[0].state = 1
    data = ctypes.c_ulong(0)

    def enum(handle, reserved, out):
        out._obj.value = ctypes.addressof(interfaces)
        return 0

    def query(handle, guid, opcode, reserved, size, out, kind):
        out._obj.value = ctypes.addressof(data)
        return 5

    api.WlanEnumInterfaces.side_effect = enum
    api.WlanQueryInterface.side_effect = query
    with (
        patch.object(wlan.sys, "platform", "win32"),
        patch.object(wlan.ctypes, "WinDLL", return_value=api),
    ):
        assert wlan.collect_windows_wifi() is None
    assert api.WlanFreeMemory.call_count == 2
    api.WlanCloseHandle.assert_called_once()


def test_native_and_fallback_selection():
    with (
        patch("netvision.core.system.collect_windows_wifi", return_value=[]),
        patch("netvision.core.system.subprocess.run") as run,
    ):
        assert collect_wifi_snapshot("Wi-Fi") is None
        run.assert_not_called()
    result = SimpleNamespace(
        returncode=0, stdout=b"Name : Wi-Fi\nState : connected\nSSID : Test\n", stderr=b""
    )
    with (
        patch("netvision.core.system.collect_windows_wifi", return_value=None),
        patch("netvision.core.system.subprocess.run", return_value=result) as run,
    ):
        assert collect_wifi_snapshot("Wi-Fi").ssid == "Test"
        run.assert_called_once()
