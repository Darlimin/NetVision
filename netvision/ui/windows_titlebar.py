"""Match the native Windows title bar to the selected application theme."""

import ctypes
import sys

from PySide6.QtWidgets import QApplication


def apply_titlebar_theme(window, dark: bool) -> None:
    app = QApplication.instance()
    if (
        sys.platform != "win32"
        or app is None
        or app.platformName().lower() in {"offscreen", "minimal"}
    ):
        return
    try:
        dwm = ctypes.WinDLL("dwmapi")
        value = ctypes.c_int(int(dark))
        hwnd = ctypes.c_void_p(int(window.winId()))
        for attribute in (20, 19):
            if (
                dwm.DwmSetWindowAttribute(
                    hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)
                )
                == 0
            ):
                break
    except (OSError, AttributeError, ValueError, RuntimeError):
        return
