from unittest.mock import Mock, patch

from netvision.ui.windows_titlebar import apply_titlebar_theme


def test_titlebar_falls_back_to_old_windows_attribute():
    api = Mock(side_effect=[1, 0])
    app = Mock()
    app.platformName.return_value = "windows"
    window = Mock()
    window.winId.return_value = 123
    with (
        patch("netvision.ui.windows_titlebar.sys.platform", "win32"),
        patch("netvision.ui.windows_titlebar.QApplication.instance", return_value=app),
        patch(
            "netvision.ui.windows_titlebar.ctypes.WinDLL",
            return_value=Mock(DwmSetWindowAttribute=api),
        ),
    ):
        apply_titlebar_theme(window, True)
    assert [call.args[1] for call in api.call_args_list] == [20, 19]


def test_titlebar_handles_unavailable_dwm():
    app = Mock()
    app.platformName.return_value = "windows"
    with (
        patch("netvision.ui.windows_titlebar.sys.platform", "win32"),
        patch("netvision.ui.windows_titlebar.QApplication.instance", return_value=app),
        patch("netvision.ui.windows_titlebar.ctypes.WinDLL", side_effect=OSError("missing")),
    ):
        apply_titlebar_theme(Mock(), False)
