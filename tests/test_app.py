from unittest.mock import MagicMock, patch

import pytest

from netvision import app as netvision_app
from netvision.app import _create_main_window


def test_module_launch_uses_dashboard_by_default() -> None:
    with patch("netvision.ui.dashboard_v2.NetVisionDashboardV2") as dashboard:
        _create_main_window(["python", "-m", "netvision"])

    dashboard.assert_called_once_with()


def test_legacy_flag_does_not_select_the_old_window() -> None:
    with patch("netvision.ui.dashboard_v2.NetVisionDashboardV2") as dashboard:
        _create_main_window(["python", "-m", "netvision", "--legacy-ui"])

    dashboard.assert_called_once_with()


def test_main_installs_crash_handler_once() -> None:
    qt_application = MagicMock()
    qt_application.exec.return_value = 0
    window = MagicMock()
    with (
        patch("netvision.app.QApplication", return_value=qt_application),
        patch("netvision.app.QFont"),
        patch("netvision.app.QIcon"),
        patch("netvision.app.QTimer") as timer,
        patch("netvision.app._load_inter_fonts", return_value="Inter"),
        patch("netvision.app._create_main_window", return_value=window),
        patch("netvision.app.setup_crash_handler") as setup_handler,
    ):
        with pytest.raises(SystemExit) as result:
            netvision_app.main()

    assert result.value.code == 0
    setup_handler.assert_called_once_with()
    timer.singleShot.assert_called_once_with(0, window.process_controller.refresh_processes)


def test_main_schedules_real_dashboard_process_controller() -> None:
    from PySide6.QtWidgets import QApplication
    from netvision.ui.controllers.dns_audit import DnsController
    from netvision.ui.dashboard_v2 import NetVisionDashboardV2

    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    with (
        patch.object(DnsController, "_load_dns_configuration"),
        patch.object(NetVisionDashboardV2, "_load_local_network_snapshot"),
    ):
        window = NetVisionDashboardV2(bootstrap=False)
        try:
            assert callable(window.process_controller.refresh_processes)
            assert not hasattr(window, "refresh_processes")
        finally:
            window._quit_requested = True
            window.close()
            app.processEvents()
