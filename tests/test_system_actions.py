import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from netvision.core import system_actions


class SystemActionTests(unittest.TestCase):
    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "run")
    def test_flush_dns_uses_hidden_windows_command(self, run_mock) -> None:
        run_mock.return_value = CompletedProcess(
            ["ipconfig", "/flushdns"],
            0,
            stdout="DNS cache was successfully flushed.".encode(),
        )

        result = system_actions.flush_dns_cache()

        self.assertTrue(result.success)
        self.assertEqual(result.message, "Кэш DNS успешно очищен")
        run_mock.assert_called_once()
        command = run_mock.call_args.args[0]
        options = run_mock.call_args.kwargs
        self.assertEqual(command, ["ipconfig", "/flushdns"])
        self.assertEqual(options["stdin"], system_actions.subprocess.DEVNULL)
        self.assertEqual(options["stderr"], system_actions.subprocess.STDOUT)
        self.assertFalse(options["check"])
        self.assertEqual(options["timeout"], 15)

    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "run")
    def test_flush_dns_reports_command_failure(self, run_mock) -> None:
        run_mock.return_value = CompletedProcess(
            ["ipconfig", "/flushdns"],
            1,
            stdout=b"Access is denied.",
        )

        result = system_actions.flush_dns_cache()

        self.assertFalse(result.success)
        self.assertIn("Очистка DNS не выполнена", result.message)
        self.assertIn("Access is denied", result.message)

    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "Popen")
    def test_navigation_actions_open_expected_windows_targets(self, popen_mock) -> None:
        for action, expected in (
            (system_actions.open_network_adapters, ["control.exe", "ncpa.cpl"]),
            (
                system_actions.open_network_proxy_settings,
                ["explorer.exe", "ms-settings:network-proxy"],
            ),
            (system_actions.open_windows_firewall, ["control.exe", "firewall.cpl"]),
        ):
            popen_mock.reset_mock()
            result = action()

            self.assertTrue(result.success)
            self.assertEqual(popen_mock.call_args.args[0], expected)
            options = popen_mock.call_args.kwargs
            self.assertEqual(options["stdin"], system_actions.subprocess.DEVNULL)
            self.assertEqual(options["stdout"], system_actions.subprocess.DEVNULL)
            self.assertEqual(options["stderr"], system_actions.subprocess.DEVNULL)

    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "Popen", side_effect=OSError("access denied"))
    def test_navigation_reports_process_error(self, _popen_mock) -> None:
        result = system_actions.open_windows_firewall()

        self.assertFalse(result.success)
        self.assertIn("Не удалось открыть", result.message)

    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "run")
    def test_apply_dns_rejects_invalid_profile_before_netsh(self, run_mock) -> None:
        result = system_actions.apply_dns_servers("Ethernet", ("not-an-ip",))

        self.assertFalse(result.success)
        self.assertIn("некорректный IP", result.message)
        run_mock.assert_not_called()

    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "run")
    def test_reset_tcpip_runs_both_hidden_netsh_commands(self, run_mock) -> None:
        run_mock.side_effect = [
            CompletedProcess(["netsh", "int", "ip", "reset"], 0, stdout=b""),
            CompletedProcess(["netsh", "winsock", "reset"], 0, stdout=b""),
        ]

        result = system_actions.reset_tcpip_stack()

        self.assertTrue(result.success)
        self.assertEqual(
            [call.args[0] for call in run_mock.call_args_list],
            [["netsh", "int", "ip", "reset"], ["netsh", "winsock", "reset"]],
        )

    @patch.object(system_actions.os, "name", "nt")
    @patch.object(system_actions.subprocess, "run")
    def test_mtu_and_adapter_restart_use_selected_interface(self, run_mock) -> None:
        run_mock.side_effect = [
            CompletedProcess(["netsh"], 0, stdout=b""),
            CompletedProcess(["netsh"], 0, stdout=b""),
            CompletedProcess(["netsh"], 0, stdout=b""),
        ]

        mtu_result = system_actions.optimize_mtu("Wi-Fi")
        restart_result = system_actions.restart_network_adapter("Wi-Fi")

        self.assertTrue(mtu_result.success)
        self.assertTrue(restart_result.success)
        self.assertEqual(
            run_mock.call_args_list[0].args[0],
            ["netsh", "interface", "ipv4", "set", "subinterface", "Wi-Fi", "mtu=1500", "store=persistent"],
        )
        self.assertEqual(run_mock.call_args_list[1].args[0][-1], "admin=disabled")
        self.assertEqual(run_mock.call_args_list[2].args[0][-1], "admin=enabled")


if __name__ == "__main__":
    unittest.main()
