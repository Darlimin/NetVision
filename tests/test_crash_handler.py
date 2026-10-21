from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from netvision.core import crash_handler


class CrashHandlerTests(unittest.TestCase):
    def test_sys_excepthook_writes_traceback_to_crash_report(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "NetVision" / "crash_reports.log"
            previous_sys_hook = sys.excepthook
            previous_thread_hook = threading.excepthook
            previous_installed = crash_handler._installed
            previous_original_sys = crash_handler._original_sys_excepthook
            previous_original_thread = crash_handler._original_threading_excepthook
            try:
                crash_handler._installed = False
                with patch.object(
                    crash_handler,
                    "_crash_report_path",
                    return_value=report_path,
                ), patch.object(crash_handler, "_queue_error_dialog"):
                    crash_handler.setup_crash_handler()
                    try:
                        raise RuntimeError("crash handler test")
                    except RuntimeError as error:
                        sys.excepthook(type(error), error, error.__traceback__)
            finally:
                sys.excepthook = previous_sys_hook
                threading.excepthook = previous_thread_hook
                crash_handler._installed = previous_installed
                crash_handler._original_sys_excepthook = previous_original_sys
                crash_handler._original_threading_excepthook = previous_original_thread

            records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["exception_type"], "RuntimeError")
            self.assertIn("crash handler test", records[0]["traceback"])
            self.assertIn("RuntimeError", records[0]["traceback"])


if __name__ == "__main__":
    unittest.main()
