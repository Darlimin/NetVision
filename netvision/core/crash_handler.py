"""Global unhandled-exception logging with safe Qt user notifications."""

from __future__ import annotations

from datetime import datetime, timezone
import ctypes
from importlib import import_module
import json
import locale
import os
from pathlib import Path
import platform
import sys
import threading
import traceback
from types import TracebackType
from typing import Callable

from netvision.version import display_version


_write_lock = threading.Lock()
_handling = threading.local()
_installed = False
_original_sys_excepthook: Callable[..., object] | None = None
_original_threading_excepthook: Callable[..., object] | None = None


def _crash_report_path() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    base = Path(root) if root else Path.home() / ".netvision"
    return base / "NetVision" / "crash_reports.log"


def setup_crash_handler() -> None:
    """Install the process-wide Python and worker-thread exception hooks.

    It is safe to call this both before and after QApplication construction.
    The second call lets the optional Qt notifier attach once an event loop exists.
    """

    global _installed, _original_sys_excepthook, _original_threading_excepthook
    if not _installed:
        _original_sys_excepthook = sys.excepthook
        _original_threading_excepthook = threading.excepthook
        sys.excepthook = _sys_excepthook
        threading.excepthook = _thread_excepthook
        _installed = True
    _ensure_qt_notifier()


def _sys_excepthook(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
) -> None:
    _handle_exception(exc_type, exc_value, exc_traceback, thread_name="main")


def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
    thread_name = args.thread.name if args.thread is not None else "worker"
    _handle_exception(args.exc_type, args.exc_value, args.exc_traceback, thread_name=thread_name)


def _handle_exception(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
    *,
    thread_name: str,
) -> None:
    if exc_type in {KeyboardInterrupt, SystemExit}:
        return
    if getattr(_handling, "active", False):
        return
    _handling.active = True
    try:
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        report_path = _write_crash_report(exc_type, exc_value, details, thread_name)
        _queue_error_dialog(report_path, details)
    except Exception:
        # Never let an exception handler become the next unhandled exception.
        return
    finally:
        _handling.active = False


def _write_crash_report(
    exc_type: type[BaseException],
    exc_value: BaseException,
    details: str,
    thread_name: str,
) -> Path:
    path = _crash_report_path()
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "netvision_version": display_version(),
        "windows_version": platform.platform(),
        "python_version": platform.python_version(),
        "oem_codepage": _oem_codepage(),
        "thread": thread_name,
        "exception_type": exc_type.__name__,
        "exception_message": str(exc_value),
        "traceback": details,
    }
    with _write_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=False))
            output.write("\n")
    return path


def _oem_codepage() -> str:
    try:
        codepage = int(ctypes.windll.kernel32.GetOEMCP()) if os.name == "nt" else 0
    except (AttributeError, OSError):
        codepage = 0
    return f"cp{codepage}" if codepage else locale.getpreferredencoding(False)


_qt_notifier: object | None = None


def _create_qt_notifier(app: object, qt_core: object, qt_widgets: object) -> object:
    """Create the optional notifier lazily, keeping the diagnostic core Qt-free."""

    class QtCrashNotifier(qt_core.QObject):  # type: ignore[attr-defined, misc]
        error_ready = qt_core.Signal(str, str)  # type: ignore[attr-defined]

        def __init__(self, parent: object) -> None:
            super().__init__(parent)
            self._dialog_open = False
            self.error_ready.connect(
                self._show_dialog,
                qt_core.Qt.ConnectionType.QueuedConnection,  # type: ignore[attr-defined]
            )

        def _show_dialog(self, report_path: str, details: str) -> None:
            if self._dialog_open:
                return
            self._dialog_open = True
            try:
                dialog = qt_widgets.QMessageBox()  # type: ignore[attr-defined]
                dialog.setIcon(qt_widgets.QMessageBox.Icon.Critical)  # type: ignore[attr-defined]
                dialog.setWindowTitle("Ошибка NetVision")
                dialog.setText(
                    "Произошла непредвиденная ошибка. "
                    f"Логи сохранены в {report_path}"
                )
                dialog.setDetailedText(details)
                copy_button = dialog.addButton(
                    "Скопировать детали",
                    qt_widgets.QMessageBox.ButtonRole.ActionRole,  # type: ignore[attr-defined]
                )
                dialog.addButton(
                    qt_widgets.QMessageBox.StandardButton.Ok  # type: ignore[attr-defined]
                )
                dialog.exec()
                if dialog.clickedButton() is copy_button:
                    current_app = qt_widgets.QApplication.instance()  # type: ignore[attr-defined]
                    if current_app is not None:
                        current_app.clipboard().setText(details)
            except Exception:
                return
            finally:
                self._dialog_open = False

    return QtCrashNotifier(app)


def _ensure_qt_notifier() -> None:
    global _qt_notifier
    try:
        qt_core = import_module("PySide6.QtCore")
        qt_widgets = import_module("PySide6.QtWidgets")
    except ImportError:
        return
    app = qt_widgets.QApplication.instance()
    if app is None:
        return
    if _qt_notifier is None or _qt_notifier.parent() is not app:  # type: ignore[attr-defined]
        _qt_notifier = _create_qt_notifier(app, qt_core, qt_widgets)


def _queue_error_dialog(report_path: Path, details: str) -> None:
    _ensure_qt_notifier()
    if _qt_notifier is not None:
        _qt_notifier.error_ready.emit(str(report_path), details)  # type: ignore[attr-defined]
