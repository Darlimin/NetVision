"""Qt event bus for communication between interface controllers."""

from PySide6.QtCore import QObject, Signal


class AppEventBus(QObject):
    log_requested = Signal(str, str)
    history_update_requested = Signal(str, dict)
    journal_event_requested = Signal(str, dict)
    quick_fix_requested = Signal(str, object, object)
    anomaly_detected = Signal(object)
