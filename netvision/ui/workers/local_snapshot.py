"""Collect the initial local network snapshot outside the GUI thread."""

from PySide6.QtCore import QObject, Signal, Slot

from netvision.core.system import collect_system_snapshot


class LocalNetworkSnapshotWorker(QObject):
    completed = Signal(object)
    finished = Signal()

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(collect_system_snapshot())
        except Exception as exc:  # The dashboard must stay neutral on failure.
            self.completed.emit(exc)
        finally:
            self.finished.emit()
