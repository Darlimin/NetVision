"""Qt adapters for core probes, with non-blocking monitor lifetime management."""
from __future__ import annotations

from threading import Event

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot

from netvision.core.tcp_diagnostics import probe_tcp_connect
from netvision.core.udp_monitor import UdpPortHistory, get_process_udp_ports


class LatencyMonitorWorker(QObject):
    sample = Signal(object, bool)
    finished = Signal()

    def __init__(self, host: str, port: int, interval_s: float = 1.0) -> None:
        super().__init__()
        self._host, self._port = host, port
        self._interval_s = interval_s
        self._stop_event = Event()

    def stop(self) -> None:
        # Called by the GUI thread; Event is thread-safe even during a probe.
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    result = probe_tcp_connect(self._host, self._port, timeout=1.0)
                    latency, success = result.connect_ms, result.is_open
                except Exception:
                    latency, success = None, False
                if self._stop_event.is_set():
                    break
                self.sample.emit(latency, success)
                self._stop_event.wait(self._interval_s)
        finally:
            self.finished.emit()


class UdpPortMonitorWorker(QObject):
    activity = Signal(object)
    finished = Signal()

    def __init__(self, pid: int, interval_s: float = 2.0) -> None:
        super().__init__()
        self._pid, self._interval_s = pid, interval_s
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        history = UdpPortHistory()
        try:
            while not self._stop_event.is_set():
                activity = history.observe(get_process_udp_ports(self._pid))
                if self._stop_event.is_set():
                    break
                self.activity.emit(activity)
                self._stop_event.wait(self._interval_s)
        finally:
            self.finished.emit()


class WorkerRegistry(QObject):
    """Retain stopped workers until QThread.finished, including replaced jobs.

    A socket's DNS lookup or an OS table read can outlive its nominal timeout.
    Never block the GUI or destroy its QThread while that call is still running.
    """

    idle = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._jobs: dict[QThread, QObject] = {}

    @property
    def busy(self) -> bool:
        return bool(self._jobs)

    def start(self, worker: LatencyMonitorWorker | UdpPortMonitorWorker) -> QThread:
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        # quit() is thread-safe. Direct delivery does not require a GUI event
        # to stop the worker's event loop after run() returns.
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        self.retain(thread, worker)
        thread.start()
        return thread

    def retain(self, thread: QThread, worker: QObject) -> None:
        """Own a one-shot worker as well as monitors until native cleanup ends."""
        self._jobs[thread] = worker
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._release)

    def stop(self, thread: QThread | None) -> None:
        worker = self._jobs.get(thread)
        if isinstance(worker, (LatencyMonitorWorker, UdpPortMonitorWorker)):
            worker.stop()

    def stop_all(self) -> None:
        for worker in self._jobs.values():
            if isinstance(worker, (LatencyMonitorWorker, UdpPortMonitorWorker)):
                worker.stop()

    @Slot()
    def _release(self) -> None:
        # finished is emitted before native thread-local cleanup completes.
        # Deleting QThread here can block Python's GIL during that cleanup.
        pending_cleanup = False
        for thread in tuple(self._jobs):
            if thread.isFinished():
                if thread.wait(0):
                    self._jobs.pop(thread)
                    thread.deleteLater()
                else:
                    pending_cleanup = True
        if pending_cleanup:
            QTimer.singleShot(10, self._release)
        if not self._jobs:
            self.idle.emit()
