"""Qt adapters for core probes, with non-blocking monitor lifetime management."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import socket
from threading import Event

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot

from netvision.core.probes import probe_ping
from netvision.core.system import collect_wifi_snapshot
from netvision.core.tcp_diagnostics import probe_tcp_connect
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds
from netvision.core.traceroute import MtrAccumulator, probe_hop
from netvision.core.udp_monitor import UdpPortHistory, get_process_udp_ports


class WifiSignalTracker:
    """State machine for low-signal entry and hysteretic recovery."""

    def __init__(self) -> None:
        self.low = False

    def reset(self) -> None:
        self.low = False

    def update(self, signal_pct: int | None, warn_pct: int, hysteresis_pct: int) -> str | None:
        if signal_pct is None:
            return None
        if not self.low and signal_pct <= warn_pct:
            self.low = True
            return "entered"
        if self.low and signal_pct >= warn_pct + hysteresis_pct:
            self.low = False
            return "cleared"
        return None


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


class WifiMonitorWorker(QObject):
    """Sample only the Wi-Fi interface that owns the active default route."""

    snapshot = Signal(object, str)
    finished = Signal()

    def __init__(
        self,
        route_interface: str,
        gateway: str,
        *,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        super().__init__()
        self._route_interface = route_interface
        self._gateway = gateway
        self._thresholds = th
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        try:
            while not self._stop_event.is_set():
                state = "ok"
                try:
                    snapshot = collect_wifi_snapshot(self._route_interface)
                except OSError:
                    snapshot = None
                    state = "unavailable"
                if snapshot is None and state == "ok":
                    state = "unparsed"
                try:
                    gateway_ping = probe_ping(self._gateway, count=1)
                    gateway_rtt = gateway_ping.average_ms
                except Exception:
                    gateway_rtt = None
                if snapshot is not None:
                    snapshot = replace(snapshot, gateway_rtt_ms=gateway_rtt)
                if self._stop_event.is_set():
                    break
                self.snapshot.emit(snapshot, state)
                self._stop_event.wait(self._thresholds.wifi_poll_interval_s)
        finally:
            self.finished.emit()


class MtrMonitorWorker(QObject):
    """Continuously probe route hops and publish bounded MTR snapshots."""

    snapshot = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        host: str,
        *,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        super().__init__()
        self._host = host
        self._thresholds = th
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    @Slot()
    def run(self) -> None:
        try:
            target_ip = self._resolve_target()
            accumulator = MtrAccumulator(
                self._thresholds.mtr_window_cycles,
                thresholds=self._thresholds,
            )
            with ThreadPoolExecutor(
                max_workers=min(8, self._thresholds.mtr_max_hops)
            ) as executor:
                while not self._stop_event.is_set():
                    probes = []
                    reached_destination = False
                    workers = min(8, self._thresholds.mtr_max_hops)
                    for first_ttl in range(1, self._thresholds.mtr_max_hops + 1, workers):
                        batch = [
                            (
                                ttl,
                                executor.submit(
                                    probe_hop,
                                    target_ip,
                                    ttl,
                                    self._thresholds.mtr_probe_timeout_ms,
                                ),
                            )
                            for ttl in range(
                                first_ttl,
                                min(first_ttl + workers, self._thresholds.mtr_max_hops + 1),
                            )
                        ]
                        for _ttl, future in batch:
                            if self._stop_event.is_set():
                                break
                            probe = future.result()
                            probes.append(probe)
                            if probe.is_destination:
                                reached_destination = True
                                break
                        if self._stop_event.is_set() or reached_destination:
                            break
                    if self._stop_event.is_set():
                        break
                    snapshot = accumulator.update(target_ip, probes)
                    if self._stop_event.is_set():
                        break
                    self.snapshot.emit(snapshot)
                    self._stop_event.wait(self._thresholds.mtr_interval_s)
        except Exception as exc:
            if not self._stop_event.is_set():
                self.failed.emit(f"MTR недоступен: {exc}")
        finally:
            self.finished.emit()

    def _resolve_target(self) -> str:
        records = socket.getaddrinfo(self._host.strip(), None, socket.AF_INET)
        if not records:
            raise RuntimeError("Цель MTR не имеет IPv4-адреса")
        return records[0][4][0]


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

    def start(self, worker: QObject) -> QThread:
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
        if hasattr(worker, "stop") and callable(worker.stop):
            worker.stop()

    def stop_all(self) -> None:
        for worker in self._jobs.values():
            if hasattr(worker, "stop") and callable(worker.stop):
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
