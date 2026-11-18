"""Qt adapters for core probes, with non-blocking monitor lifetime management."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import socket
from threading import Event

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from shiboken6 import isValid

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

    def __init__(
        self,
        host: str,
        port: int,
        interval_s: float = 1.0,
        protocol: str = "TCP",
    ) -> None:
        super().__init__()
        self._host, self._port = host, port
        self._interval_s = interval_s
        self._protocol = protocol.upper()
        self._stop_event = Event()

    def stop(self) -> None:
        # Called by the GUI thread; Event is thread-safe even during a probe.
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    if self._protocol == "UDP":
                        result = probe_ping(self._host, count=1, wait_ms=1000)
                        latency, success = result.average_ms, bool(result.received)
                    else:
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
        route_is_vpn: bool = False,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        super().__init__()
        self._route_interface = route_interface
        self._gateway = gateway
        self._route_is_vpn = route_is_vpn
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
                    snapshot = collect_wifi_snapshot(
                        self._route_interface,
                        allow_vpn_fallback=self._route_is_vpn,
                    )
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
            if self._stop_event.is_set():
                return
            target_ip = self._resolve_target()
            accumulator = MtrAccumulator(
                self._thresholds.mtr_window_cycles,
                thresholds=self._thresholds,
            )
            with ThreadPoolExecutor(max_workers=min(8, self._thresholds.mtr_max_hops)) as executor:
                while not self._stop_event.is_set():
                    probes, _reached_destination = self._collect_probe_cycle(executor, target_ip)
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

    def _collect_probe_cycle(self, executor, target_ip: str) -> tuple[list, bool]:
        probes = []
        reached_destination = False
        workers = min(8, self._thresholds.mtr_max_hops)
        for first_ttl in range(1, self._thresholds.mtr_max_hops + 1, workers):
            if self._stop_event.is_set():
                break
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
        return probes, reached_destination

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
        self._active_threads: set[QThread] = set()
        self._release_timer = QTimer(self)
        self._release_timer.setSingleShot(True)
        self._release_timer.timeout.connect(self._release, Qt.ConnectionType.QueuedConnection)

    @property
    def busy(self) -> bool:
        return bool(self._jobs)

    @staticmethod
    def _is_alive(value: object | None) -> bool:
        try:
            return value is not None and isValid(value)
        except RuntimeError:
            return False

    def start(self, worker: QObject) -> QThread:
        if not self._is_alive(self) or not self._is_alive(worker):
            raise RuntimeError("Cannot start a deleted registry or worker")
        if QThread.currentThread() != self.thread() or worker.thread() != self.thread():
            raise RuntimeError("Registry and worker must belong to the calling thread")
        if worker.parent() is not None:
            raise ValueError("A worker moved to a thread must not have a QObject parent")
        thread = QThread()
        self._active_threads.add(thread)
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
        self._active_threads.add(thread)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._release, Qt.ConnectionType.QueuedConnection)

    def stop(self, thread: QThread | None) -> None:
        if not self._is_alive(thread):
            return
        worker = self._jobs.get(thread)
        if self._is_alive(worker) and hasattr(worker, "stop") and callable(worker.stop):
            worker.stop()

    def stop_all(self) -> None:
        for worker in self._jobs.values():
            if self._is_alive(worker) and hasattr(worker, "stop") and callable(worker.stop):
                worker.stop()

    def wait_for_all(self, timeout_ms: int) -> bool:
        """Wait at most timeout_ms in total; intended for bounded test teardown."""
        from time import monotonic

        deadline = monotonic() + max(timeout_ms, 0) / 1000
        for thread in tuple(self._active_threads):
            if self._is_alive(thread):
                remaining = max(0, int((deadline - monotonic()) * 1000))
                if not thread.wait(remaining):
                    return False
        return True

    @Slot()
    def _release(self) -> None:
        # finished is emitted before native thread-local cleanup completes.
        # Deleting QThread here can block Python's GIL during that cleanup.
        pending_cleanup = False
        for thread in tuple(self._jobs):
            if not self._is_alive(thread):
                self._jobs.pop(thread, None)
                self._active_threads.discard(thread)
                continue
            try:
                finished = thread.isFinished()
                joined = thread.wait(0) if finished else False
            except RuntimeError:
                self._jobs.pop(thread, None)
                self._active_threads.discard(thread)
                continue
            if joined:
                self._jobs.pop(thread, None)
                self._active_threads.discard(thread)
                if self._is_alive(thread):
                    thread.deleteLater()
            else:
                pending_cleanup = True
        if pending_cleanup:
            if not self._release_timer.isActive():
                self._release_timer.start(10)
        if not self._jobs:
            self.idle.emit()
