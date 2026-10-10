"""Exercise real Qt threads using deterministic probes, never the network."""
from threading import Event
from time import monotonic
from unittest.mock import patch

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from netvision.core.tcp_diagnostics import TcpConnectMeasurement
from netvision.ui.main_window import MainWindow
from netvision.ui.monitor_workers import LatencyMonitorWorker, WorkerRegistry


def pump_until(app, condition, timeout=3):
    deadline = monotonic() + timeout
    while not condition() and monotonic() < deadline:
        app.processEvents()
        QTest.qWait(5)
    assert condition(), "Qt operation did not finish before the deadline"


def test_stop_keeps_worker_alive_and_gui_responsive_until_probe_finishes():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()
    entered, release = Event(), Event()
    ticks, samples = [], []
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: ticks.append(1))

    def blocked_probe(*args, **kwargs):
        entered.set()
        release.wait(3)
        return TcpConnectMeasurement("example.test", 443, 12.0, "Открыт")

    worker = LatencyMonitorWorker("example.test", 443)
    worker.sample.connect(lambda *args: samples.append(args))
    with patch("netvision.ui.monitor_workers.probe_tcp_connect", side_effect=blocked_probe):
        try:
            thread = registry.start(worker)
            pump_until(app, entered.is_set)
            registry.stop(thread)
            assert registry.busy
            timer.start()
            pump_until(app, lambda: len(ticks) >= 3)
            assert registry.busy
        finally:
            timer.stop()
            release.set()
            pump_until(app, lambda: not registry.busy)
    assert samples == []  # A cancelled probe must not publish a stale result.


def test_worker_results_are_delivered_in_gui_thread():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()

    class Receiver(QObject):
        threads = []

        @Slot(object, bool)
        def receive(self, _value, _success):
            self.threads.append(QThread.currentThread())
            registry.stop_all()

    receiver = Receiver()
    worker = LatencyMonitorWorker("example.test", 443)
    worker.sample.connect(receiver.receive)
    with patch("netvision.ui.monitor_workers.probe_tcp_connect",
               return_value=TcpConnectMeasurement("example.test", 443, 12.0, "Открыт")):
        registry.start(worker)
        pump_until(app, lambda: not registry.busy)
    assert receiver.threads == [app.thread()]


def test_window_waits_for_old_probe_on_close_without_blocking_gui():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    entered, release = Event(), Event()

    def blocked_probe(*args, **kwargs):
        entered.set()
        release.wait(3)
        return TcpConnectMeasurement("example.test", 443, 999.0, "Открыт")

    with patch("netvision.ui.monitor_workers.probe_tcp_connect", side_effect=blocked_probe):
        window = MainWindow()
        try:
            window.show()
            pump_until(app, entered.is_set)
            window._stop_latency_monitor()
            assert window._worker_registry.busy
            window.close()
            assert window.isVisible()
            assert window._closing
            app.processEvents()
        finally:
            release.set()
            pump_until(app, lambda: not window._worker_registry.busy)
            pump_until(app, lambda: not window.isVisible())
        assert not window._latency_window


def test_one_shot_worker_is_retained_after_result_until_thread_exits():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()
    emitted, release = Event(), Event()

    class Job(QObject):
        completed = Signal()

        @Slot()
        def run(self):
            self.completed.emit()
            emitted.set()
            release.wait(3)

    job = Job()
    thread = QThread()
    job.moveToThread(thread)
    thread.started.connect(job.run)
    job.completed.connect(thread.quit, Qt.ConnectionType.DirectConnection)
    registry.retain(thread, job)
    thread.start()
    try:
        pump_until(app, emitted.is_set)
        registry.stop_all()
        assert registry.busy
        assert thread.isRunning()
    finally:
        release.set()
        pump_until(app, lambda: not registry.busy)
