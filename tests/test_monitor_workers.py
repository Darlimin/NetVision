"""Exercise real Qt threads using deterministic probes, never the network."""

from concurrent.futures import CancelledError
import gc
import weakref
from threading import Event, Thread
from time import monotonic
from unittest.mock import patch

import pytest
from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from netvision.core.tcp_diagnostics import TcpConnectMeasurement
from netvision.core.dns_benchmark import DnsResolverProfile, benchmark_resolvers
from netvision.core.mtu_optimizer import MtuOptimizerProbe, run_mtu_optimizer
from netvision.ui.legacy_workers import (
    DnsBenchmarkWorker,
    DnsConfigurationWorker,
    MtuControlProbeWorker,
    MtuOptimizerWorker,
    TcpDiagnosticsWorker,
)
from netvision.ui.dialogs import GeoHideDialog
from netvision.ui.legacy_workers import GeoHideWorker
from netvision.ui.monitor_workers import (
    LatencyMonitorWorker,
    MtrMonitorWorker,
    WifiMonitorWorker,
    WorkerRegistry,
)
from netvision.ui.dashboard_v2 import NetVisionDashboardV2

_THREAD_WAIT_MS = 2000
_BLOCKED_PROBE_WAIT_S = 1.0


@pytest.mark.parametrize("kind", ["latency", "gateway"])
def test_monitor_probe_errors_are_logged_without_spam(kind, caplog):
    worker = (
        LatencyMonitorWorker("example.test", 443)
        if kind == "latency"
        else WifiMonitorWorker("adapter", "192.0.2.1")
    )
    waits = 0

    def wait(_seconds):
        nonlocal waits
        waits += 1
        if waits == 2:
            worker.stop()

    probe = "probe_tcp_connect" if kind == "latency" else "probe_ping"
    with (
        patch.object(worker._stop_event, "wait", side_effect=wait),
        patch(f"netvision.ui.monitor_workers.{probe}", side_effect=OSError("offline")),
        patch("netvision.ui.monitor_workers.collect_wifi_snapshot", return_value=None),
        caplog.at_level("WARNING"),
    ):
        worker.run()
    assert waits == 2
    assert len(caplog.records) == 1
    assert "OSError: offline" in caplog.text


def test_registry_rejects_parented_worker():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()
    worker = DnsBenchmarkWorker(())
    worker.setParent(registry)
    with pytest.raises(ValueError, match="must not have a QObject parent"):
        registry.start(worker)
    assert not registry.busy
    assert app is not None


def test_mtr_stopped_before_start_skips_dns_and_finishes():
    worker = MtrMonitorWorker("example.test")
    finished = []
    worker.finished.connect(lambda: finished.append(True))
    worker.stop()
    with patch.object(worker, "_resolve_target") as resolve:
        worker.run()
    resolve.assert_not_called()
    assert finished == [True]


def test_mtr_registry_retains_worker_until_probe_returns():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()
    entered, release = Event(), Event()
    snapshots = []
    worker = MtrMonitorWorker("example.test")
    worker.snapshot.connect(snapshots.append)

    def collect(_executor, _target):
        entered.set()
        release.wait(_BLOCKED_PROBE_WAIT_S)
        return [], False

    with (
        patch.object(worker, "_resolve_target", return_value="127.0.0.1"),
        patch.object(worker, "_collect_probe_cycle", side_effect=collect),
    ):
        thread = registry.start(worker)
        try:
            pump_until(app, entered.is_set)
            registry.stop(thread)
            assert registry.busy
            assert thread.isRunning()
        finally:
            release.set()
            assert thread.wait(_THREAD_WAIT_MS)
            pump_until(app, lambda: not registry.busy)
    assert not snapshots


def test_registry_retains_stopped_worker_and_thread_during_gc():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()
    entered, release = Event(), Event()

    class BlockingWorker(QObject):
        finished = Signal()

        @Slot()
        def run(self):
            entered.set()
            release.wait(3)
            self.finished.emit()

        def stop(self):
            pass

    worker = BlockingWorker()
    thread = registry.start(worker)
    worker_ref, thread_ref = weakref.ref(worker), weakref.ref(thread)
    try:
        pump_until(app, entered.is_set)
        registry.stop_all()
        del worker, thread
        gc.collect()
        assert worker_ref() is not None and thread_ref() is not None
        assert registry.busy and thread_ref().isRunning()
    finally:
        release.set()
        assert registry.wait_for_all(_THREAD_WAIT_MS)
        pump_until(app, lambda: not registry.busy)


def test_cancelled_workers_finish_without_starting_work():
    workers = (
        DnsBenchmarkWorker(()),
        DnsConfigurationWorker(),
        GeoHideWorker(),
        MtuOptimizerWorker("example.test"),
        MtuControlProbeWorker("127.0.0.1", 1500, 100),
        TcpDiagnosticsWorker("example.test", 443, (443,)),
    )
    for worker in workers:
        results, finished = [], []
        worker.completed.connect(lambda *args: results.append(args))
        worker.finished.connect(lambda: finished.append(True))
        worker.stop()
        worker.run()
        assert not results
        assert finished == [True]


def test_tcp_worker_cancellation_between_operations():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    registry = WorkerRegistry()
    entered, release = Event(), Event()

    def scan():
        entered.set()
        release.wait(_BLOCKED_PROBE_WAIT_S)
        return ()

    worker = TcpDiagnosticsWorker("example.test", 443, (443,))
    results = []
    worker.completed.connect(lambda *args: results.append(args))
    with (
        patch("netvision.ui.legacy_workers.scan_tcp_sockets", side_effect=scan),
        patch("netvision.ui.legacy_workers.probe_tcp_connect") as probe,
    ):
        thread = registry.start(worker)
        try:
            pump_until(app, entered.is_set)
            registry.stop_all()
        finally:
            release.set()
            assert thread.wait(_THREAD_WAIT_MS)
            pump_until(app, lambda: not registry.busy)
    probe.assert_not_called()
    assert not results


def test_dns_benchmark_cancels_queued_probes():
    entered, release, cancelled, finished = Event(), Event(), Event(), Event()
    failures = []

    def probe(*_args):
        entered.set()
        release.wait(_BLOCKED_PROBE_WAIT_S)
        return (1.0, None)

    def run():
        try:
            benchmark_resolvers(
                (DnsResolverProfile("test", ("127.0.0.1",)),), cancel_event=cancelled
            )
            failures.append("not cancelled")
        except CancelledError:
            pass
        finally:
            finished.set()

    with patch("netvision.core.dns_benchmark._probe_dns_port", side_effect=probe):
        thread = Thread(target=run)
        thread.start()
        try:
            assert entered.wait(_BLOCKED_PROBE_WAIT_S)
            cancelled.set()
            assert finished.wait(0.5)
        finally:
            release.set()
            thread.join(_BLOCKED_PROBE_WAIT_S)
    assert not failures


def test_window_closes_after_dns_worker_cancellation():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    entered, release = Event(), Event()

    def benchmark(_profiles, *, cancel_event):
        entered.set()
        release.wait(_BLOCKED_PROBE_WAIT_S)
        assert cancel_event.is_set()
        return ()

    with (
        patch.object(NetVisionDashboardV2, "_load_local_network_snapshot"),
        patch("netvision.ui.legacy_workers.benchmark_resolvers", side_effect=benchmark),
    ):
        window = NetVisionDashboardV2(bootstrap=False)
        window._quit_requested = True
        try:
            worker = DnsBenchmarkWorker(())
            window._dns_benchmark_worker = worker
            window._dns_benchmark_thread = window._worker_registry.start(worker)
            assert window._dns_benchmark_thread.parent() is None
            assert worker.parent() is None
            window.show()
            pump_until(app, entered.is_set)
            window.close()
            assert window._closing
            assert not window.isEnabled()
        finally:
            window._worker_registry.stop_all()
            release.set()
            assert window._worker_registry.wait_for_all(_THREAD_WAIT_MS)
            pump_until(app, lambda: not window._worker_registry.busy)
            if not window._closing:
                window.close()
            pump_until(app, lambda: not window.isVisible())


def test_mtu_cancellation_stops_subsequent_probes():
    cancelled = Event()

    def probe(_target, mtu, _timeout):
        cancelled.set()
        return MtuOptimizerProbe(mtu, mtu - 28, True, 1.0)

    with (
        patch("netvision.core.mtu_optimizer._resolve_target_ipv4", return_value="127.0.0.1"),
        patch("netvision.core.mtu_optimizer._route_local_ipv4", return_value=None),
        patch("netvision.core.mtu_optimizer.collect_system_snapshot"),
        patch("netvision.core.mtu_optimizer.detect_system_mtu", return_value=1500),
        patch("netvision.core.mtu_optimizer._probe_mtu", side_effect=probe) as run_probe,
    ):
        try:
            run_mtu_optimizer("example.test", cancel_event=cancelled)
        except CancelledError:
            pass
        else:
            raise AssertionError("MTU cancellation was not propagated")
    assert run_probe.call_count == 1


def pump_until(app, condition, timeout=2):
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
        release.wait(_BLOCKED_PROBE_WAIT_S)
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
            assert thread.wait(_THREAD_WAIT_MS)
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
    with patch(
        "netvision.ui.monitor_workers.probe_tcp_connect",
        return_value=TcpConnectMeasurement("example.test", 443, 12.0, "Открыт"),
    ):
        registry.start(worker)
        pump_until(app, lambda: not registry.busy)
    assert receiver.threads == [app.thread()]


def test_window_waits_for_old_probe_on_close_without_blocking_gui():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    entered, release = Event(), Event()

    def blocked_probe(*args, **kwargs):
        entered.set()
        release.wait(_BLOCKED_PROBE_WAIT_S)
        return TcpConnectMeasurement("example.test", 443, 999.0, "Открыт")

    with (
        patch("netvision.ui.monitor_workers.probe_tcp_connect", side_effect=blocked_probe),
        patch.object(NetVisionDashboardV2, "_record_journal_event"),
    ):
        window = NetVisionDashboardV2(bootstrap=False)
        try:
            window.show()
            window.ping_controller._start_latency_monitor("example.test", 443)
            pump_until(app, entered.is_set)
            window.ping_controller._stop_latency_monitor()
            assert window._worker_registry.busy
            window._quit_requested = True
            window.close()
            assert window.isVisible()
            assert window._closing
            app.processEvents()
        finally:
            release.set()
            pump_until(app, lambda: not window._worker_registry.busy)
            pump_until(app, lambda: not window.isVisible())
        assert not window._latency_window


def test_geohide_close_hides_until_worker_finishes():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    entered, release = Event(), Event()
    finished = []

    def fetch():
        entered.set()
        release.wait(_BLOCKED_PROBE_WAIT_S)
        return None

    with (
        patch("netvision.ui.dialogs.QWebEngineView", None),
        patch("netvision.ui.legacy_workers.fetch_geohide_dns", side_effect=fetch),
    ):
        dialog = GeoHideDialog()
        registry = dialog._worker_registry
        dialog.finished.connect(lambda _result: finished.append(True))
        dialog.show()
        thread = dialog._thread
        try:
            pump_until(app, entered.is_set)
            worker = dialog._worker
            dialog.close()
            assert not dialog.isVisible()
            assert worker._cancel_event.is_set()
            assert thread.isRunning()
            assert dialog._worker_registry.busy
            assert not finished
        finally:
            release.set()
            assert thread.wait(_THREAD_WAIT_MS)
            pump_until(app, lambda: not registry.busy)
            pump_until(app, lambda: bool(finished))


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
            release.wait(_BLOCKED_PROBE_WAIT_S)

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
        assert thread.wait(_THREAD_WAIT_MS)
        pump_until(app, lambda: not registry.busy)
