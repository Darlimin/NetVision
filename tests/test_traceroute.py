from dataclasses import replace
import time
import unittest
from unittest.mock import patch

from PySide6.QtCore import QCoreApplication

from netvision.core.thresholds import DEFAULT_THRESHOLDS
from netvision.core.traceroute import HopProbe, MtrAccumulator
from netvision.ui.monitor_workers import MtrMonitorWorker, WorkerRegistry


TARGET = "8.8.8.8"


def _probe(ttl: int, address: str | None, *, destination: bool = False) -> HopProbe:
    return HopProbe(
        ttl,
        address,
        10.0 if address else None,
        "success" if destination else "ttl_expired" if address else "timeout",
        is_destination=destination,
    )


class MtrAccumulatorTests(unittest.TestCase):
    def test_intermediate_loss_with_clean_destination_is_icmp_limited(self) -> None:
        accumulator = MtrAccumulator(20)
        for index in range(10):
            snapshot = accumulator.update(
                TARGET,
                (
                    _probe(1, "192.168.1.1"),
                    _probe(2, "10.0.0.1"),
                    _probe(3, "203.0.113.3") if index % 2 else _probe(3, None),
                    _probe(4, TARGET, destination=True),
                ),
            )

        hop = next(item for item in snapshot.hops if item.ttl == 3)
        self.assertTrue(hop.icmp_limited)
        self.assertFalse(hop.real_loss)
        self.assertIsNone(snapshot.real_loss_start_hop)

    def test_loss_continuing_to_destination_is_real(self) -> None:
        accumulator = MtrAccumulator(20)
        for index in range(10):
            snapshot = accumulator.update(
                TARGET,
                (
                    _probe(1, "192.168.1.1"),
                    _probe(2, "10.0.0.1"),
                    _probe(3, "203.0.113.3") if index % 2 else _probe(3, None),
                    _probe(4, TARGET, destination=True) if index % 2 else _probe(4, None),
                ),
            )

        self.assertEqual(snapshot.real_loss_start_hop, 3)
        self.assertTrue(next(item for item in snapshot.hops if item.ttl == 3).real_loss)

    def test_hop_address_change_emits_route_event(self) -> None:
        accumulator = MtrAccumulator(5)
        accumulator.update(TARGET, (_probe(1, "192.168.1.1"), _probe(2, TARGET, destination=True)))
        snapshot = accumulator.update(
            TARGET,
            (_probe(1, "192.168.1.1"), _probe(2, "10.0.0.2"), _probe(3, TARGET, destination=True)),
        )

        event = next(item for item in snapshot.events if item.kind == "route_changed")
        self.assertEqual(event.hop, 2)
        self.assertEqual(event.previous_address, TARGET)
        self.assertEqual(event.address, "10.0.0.2")

    def test_real_loss_episode_uses_confirmation_and_clear_threshold(self) -> None:
        thresholds = replace(DEFAULT_THRESHOLDS, mtr_confirm_cycles=2)
        accumulator = MtrAccumulator(3, thresholds=thresholds)
        healthy_cycle = (
            _probe(1, "192.168.1.1"),
            _probe(2, "10.0.0.2"),
            _probe(3, TARGET, destination=True),
        )
        lossy_cycle = (
            _probe(1, "192.168.1.1"),
            _probe(2, None),
            _probe(3, None),
        )
        accumulator.update(TARGET, healthy_cycle)
        accumulator.update(TARGET, lossy_cycle)
        opened = accumulator.update(TARGET, lossy_cycle)
        accumulator.update(TARGET, healthy_cycle)
        accumulator.update(TARGET, healthy_cycle)
        closed = accumulator.update(TARGET, healthy_cycle)

        self.assertTrue(any(event.kind == "loss_opened" for event in opened.events))
        self.assertTrue(any(event.kind == "loss_closed" for event in closed.events))


class MtrMonitorWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def test_registry_stop_is_non_blocking_and_stale_snapshot_is_not_emitted(self) -> None:
        thresholds = replace(
            DEFAULT_THRESHOLDS,
            mtr_interval_s=0.01,
            mtr_max_hops=2,
            mtr_probe_timeout_ms=10,
        )
        registry = WorkerRegistry()
        worker = MtrMonitorWorker(TARGET, th=thresholds)
        received: list[object] = []
        worker.snapshot.connect(received.append)

        with patch("netvision.ui.monitor_workers.socket.getaddrinfo", return_value=[(2, 0, 0, "", (TARGET, 0))]), patch(
            "netvision.ui.monitor_workers.probe_hop",
            side_effect=[_probe(1, "192.168.1.1"), _probe(2, TARGET, destination=True)],
        ):
            thread = registry.start(worker)
            started = time.monotonic()
            registry.stop(thread)
            self.assertLess(time.monotonic() - started, 0.1)
            deadline = time.monotonic() + 0.5
            while thread.isRunning() and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.01)

        self.app.processEvents()
        self.assertFalse(received)


if __name__ == "__main__":
    unittest.main()
