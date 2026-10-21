from dataclasses import replace
from threading import Event, Thread
import time
import unittest
from unittest.mock import patch

from netvision.core import bufferbloat
from netvision.core.thresholds import DEFAULT_THRESHOLDS
from netvision.ui.main_window import BufferbloatWorker


class BufferbloatTests(unittest.TestCase):
    def test_timed_load_holds_for_configured_duration(self) -> None:
        thresholds = replace(
            DEFAULT_THRESHOLDS,
            bufferbloat_load_s=0.3,
            bufferbloat_baseline_s=0.0,
            bufferbloat_streams=1,
            bufferbloat_max_bytes=256 * 1024 * 1024,
            bufferbloat_sample_interval_s=0.01,
        )

        def instant_download(*_args, **_kwargs):
            time.sleep(0.01)
            return 1, 0.01

        with patch.object(bufferbloat, "_download", side_effect=instant_download), patch.object(
            bufferbloat, "_upload", side_effect=instant_download
        ), patch.object(bufferbloat, "_measure_tcp_latency", return_value=20.0):
            started = time.monotonic()
            report = bufferbloat.run_bufferbloat_test(
                target=None,
                thresholds=thresholds,
            )

        self.assertGreaterEqual(time.monotonic() - started, 0.3)
        self.assertIsNotNone(report.download_active.speed_mbps)

    def test_p95_delta_detects_rare_large_spikes(self) -> None:
        baseline = bufferbloat._phase_from_samples({"ref": [20.0] * 30})
        active = bufferbloat._phase_from_samples({"ref": [20.0] * 27 + [180.0] * 3})
        active_with_delta = bufferbloat._with_delta(active, baseline)

        self.assertEqual(active_with_delta.delta_ms, 160.0)
        self.assertEqual(bufferbloat._grade(active_with_delta.delta_ms, None), "F")

    def test_stop_event_finishes_before_one_second(self) -> None:
        thresholds = replace(
            DEFAULT_THRESHOLDS,
            bufferbloat_baseline_s=5.0,
            bufferbloat_load_s=5.0,
            bufferbloat_sample_interval_s=0.1,
        )
        stop_event = Event()
        thread = Thread(
            target=bufferbloat.run_bufferbloat_test,
            kwargs={"stop_event": stop_event, "thresholds": thresholds},
        )
        with patch.object(bufferbloat, "_measure_tcp_latency", return_value=20.0):
            thread.start()
            time.sleep(0.05)
            started = time.monotonic()
            stop_event.set()
            thread.join(timeout=1.0)

        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 1.0)

    def test_worker_stop_sets_cancellation_event(self) -> None:
        worker = BufferbloatWorker(None, None)

        worker.stop()

        self.assertTrue(worker._stop_event.is_set())

    def test_maximum_bytes_stops_streams(self) -> None:
        thresholds = replace(
            DEFAULT_THRESHOLDS,
            bufferbloat_load_s=5.0,
            bufferbloat_streams=1,
            bufferbloat_max_bytes=64,
            bufferbloat_sample_interval_s=0.01,
        )
        created_budgets: list[bufferbloat._ByteBudget] = []
        original_budget = bufferbloat._ByteBudget

        class CapturingBudget(original_budget):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)
                created_budgets.append(self)

        with patch.object(bufferbloat, "_ByteBudget", CapturingBudget), patch.object(
            bufferbloat, "_download", return_value=(64, 0.0)
        ), patch.object(
            bufferbloat, "_measure_tcp_latency", return_value=20.0
        ):
            phase = bufferbloat._load_phase(
                "download",
                "1.1.1.1",
                53,
                target_ip=None,
                gateway=None,
                stop_event=Event(),
                thresholds=thresholds,
            )

        self.assertIsNotNone(phase.speed_mbps)
        self.assertEqual(created_budgets[0].completed, 64)
        self.assertTrue(created_budgets[0]._stop_event.is_set())


if __name__ == "__main__":
    unittest.main()
