from unittest.mock import patch

import pytest

from netvision.ui.workers.local_snapshot import LocalNetworkSnapshotWorker


@pytest.mark.parametrize("failed", [False, True])
def test_snapshot_worker_emits_result_then_finishes(failed):
    worker = LocalNetworkSnapshotWorker()
    events = []
    result = RuntimeError("snapshot failed") if failed else object()
    worker.completed.connect(lambda value: events.append(("completed", value)))
    worker.finished.connect(lambda: events.append(("finished", None)))
    with patch(
        "netvision.ui.workers.local_snapshot.collect_system_snapshot",
        side_effect=result if failed else None,
        return_value=None if failed else result,
    ):
        worker.run()
    assert events == [("completed", result), ("finished", None)]
