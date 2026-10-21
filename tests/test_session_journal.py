from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from netvision.core.session_journal import (
    KIND_LAYER,
    JournalStore,
    Layer,
    SessionJournal,
)


class SessionJournalTests(unittest.TestCase):
    def test_records_are_persisted_and_loaded_with_aware_time(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event_journal.jsonl"
            journal = SessionJournal(JournalStore(path), "session-a")

            event = journal.record(
                "udp.port_opened",
                subject="UDP:27015",
                template="UDP-порт {port}",
                values={"port": 27015},
                at=datetime(2026, 10, 20, 12, 0, 0),
            )

            loaded = JournalStore(path).load()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].id, event.id)
            self.assertEqual(loaded[0].layer, Layer.MEASUREMENT)
            self.assertIsNotNone(loaded[0].at.tzinfo)
            self.assertEqual(journal.events(), loaded)

    def test_store_keeps_only_configured_number_of_events(self) -> None:
        with TemporaryDirectory() as directory:
            store = JournalStore(Path(directory) / "event_journal.jsonl", limit=2)
            journal = SessionJournal(store, "session-a")

            for index in range(3):
                journal.record(
                    "action.system_started",
                    subject=str(index),
                    at=datetime(2026, 10, 20, 12, index, tzinfo=timezone.utc),
                )

            self.assertEqual([event.subject for event in store.load()], ["1", "2"])

    def test_kind_layer_mapping_is_strict(self) -> None:
        self.assertIs(KIND_LAYER["udp.possible_disconnect"], Layer.INFERENCE)
        self.assertIs(KIND_LAYER["action.system_started"], Layer.ACTION)
        with TemporaryDirectory() as directory:
            journal = SessionJournal(JournalStore(Path(directory) / "journal.jsonl"), "session-a")
            with self.assertRaises(KeyError):
                journal.record("unknown.kind")


if __name__ == "__main__":
    unittest.main()
