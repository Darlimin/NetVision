"""Small local history store for completed network tests."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import tempfile


MAX_HISTORY_ENTRIES = 500


def default_history_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "NetVision" / "test_history.json"
    return Path.home() / ".netvision" / "test_history.json"


class TestHistoryStore:
    """Persist compact test summaries without coupling the core to Qt."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_history_path()

    def load(self) -> list[dict[str, object]]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return []
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)][-MAX_HISTORY_ENTRIES:]

    def append(
        self,
        test_type: str,
        *,
        download_mbps: float | None = None,
        upload_mbps: float | None = None,
        ping_ms: float | None = None,
        bufferbloat_grade: str | None = None,
    ) -> dict[str, object]:
        record: dict[str, object] = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "test_type": test_type,
            "download_mbps": download_mbps,
            "upload_mbps": upload_mbps,
            "ping_ms": ping_ms,
            "bufferbloat_grade": bufferbloat_grade,
        }
        records = self.load()
        records.append(record)
        self._write(records[-MAX_HISTORY_ENTRIES:])
        return record

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return

    def _write(self, records: list[dict[str, object]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f"{self.path.stem}-",
                suffix=".tmp",
                delete=False,
            ) as output:
                temporary_path = Path(output.name)
                json.dump(records, output, ensure_ascii=False, indent=2)
                output.write("\n")
            temporary_path.replace(self.path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
