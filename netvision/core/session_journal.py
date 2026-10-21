"""Persistent, session-scoped journal for network measurements and actions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import os
from pathlib import Path
import tempfile
from uuid import uuid4

from netvision.core.test_history import default_history_path


MAX_JOURNAL_EVENTS = 2000


class Layer(str, Enum):
    """The semantic layer represented by a journal event."""

    MEASUREMENT = "measurement"
    INFERENCE = "inference"
    ACTION = "action"


KIND_LAYER: dict[str, Layer] = {
    "udp.port_opened": Layer.MEASUREMENT,
    "udp.port_closed": Layer.MEASUREMENT,
    "udp.monitor_error": Layer.MEASUREMENT,
    "udp.possible_disconnect": Layer.INFERENCE,
    "process.sockets": Layer.MEASUREMENT,
    "vpn.bypass_suspected": Layer.INFERENCE,
    "endpoint.choice": Layer.INFERENCE,
    "jitter.episode": Layer.MEASUREMENT,
    "loss.episode": Layer.MEASUREMENT,
    "header.anomaly": Layer.INFERENCE,
    "action.system_started": Layer.ACTION,
    "action.system_finished": Layer.ACTION,
    "action.system_confirmed": Layer.ACTION,
    "action.system_rolled_back": Layer.ACTION,
    "action.process_selected": Layer.ACTION,
    "action.target_selected": Layer.ACTION,
    "action.monitor_scope": Layer.ACTION,
    "action.network_boost": Layer.ACTION,
    "mtu.measured": Layer.MEASUREMENT,
    "mtu.probe_failed": Layer.MEASUREMENT,
    "bufferbloat.measured": Layer.MEASUREMENT,
    "mtr.route_changed": Layer.MEASUREMENT,
    "mtr.probe_failed": Layer.MEASUREMENT,
    "nat.measured": Layer.MEASUREMENT,
    "nat.probe_failed": Layer.MEASUREMENT,
    "wifi.roam": Layer.MEASUREMENT,
    "wifi.probe_failed": Layer.MEASUREMENT,
    "mtu.recommendation": Layer.INFERENCE,
    "bufferbloat.verdict": Layer.INFERENCE,
    "mtr.loss_episode": Layer.INFERENCE,
    "nat.inferred": Layer.INFERENCE,
    "wifi.signal_low": Layer.INFERENCE,
    "wifi.suspected_cause": Layer.INFERENCE,
    "game.session_ended": Layer.INFERENCE,
    "mtu.apply_trial": Layer.ACTION,
    "mtu.confirmed": Layer.ACTION,
    "mtu.rolled_back": Layer.ACTION,
    "mtr.started": Layer.ACTION,
    "mtr.stopped": Layer.ACTION,
    "app.background_entered": Layer.ACTION,
    "app.background_left": Layer.ACTION,
    "monitor.auto_started": Layer.ACTION,
    "monitor.auto_stopped": Layer.ACTION,
    "export.created": Layer.ACTION,
}


@dataclass(frozen=True, slots=True)
class JournalEvent:
    id: str
    session: str
    at: datetime
    layer: Layer
    kind: str
    severity: str
    subject: str
    template: str
    values: dict[str, object]
    refs: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "session": self.session,
            "at": self.at.isoformat(),
            "layer": self.layer.value,
            "kind": self.kind,
            "severity": self.severity,
            "subject": self.subject,
            "template": self.template,
            "values": self.values,
            "refs": self.refs,
        }

    @classmethod
    def from_dict(cls, payload: object) -> JournalEvent | None:
        if not isinstance(payload, dict):
            return None
        try:
            at = datetime.fromisoformat(str(payload["at"]))
            layer = Layer(str(payload["layer"]))
        except (KeyError, TypeError, ValueError):
            return None
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        values = payload.get("values", {})
        refs = payload.get("refs", {})
        if not isinstance(values, dict) or not isinstance(refs, dict):
            return None
        required = ("id", "session", "kind", "severity", "subject", "template")
        if any(key not in payload for key in required):
            return None
        return cls(
            id=str(payload["id"]),
            session=str(payload["session"]),
            at=at,
            layer=layer,
            kind=str(payload["kind"]),
            severity=str(payload["severity"]),
            subject=str(payload["subject"]),
            template=str(payload["template"]),
            values={str(key): value for key, value in values.items()},
            refs={str(key): value for key, value in refs.items()},
        )


def default_journal_path() -> Path:
    return default_history_path().with_name("event_journal.jsonl")


class JournalStore:
    """JSONL storage with bounded retention and atomic replacement."""

    def __init__(self, path: Path | None = None, *, limit: int = MAX_JOURNAL_EVENTS) -> None:
        if limit < 1:
            raise ValueError("Journal limit must be positive")
        self.path = path or default_journal_path()
        self.limit = limit

    def load(self) -> list[JournalEvent]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return []
        events = [event for line in lines if (event := self._decode_line(line)) is not None]
        return events[-self.limit:]

    def append(self, event: JournalEvent) -> JournalEvent:
        events = self.load()
        events.append(event)
        self._write(events[-self.limit:])
        return event

    def clear(self, *, session: str | None = None) -> None:
        events = self.load()
        remaining = [] if session is None else [event for event in events if event.session != session]
        self._write(remaining)

    @staticmethod
    def _decode_line(line: str) -> JournalEvent | None:
        try:
            return JournalEvent.from_dict(json.loads(line))
        except json.JSONDecodeError:
            return None

    def _write(self, events: list[JournalEvent]) -> None:
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
                for event in events:
                    output.write(json.dumps(event.to_dict(), ensure_ascii=False, default=_json_default))
                    output.write("\n")
            os.replace(temporary_path, self.path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()


class SessionJournal:
    """Records typed events for one application session."""

    def __init__(self, store: JournalStore, session: str) -> None:
        self.store = store
        self.session = session

    @classmethod
    def create(cls, store: JournalStore) -> SessionJournal:
        return cls(store, uuid4().hex)

    def events(self, *, include_past_sessions: bool = False) -> list[JournalEvent]:
        events = self.store.load()
        return events if include_past_sessions else [event for event in events if event.session == self.session]

    def recent(self, kind_prefix: str = "", since_s: float | None = None) -> list[JournalEvent]:
        """Return current-session events matching a kind prefix and optional age limit."""
        cutoff = None
        if since_s is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(0.0, since_s))
        return [
            event
            for event in self.events()
            if event.kind.startswith(kind_prefix) and (cutoff is None or event.at >= cutoff)
        ]

    def export(self, since: datetime | None = None) -> list[dict[str, object]]:
        """Serialize current-session events for inclusion in a diagnostic bundle."""
        cutoff = _as_aware(since) if since is not None else None
        return [
            event.to_dict()
            for event in self.events()
            if cutoff is None or event.at >= cutoff
        ]

    def record(
        self,
        kind: str,
        *,
        severity: str = "info",
        subject: str = "",
        template: str = "",
        values: dict[str, object] | None = None,
        refs: dict[str, object] | None = None,
        at: datetime | None = None,
    ) -> JournalEvent:
        layer = KIND_LAYER[kind]
        event = JournalEvent(
            id=uuid4().hex,
            session=self.session,
            at=_as_aware(at),
            layer=layer,
            kind=kind,
            severity=severity,
            subject=subject,
            template=template,
            values=dict(values or {}),
            refs=dict(refs or {}),
        )
        return self.store.append(event)


def _as_aware(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _json_default(value: object) -> str:
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)
