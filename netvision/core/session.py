from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable

log = logging.getLogger(__name__)
Listener = Callable[[str, Any, Any], None]


@dataclass(frozen=True, slots=True)
class Scope:
    host: str = ""
    port: int = 0

    @classmethod
    def of(cls, host: object, port: object) -> "Scope":
        try:
            return cls(str(host or "").strip().casefold(), int(port or 0))
        except (TypeError, ValueError):
            return cls()


class StateStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values: dict[str, Any] = {}
        self._listeners: dict[str, list[Listener]] = {}
        self.revision = 0

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._values.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        with self._lock:
            old = self._values.get(key)
            if old is value:
                return False
            self._values[key] = value
            self.revision += 1
            listeners = [*self._listeners.get(key, ()), *self._listeners.get("*", ())]
        for listener in listeners:
            try:
                listener(key, old, value)
            except Exception:
                log.exception("state listener failed for %r", key)
        return True

    def subscribe(self, keys: Iterable[str], listener: Listener) -> Callable[[], None]:
        wanted = tuple(keys) or ("*",)
        with self._lock:
            for key in wanted:
                self._listeners.setdefault(key, []).append(listener)

        def unsubscribe() -> None:
            with self._lock:
                for key in wanted:
                    if listener in self._listeners.get(key, []):
                        self._listeners[key].remove(listener)

        return unsubscribe
