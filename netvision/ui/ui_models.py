"""Data structures shared by NetVision UI components."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class UdpEventRow:
    observed_at: datetime
    event_type: str
    port: int | None
    details: str
    is_anomaly: bool = False
    pid: int | None = None


@dataclass(frozen=True, slots=True)
class JitterEventRow:
    observed_at: datetime
    deviation_ms: float
    endpoint: str
    details: str
    kind: str = "spike"
    ended_at: datetime | None = None
    samples: int = 1


@dataclass(frozen=True, slots=True)
class HeaderAnomalyEvent:
    """A compact history row rendered from the header session capsule."""

    observed_at: datetime
    state: str
    source: str
    values: tuple[tuple[str, object], ...]
