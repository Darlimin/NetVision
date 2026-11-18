"""Shared data types for reversible actions."""

from collections.abc import Callable
from dataclasses import dataclass

from netvision.core.system_actions import SystemActionResult


@dataclass(slots=True)
class PendingAction:
    """A reversible system change awaiting the user's confirmation."""

    apply: Callable[[], None]
    rollback: Callable[[], SystemActionResult]
    timeout_s: float
