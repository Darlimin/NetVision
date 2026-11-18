"""Selection heuristics for game network endpoints."""

from collections.abc import Callable
from dataclasses import dataclass
import ipaddress

from netvision.core.process_inspector import ProcessConnection, is_loopback_address


@dataclass(frozen=True, slots=True)
class EndpointChoice:
    connection: ProcessConnection
    rule: str
    candidates: int
    excluded_cdn: int


def _is_background_cdn(address: str) -> bool:
    """Exclude Cloudflare edge endpoints before selecting a game target."""
    try:
        candidate = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    cloudflare_ranges = (
        ipaddress.ip_network("104.16.0.0/12"),
        ipaddress.ip_network("172.64.0.0/13"),
        ipaddress.ip_network("162.158.0.0/15"),
        ipaddress.ip_network("188.114.96.0/20"),
        ipaddress.ip_network("2606:4700::/32"),
    )
    return any(candidate in network for network in cloudflare_ranges)


def _is_game_remote_port(port: int) -> bool:
    return any(
        start <= port <= end
        for start, end in (
            (27000, 27100),
            (3074, 3074),
            (3478, 3480),
            (3659, 3659),
            (7777, 7777),
            (30000, 30100),
        )
    )


_GAME_RULES: tuple[tuple[str, Callable[[ProcessConnection], bool]], ...] = (
    (
        "UDP + игровой порт",
        lambda connection: connection.protocol == "UDP"
        and _is_game_remote_port(connection.remote_port),
    ),
    (
        "UDP + известный удалённый порт",
        lambda connection: connection.protocol == "UDP" and connection.remote_port > 0,
    ),
    ("Игровой удалённый порт", lambda connection: _is_game_remote_port(connection.remote_port)),
    ("Установленное соединение", lambda connection: connection.status == "ESTABLISHED"),
    ("Известный удалённый порт", lambda connection: connection.remote_port > 0),
)


def _game_connection_key(connection: ProcessConnection) -> tuple[int, int, int, int, int, str]:
    """Rank likely in-match sockets before generic client connections."""
    priorities = [0 if predicate(connection) else 1 for _, predicate in _GAME_RULES]
    # Preserve the established game-socket rule order while placing local
    # proxies after every externally reachable endpoint.
    if is_loopback_address(connection.remote_address):
        priorities[0] = 2
    return (
        *priorities,
        connection.remote_address,
    )


def _explain_game_connection(
    selected: ProcessConnection | None,
    candidates: tuple[ProcessConnection, ...],
) -> EndpointChoice | None:
    if selected is None:
        return None
    remote_candidates = tuple(item for item in candidates if item.remote_address)
    non_cdn_candidates = tuple(
        item for item in remote_candidates if not _is_background_cdn(item.remote_address)
    )
    for rule, predicate in _GAME_RULES:
        if predicate(selected):
            return EndpointChoice(
                connection=selected,
                rule=rule,
                candidates=len(non_cdn_candidates),
                excluded_cdn=len(remote_candidates) - len(non_cdn_candidates),
            )
    return EndpointChoice(
        connection=selected,
        rule="Известный удалённый порт",
        candidates=len(non_cdn_candidates),
        excluded_cdn=len(remote_candidates) - len(non_cdn_candidates),
    )
