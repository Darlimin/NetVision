from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import socket
from time import perf_counter


@dataclass(frozen=True, slots=True)
class DnsResolverProfile:
    name: str
    addresses: tuple[str, ...]
    is_custom: bool = False

    @property
    def display_addresses(self) -> str:
        return " / ".join(self.addresses)


@dataclass(frozen=True, slots=True)
class DnsBenchmarkResult:
    profile: DnsResolverProfile
    address: str | None
    latency_ms: float | None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.latency_ms is not None


PUBLIC_DNS_PROFILES: tuple[DnsResolverProfile, ...] = (
    DnsResolverProfile("Cloudflare", ("1.1.1.1", "1.0.0.1")),
    DnsResolverProfile("Google Public DNS", ("8.8.8.8", "8.8.4.4")),
    DnsResolverProfile("Quad9", ("9.9.9.9", "149.112.112.112")),
    DnsResolverProfile("OpenDNS", ("208.67.222.222", "208.67.220.220")),
    DnsResolverProfile("Яндекс DNS", ("77.88.8.8", "77.88.8.1")),
    DnsResolverProfile("AdGuard DNS", ("94.140.14.14", "94.140.15.15")),
)


def custom_dns_profile(address: str) -> DnsResolverProfile:
    """Validate a user-supplied resolver address before it enters the benchmark."""
    try:
        parsed = ipaddress.ip_address(address.strip())
    except ValueError as exc:
        raise ValueError("Введите корректный IPv4 или IPv6 адрес DNS-сервера") from exc
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise ValueError("Этот адрес нельзя использовать как DNS-сервер")
    return DnsResolverProfile(f"Пользовательский DNS ({parsed})", (str(parsed),), is_custom=True)


def benchmark_resolvers(
    profiles: tuple[DnsResolverProfile, ...] | list[DnsResolverProfile],
    timeout: float = 1.5,
) -> tuple[DnsBenchmarkResult, ...]:
    """Measure every resolver endpoint concurrently using TCP port 53."""
    endpoint_results: dict[tuple[int, str], tuple[float | None, str | None]] = {}
    tasks = [
        (profile_index, address)
        for profile_index, profile in enumerate(profiles)
        for address in profile.addresses
    ]
    if not tasks:
        return ()

    with ThreadPoolExecutor(max_workers=min(12, len(tasks))) as executor:
        futures = {
            executor.submit(_probe_dns_port, address, timeout): (profile_index, address)
            for profile_index, address in tasks
        }
        for future in as_completed(futures):
            try:
                endpoint_results[futures[future]] = future.result()
            except Exception as exc:  # Keep one resolver failure from aborting the comparison.
                endpoint_results[futures[future]] = (None, str(exc))

    results: list[DnsBenchmarkResult] = []
    for index, profile in enumerate(profiles):
        attempts = [
            (address, *endpoint_results[(index, address)])
            for address in profile.addresses
        ]
        successful = [attempt for attempt in attempts if attempt[1] is not None]
        if successful:
            address, latency_ms, _error = min(successful, key=lambda attempt: attempt[1] or float("inf"))
            results.append(DnsBenchmarkResult(profile, address, latency_ms))
            continue
        errors = "; ".join(error for _address, _latency, error in attempts if error) or "Нет ответа на TCP/53"
        results.append(DnsBenchmarkResult(profile, None, None, errors))
    return tuple(results)


def _probe_dns_port(address: str, timeout: float) -> tuple[float | None, str | None]:
    started = perf_counter()
    try:
        with socket.create_connection((address, 53), timeout=timeout):
            return round((perf_counter() - started) * 1000, 1), None
    except OSError as exc:
        return None, str(exc)
