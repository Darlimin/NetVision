from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ProbeStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Target:
    original: str
    host: str
    port: int
    scheme: str

    @property
    def display_name(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def uses_tls(self) -> bool:
        return self.scheme == "https" or self.port in {443, 8443}


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    name: str
    kind: str
    is_up: bool
    speed_mbps: int
    mac: str | None = None
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GatewayInfo:
    address: str
    interface: str | None = None
    metric: int | None = None


@dataclass(frozen=True, slots=True)
class DefaultRoute:
    gateway: str
    interface: str | None
    local_address: str
    metric: int
    is_vpn: bool
    on_link: bool = False


@dataclass(frozen=True, slots=True)
class SystemSnapshot:
    hostname: str
    interfaces: tuple[NetworkInterface, ...]
    gateway: GatewayInfo | None
    dns_servers: tuple[str, ...]
    external_ip: str | None
    proxies: tuple[tuple[str, str], ...]
    warnings: tuple[str, ...] = ()
    default_routes: tuple[DefaultRoute, ...] = ()


@dataclass(frozen=True, slots=True)
class DnsResult:
    host: str
    addresses: tuple[str, ...]
    latency_ms: float | None
    status: ProbeStatus
    error: str | None = None


@dataclass(frozen=True, slots=True)
class TcpResult:
    host: str
    port: int
    peer_address: str | None
    latency_ms: float | None
    status: ProbeStatus
    error: str | None = None


@dataclass(frozen=True, slots=True)
class PingResult:
    host: str
    sent: int
    received: int
    loss_percent: float
    average_ms: float | None
    minimum_ms: float | None
    maximum_ms: float | None
    jitter_ms: float | None
    samples_ms: tuple[float, ...]
    status: ProbeStatus
    error: str | None = None


@dataclass(frozen=True, slots=True)
class GeoResult:
    address: str
    country: str | None
    region: str | None
    city: str | None
    asn: str | None
    organization: str | None
    isp: str | None
    status: ProbeStatus
    error: str | None = None


@dataclass(frozen=True, slots=True)
class TlsResult:
    version: str | None
    cipher: str | None
    alpn: str | None
    subject: str | None
    issuer: str | None
    expires_at: datetime | None
    latency_ms: float | None
    status: ProbeStatus
    error: str | None = None


@dataclass(frozen=True, slots=True)
class HopResult:
    index: int
    address: str | None
    latency_ms: float | None
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    target: Target
    system: SystemSnapshot
    dns: DnsResult
    tcp: TcpResult
    ping: PingResult
    tls: TlsResult | None
    hops: tuple[HopResult, ...]
    geolocation: tuple[GeoResult, ...]
    started_at: datetime
    total_ms: float
    errors: tuple[str, ...] = field(default_factory=tuple)

