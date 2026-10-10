from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from datetime import datetime

from netvision.core.probes import lookup_geo, probe_ping, probe_tcp, probe_tls, resolve_dns, trace_route
from netvision.core.system import collect_system_snapshot
from netvision.models import (
    DiagnosticReport,
    DnsResult,
    HopResult,
    PingResult,
    ProbeStatus,
    SystemSnapshot,
    Target,
    TcpResult,
)

ProgressCallback = Callable[[str, str], None]


class DiagnosticService:
    def run(self, target: Target, progress: ProgressCallback | None = None) -> DiagnosticReport:
        notify = progress or (lambda _stage, _message: None)
        started_at = datetime.now()
        started = time.perf_counter()
        errors: list[str] = []

        notify("parallel", "Параллельно проверяем сеть, DNS, ping и маршрут")
        jobs = {
            "system": (collect_system_snapshot, "Сетевые интерфейсы и маршруты собраны"),
            "dns": (lambda: resolve_dns(target), "DNS-проверка завершена"),
            "tcp": (lambda: probe_tcp(target), "TCP-проверка завершена"),
            "ping": (lambda: probe_ping(target.host), "Измерение ping/jitter/loss завершено"),
            "route": (lambda: trace_route(target), "Построение маршрута завершено"),
        }
        results: dict[str, object] = {}
        with ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="netvision-probe") as pool:
            futures = {pool.submit(operation): (name, message) for name, (operation, message) in jobs.items()}
            for future in as_completed(futures):
                name, message = futures[future]
                try:
                    results[name] = future.result()
                except Exception as exc:
                    errors.append(f"{name.upper()}: {exc}")
                notify("parallel", message)

        system = _system_result(results.get("system"), errors)
        dns = _dns_result(results.get("dns"), target.host, errors)
        tcp = _tcp_result(results.get("tcp"), target, errors)
        ping = _ping_result(results.get("ping"), target.host, errors)
        hops = results.get("route") if isinstance(results.get("route"), tuple) else ()
        errors.extend(system.warnings)
        if dns.error:
            errors.append(f"DNS: {dns.error}")
        if tcp.error:
            errors.append(f"TCP: {tcp.error}")
        if ping.error:
            errors.append(f"Ping: {ping.error}")

        tls = None
        if target.uses_tls and tcp.status == ProbeStatus.SUCCESS:
            notify("tls", "Проверяем TLS и сертификат")
            tls = probe_tls(target)
            if tls.error:
                errors.append(f"TLS: {tls.error}")

        if not hops:
            errors.append("Маршрут не удалось получить; остальные результаты сохранены")

        geo_addresses = _public_route_addresses(dns.addresses, tcp.peer_address, hops)
        geolocation = ()
        if geo_addresses:
            notify("geo", f"Определяем ASN/GeoIP для {len(geo_addresses)} публичных узлов")
            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="netvision-geo") as pool:
                futures = {pool.submit(lookup_geo, address): address for address in geo_addresses}
                geo_results = []
                for future in as_completed(futures):
                    try:
                        geo_results.append(future.result())
                    except Exception as exc:
                        errors.append(f"GeoIP {futures[future]}: {exc}")
            geolocation = tuple(sorted(geo_results, key=lambda item: geo_addresses.index(item.address)))
            for result in geolocation:
                if result.error and result.status == ProbeStatus.ERROR:
                    errors.append(f"GeoIP {result.address}: {result.error}")

        notify("complete", "Диагностика завершена")
        return DiagnosticReport(
            target=target,
            system=system,
            dns=dns,
            tcp=tcp,
            ping=ping,
            tls=tls,
            hops=hops,
            geolocation=geolocation,
            started_at=started_at,
            total_ms=round((time.perf_counter() - started) * 1000, 1),
            errors=tuple(errors),
        )


def _system_result(value: object, errors: list[str]) -> SystemSnapshot:
    if isinstance(value, SystemSnapshot):
        return value
    errors.append("SYSTEM: не удалось собрать сведения о сетевых интерфейсах")
    return SystemSnapshot(
        hostname="unknown",
        interfaces=(),
        gateway=None,
        dns_servers=(),
        external_ip=None,
        proxies=(),
    )


def _dns_result(value: object, host: str, errors: list[str]) -> DnsResult:
    if isinstance(value, DnsResult):
        return value
    errors.append("DNS: проверка не вернула результат")
    return DnsResult(host, (), None, ProbeStatus.ERROR, "проверка завершилась ошибкой")


def _tcp_result(value: object, target: Target, errors: list[str]) -> TcpResult:
    if isinstance(value, TcpResult):
        return value
    errors.append("TCP: проверка не вернула результат")
    return TcpResult(target.host, target.port, None, None, ProbeStatus.ERROR, "проверка завершилась ошибкой")


def _ping_result(value: object, host: str, errors: list[str]) -> PingResult:
    if isinstance(value, PingResult):
        return value
    errors.append("PING: проверка не вернула результат")
    return PingResult(host, 0, 0, 0.0, None, None, None, None, (), ProbeStatus.ERROR, "проверка завершилась ошибкой")


def _public_route_addresses(
    dns_addresses: tuple[str, ...],
    peer_address: str | None,
    hops: tuple[HopResult, ...],
) -> tuple[str, ...]:
    candidates = list(dns_addresses)
    if peer_address:
        candidates.append(peer_address)
    candidates.extend(hop.address for hop in hops if hop.address)
    public: list[str] = []
    for candidate in candidates:
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.is_global and str(parsed) not in public:
            public.append(str(parsed))
        if len(public) >= 12:
            break
    return tuple(public)

