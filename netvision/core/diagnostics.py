from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from datetime import datetime

from netvision.core.probes import (
    lookup_geo,
    probe_ping,
    probe_tcp,
    probe_tls,
    resolve_dns,
    trace_route,
)
from netvision.core.system import collect_system_snapshot
from netvision.core.judgement import tls_domain_required
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
        results = _run_parallel_probes(target, notify, errors)
        system, dns, tcp, ping, hops = _probe_results(target, results, errors)
        tls = _run_tls_probe(target, tcp, notify, errors)
        geolocation = _lookup_geolocation(dns, tcp, hops, notify, errors)

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


def _run_parallel_probes(
    target: Target, notify: ProgressCallback, errors: list[str]
) -> dict[str, object]:
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
        futures = {
            pool.submit(operation): (name, message) for name, (operation, message) in jobs.items()
        }
        for future in as_completed(futures):
            name, message = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                errors.append(f"{name.upper()}: {exc}")
            notify("parallel", message)
    return results


def _probe_results(
    target: Target, results: dict[str, object], errors: list[str]
) -> tuple[SystemSnapshot, DnsResult, TcpResult, PingResult, tuple[HopResult, ...]]:
    system = _system_result(results.get("system"), errors)
    dns = _dns_result(results.get("dns"), target.host, errors)
    tcp = _tcp_result(results.get("tcp"), target, errors)
    ping = _ping_result(results.get("ping"), target.host, errors)
    hops = results.get("route") if isinstance(results.get("route"), tuple) else ()
    errors.extend(system.warnings)
    for label, result in (("DNS", dns), ("TCP", tcp), ("Ping", ping)):
        if result.error:
            errors.append(f"{label}: {result.error}")
    if not hops:
        errors.append("Маршрут не удалось получить; остальные результаты сохранены")
    return system, dns, tcp, ping, hops


def _run_tls_probe(target: Target, tcp: TcpResult, notify: ProgressCallback, errors: list[str]):
    if not target.uses_tls or tcp.status != ProbeStatus.SUCCESS:
        return None
    notify("tls", "Проверяем TLS и сертификат")
    tls = probe_tls(target)
    if tls.error:
        if tls_domain_required(target.host, tls.error):
            notify("tls", "TLS-сертификат требует доменное имя; транспорт доступен")
        else:
            errors.append(f"TLS: {tls.error}")
    return tls


def _lookup_geolocation(
    dns: DnsResult,
    tcp: TcpResult,
    hops: tuple[HopResult, ...],
    notify: ProgressCallback,
    errors: list[str],
):
    addresses = _public_route_addresses(dns.addresses, tcp.peer_address, hops)
    if not addresses:
        return ()
    notify("geo", f"Определяем ASN/GeoIP для {len(addresses)} публичных узлов")
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="netvision-geo") as pool:
        futures = {pool.submit(lookup_geo, address): address for address in addresses}
        results = [_geo_result(future, futures[future], errors) for future in as_completed(futures)]
    geolocation = tuple(
        sorted(
            (result for result in results if result is not None),
            key=lambda item: addresses.index(item.address),
        )
    )
    for result in geolocation:
        if result.error and result.status == ProbeStatus.ERROR:
            errors.append(f"GeoIP {result.address}: {result.error}")
    return geolocation


def _geo_result(future, address: str, errors: list[str]):
    try:
        return future.result()
    except Exception as exc:
        errors.append(f"GeoIP {address}: {exc}")
        return None


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
    return TcpResult(
        target.host, target.port, None, None, ProbeStatus.ERROR, "проверка завершилась ошибкой"
    )


def _ping_result(value: object, host: str, errors: list[str]) -> PingResult:
    if isinstance(value, PingResult):
        return value
    errors.append("PING: проверка не вернула результат")
    return PingResult(
        host,
        0,
        0,
        0.0,
        None,
        None,
        None,
        None,
        (),
        ProbeStatus.ERROR,
        "проверка завершилась ошибкой",
    )


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
