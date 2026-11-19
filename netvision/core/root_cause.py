from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import ipaddress

from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo
from netvision.core.nat_diagnostics import NatReport
from netvision.core.system import _is_vpn_name
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds
from netvision.core.traceroute import MtrSnapshot
from netvision.models import DiagnosticReport, ProbeStatus, WifiSnapshot


class CauseSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RootCauseFinding:
    severity: CauseSeverity
    title: str
    explanation: str
    evidence: str


@dataclass(frozen=True, slots=True)
class RootCauseAnalysis:
    subject: str
    headline: str
    findings: tuple[RootCauseFinding, ...]


def analyze_report(
    report: DiagnosticReport,
    process: ProcessNetworkInfo | None = None,
    connection: ProcessConnection | None = None,
    th: Thresholds = DEFAULT_THRESHOLDS,
    mtr: MtrSnapshot | None = None,
    nat: NatReport | None = None,
    wifi: WifiSnapshot | None = None,
) -> RootCauseAnalysis:
    subject = process.name if process else report.target.display_name
    findings: list[RootCauseFinding] = []
    is_udp_target = getattr(connection, "protocol", None) == "UDP"

    bypass_finding = vpn_bypass_connections(report, process)
    if bypass_finding is not None:
        findings.append(bypass_finding)

    findings.extend(_udp_target_findings(is_udp_target, nat))

    if report.dns.status == ProbeStatus.ERROR:
        findings.append(
            RootCauseFinding(
                CauseSeverity.ERROR,
                "Не удаётся найти адрес сервера",
                "DNS не преобразовал имя узла в IP-адрес. Проверьте DNS-сервер или настройки VPN.",
                report.dns.error or "DNS вернул ошибку",
            )
        )

    if report.tcp.status != ProbeStatus.SUCCESS and not is_udp_target:
        findings.append(
            RootCauseFinding(
                CauseSeverity.ERROR,
                "Порт недоступен",
                "Порты приложения могут блокироваться Брандмауэром Windows или антивирусом.",
                report.tcp.error or f"TCP-порт {report.target.port} не подтвердил соединение",
            )
        )

    mtu_finding = _mtu_finding(report, th)
    if mtu_finding is not None:
        findings.append(mtu_finding)

    if _has_local_latency_problem(report, th) or _has_wifi_problem(wifi, th):
        findings.append(
            RootCauseFinding(
                CauseSeverity.WARNING,
                "Высокая задержка или Jitter",
                "Проблема может быть в локальной сети, Wi-Fi или роутере.",
                _latency_evidence(report, wifi, th),
            )
        )

    route_finding = _mtr_route_finding(mtr) if mtr is not None else _legacy_route_finding(report)
    if route_finding is not None:
        findings.append(route_finding)

    if _has_vpn_problem(report, th):
        findings.append(
            RootCauseFinding(
                CauseSeverity.WARNING,
                "Нестабильный VPN-маршрут",
                "VPN-сервер может замедлять или обрывать подключение.",
                "Активный VPN-маршрут сочетается с потерями или высоким Jitter",
            )
        )

    if not findings:
        findings.append(
            RootCauseFinding(
                CauseSeverity.INFO,
                "Явная причина дисконнекта не выявлена",
                "Основные проверки прошли. Подробности доступны в экспертном режиме.",
                "DNS, TCP и сетевые показатели не дали критичного сигнала",
            )
        )

    return RootCauseAnalysis(
        subject=subject,
        headline=findings[0].title,
        findings=tuple(findings),
    )


def _udp_target_findings(
    is_udp_target: bool,
    nat: NatReport | None,
) -> tuple[RootCauseFinding, ...]:
    if not is_udp_target:
        return ()
    findings = [
        RootCauseFinding(
            CauseSeverity.INFO,
            "Выбран UDP-endpoint",
            "TCP-проверка не является решающей для игрового UDP-трафика; ориентируйтесь на ping, потери и маршрут.",
            "Процесс установил UDP-соединение с выбранным адресом",
        )
    ]
    if nat is not None and nat.nat_type == "apdm":
        findings.append(
            RootCauseFinding(
                CauseSeverity.WARNING,
                "Strict NAT: P2P-соединения (голос, пати) могут не устанавливаться",
                "STUN обнаружил зависимое от адреса или порта сопоставление UDP."
                " Это усложняет прямые P2P-соединения.",
                "; ".join(endpoint.display for endpoint in nat.mapped_endpoints),
            )
        )
    return tuple(findings)


def _legacy_route_finding(report: DiagnosticReport) -> RootCauseFinding | None:
    if not _has_route_problem(report):
        return None
    return RootCauseFinding(
        CauseSeverity.WARNING,
        "Потери на промежуточном узле",
        "Возможен сбой у магистрального провайдера по пути к серверу.",
        _route_evidence(report),
    )


def _mtr_route_finding(mtr: MtrSnapshot) -> RootCauseFinding | None:
    """Use only confirmed end-to-end MTR loss; ICMP rate limiting is informational."""
    if mtr.undetermined or mtr.real_loss_start_hop is None:
        return None
    return RootCauseFinding(
        CauseSeverity.WARNING,
        "Сквозные потери по маршруту",
        "Потери подтверждаются от указанного узла до конечной цели.",
        f"Начало: hop {mtr.real_loss_start_hop}; потери {mtr.real_loss_pct:.1f}%",
    )


def vpn_bypass_connections(
    report: DiagnosticReport,
    process: ProcessNetworkInfo | None,
) -> RootCauseFinding | None:
    """Detect global process sockets that bypass an active VPN interface."""
    routes = report.system.default_routes
    if process is None or not routes or not routes[0].is_vpn or _is_vpn_name(process.name):
        return None

    vpn_addresses, physical_addresses = _interface_address_sets(report)
    evidence = _vpn_bypass_evidence(process, vpn_addresses, physical_addresses)

    if not evidence:
        return None
    return RootCauseFinding(
        CauseSeverity.WARNING,
        "Возможный обход VPN",
        "Сокеты выбранного процесса используют физический интерфейс при активном VPN-маршруте.",
        "; ".join(evidence),
    )


def _interface_address_sets(report: DiagnosticReport) -> tuple[set[str], dict[str, str]]:
    vpn_addresses: set[str] = set()
    physical_addresses: dict[str, str] = {}
    for interface in report.system.interfaces:
        addresses = (_ip_address(value) for value in (*interface.ipv4, *interface.ipv6))
        if interface.kind == "VPN":
            vpn_addresses.update(address for address in addresses if address is not None)
        elif interface.kind != "Loopback":
            physical_addresses.update(
                {address: interface.name for address in addresses if address is not None}
            )
    vpn_addresses.update(
        address
        for route in report.system.default_routes
        if route.is_vpn and (address := _ip_address(route.local_address)) is not None
    )
    return vpn_addresses, physical_addresses


def _vpn_bypass_evidence(
    process: ProcessNetworkInfo,
    vpn_addresses: set[str],
    physical_addresses: dict[str, str],
) -> list[str]:
    evidence: list[str] = []
    for connection in process.connections:
        item = _physical_connection_evidence(connection, vpn_addresses, physical_addresses)
        if item is not None and item not in evidence:
            evidence.append(item)
        if len(evidence) == 3:
            break
    return evidence


def _physical_connection_evidence(
    connection: ProcessConnection,
    vpn_addresses: set[str],
    physical_addresses: dict[str, str],
) -> str | None:
    remote_address = _global_address(connection.remote_address)
    local_address = _ip_address(connection.local_address)
    if remote_address is None or local_address is None or local_address in vpn_addresses:
        return None
    interface = physical_addresses.get(local_address)
    return f"{local_address} -> {remote_address} ({interface})" if interface else None


def _has_local_latency_problem(
    report: DiagnosticReport,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> bool:
    average_high = report.ping.average_ms is not None and report.ping.average_ms > th.rtt_high_ms
    jitter_high = (
        report.ping.jitter_ms is not None and report.ping.jitter_ms > th.jitter_critical_ms
    )
    return average_high or jitter_high


def _has_route_problem(report: DiagnosticReport) -> bool:
    return any(hop.timed_out and hop.index >= 2 for hop in report.hops)


def _has_vpn_problem(
    report: DiagnosticReport,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> bool:
    vpn_active = any(route.is_vpn for route in report.system.default_routes)
    return vpn_active and (
        report.ping.loss_percent > 0
        or (report.ping.jitter_ms is not None and report.ping.jitter_ms > th.jitter_critical_ms)
    )


def _mtu_finding(
    report: DiagnosticReport,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> RootCauseFinding | None:
    if _tls_transport_failure(report):
        return RootCauseFinding(
            CauseSeverity.INFO,
            "Проверить MTU",
            "TCP-соединение открыто, но защищённое соединение не завершилось."
            " Проверьте Path MTU до цели.",
            report.tls.error or "TLS не завершил соединение",
        )
    if _loss_with_normal_latency(report, th):
        return RootCauseFinding(
            CauseSeverity.INFO,
            "Проверить MTU",
            "Потери появляются без высокой базовой задержки." " Проверьте Path MTU до цели.",
            f"Ping {_format_ms(report.ping.average_ms)}, потери {report.ping.loss_percent:.0f}%",
        )
    return None


def _tls_transport_failure(report: DiagnosticReport) -> bool:
    if report.tcp.status != ProbeStatus.SUCCESS or report.tls is None:
        return False
    if report.tls.status != ProbeStatus.ERROR:
        return False
    error = (report.tls.error or "").casefold()
    if "ip address mismatch" in error:
        try:
            ipaddress.ip_address(report.target.host)
        except ValueError:
            pass
        else:
            return False
    markers = ("timeout", "timed out", "время ожидания", "reset", "обрыв")
    return any(marker in error for marker in markers)


def _loss_with_normal_latency(report: DiagnosticReport, th: Thresholds) -> bool:
    return bool(
        report.ping.loss_percent > 0
        and report.ping.average_ms is not None
        and report.ping.average_ms <= th.rtt_normal_ms
    )


def _latency_evidence(
    report: DiagnosticReport,
    wifi: WifiSnapshot | None = None,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> str:
    evidence = (
        f"Ping {_format_ms(report.ping.average_ms)}, "
        f"Jitter {_format_ms(report.ping.jitter_ms)}, "
        f"потери {report.ping.loss_percent:.0f}%"
    )
    if wifi is None:
        return evidence
    wifi_values: list[str] = []
    if wifi.signal_pct is not None and wifi.signal_pct <= th.wifi_signal_warn_pct:
        wifi_values.append(f"сигнал Wi-Fi {wifi.signal_pct}%")
    if wifi.channel:
        wifi_values.append(f"канал {wifi.channel}")
    if wifi.gateway_rtt_ms is not None and wifi.gateway_rtt_ms > th.wifi_gateway_rtt_warn_ms:
        wifi_values.append(f"шлюз {wifi.gateway_rtt_ms:.1f} мс")
    return f"{evidence}; Wi-Fi: {', '.join(wifi_values)}" if wifi_values else evidence


def _has_wifi_problem(wifi: WifiSnapshot | None, th: Thresholds) -> bool:
    return bool(
        wifi is not None
        and (
            (wifi.signal_pct is not None and wifi.signal_pct <= th.wifi_signal_warn_pct)
            or (
                wifi.gateway_rtt_ms is not None
                and wifi.gateway_rtt_ms > th.wifi_gateway_rtt_warn_ms
            )
        )
    )


def _route_evidence(report: DiagnosticReport) -> str:
    timed_out = [str(hop.index) for hop in report.hops if hop.timed_out and hop.index >= 2]
    return f"Тайм-ауты на узлах маршрута: {', '.join(timed_out)}"


def _ip_address(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


def _global_address(value: str | None) -> str | None:
    address = _ip_address(value)
    if address is None:
        return None
    return address if ipaddress.ip_address(address).is_global else None


def _format_ms(value: float | None) -> str:
    return "нет данных" if value is None else f"{value:.1f} мс"
