from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from netvision.core.process_inspector import ProcessConnection, ProcessNetworkInfo
from netvision.models import DiagnosticReport, ProbeStatus


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
) -> RootCauseAnalysis:
    subject = process.name if process else report.target.display_name
    findings: list[RootCauseFinding] = []
    is_udp_target = getattr(connection, "protocol", None) == "UDP"

    if is_udp_target:
        findings.append(
            RootCauseFinding(
                CauseSeverity.INFO,
                "Выбран UDP-endpoint",
                "TCP-проверка не является решающей для игрового UDP-трафика; ориентируйтесь на ping, потери и маршрут.",
                "Процесс установил UDP-соединение с выбранным адресом",
            )
        )

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

    if _has_local_latency_problem(report):
        findings.append(
            RootCauseFinding(
                CauseSeverity.WARNING,
                "Высокая задержка или Jitter",
                "Проблема может быть в локальной сети, Wi-Fi или роутере.",
                _latency_evidence(report),
            )
        )

    if _has_route_problem(report):
        findings.append(
            RootCauseFinding(
                CauseSeverity.WARNING,
                "Потери на промежуточном узле",
                "Возможен сбой у магистрального провайдера по пути к серверу.",
                _route_evidence(report),
            )
        )

    if _has_vpn_problem(report):
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


def _has_local_latency_problem(report: DiagnosticReport) -> bool:
    average_high = report.ping.average_ms is not None and report.ping.average_ms > 100
    jitter_high = report.ping.jitter_ms is not None and report.ping.jitter_ms > 20
    return average_high or jitter_high


def _has_route_problem(report: DiagnosticReport) -> bool:
    return any(hop.timed_out and hop.index >= 2 for hop in report.hops)


def _has_vpn_problem(report: DiagnosticReport) -> bool:
    vpn_active = any(route.is_vpn for route in report.system.default_routes)
    return vpn_active and (
        report.ping.loss_percent > 0
        or (report.ping.jitter_ms is not None and report.ping.jitter_ms > 20)
    )


def _latency_evidence(report: DiagnosticReport) -> str:
    return (
        f"Ping {_format_ms(report.ping.average_ms)}, "
        f"Jitter {_format_ms(report.ping.jitter_ms)}, "
        f"потери {report.ping.loss_percent:.0f}%"
    )


def _route_evidence(report: DiagnosticReport) -> str:
    timed_out = [str(hop.index) for hop in report.hops if hop.timed_out and hop.index >= 2]
    return f"Тайм-ауты на узлах маршрута: {', '.join(timed_out)}"


def _format_ms(value: float | None) -> str:
    return "нет данных" if value is None else f"{value:.1f} мс"
