from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from netvision.models import DiagnosticReport, ProbeStatus
from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds


class LiteStatus(StrEnum):
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class LiteSummary:
    status: LiteStatus
    title: str
    message: str
    lines: tuple[str, ...]


def summarize_report(
    report: DiagnosticReport,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> LiteSummary:
    """Turn the detailed report into a short, user-oriented result."""
    if report.dns.status == ProbeStatus.ERROR or report.tcp.status != ProbeStatus.SUCCESS:
        return LiteSummary(
            status=LiteStatus.ERROR,
            title="Нет связи с узлом",
            message="Проверьте DNS и доступность порта.",
            lines=_summary_lines(report, th),
        )

    has_warning = (
        report.dns.status != ProbeStatus.SUCCESS
        or
        report.ping.status != ProbeStatus.SUCCESS
        or report.ping.loss_percent > 0
        or report.ping.jitter_ms is None
        or report.ping.jitter_ms > th.jitter_critical_ms
        or (report.tls is not None and report.tls.status != ProbeStatus.SUCCESS)
    )
    if has_warning:
        return LiteSummary(
            status=LiteStatus.WARNING,
            title="Сайт доступен, но есть предупреждения",
            message="Проверьте ICMP/Ping и стабильность задержки.",
            lines=_summary_lines(report, th),
        )

    return LiteSummary(
        status=LiteStatus.SUCCESS,
        title="Сайт полностью доступен",
        message="Соединение стабильное.",
        lines=_summary_lines(report, th),
    )


def _summary_lines(
    report: DiagnosticReport,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> tuple[str, ...]:
    latency = report.ping.average_ms
    if latency is None:
        latency_text = "Задержка не измерена"
    elif latency <= 50:
        latency_text = f"Задержка низкая: {latency:.1f} мс"
    elif latency <= th.rtt_high_ms:
        latency_text = f"Задержка средняя: {latency:.1f} мс"
    else:
        latency_text = f"Задержка высокая: {latency:.1f} мс"

    if report.dns.latency_ms is None:
        dns_text = "DNS не ответил"
    else:
        dns_text = f"DNS отвечает за {report.dns.latency_ms:.1f} мс"

    connection_text = (
        f"Порт {report.target.port} открыт"
        if report.tcp.status == ProbeStatus.SUCCESS
        else f"Порт {report.target.port} недоступен"
    )
    vpn_text = (
        "Используется VPN"
        if any(route.is_vpn for route in report.system.default_routes)
        else "VPN не обнаружен"
    )
    return (
        dns_text,
        connection_text,
        latency_text,
        f"Потери: {report.ping.loss_percent:.0f}% · Jitter: {_format_ms(report.ping.jitter_ms)}",
        vpn_text,
    )


def _format_ms(value: float | None) -> str:
    return "нет данных" if value is None else f"{value:.1f} мс"
