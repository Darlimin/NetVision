"""Pure decisions used to classify diagnostic results for presentation."""

from __future__ import annotations

import ipaddress
from netvision.core.session import Scope
from netvision.core.thresholds import Thresholds
from netvision.models import DiagnosticReport, ProbeStatus


def tls_domain_required(host: str, error: str | None) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    text = (error or "").casefold()
    return "ip address mismatch" in text or "certificate_verify_failed" in text


def header_anomaly(
    report: DiagnosticReport,
    th: Thresholds,
) -> tuple[str, str, dict[str, float]]:
    if report.tcp.status != ProbeStatus.SUCCESS:
        return "error", "Нет подключения к целевому узлу", {}
    if (
        report.tls is not None
        and report.tls.status != ProbeStatus.SUCCESS
        and not tls_domain_required(report.target.host, report.tls.error)
    ):
        return "warning", "Ошибка проверки TLS", {}
    loss = report.ping.loss_percent
    if loss >= 20:
        return "error", "Потери пакетов: {loss:.0f}%", {"loss": loss}
    if loss > 0:
        return "warning", "Потери пакетов: {loss:.0f}%", {"loss": loss}
    latency = report.ping.average_ms or 0.0
    if latency >= th.rtt_peak_ms:
        return "error", "Пик пинга > {latency:.0f} мс", {"latency": latency}
    if latency >= th.rtt_high_ms:
        return "warning", "Высокий пинг: {latency:.0f} мс", {"latency": latency}
    return "good", "Связь стабильна", {}


def metric_states(
    loss: float,
    jitter: float | None,
    th: Thresholds,
) -> tuple[str, str]:
    loss_state = "good" if loss == 0 else "warning" if loss < th.loss_warn_pct else "error"
    if jitter is None:
        return loss_state, "neutral"
    if jitter >= th.rtt_peak_ms:
        return loss_state, "error"
    return loss_state, "warning" if jitter > th.jitter_critical_ms else "good"


def is_stale(
    report: DiagnosticReport,
    started: Scope | None,
    current: Scope,
) -> bool:
    scope = Scope.of(report.target.host, report.target.port)
    return started is not None and scope == started and scope != current
