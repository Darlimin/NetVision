"""OverviewController for dashboard orchestration."""

from datetime import datetime
from PySide6.QtCore import QObject
from netvision.core.session import StateStore
from netvision.core.root_cause import analyze_report
from netvision.core.judgement import tls_domain_required
from netvision.models import DiagnosticReport, ProbeStatus
from netvision.ui.ui_models import HeaderAnomalyEvent
from netvision.ui import constants as ui_constants
from netvision.ui.utils import (
    _ms,
    _severity_label,
    _ping_verdict,
    _latency_state,
    _loss_verdict,
    _jitter_verdict,
)


from netvision.ui.workspaces.core_workspace import CoreOverviewWorkspace


class OverviewController(QObject):
    def __init__(
        self, workspace: CoreOverviewWorkspace, facts: StateStore, parent: QObject
    ) -> None:
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts

    def _inherited__set_header_anomaly(self, state: str, source: str, **values: object) -> None:
        normalized_state = state if state in {"good", "info", "warning", "error"} else "info"
        if normalized_state in {"warning", "error"}:
            signature = (normalized_state, source)
            if signature != self.host._last_header_anomaly_signature:
                observed_at = datetime.now().astimezone()
                self.host._header_anomaly_history.append(
                    HeaderAnomalyEvent(
                        observed_at=observed_at,
                        state=normalized_state,
                        source=source,
                        values=tuple(values.items()),
                    )
                )
                self.event_bus.journal_event_requested.emit(
                    "header.anomaly",
                    {
                        "severity": normalized_state,
                        "subject": "network-health",
                        "template": source,
                        "values": values,
                        "refs": {"state": normalized_state},
                        "at": observed_at,
                    },
                )
            self.host._last_header_anomaly_signature = signature
        else:
            self.host._last_header_anomaly_signature = None
        self.host._header_anomaly_state = normalized_state
        self.host._header_anomaly_source = source
        self.host._header_anomaly_values = values
        self.host._refresh_session_capsule()

    def _inherited__update_root_cause_analysis(self, report: DiagnosticReport) -> None:
        analysis = analyze_report(
            report,
            (
                self.host._vpn_process_sockets
                if self.host._vpn_process_sockets_ready
                else self.host._selected_process
            ),
            self.host._selected_connection,
            self.host._thresholds,
            mtr=self.host._mtr_snapshot,
            nat=self.host._nat_report,
            wifi=self.host._wifi_snapshot,
        )
        self.host._root_cause_analysis = analysis
        self.host.analysis_panel.analysis_title.setText(f"{analysis.subject}: {analysis.headline}")
        primary = analysis.findings[0]
        self.host.lite_panel.lite_cause.setText(f"Диагноз: {primary.title}. {primary.explanation}")
        lines = []
        for finding in analysis.findings:
            lines.extend(
                (
                    f"{_severity_label(finding.severity)} · {finding.title}",
                    finding.explanation,
                    f"Основание: {finding.evidence}",
                    "",
                )
            )
        self.host.analysis_panel.analysis_output.setPlainText("\n".join(lines).rstrip())

    def _fill_metrics(self, report: DiagnosticReport) -> None:
        dns_ok = report.dns.status == ProbeStatus.SUCCESS
        dns_value = _ms(report.dns.latency_ms) if dns_ok else "ERROR"
        self.host.expert_view.metrics["dns"].set_metric(
            dns_value,
            self.host._tr("Имя сайта найдено" if dns_ok else "Не удалось найти адрес сайта"),
            "good" if dns_ok else "bad",
        )

        self.host.expert_view.metrics["ping"].set_metric(
            _ms(report.ping.average_ms),
            self.host._tr(_ping_verdict(report.ping.average_ms, self.host._thresholds)),
            _latency_state(report.ping.average_ms, self.host._thresholds.rtt_high_ms),
        )
        self.host.expert_view.metrics["loss"].set_metric(
            f"{report.ping.loss_percent:.0f}%",
            self.host._tr(_loss_verdict(report.ping.loss_percent)),
            "good" if report.ping.loss_percent == 0 else "bad",
        )
        self.host.expert_view.metrics["jitter"].set_metric(
            _ms(report.ping.jitter_ms),
            self.host._tr(_jitter_verdict(report.ping.jitter_ms, self.host._thresholds)),
            _latency_state(report.ping.jitter_ms, self.host._thresholds.jitter_critical_ms),
        )

        tcp_ok = report.tcp.status == ProbeStatus.SUCCESS
        tcp_value = _ms(report.tcp.latency_ms) if tcp_ok else "CLOSED"
        self.host.expert_view.metrics["tcp"].set_metric(
            tcp_value,
            self.host._tr(
                "Сайт принимает соединение" if tcp_ok else "Соединение с сайтом не установлено"
            ),
            "good" if tcp_ok else "bad",
        )

        if report.tls:
            tls_ok = report.tls.status == ProbeStatus.SUCCESS
            tls_ip_mismatch = not tls_ok and tls_domain_required(
                report.target.host, report.tls.error
            )
            self.host.expert_view.metrics["tls"].set_metric(
                (
                    self.host._tr("Требует домен")
                    if tls_ip_mismatch
                    else report.tls.version or "ERROR"
                ),
                self.host._tr(
                    "Безопасное соединение подтверждено"
                    if tls_ok
                    else (
                        "Требует домен"
                        if tls_ip_mismatch
                        else "Сертификат или шифрование не прошли проверку"
                    )
                ),
                "neutral" if tls_ip_mismatch else "good" if tls_ok else "bad",
            )
            if (
                hasattr(self.host.tls_workspace, "tls_overview_values")
                and self.host._tls_audit_result is None
            ):
                self.host._render_tls_report_summary(report.tls)
        else:
            self.host.expert_view.metrics["tls"].set_metric(
                "N/A", self.host._tr("Проверка защиты не требуется"), "neutral"
            )

    def _dashboard_apply_report(self, report: DiagnosticReport) -> None:
        self.host._dashboard_add_sample("dns", report.dns.latency_ms)
        self.host._dashboard_add_sample("ping", report.ping.average_ms)
        self.host._dashboard_add_sample("loss", report.ping.loss_percent)
        self.host._dashboard_add_sample("jitter", report.ping.jitter_ms)
        self.host._dashboard_add_sample("tcp", report.tcp.latency_ms)
        self.host._dashboard_add_sample("tls", report.tls.latency_ms if report.tls else None)

        loss_state, jitter_state = self.host._dashboard_quality_states(
            report.ping.loss_percent,
            report.ping.jitter_ms,
            self.host._thresholds,
        )
        self._set_dashboard_metric(
            "dns",
            (
                self.host._format_ms(report.dns.latency_ms)
                if report.dns.status == ProbeStatus.SUCCESS
                else "ошибка"
            ),
            "good" if report.dns.status == ProbeStatus.SUCCESS else "error",
        )
        self._set_dashboard_metric(
            "ping",
            self.host._format_ms(report.ping.average_ms),
            self.host._latency_state(report.ping.average_ms),
        )
        self._set_dashboard_metric(
            "loss",
            f"{report.ping.loss_percent:.0f}%",
            loss_state,
        )
        self._set_dashboard_metric(
            "jitter",
            self.host._format_ms(report.ping.jitter_ms),
            jitter_state,
        )
        tcp_ok = report.tcp.status == ProbeStatus.SUCCESS
        self._set_dashboard_metric(
            "tcp",
            self.host._format_ms(report.tcp.latency_ms) if tcp_ok else "закрыт",
            "good" if tcp_ok else "error",
        )
        tls_ok = report.tls is not None and report.tls.status == ProbeStatus.SUCCESS
        tls_text = (
            self.host._tr("Требует домен")
            if report.tls and tls_domain_required(report.target.host, report.tls.error)
            else report.tls.version or "OK" if tls_ok and report.tls else "—"
        )
        self._set_dashboard_metric("tls", tls_text, "good" if tls_ok else "neutral")
        self.workspace.dashboard_latency_chart.set_samples(
            self.host._dashboard_histories["latency"]
        )
        self.host._dashboard_render_topology(report)
        self.host._dashboard_render_regions(report)

    def _set_dashboard_metric(self, key: str, value: str, state: str) -> None:
        self.workspace.dashboard_metric_cards[key].set_metric(
            value, state, self.host._dashboard_histories[key]
        )

    def _dashboard_apply_health(self, state: str, source: str) -> None:
        mapping = ui_constants.DASHBOARD_HEALTH_STATE_MAPPING
        text, style = mapping.get(state, mapping["info"])
        self.workspace.dashboard_status_pill.setText(self.host._tr(text))
        self.workspace.dashboard_status_pill.setProperty("healthState", style)
        self.workspace.dashboard_status_pill.style().unpolish(self.workspace.dashboard_status_pill)
        self.workspace.dashboard_status_pill.style().polish(self.workspace.dashboard_status_pill)
        self.workspace.dashboard_status_subtitle.setText(
            f"{self.host._format_session_elapsed(self.host._session_elapsed_seconds)} • {source}"
        )

    def _set_header_anomaly(self, state: str, source: str, **values: object) -> None:
        self._inherited__set_header_anomaly(state, source, **values)
        self.facts.set("overview.anomaly", (state, source, dict(values)))
        if (
            self.host._dashboard_ready
            and self.host._report is not None
            and self.host._dashboard_widgets_alive(self.workspace.dashboard_status_pill)
        ):
            self._dashboard_apply_health(state, self.host._translator.format(source, **values))

    def _update_root_cause_analysis(self, report: DiagnosticReport) -> None:
        self._inherited__update_root_cause_analysis(report)
        analysis = getattr(self.host, "_root_cause_analysis", None)
        findings = getattr(analysis, "findings", ())
        primary = findings[0] if findings else None
        cause = f"Диагноз: {primary.title}. {primary.explanation}" if primary is not None else ""
        self.facts.set("cause", cause)
        if not self.host._dashboard_ready:
            return
        self.host._dashboard_update_mtu_hint()
        summary = str(self.facts.get("cause", "")).strip()
        if summary and summary != self.host._dashboard_last_cause:
            self.host._dashboard_last_cause = summary
            self.host._dashboard_append_event(summary)
