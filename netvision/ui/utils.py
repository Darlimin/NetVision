"""Small UI helpers shared by dialog and dashboard surfaces."""

from datetime import datetime

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QColor, QWheelEvent
from PySide6.QtWidgets import QAbstractScrollArea

from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds
from netvision.models import DiagnosticReport, ProbeStatus, WifiSnapshot
from netvision.ui.ui_models import UdpEventRow

_FULL_PACKET_LOSS_PERCENT = 100.0


class _NestedScrollWheelFilter(QObject):
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() != QEvent.Type.Wheel or not isinstance(event, QWheelEvent):
            return super().eventFilter(watched, event)
        scroll_area = watched.parent()
        if not isinstance(scroll_area, QAbstractScrollArea):
            return super().eventFilter(watched, event)
        delta = event.angleDelta().y()
        scrollbar = scroll_area.verticalScrollBar()
        if delta and scrollbar.maximum() > scrollbar.minimum():
            step = scrollbar.singleStep() or 1
            scrollbar.setValue(scrollbar.value() - (step if delta > 0 else -step) * 3)
        event.accept()
        return True


_NESTED_SCROLL_WHEEL_FILTER = _NestedScrollWheelFilter()


def keep_wheel_scroll_local(scroll_area: QAbstractScrollArea) -> None:
    scroll_area.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
    scroll_area.viewport().installEventFilter(_NESTED_SCROLL_WHEEL_FILTER)


def _is_thread_alive(thread: object | None) -> bool:
    """Return whether a Qt thread is running without touching deleted wrappers."""
    if thread is None:
        return False
    try:
        return bool(thread.isRunning())  # type: ignore[attr-defined]
    except RuntimeError:
        return False


def _format_diagnostic_failure(failure: object) -> str:
    """Keep the primary exception and its context available to support export."""
    if not isinstance(failure, BaseException):
        return str(failure)
    context = failure.__context__
    primary = f"{type(failure).__name__}: {failure}"
    if context is None:
        return primary
    return f"{primary}\nКонтекст: {type(context).__name__}: {context}"


def _ms(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} ms"


def _tls_datetime(value: datetime | None) -> str:
    return "--" if value is None else value.astimezone().strftime("%Y-%m-%d %H:%M")


def _tls_certificate_state(status: str, valid: bool) -> str:
    normalized = status.casefold()
    if valid and "истекает" not in normalized:
        return "good"
    if "истекает" in normalized or "окончания не указана" in normalized:
        return "warning"
    return "bad"


def _tls_state_color(state: str) -> QColor:
    return {
        "good": QColor("#00E5A3"),
        "warning": QColor("#FFB800"),
        "bad": QColor("#FF4757"),
        "neutral": QColor("#8A99AD"),
    }.get(state, QColor("#8A99AD"))


def _jitter_state(value: float | None, th: Thresholds = DEFAULT_THRESHOLDS) -> str:
    if value is None:
        return "neutral"
    if value > th.jitter_bad_ms:
        return "bad"
    if value > th.jitter_spike_ms:
        return "warning"
    return "good"


def _voice_jitter_rating(value: float | None, th: Thresholds = DEFAULT_THRESHOLDS) -> str:
    if value is None:
        return "N/A"
    if value <= 5:
        return "Отлично"
    if value <= th.jitter_spike_ms:
        return "Допустимо"
    if value <= th.jitter_bad_ms:
        return "Рывки"
    return "Плохо"


def _gaming_jitter_rating(value: float | None, th: Thresholds = DEFAULT_THRESHOLDS) -> str:
    if value is None:
        return "N/A"
    if value <= 5:
        return "Стабильно"
    if value <= th.jitter_spike_ms:
        return "Играбельно"
    if value <= th.jitter_bad_ms:
        return "Микрофризы"
    return "Нестабильно"


def _jitter_stability_rating(
    value: float | None,
    spike_count: int,
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> str:
    if value is None:
        return "Нестабильно" if spike_count else "Ожидание"
    if value > th.jitter_bad_ms or spike_count >= th.episode_quiet_samples:
        return "Критично"
    if value > th.jitter_spike_ms or spike_count:
        return "Есть колебания"
    return "Стабильно"


def _udp_event_color(event: UdpEventRow) -> QColor:
    if event.is_anomaly:
        return QColor("#FF4757")
    if event.event_type == "Порт открыт":
        return QColor("#00E5A3")
    if event.event_type == "Порт закрыт":
        return QColor("#FFB800")
    return QColor("#8A99AD")


def _journal_event_color(severity: str) -> QColor:
    if severity == "error":
        return QColor("#FF4757")
    if severity == "warning":
        return QColor("#FFB800")
    return QColor("#00E5A3")


def _latency_state(value: float | None, warning_threshold: float) -> str:
    if value is None:
        return "neutral"
    return "good" if value <= warning_threshold else "bad"


def _ping_verdict(value: float | None, th: Thresholds = DEFAULT_THRESHOLDS) -> str:
    if value is None:
        return "Нет ответа от сервера"
    if value < th.jitter_bad_ms:
        return "Отлично для игр и звонков"
    if value <= th.rtt_normal_ms:
        return "Нормально для веб-серфинга"
    if value > th.rtt_high_ms:
        return "Высокая задержка"
    return "Задержка выше комфортной"


def _loss_verdict(loss_percent: float) -> str:
    return "Связь стабильная" if loss_percent == 0 else "Возможны фризы и задержки"


def _jitter_verdict(value: float | None, th: Thresholds = DEFAULT_THRESHOLDS) -> str:
    if value is None:
        return "Стабильность не удалось оценить"
    if value <= th.jitter_clear_ms:
        return "Связь ровная, без заметных скачков"
    if value <= th.jitter_critical_ms:
        return "Небольшие колебания связи"
    return "Задержка заметно скачет"


def _lite_summary_cards(report: DiagnosticReport) -> tuple[tuple[str, str, str], ...]:
    dns_latency = report.dns.latency_ms
    if report.dns.status == ProbeStatus.SUCCESS and dns_latency is not None:
        dns_value = (
            f"{dns_latency:.1f} мс (Быстрый отклик)"
            if dns_latency <= DEFAULT_THRESHOLDS.dns_good_ms
            else f"{dns_latency:.1f} мс (Медленный отклик)"
        )
        dns_state = "good" if dns_latency <= DEFAULT_THRESHOLDS.dns_ok_ms else "bad"
    else:
        dns_value = "Нет ответа"
        dns_state = "bad"

    port_open = report.tcp.status == ProbeStatus.SUCCESS
    port_value = "Открыт" if port_open else "Закрыт"
    port_state = "good" if port_open else "bad"

    if report.ping.loss_percent == 0:
        loss_value = "0% (Связь стабильная)"
        loss_state = "good"
    elif report.ping.loss_percent >= _FULL_PACKET_LOSS_PERCENT:
        loss_value = "100% (Обрыв связи)"
        loss_state = "bad"
    else:
        loss_value = f"{report.ping.loss_percent:.0f}% (Возможны задержки)"
        loss_state = "bad"

    vpn_active = any(route.is_vpn for route in report.system.default_routes)
    route_value = "VPN активен" if vpn_active else "Прямое соединение"
    route_state = "good" if vpn_active else "neutral"
    return (
        ("🌐 DNS", dns_value, dns_state),
        (f"🔓 Порт {report.target.port}", port_value, port_state),
        ("📉 Потери", loss_value, loss_state),
        ("🛡️ Маршрут", route_value, route_state),
    )


def _severity_label(severity: object) -> str:
    return {
        "error": "КРИТИЧНО",
        "warning": "ПРЕДУПРЕЖДЕНИЕ",
        "info": "ИНФОРМАЦИЯ",
    }.get(str(severity), "РЕЗУЛЬТАТ")


def _wifi_roamed(previous: WifiSnapshot, current: WifiSnapshot) -> bool:
    return any(
        getattr(previous, field) != getattr(current, field)
        for field in ("bssid", "channel", "band")
    )


def _wifi_route_signature(snapshot: WifiSnapshot) -> str:
    return " / ".join(value or "--" for value in (snapshot.bssid, snapshot.band, snapshot.channel))


def _format_wifi_snapshot(snapshot: WifiSnapshot) -> str:
    signal = "--" if snapshot.signal_pct is None else f"{snapshot.signal_pct}%"
    gateway = _ms(snapshot.gateway_rtt_ms)
    return (
        f"Wi-Fi: {snapshot.interface_name} · {snapshot.ssid or '--'} · "
        f"сигнал {signal} · {snapshot.band or '--'} · канал {snapshot.channel or '--'} · "
        f"RX {snapshot.rx_mbps or 0:.1f} / TX {snapshot.tx_mbps or 0:.1f} Мбит/с · "
        f"шлюз {gateway}"
    )


def _wifi_correlation_evidence(
    snapshot: WifiSnapshot | None,
    signal_low: bool,
    event_kinds: set[str],
    th: Thresholds = DEFAULT_THRESHOLDS,
) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    if "wifi.roam" in event_kinds:
        evidence.append("roaming")
    if signal_low or "wifi.signal_low" in event_kinds:
        evidence.append("низкий сигнал")
    if (
        snapshot is not None
        and snapshot.gateway_rtt_ms is not None
        and snapshot.gateway_rtt_ms > th.wifi_gateway_rtt_warn_ms
    ):
        evidence.append(f"шлюз {snapshot.gateway_rtt_ms:.1f} мс")
    return bool(evidence), evidence


def _speed(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} Мбит/с"


def _bufferbloat_speed(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} Mbps"


def _latency(value: float | None) -> str:
    return "--" if value is None else f"{value:.1f} мс"
