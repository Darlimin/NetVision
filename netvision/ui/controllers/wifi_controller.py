from __future__ import annotations

from PySide6.QtCore import QObject
from netvision.models import WifiSnapshot
from netvision.ui.utils import _format_wifi_snapshot, _wifi_roamed, _wifi_route_signature


class WifiController(QObject):
    def __init__(self, host):
        super().__init__(host)
        self.host = host

    def _on_wifi_snapshot(self, value: object, state: str) -> None:
        snapshot = value if isinstance(value, WifiSnapshot) else None
        if state != "ok":
            self.host._set_wifi_status(
                "Wi-Fi недоступен: проверьте разрешение «Расположение» в Windows 11"
                if state == "unavailable"
                else "Wi-Fi активного маршрута не распознан"
            )
            if self.host._wifi_probe_state != state:
                self.host._record_journal_event(
                    "wifi.probe_failed",
                    severity="warning",
                    subject="Wi-Fi",
                    template="Wi-Fi: {reason}",
                    values={"reason": state},
                )
            self.host._wifi_probe_state = state
            return
        previous = self.host._wifi_snapshot
        self.host._wifi_probe_state = None
        self.host._wifi_snapshot = snapshot
        if snapshot is None:
            return
        if self.host._report is not None:
            self.host.overview_controller._update_dashboard_verdict(self.host._report)
        self.host._set_wifi_status(_format_wifi_snapshot(snapshot))
        if previous is not None and _wifi_roamed(previous, snapshot):
            self.host._record_journal_event(
                "wifi.roam",
                severity="warning",
                subject=snapshot.interface_name,
                template="Wi-Fi roaming: {from_value} -> {to_value}",
                values={
                    "from_value": _wifi_route_signature(previous),
                    "to_value": _wifi_route_signature(snapshot),
                },
            )
        signal = snapshot.signal_pct
        if signal is None:
            return
        signal_transition = self.host._wifi_signal_tracker.update(
            signal,
            self.host._thresholds.wifi_signal_warn_pct,
            self.host._thresholds.wifi_signal_hysteresis_pct,
        )
        if signal_transition == "entered":
            self.host._wifi_signal_low = True
            self.host._record_journal_event(
                "wifi.signal_low",
                severity="warning",
                subject=snapshot.interface_name,
                template="Wi-Fi signal low: {signal}%",
                values={"state": "entered", "signal": signal},
            )
        elif signal_transition == "cleared":
            self.host._wifi_signal_low = False
            self.host._record_journal_event(
                "wifi.signal_low",
                subject=snapshot.interface_name,
                template="Wi-Fi signal restored: {signal}%",
                values={"state": "cleared", "signal": signal},
            )
        if self.host._report is not None:
            self.host.overview_controller._update_root_cause_analysis(self.host._report)
