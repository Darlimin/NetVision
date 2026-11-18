from __future__ import annotations

from PySide6.QtCore import QObject
from netvision.core.game_monitor import GameMonitorEvent
from netvision.ui.utils import _ms


class GameMonitorController(QObject):
    def __init__(self, host):
        super().__init__(host)
        self.host = host

    def _on_game_monitor_event(self, value: object) -> None:
        if not isinstance(value, GameMonitorEvent):
            return
        if value.kind == "started":
            baseline = _ms(value.baseline_latency_ms)
            message = self.host._translator.format(
                "Игра запущена: {process} (PID {pid}) · базовый ping: {latency}",
                process=value.process_name,
                pid=value.pid,
                latency=baseline,
            )
            self.host.process_selector_panel.game_monitor_status.setText(message)
            self.host.overview_controller._set_header_anomaly("info", "Игровая сессия начата")
            self.host._append_log(message)
            if self.host._background_auto_monitor:
                self.host._start_auto_monitor_probe(value.process_name, value.pid)
            return
        if value.kind == "spike":
            message = self.host._translator.format(
                "Игровая сессия: всплеск RTT {latency}", latency=_ms(value.latency_ms)
            )
            self.host.process_selector_panel.game_monitor_status.setText(message)
            self.host.overview_controller._set_header_anomaly(
                "warning", "Игровая сессия: всплеск RTT {latency}", latency=_ms(value.latency_ms)
            )
            self.host._append_log(message)
            return
        if value.kind != "ended" or value.summary is None:
            return
        summary = value.summary
        message = self.host._translator.format(
            "Игровая сессия завершена: потери {loss}% · всплесков RTT: {spikes}",
            loss=f"{summary.loss_percent:.1f}",
            spikes=summary.spike_count,
        )
        self.host.process_selector_panel.game_monitor_status.setText(message)
        self.host.overview_controller._set_header_anomaly(
            "warning" if summary.loss_percent > 0 or summary.spike_count else "good",
            "Игровая сессия завершена: потери {loss}% · всплесков RTT: {spikes}",
            loss=f"{summary.loss_percent:.1f}",
            spikes=summary.spike_count,
        )
        self.host._append_log(message)
        auto_was_active = self.host._auto_monitor_active
        self.host._stop_auto_monitors("game_ended")
        if auto_was_active:
            self.host._record_journal_event(
                "monitor.auto_stopped",
                subject=value.process_name,
                template="Автомониторинг остановлен: {reason}",
                values={"reason": "игровая сессия завершена", "pid": value.pid},
            )
        self.host._record_journal_event(
            "game.session_ended",
            severity="warning" if summary.loss_percent or summary.spike_count else "info",
            subject=value.process_name,
            template="Игровая сессия завершена: потери {loss}% · всплесков RTT: {spikes}",
            values={"loss": f"{summary.loss_percent:.1f}", "spikes": summary.spike_count},
            refs={"pid": value.pid},
        )
