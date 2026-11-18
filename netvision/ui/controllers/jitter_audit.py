"""JitterController for diagnostics."""

from dataclasses import replace
from datetime import datetime
from PySide6.QtCore import QObject, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem
from netvision.core.session import StateStore
from netvision.core.episodes import Episode
from netvision.ui.monitor_workers import WorkerRegistry
from netvision.ui.ui_models import JitterEventRow
from netvision.ui.utils import (
    _ms,
    _gaming_jitter_rating,
    _jitter_stability_rating,
    _jitter_state,
    _voice_jitter_rating,
)


from netvision.ui.workspaces.jitter_audit import JitterWorkspace


class JitterController(QObject):
    def __init__(
        self,
        workspace: JitterWorkspace,
        facts: StateStore,
        registry: WorkerRegistry,
        parent: QObject,
    ) -> None:
        super().__init__(parent)
        self.event_bus = parent.event_bus
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        self.registry = registry
        workspace.jitter_refresh_button.clicked.connect(self._refresh_jitter_workspace)
        workspace.jitter_clear_button.clicked.connect(self._clear_jitter_events)

    def _record_jitter_sample(self, value: float | None, success: bool) -> None:
        previous = self.host._jitter_previous_rtt
        deviation = (
            abs(value - previous)
            if success and value is not None and previous is not None
            else None
        )
        self.workspace.jitter_chart.add_sample(deviation)
        self.facts.set("jitter.deviation_ms", deviation)
        observed_at = datetime.now().astimezone()
        if success and value is not None:
            self.host._jitter_timeout_row_index = None
        if deviation is not None:
            self.host._jitter_deviations.append(deviation)
            self.host._jitter_deviations = self.host._jitter_deviations[-60:]
            step, episode = self.host._jitter_episode_tracker.update(deviation, observed_at)
            self._sync_jitter_episode(step, episode)
            if step == "opened":
                self.host._record_wifi_correlation("jitter")
        elif not success:
            self._sync_jitter_episode(
                "closed",
                self.host._jitter_episode_tracker.close("break", observed_at),
            )
            self._record_jitter_timeout(observed_at)
        self.host._jitter_previous_rtt = value if success and value is not None else None
        if self.host.mode_stack.currentWidget() is self.host.jitter_view:
            self._refresh_jitter_workspace()

    @Slot()
    def _refresh_jitter_workspace(self) -> None:
        values = tuple(self.host._jitter_deviations)
        chart_samples = self.workspace.jitter_chart.samples
        current = chart_samples[-1] if chart_samples and chart_samples[-1] is not None else None
        maximum = max(values) if values else None
        spike_count = len(self.host._jitter_events)
        state = _jitter_state(current, self.host._thresholds)
        self._set_jitter_impact_value("current", _ms(current), state)
        self._set_jitter_impact_value(
            "maximum", _ms(maximum), _jitter_state(maximum, self.host._thresholds)
        )
        self._set_jitter_impact_value("spikes", str(spike_count), "bad" if spike_count else "good")
        self._set_jitter_impact_value(
            "voice", self.host._tr(_voice_jitter_rating(current, self.host._thresholds)), state
        )
        self._set_jitter_impact_value(
            "gaming", self.host._tr(_gaming_jitter_rating(current, self.host._thresholds)), state
        )
        self._set_jitter_impact_value(
            "stability",
            self.host._tr(_jitter_stability_rating(current, spike_count, self.host._thresholds)),
            state,
        )
        self.workspace.jitter_graph_status.setText(
            self.host._tr("Нет достаточного числа измерений для расчёта jitter")
            if current is None
            else self.host._translator.format(
                "Текущий Δ RTT: {current:.1f} ms · порог micro-spike: {threshold:.0f} ms",
                current=current,
                threshold=self.host._thresholds.jitter_spike_ms,
            )
        )
        self._render_jitter_events()

    def _set_jitter_impact_value(self, key: str, text: str, state: str) -> None:
        label = self.workspace.jitter_impact_values[key]
        label.setText(text)
        label.setToolTip(text)
        label.setProperty("state", state)
        label.style().unpolish(label)
        label.style().polish(label)

    def _sync_jitter_episode(self, step: str | None, episode: Episode | None) -> None:
        if step == "opened" and episode is not None:
            self.host._jitter_episode_row_index = self._append_jitter_event(
                JitterEventRow(
                    episode.started_at,
                    episode.peak,
                    self.host._jitter_endpoint(),
                    "Превышен безопасный порог вариации RTT",
                )
            )
            self.event_bus.journal_event_requested.emit(
                "jitter.episode",
                {
                    "severity": "warning",
                    "subject": self.host._jitter_endpoint(),
                    "template": "Эпизод jitter: пик {peak:.1f} мс · отсчётов: {samples}",
                    "values": {"peak": episode.peak, "samples": episode.samples_over},
                    "refs": {"started_at": episode.started_at.isoformat()},
                    "at": episode.started_at,
                },
            )
        if episode is None or self.host._jitter_episode_row_index is None:
            return
        row_index = self.host._jitter_episode_row_index
        if row_index >= len(self.host._jitter_events):
            self.host._jitter_episode_row_index = None
            return
        current = self.host._jitter_events[row_index]
        details = f"Превышен безопасный порог вариации RTT · отсчётов: {episode.samples_over}"
        self.host._jitter_events[row_index] = replace(
            current,
            deviation_ms=episode.peak,
            details=details,
            ended_at=episode.ended_at,
            samples=episode.samples_over,
        )
        if step == "closed":
            self.host._jitter_episode_row_index = None

    def _record_jitter_timeout(self, observed_at: datetime) -> None:
        if self.host._jitter_timeout_row_index is None:
            self.host._jitter_timeout_row_index = self._append_jitter_event(
                JitterEventRow(
                    observed_at,
                    0.0,
                    self.host._jitter_endpoint(),
                    "Timeout: непрерывность RTT нарушена · подряд: 1",
                    kind="timeout",
                )
            )
            self.event_bus.journal_event_requested.emit(
                "jitter.episode",
                {
                    "severity": "warning",
                    "subject": self.host._jitter_endpoint(),
                    "template": "Timeout RTT: непрерывность нарушена",
                    "refs": {"kind": "timeout"},
                    "at": observed_at,
                },
            )
            return
        row_index = self.host._jitter_timeout_row_index
        if row_index >= len(self.host._jitter_events):
            self.host._jitter_timeout_row_index = None
            self._record_jitter_timeout(observed_at)
            return
        current = self.host._jitter_events[row_index]
        samples = current.samples + 1
        self.host._jitter_events[row_index] = replace(
            current,
            details=f"Timeout: непрерывность RTT нарушена · подряд: {samples}",
            samples=samples,
        )

    def _render_jitter_events(self) -> None:
        self.workspace.jitter_events_table.setRowCount(len(self.host._jitter_events))
        for row, event in enumerate(reversed(self.host._jitter_events)):
            deviation = "timeout" if event.kind == "timeout" else f"{event.deviation_ms:.1f} ms"
            values = (f"{event.observed_at:%H:%M:%S}", deviation, event.endpoint, event.details)
            color = (
                QColor("#FF4757")
                if event.kind == "timeout"
                or event.deviation_ms > self.host._thresholds.jitter_bad_ms
                else QColor("#FFB800")
            )
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                item.setForeground(color)
                self.workspace.jitter_events_table.setItem(row, column, item)
        self.workspace.jitter_event_status.setText(
            self.host._translator.format(
                "Критический порог: Δ RTT > {threshold:.0f} мс · событий: {count}",
                threshold=self.host._thresholds.jitter_spike_ms,
                count=len(self.host._jitter_events),
            )
        )

    def _append_jitter_event(self, event: JitterEventRow) -> int:
        self.host._jitter_events.append(event)
        self.host._jitter_events = self.host._jitter_events[-120:]
        return len(self.host._jitter_events) - 1

    @Slot()
    def _clear_jitter_events(self) -> None:
        self.host._jitter_events.clear()
        self.host._jitter_episode_tracker = self.host._new_jitter_episode_tracker()
        self.host._jitter_episode_row_index = None
        self.host._jitter_timeout_row_index = None
        self._refresh_jitter_workspace()
