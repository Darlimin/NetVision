from __future__ import annotations

from PySide6.QtCore import QObject
from netvision.core.udp_monitor import UdpPortActivity
from netvision.ui.ui_models import UdpEventRow


class UdpController(QObject):
    def __init__(self, host):
        super().__init__(host)
        self.host = host

    def _record_udp_activity(self, activity: UdpPortActivity, include_warning: bool) -> None:
        snapshot = activity.snapshot
        rows: list[UdpEventRow] = []
        for port in activity.opened_ports:
            rows.append(
                UdpEventRow(
                    activity.observed_at,
                    "Порт открыт",
                    port,
                    f"UDP-порт {port} появился у PID {snapshot.pid}",
                    pid=snapshot.pid,
                )
            )
            self.host._record_journal_event(
                "udp.port_opened",
                subject=f"UDP:{port}",
                template="UDP-порт {port} появился у PID {pid}",
                values={"port": port, "pid": snapshot.pid},
                refs={"pid": snapshot.pid, "port": port},
                at=activity.observed_at,
            )
        for port in activity.closed_ports:
            rows.append(
                UdpEventRow(
                    activity.observed_at,
                    "Порт закрыт",
                    port,
                    f"UDP-порт {port} исчез у PID {snapshot.pid}",
                    pid=snapshot.pid,
                )
            )
            self.host._record_journal_event(
                "udp.port_closed",
                subject=f"UDP:{port}",
                template="UDP-порт {port} исчез у PID {pid}",
                values={"port": port, "pid": snapshot.pid},
                refs={"pid": snapshot.pid, "port": port},
                at=activity.observed_at,
            )
        if activity.anomaly is not None:
            details = (
                "Все ранее активные UDP-порты исчезли между опросами"
                if activity.anomaly.value == "all_ports_lost"
                else "Набор UDP-портов полностью сменился между опросами"
            )
            rows.append(
                UdpEventRow(
                    activity.observed_at,
                    "Возможный обрыв",
                    None,
                    details,
                    is_anomaly=True,
                    pid=snapshot.pid,
                )
            )
            self.host._record_journal_event(
                "udp.possible_disconnect",
                severity="warning",
                subject=f"PID {snapshot.pid}",
                template=details,
                refs={"pid": snapshot.pid, "anomaly": activity.anomaly.value},
                at=activity.observed_at,
            )
        if include_warning and snapshot.warning:
            rows.append(
                UdpEventRow(
                    activity.observed_at,
                    "Ошибка мониторинга",
                    None,
                    snapshot.warning,
                    pid=snapshot.pid,
                )
            )
            self.host._record_journal_event(
                "udp.monitor_error",
                severity="warning",
                subject=f"PID {snapshot.pid}",
                template="Ошибка UDP-монитора: {message}",
                values={"message": snapshot.warning},
                refs={"pid": snapshot.pid},
                at=activity.observed_at,
            )
        if not rows:
            return
        self.host._udp_event_rows.extend(rows)
        if len(self.host._udp_event_rows) > 500:
            del self.host._udp_event_rows[:-500]
        self.host.udp_history_workspace.export_udp_json_button.setEnabled(True)
        self.host.udp_history_workspace.export_udp_csv_button.setEnabled(True)
        self.host._refresh_udp_event_table()
