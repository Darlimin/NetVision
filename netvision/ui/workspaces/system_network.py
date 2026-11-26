"""On-demand presentation of the system traffic path."""

from threading import Event
from concurrent.futures import CancelledError
import re

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netvision.core.traffic_path import (
    _proxy_entries,
    _sanitize_pac,
    collect_traffic_path_snapshot,
    format_traffic_path_summary,
)
from netvision.ui.components.factory import configure_table, new_card


class _SnapshotWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self):
        super().__init__()
        self.cancelled = Event()

    def stop(self):
        self.cancelled.set()

    @Slot()
    def run(self):
        try:
            snapshot = collect_traffic_path_snapshot(
                include_egress=True, cancel_event=self.cancelled
            )
            if not self.cancelled.is_set():
                self.completed.emit(snapshot)
        except CancelledError:
            pass
        except Exception:
            if not self.cancelled.is_set():
                self.failed.emit("error")
        finally:
            self.finished.emit()


class SystemNetworkWorkspace(QWidget):
    def __init__(self, host):
        super().__init__()
        self.host = host
        self.snapshot = None
        self.thread = None
        self.started = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        self.scroll.setWidget(content)
        outer.addWidget(self.scroll)
        layout = QVBoxLayout(content)
        controls = QHBoxLayout()
        self.refresh_button = QPushButton()
        self.copy_button = QPushButton()
        self.copy_button.setObjectName("SecondaryActionBtn")
        self.status = QLabel()
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.copy_button)
        controls.addWidget(self.status, 1)
        layout.addLayout(controls)
        grid = QGridLayout()
        self.cards = []
        for i in range(4):
            card = new_card()
            card_layout = QVBoxLayout(card)
            title, value = QLabel(), QLabel("—")
            title.setObjectName("CardTitle")
            value.setWordWrap(True)
            value.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            card_layout.addWidget(title)
            card_layout.addWidget(value)
            self.cards.append((title, value))
            grid.addWidget(card, i // 2, i % 2)
            if i == 3:
                self.egress_badge = QLabel()
                self.egress_badge.setObjectName("StatusPill")
                self.egress_badge.hide()
                card_layout.addWidget(self.egress_badge)
        layout.addLayout(grid)
        self.table_title = QLabel()
        self.table_title.setObjectName("CardTitle")
        layout.addWidget(self.table_title)
        self.table = QTableWidget(0, 4)
        channel_width = max(
            160,
            self.table.fontMetrics().horizontalAdvance("Физический адаптер") + 24,
            self.table.fontMetrics().horizontalAdvance("Physical adapter") + 24,
        )
        configure_table(self.table, (channel_width, 260, 100, 180))
        layout.addWidget(self.table, 1)
        self.empty_label = QLabel()
        self.empty_label.setObjectName("SubLabel")
        layout.addWidget(self.empty_label)
        self.refresh_button.clicked.connect(self.refresh)
        self.copy_button.clicked.connect(self.copy_summary)
        host._translator.language_changed.connect(self.retranslate)
        self.retranslate()

    def _text(self, ru, en):
        return en if self.host._translator.language == "en" else ru

    @Slot()
    def refresh(self):
        if self.thread is not None or self.host._dashboard_closing:
            return
        self.started = True
        self.status.setText(self._text("Загрузка...", "Loading..."))
        self.refresh_button.setEnabled(False)
        worker = _SnapshotWorker()
        worker.completed.connect(self._received, Qt.ConnectionType.QueuedConnection)
        worker.failed.connect(self._failed, Qt.ConnectionType.QueuedConnection)
        self.thread = self.host._worker_registry.start(worker)
        self.thread.finished.connect(self._finished, Qt.ConnectionType.QueuedConnection)

    @Slot(object)
    def _received(self, snapshot):
        if self.host._dashboard_closing:
            return
        self.snapshot = snapshot
        self.retranslate()

    @Slot(str)
    def _failed(self, _error):
        self.status.setText(self._text("Не удалось получить снимок", "Snapshot failed"))

    @Slot()
    def _finished(self):
        self.thread = None
        self.refresh_button.setEnabled(True)

    @Slot()
    def copy_summary(self):
        if self.snapshot is not None:
            QApplication.clipboard().setText(
                format_traffic_path_summary(self.snapshot, self.host._translator.language)
            )
            self.status.setText(self._text("Скопировано", "Copied"))

    @Slot()
    @Slot(str)
    def retranslate(self, _language=None):
        t = self._text
        self.refresh_button.setText(t("Обновить снимок", "Refresh snapshot"))
        self.copy_button.setText(t("Копировать сводку", "Copy summary"))
        self.copy_button.setEnabled(self.snapshot is not None)
        for (label, _), names in zip(
            self.cards,
            (
                ("Маршрут ядра ОС", "Kernel route"),
                ("Системный прокси", "System proxy"),
                ("Реальный DNS и DoH", "DNS and DoH"),
                ("Фактический выход", "Egress"),
            ),
        ):
            label.setText(t(*names))
        self.table_title.setText(t("Распределение живых соединений", "Live connection channels"))
        self.empty_label.setText(t("Нет данных о соединениях", "No connection data"))
        self.empty_label.setVisible(self.snapshot is not None and not self.snapshot.channels)
        self.table.setHorizontalHeaderLabels(
            [
                t("Канал", "Channel"),
                t("Интерфейс / адрес", "Interface / address"),
                t("Соединений", "Connections"),
                t("Основные процессы", "Top processes"),
            ]
        )
        if self.snapshot is None:
            return
        self.status.setText(
            t("Обновлено: ", "Updated: ")
            + self.snapshot.collected_at.astimezone().strftime("%H:%M:%S")
        )
        lines = format_traffic_path_summary(
            self.snapshot, self.host._translator.language
        ).splitlines()
        for (_, value), line in zip(self.cards, lines):
            value.setText(line.partition(": ")[2])
        route = self.snapshot.route
        mode = self.cards[0][1].text().split(" · ")[0]
        source = (
            "Windows API"
            if route.source == "windows_api"
            else t("Резервный (route)", "Fallback (route)")
        )
        self.cards[0][1].setText(
            "\n".join(
                (
                    mode,
                    route.adapter or "—",
                    f"IP: {route.local_ip or '—'}",
                    f"{t('Шлюз', 'Gateway')}: {route.gateway or '—'}",
                    f"{t('Метрика', 'Metric')}: {route.metric if route.metric is not None else '—'}",
                    f"{t('Источник', 'Source')}: {source}",
                )
            )
        )
        self.cards[2][1].setText(self.cards[2][1].text().replace(" · DoH:", "\nDoH:", 1))
        proxy = self.snapshot.proxy
        if proxy.server or proxy.winhttp or proxy.pac_url:
            _, server = _proxy_entries(proxy.server or "")
            _, winhttp = _proxy_entries(proxy.winhttp or "")
            details = [
                f"{name}: {value}"
                for name, value in (
                    ("WinINET", server),
                    ("WinHTTP", winhttp),
                    ("PAC", _sanitize_pac(proxy.pac_url) if proxy.pac_url else None),
                )
                if value
            ]
            if proxy.owner_pid:
                details.append(f"{proxy.owner_name or 'PID'} ({proxy.owner_pid})")
            self.cards[1][1].setText("\n".join(details))
        for _, value in self.cards:
            value.setText(
                re.sub(
                    r"([^\s\u200b]{24})(?=\S)",
                    lambda match: match.group(1) + "\u200b",
                    value.text()
                    .replace("/", "/\u200b")
                    .replace(";", ";\u200b")
                    .replace(".", ".\u200b"),
                )
            )
        different = self.snapshot.egress.differs_from_direct is True
        self.egress_badge.setVisible(different)
        self.egress_badge.setText(t("Выходы различаются", "Egress addresses differ"))
        names = {
            "vpn_tun": "VPN (TUN)",
            "physical": t("Физический адаптер", "Physical adapter"),
            "local_proxy": t("Локальный прокси", "Local proxy"),
            "other": t("Другое", "Other"),
        }
        self.table.setRowCount(len(self.snapshot.channels))
        for row, channel in enumerate(self.snapshot.channels):
            for column, text in enumerate(
                (
                    names.get(channel.channel, "—"),
                    " / ".join(filter(None, (channel.interface, channel.address))) or "—",
                    str(channel.count),
                    ", ".join(channel.top_processes) or "—",
                )
            ):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row, column, item)
