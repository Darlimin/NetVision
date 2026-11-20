"""DnsController for diagnostics."""

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Slot
from PySide6.QtGui import QColor, QCursor
from PySide6.QtWidgets import QTableWidgetItem, QApplication, QPushButton, QSizePolicy, QToolTip
from netvision.core.session import StateStore
from netvision.core.dns_benchmark import DnsBenchmarkResult, custom_dns_profile
from netvision.core.system import DnsConfiguration
from netvision.core.internet_quality import PublicIpAddresses
from netvision.core.system_actions import apply_dns_servers, open_network_adapters
from netvision.ui.legacy_workers import (
    DnsBenchmarkWorker,
    DnsConfigurationWorker,
    NetworkIdentityWorker,
)
from netvision.ui.monitor_workers import WorkerRegistry


from netvision.ui.workspaces.dns_audit import DnsWorkspace


class DnsController(QObject):
    def __init__(
        self, workspace: DnsWorkspace, facts: StateStore, registry: WorkerRegistry, parent: QObject
    ) -> None:
        super().__init__(parent)
        self.host = parent
        self.workspace = workspace
        self.facts = facts
        self.registry = registry
        self._network_identity = None
        self._measured_identity = None
        self._request_identity = None
        self._identity_thread = None
        self._reload_pending = False
        self._shutting_down = False
        self._retry_public_ip = False
        self._retry_timer = QTimer(self)
        self._retry_timer.setSingleShot(True)
        self._retry_timer.timeout.connect(self._load_dns_configuration)
        self._identity_timer = QTimer(self)
        self._identity_timer.setInterval(15000)
        self._identity_timer.timeout.connect(self._check_network_identity)
        self._identity_timer.start()
        workspace.dns_run_button.clicked.connect(self.start_dns_benchmark)
        workspace.dns_apply_button.clicked.connect(self._apply_selected_dns_profile)
        workspace.dns_custom_button.clicked.connect(self._add_custom_dns_profile)
        workspace.dns_adapter_properties_button.clicked.connect(self._open_dns_adapter_properties)

    def stop(self) -> None:
        self._shutting_down = True
        self._reload_pending = False
        self._identity_timer.stop()
        self._retry_timer.stop()
        self.registry.stop(self.host._dns_benchmark_thread)
        self.registry.stop(self.host._dns_config_thread)
        self.registry.stop(self._identity_thread)

    @Slot(str)
    def _on_dns_benchmark_failed(self, message: str) -> None:
        if self._shutting_down:
            return
        self.host._set_task_button_busy(self.workspace.dns_run_button, False)
        self.workspace.dns_status.setText(message)

    @Slot()
    def _clear_dns_benchmark_worker(self) -> None:
        if self.sender() is not self.host._dns_benchmark_thread:
            return
        self.host._dns_benchmark_thread = None
        self.host._dns_benchmark_worker = None

    def _render_dns_profiles(self) -> None:
        self.workspace.dns_table.setRowCount(len(self.host._dns_profiles))
        for row, profile in enumerate(self.host._dns_profiles):
            values = [profile.name, profile.display_addresses, "--", "--", "Готов к тесту"]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.workspace.dns_table.setItem(row, column, item)

    @Slot()
    def start_dns_benchmark(self) -> None:
        if self._shutting_down:
            return
        if self.host._dns_benchmark_thread and self.host._dns_benchmark_thread.isRunning():
            return
        self.host._dns_public_addresses = PublicIpAddresses()
        self._render_dns_info()
        if self.host._dns_config_thread is not None:
            self._reload_pending = True
        self._load_dns_configuration()
        self.host._set_task_button_busy(self.workspace.dns_run_button, True, "Проверка")
        self.workspace.dns_status.setText(
            self.host._tr("Проверяем TCP/53 параллельно для всех резолверов...")
        )
        self._render_dns_profiles()
        thread = QThread(self.host)
        worker = DnsBenchmarkWorker(tuple(self.host._dns_profiles))
        worker.moveToThread(thread)
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_dns_benchmark_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_dns_benchmark_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_dns_benchmark_worker)
        self.host._dns_benchmark_thread = thread
        self.host._dns_benchmark_worker = worker
        thread.start()

    @Slot(object)
    def _on_dns_benchmark_completed(self, value: object) -> None:
        if self._shutting_down:
            return
        self.host._set_task_button_busy(self.workspace.dns_run_button, False)
        if not isinstance(value, tuple) or not all(
            isinstance(item, DnsBenchmarkResult) for item in value
        ):
            self._on_dns_benchmark_failed("DNS-бенчмарк вернул некорректный результат")
            return
        successful = [item for item in value if item.success]
        self.facts.set(
            "dns.best", min(successful, key=lambda item: item.latency_ms) if successful else None
        )
        self.facts.set(
            "dns.worst", max(successful, key=lambda item: item.latency_ms) if successful else None
        )
        fastest = (
            min(successful, key=lambda item: item.latency_ms or float("inf"))
            if successful
            else None
        )
        for row, result in enumerate(value):
            latency = f"{result.latency_ms:.1f} мс" if result.latency_ms is not None else "--"
            status = (
                "Лучший" if fastest is result else ("Доступен" if result.success else "Нет ответа")
            )
            values = [
                result.profile.name,
                result.profile.display_addresses,
                result.address or "--",
                latency,
                status,
            ]
            for column, value_text in enumerate(values):
                item = QTableWidgetItem(value_text)
                item.setToolTip(result.error if column == 4 and result.error else value_text)
                if fastest is result:
                    item.setBackground(QColor("#124F43"))
                    item.setForeground(QColor("#00E5A3"))
                elif not result.success:
                    item.setForeground(QColor("#FF6B78"))
                self.workspace.dns_table.setItem(row, column, item)
        if fastest:
            self.workspace.dns_status.setText(
                self.host._translator.format(
                    "Лучший резолвер: {name} · {address} · {latency:.1f} мс",
                    name=fastest.profile.name,
                    address=fastest.address,
                    latency=fastest.latency_ms,
                )
            )
        else:
            self.workspace.dns_status.setText(self.host._tr("Доступных DNS-серверов не найдено"))

    @Slot(object, object, object, object)
    def _on_dns_configuration_completed(
        self,
        configuration: object,
        public_addresses: object,
        before: object,
        after: object,
    ) -> None:
        if self._shutting_down:
            return
        if not isinstance(configuration, DnsConfiguration):
            self._on_dns_configuration_failed("Системные DNS не распознаны")
            return
        if before != after or (
            self._network_identity != self._request_identity and after != self._network_identity
        ):
            self._reload_pending = True
            return
        previous_identity = self._measured_identity
        self._network_identity = after
        self._measured_identity = after
        self.workspace.dns_adapter_combo.clear()
        for name in configuration.adapter_names:
            self.workspace.dns_adapter_combo.addItem(name, name)
        self.host._dns_configuration = configuration
        received_ipv4 = isinstance(public_addresses, PublicIpAddresses) and bool(
            public_addresses.ipv4
        )
        if after is not None and isinstance(public_addresses, PublicIpAddresses):
            previous = self.host._dns_public_addresses
            if after == previous_identity and previous is not None:
                public_addresses = PublicIpAddresses(
                    ipv4=public_addresses.ipv4 or previous.ipv4,
                    ipv6=public_addresses.ipv6 or previous.ipv6,
                    error=(
                        public_addresses.error
                        if not (public_addresses.ipv4 or previous.ipv4)
                        else None
                    ),
                )
            self.host._dns_public_addresses = public_addresses
        else:
            self.host._dns_public_addresses = PublicIpAddresses()
        if getattr(self, "_retry_public_ip", False):
            self._retry_public_ip = False
            if not received_ipv4:
                self._retry_timer.start(3000)
        self._render_dns_info()
        self.workspace.dns_apply_button.setEnabled(bool(configuration.adapter_names))

    @Slot(str)
    def _on_dns_configuration_failed(self, message: str) -> None:
        if self._shutting_down:
            return
        self.host._dns_configuration = None
        if self.host._dns_public_addresses is None:
            self.host._dns_public_addresses = PublicIpAddresses(error=message)
        if self._retry_public_ip:
            self._retry_public_ip = False
            self._retry_timer.start(3000)
        self._render_dns_info()
        self.workspace.dns_status.setText(message)

    @Slot()
    def _clear_dns_configuration_worker(self) -> None:
        if self.sender() is not self.host._dns_config_thread:
            return
        self.host._dns_config_thread = None
        self.host._dns_config_worker = None
        if self._reload_pending and not self._shutting_down:
            self._reload_pending = False
            self._load_dns_configuration()

    def _check_network_identity(self) -> None:
        if self._shutting_down or self._identity_thread is not None or self.host._dashboard_closing:
            return
        worker = NetworkIdentityWorker()
        worker.completed.connect(self._network_identity_changed)
        thread = self.registry.start(worker)
        self._identity_thread = thread
        thread.finished.connect(self._clear_identity_worker)
        if thread.isFinished():
            self._identity_thread = None

    @Slot()
    def _clear_identity_worker(self) -> None:
        if self.sender() is self._identity_thread:
            self._identity_thread = None

    @Slot(object)
    def _network_identity_changed(self, identity: object) -> None:
        if self._shutting_down:
            return
        if identity == self._network_identity:
            return
        self._network_identity = identity
        if identity != self._measured_identity:
            self.host._dns_public_addresses = PublicIpAddresses()
            self._render_dns_info()
            if self.host._dns_config_thread is not None:
                self._reload_pending = True
            elif identity is not None:
                self._load_dns_configuration()

    def _load_dns_configuration(self) -> None:
        if self._shutting_down:
            return
        if self.host._dns_config_thread and self.host._dns_config_thread.isRunning():
            return
        self._request_identity = self._network_identity
        thread = QThread(self.host)
        worker = DnsConfigurationWorker()
        worker.moveToThread(thread)
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.started.connect(worker.run)
        worker.completed.connect(
            self.host._queue_ui_slot(self._on_dns_configuration_completed),
        )
        worker.failed.connect(
            self.host._queue_ui_slot(self._on_dns_configuration_failed),
        )
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        self.registry.retain(thread, worker)
        thread.finished.connect(self._clear_dns_configuration_worker)
        self.host._dns_config_thread = thread
        self.host._dns_config_worker = worker
        thread.start()

    @Slot()
    def _apply_selected_dns_profile(self) -> None:
        row = self.workspace.dns_table.currentRow()
        if row < 0 or row >= len(self.host._dns_profiles):
            self.workspace.dns_status.setText(self.host._tr("Выберите DNS-профиль в таблице"))
            return
        adapter = self.workspace.dns_adapter_combo.currentData()
        profile = self.host._dns_profiles[row]
        if not isinstance(adapter, str):
            self.workspace.dns_status.setText(self.host._tr("Активный сетевой адаптер не найден"))
            return
        self.host._run_system_action(
            f"Применение DNS {profile.name}",
            lambda profile=profile, adapter=adapter: apply_dns_servers(adapter, profile.addresses),
            self.workspace.dns_apply_button,
        )

    def on_dns_applied(self) -> None:
        if self._shutting_down:
            return
        self._retry_public_ip = True
        if self.host._dns_config_thread is not None:
            self._reload_pending = True
        else:
            self._load_dns_configuration()

    def _render_dns_info(self) -> None:
        while self.workspace.dns_info_grid.count():
            item = self.workspace.dns_info_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        configuration = self.host._dns_configuration
        public_addresses = self.host._dns_public_addresses or PublicIpAddresses()
        chips: list[tuple[str, str | None, str]] = []
        if configuration is not None:
            for index, address in enumerate(configuration.servers):
                provider = self.host._tr(self._dns_provider_name(address))
                ip_version = "IPv6" if ":" in address else "IPv4"
                chips.append(
                    (
                        f"{ip_version} · {provider}",
                        address,
                        self.host._translator.format(
                            (
                                "Основной DNS-резолвер {provider} ({version}). Используется для преобразования доменных имён в IP-адреса. Нажмите, чтобы скопировать."
                                if index == 0
                                else "Дополнительный DNS-резолвер {provider} ({version}). Используется, если основной сервер недоступен. Нажмите, чтобы скопировать."
                            ),
                            provider=provider,
                            version=ip_version,
                        ),
                    )
                )
        if not chips:
            chips.append((self.host._tr("DNS-серверы не определены"), None, ""))

        chips.extend(
            (
                (
                    self.host._tr("Публичный IPv4"),
                    public_addresses.ipv4,
                    public_addresses.error
                    or self.host._tr(
                        "Ваш внешний IPv4-адрес: так вашу сеть видят сайты и интернет-сервисы. Нажмите, чтобы скопировать."
                    ),
                ),
                (
                    self.host._tr("Публичный IPv6"),
                    public_addresses.ipv6,
                    public_addresses.error
                    or self.host._tr(
                        "Ваш внешний IPv6-адрес: так вашу сеть видят сайты и интернет-сервисы через IPv6. Нажмите, чтобы скопировать."
                    ),
                ),
            )
        )
        for index, (caption, address, tooltip) in enumerate(chips):
            chip = QPushButton(f"{caption}\n{address or self.host._tr('Не определён')}")
            chip.setObjectName("DnsInfoChip")
            chip.setToolTip(tooltip or (address or ""))
            chip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            if address:
                chip.setCursor(Qt.CursorShape.PointingHandCursor)
                chip.clicked.connect(
                    lambda _checked=False, value=address: self._copy_dns_info(value)
                )
            else:
                chip.setEnabled(False)
            row, column = divmod(index, 3)
            self.workspace.dns_info_grid.addWidget(chip, row, column)
            self.workspace.dns_info_grid.setColumnStretch(column, 1)

    @staticmethod
    def _dns_provider_name(address: str) -> str:
        value = address.casefold()
        if value in {
            "159.194.200.33",
            "193.233.112.67",
            "193.233.112.88",
            "193.233.112.68",
            "37.230.192.51",
            "46.8.158.6",
        }:
            return "GeoHide DNS"
        if value.startswith(("8.8.", "2001:4860:4860:")):
            return "Google DNS"
        if value.startswith(("1.1.", "1.0.", "2606:4700:4700:")):
            return "Cloudflare DNS"
        if value.startswith(("9.9.", "149.112.")):
            return "Quad9 DNS"
        if value.startswith("208.67."):
            return "OpenDNS"
        if value.startswith(("77.88.", "2a02:6b8:")):
            return "Yandex DNS"
        if value.startswith(("94.140.", "2a10:50c0:")):
            return "AdGuard DNS"
        return "DNS провайдера"

    def _copy_dns_info(self, address: str) -> None:
        QApplication.clipboard().setText(address)
        QToolTip.showText(
            QCursor.pos(), self.host._tr("Скопировано"), self.workspace.dns_info_container
        )

    def _use_geohide_dns(self, address: str) -> None:
        self.workspace.dns_custom_input.setText(address)
        self.workspace.dns_custom_input.setFocus()
        self.workspace.dns_status.setText(
            self.host._translator.format("Адрес GeoHide подставлен: {address}", address=address)
        )
        self.host.statusBar().showMessage(
            self.host._translator.format("Адрес GeoHide подставлен: {address}", address=address),
            4000,
        )

    @Slot()
    def _add_custom_dns_profile(self) -> None:
        try:
            profile = custom_dns_profile(self.workspace.dns_custom_input.text())
        except ValueError as exc:
            self.workspace.dns_status.setText(str(exc))
            return
        if any(profile.addresses == item.addresses for item in self.host._dns_profiles):
            self.workspace.dns_status.setText(self.host._tr("Этот DNS-сервер уже добавлен"))
            return
        self.host._dns_profiles.append(profile)
        self._render_dns_profiles()
        self.workspace.dns_custom_input.clear()
        self.workspace.dns_status.setText(
            self.host._translator.format(
                "Добавлен {addresses}. Запустите тест для проверки.",
                addresses=profile.display_addresses,
            )
        )

    @Slot()
    def _open_dns_adapter_properties(self) -> None:
        """Open Windows Network Connections without blocking the DNS workspace."""
        self.host._run_system_action(
            self.host._tr("Открыть свойства адаптера"),
            open_network_adapters,
            self.workspace.dns_adapter_properties_button,
            self.workspace.dns_status,
        )
