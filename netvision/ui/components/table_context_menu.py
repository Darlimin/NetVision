"""Context actions for diagnostic tables."""

import ipaddress
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMenu


_HOST = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?![\w.-])")
_TOKEN = re.compile(r"[a-fA-F0-9:.%]+")


def find_target(text: str) -> tuple[str, bool] | None:
    for match in _TOKEN.finditer(text):
        candidate = match.group().strip(".")
        try:
            return str(ipaddress.ip_address(candidate)), True
        except ValueError:
            if candidate.count(":") == 1:
                address, port = candidate.rsplit(":", 1)
                if port.isdigit() and 0 < int(port) <= 65535:
                    try:
                        return str(ipaddress.IPv4Address(address)), True
                    except ValueError:
                        pass
    for match in _HOST.finditer(text):
        candidate = match.group().rstrip(".")
        labels = candidate.split(".")
        if all(label and not label.startswith("-") and not label.endswith("-") for label in labels):
            if any(ch.isalpha() for ch in labels[-1]):
                return candidate.lower(), False
    return None


def parse_remote_endpoint(text: str) -> tuple[str, int] | None:
    match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:\s]+)):(\d{1,5})", text.strip())
    if not match:
        return None
    address = match.group(1) or match.group(2)
    port = int(match.group(3))
    if not 1 <= port <= 65535:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        target = find_target(address)
        if not target or target[1] or target[0].casefold() != address.casefold():
            return None
        return target[0], port
    if ip.is_loopback or ip.is_unspecified:
        return None
    return str(ip), port


def create_menu(
    host,
    table,
    row: int,
    target_columns: tuple[int, ...],
    open_mtr: bool,
    *,
    socket_matrix: bool = False,
) -> QMenu:
    menu = QMenu(table)
    menu.setObjectName("DiagnosticContextMenu")
    light = host._theme == "light"
    background, foreground, border, selected = (
        ("#ffffff", "#172033", "#d8e1ee", "#d9f3e9")
        if light
        else ("#142337", "#e7eef8", "#36506b", "#24574f")
    )
    menu.setStyleSheet(
        f"QMenu {{ background: {background}; color: {foreground}; border: 1px solid {border}; }}"
        f" QMenu::item {{ padding: 6px 22px; }} QMenu::item:selected {{ background: {selected}; }}"
    )
    if row < 0 or row >= table.rowCount():
        return menu
    values = [
        table.item(row, col).text() if table.item(row, col) else ""
        for col in range(table.columnCount())
    ]
    endpoint = parse_remote_endpoint(values[2]) if socket_matrix and len(values) > 2 else None
    target = (endpoint[0], bool(_is_ip(endpoint[0]))) if endpoint else None
    if not socket_matrix:
        target = next(
            (
                result
                for col in target_columns
                if col < len(values) and (result := find_target(values[col]))
            ),
            None,
        )
    if target:
        address, is_ip = target
        action = menu.addAction(host._tr("Копировать IP" if is_ip else "Копировать цель (хост)"))
        action.triggered.connect(lambda: QApplication.clipboard().setText(address))
    row_text = " · ".join(value.strip() for value in values if value.strip())
    if row_text:
        action = menu.addAction(host._tr("Копировать строку"))
        action.triggered.connect(lambda: QApplication.clipboard().setText(row_text))
    if target and open_mtr:

        def navigate():
            host.mtr_controller.stop_mtr_monitor("target_changed")
            host.mtr_workspace.traceroute_target_input.setText(target[0])
            host._show_dashboard_section("traceroute")
            host.mtr_workspace.traceroute_mode_tabs.setCurrentIndex(1)

        menu.addAction(host._tr("Открыть в MTR")).triggered.connect(navigate)
    if endpoint:

        def apply_endpoint():
            address, port = endpoint
            host.apply_endpoint_target(address, port)

        menu.addAction(host._tr("Подставить в проверку порта / TLS")).triggered.connect(
            apply_endpoint
        )
    return menu


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def install_context_menu(
    host, table, target_columns: tuple[int, ...], *, open_mtr: bool, socket_matrix: bool = False
) -> None:
    table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def show_menu(point):
        row = table.rowAt(point.y())
        if row < 0:
            return
        table.selectRow(row)
        menu = create_menu(host, table, row, target_columns, open_mtr, socket_matrix=socket_matrix)
        if menu.actions():
            menu.aboutToHide.connect(menu.deleteLater)
            menu.popup(table.viewport().mapToGlobal(point))
        else:
            menu.deleteLater()

    table.customContextMenuRequested.connect(show_menu)
