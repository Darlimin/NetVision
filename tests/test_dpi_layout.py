from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QHeaderView, QTableWidget

from netvision.ui.components.factory import configure_table
from netvision.ui.workspaces.tls_audit import TlsAuditWorkspace


def test_table_rows_follow_font_changes():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    table = QTableWidget(0, 1)
    configure_table(table, (100,))
    font = QFont(table.font())
    font.setPointSize(24)
    table.setFont(font)
    app.processEvents()
    assert table.verticalHeader().defaultSectionSize() >= table.fontMetrics().height() + 12
    table.deleteLater()


def test_certificate_table_wraps_and_resizes_rows():
    app = QApplication.instance() or QApplication(["tests", "-platform", "offscreen"])
    workspace = TlsAuditWorkspace()
    table = workspace.tls_certificate_table
    table.setRowCount(1)
    assert table.wordWrap()
    assert table.verticalHeader().sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents
    workspace.deleteLater()
    app.processEvents()
