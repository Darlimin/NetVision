from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont, QFontDatabase, QIcon
from PySide6.QtWidgets import QApplication

from netvision.ui.main_window import MainWindow
from netvision.ui.theme import APP_STYLE


def _load_inter_fonts() -> str:
    """Register the bundled Inter faces and return the usable family name."""
    project_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    fonts_dir = project_root / "fonts" / "static"
    font_files = (
        "Inter_18pt-Regular.ttf",
        "Inter_18pt-Medium.ttf",
        "Inter_18pt-SemiBold.ttf",
        "Inter_18pt-Bold.ttf",
    )
    registered_families: list[str] = []
    for font_file in font_files:
        font_id = QFontDatabase.addApplicationFont(str(fonts_dir / font_file))
        if font_id >= 0:
            registered_families.extend(QFontDatabase.applicationFontFamilies(font_id))

    return registered_families[0] if registered_families else "Inter"


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("NetVision")
    app.setApplicationDisplayName("NetVision")
    app.setOrganizationName("NetVision")
    app.setWindowIcon(QIcon(str(Path(__file__).resolve().parent.parent / "NetVision.ico")))
    app.setStyle("Fusion")
    app_font = QFont(_load_inter_fonts(), 10)
    app_font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    app.setFont(app_font)
    app.setStyleSheet(APP_STYLE)

    window = MainWindow()
    window.show()
    QTimer.singleShot(0, window.refresh_processes)
    raise SystemExit(app.exec())

