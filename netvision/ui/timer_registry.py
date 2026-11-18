"""Owned Qt timers used by the dashboard shell."""

from PySide6.QtCore import QObject, QTimer


class TimerRegistry(QObject):
    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        self.responsive_layout = QTimer(self)
        self.responsive_layout.setSingleShot(True)
        self.task_buttons = QTimer(self)
        self.task_buttons.setInterval(420)
        self.session = QTimer(self)
        self.session.setInterval(1000)
        self.bootstrap: QTimer | None = None

    def create_bootstrap(self) -> QTimer:
        if self.bootstrap is None:
            self.bootstrap = QTimer(self)
            self.bootstrap.setSingleShot(True)
        return self.bootstrap

    def stop_all(self) -> None:
        for timer in (self.responsive_layout, self.task_buttons, self.session, self.bootstrap):
            if timer is not None:
                timer.stop()
