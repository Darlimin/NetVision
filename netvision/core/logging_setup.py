"""Configure bounded on-disk application logging at startup."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from netvision.core.test_history import default_history_path


def setup_application_logging(log_directory: Path | None = None) -> None:
    logger = logging.getLogger("netvision")
    if any(getattr(handler, "_netvision_file_handler", False) for handler in logger.handlers):
        return
    directory = log_directory or default_history_path().parent / "logs"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            directory / "netvision.log", maxBytes=2 * 1024 * 1024, backupCount=2, encoding="utf-8"
        )
    except OSError:
        return
    handler._netvision_file_handler = True
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
