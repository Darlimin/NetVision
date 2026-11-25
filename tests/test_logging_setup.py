import logging

from netvision.core.logging_setup import setup_application_logging


def test_file_logging_is_bounded_and_idempotent(tmp_path):
    logger = logging.getLogger("netvision")
    previous_level = logger.level
    try:
        setup_application_logging(tmp_path)
        setup_application_logging(tmp_path)
        handlers = [h for h in logger.handlers if getattr(h, "_netvision_file_handler", False)]
        assert len(handlers) == 1
        assert handlers[0].maxBytes == 2 * 1024 * 1024
        assert handlers[0].backupCount == 2
        logger.warning("worker failure: OSError")
        handlers[0].flush()
        assert "worker failure: OSError" in (tmp_path / "netvision.log").read_text(encoding="utf-8")
    finally:
        for handler in list(logger.handlers):
            if getattr(handler, "_netvision_file_handler", False):
                logger.removeHandler(handler)
                handler.close()
        logger.setLevel(previous_level)


def test_logging_failure_does_not_break_startup(tmp_path):
    file = tmp_path / "not-a-directory"
    file.write_text("x", encoding="utf-8")
    setup_application_logging(file)
