import logging

from tools.logger import get_logger


def test_logger_creates_log_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    logger = get_logger(
        "test_logger"
    )

    logger.info(
        "Test security event"
    )

    for handler in logger.handlers:
        handler.flush()

    log_file = (
        tmp_path
        / "logs"
        / "security.log"
    )

    assert log_file.exists()

    content = log_file.read_text(
        encoding="utf-8"
    )

    assert "Test security event" in content

    logger.handlers.clear()

    for handler in list(logger.handlers):
        handler.close()

    logging.getLogger(
        "test_logger"
    ).handlers.clear()