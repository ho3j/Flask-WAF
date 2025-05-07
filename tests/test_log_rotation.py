import pytest
import logging
from logging.handlers import TimedRotatingFileHandler
import os
from waf.config import LOG_FILE

@pytest.fixture
def temp_log_file(tmp_path):
    """
    Create a temporary log file with TimedRotatingFileHandler for testing.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "test_waf.log"
    logger = logging.getLogger('test_logger')
    logger.setLevel(logging.INFO)
    handler = TimedRotatingFileHandler(
        log_file,
        when='midnight',
        interval=1,
        backupCount=5
    )
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.handlers = [handler]
    yield log_file, handler
    # Cleanup
    for f in log_dir.glob("test_waf.log*"):
        try:
            f.unlink()
        except PermissionError:
            pass

def test_log_rotation(temp_log_file):
    """
    Test log rotation by triggering a manual rollover.
    """
    log_file, handler = temp_log_file
    logger = logging.getLogger('test_logger')

    # تولید چند پیام لاگ
    log_message = "Test log message " + "x" * 1000000
    for _ in range(5):
        logger.info(log_message)

    # شبیه‌سازی چرخش
    handler.doRollover()

    # چک کردن وجود فایل لاگ
    assert log_file.exists(), f"Log file {log_file} was not created"

    # چک کردن فایل‌های چرخشی
    rotated_files = [f for f in log_file.parent.glob("test_waf.log.*")]
    assert len(rotated_files) > 0, f"No rotated files found. Log file size: {log_file.stat().st_size} bytes"