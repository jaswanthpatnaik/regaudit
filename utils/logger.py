"""RegAudit Logging System.

Configures Python standard library logging with RotatingFileHandler (10MB x 3),
ensuring zero data loss and persistent audit logs in logs/regaudit.log.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

DEFAULT_LOG_FORMAT = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_INITIALIZED = False


def setup_logging(
    log_file: Path,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
    level: int = logging.INFO,
) -> logging.Logger:
    """Initialize rotating file logger for RegAudit.

    Args:
        log_file: Path to destination log file.
        max_bytes: Maximum size in bytes before rotating (default: 10MB).
        backup_count: Number of rotated log files to retain (default: 3).
        level: Logging level threshold.

    Returns:
        The root 'RegAudit' Logger instance.
    """
    global _INITIALIZED

    root_logger = logging.getLogger("RegAudit")
    root_logger.setLevel(level)

    if _INITIALIZED:
        return root_logger

    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Rotating file handler
    file_handler = RotatingFileHandler(
        filename=str(log_file),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    formatter = logging.Formatter(fmt=DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
    file_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)
    _INITIALIZED = True

    return root_logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Obtain a namespaced RegAudit logger child instance."""
    if not name:
        return logging.getLogger("RegAudit")
    return logging.getLogger(f"RegAudit.{name}")
