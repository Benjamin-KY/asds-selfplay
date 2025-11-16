"""
Logging configuration for ASDS Self-Play.

Sets up structured logging with file and console handlers.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from src.utils.config import get_config


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[str] = None,
    console: Optional[bool] = None
) -> logging.Logger:
    """
    Configure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR). Overrides config.
        log_file: Path to log file. Overrides config.
        console: Enable console logging. Overrides config.

    Returns:
        Root logger
    """
    config = get_config()

    # Use provided args or fall back to config
    level = log_level or config.logging.level
    file_path = log_file or config.logging.file
    enable_console = console if console is not None else config.logging.console
    log_format = config.logging.format

    # Create logs directory
    log_path = Path(file_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(log_format)

    # File handler
    file_handler = logging.FileHandler(file_path)
    file_handler.setLevel(getattr(logging, level.upper()))
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Module-level logger for testing
logger = get_logger(__name__)


if __name__ == "__main__":
    # Test logging setup
    setup_logging()

    logger = get_logger(__name__)
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")

    print(f"\nLog file created at: {get_config().logging.file}")
