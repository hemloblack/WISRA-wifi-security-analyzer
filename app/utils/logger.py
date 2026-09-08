"""
Centralized logging configuration.

Writes to both the console and logs/wisra.log (rotating, so it never
grows unbounded). Deliberately never logs full BSSIDs/SSIDs at INFO
level for privacy-conscious defaults — only counts and outcomes. Use
DEBUG level locally if you need per-network detail while developing.
"""
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False
LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
LOG_FILE = LOG_DIR / "wisra.log"


def _configure_root():
    global _CONFIGURED
    if _CONFIGURED:
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError:
        # If the filesystem is read-only or logs/ can't be created, fall
        # back to console-only logging instead of crashing the app.
        root.warning("Could not open %s for writing; file logging disabled.", LOG_FILE)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure_root()
    return logging.getLogger(name)
