from __future__ import annotations

import logging
from pathlib import Path


def configure_logger(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("neon_ape")
    if logger.handlers:
        return logger

    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
