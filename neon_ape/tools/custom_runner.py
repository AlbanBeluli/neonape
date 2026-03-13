from __future__ import annotations

from pathlib import Path


def validate_custom_script_path(path: Path) -> bool:
    """Restrict future custom script execution to local Python files."""
    return path.suffix == ".py" and path.exists() and path.is_file()
