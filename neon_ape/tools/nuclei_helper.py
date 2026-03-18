from __future__ import annotations

import os
from pathlib import Path
import pwd
import shutil

from neon_ape.tools.base import run_command


def nuclei_templates_path() -> Path:
    return Path.home() / ".neonape" / "nuclei-templates"


def download_templates() -> tuple[Path, str, bool]:
    target = nuclei_templates_path()
    if _templates_present(target):
        return target, f"Templates already present: {_display_path(target)}", True

    target.parent.mkdir(parents=True, exist_ok=True)
    seeded = _seed_from_existing_templates(target)
    if seeded:
        return target, f"Templates already present: {_display_path(target)}", True

    message = "Downloading nuclei templates (one-time setup)..."
    result = run_command(
        "nuclei",
        "template-update",
        ["nuclei", "-update-templates", "-ud", str(target)],
        timeout=600,
        raw_output_path=str(target),
    )
    if _templates_present(target):
        return target, message, True
    return target, message, False


def _seed_from_existing_templates(target: Path) -> bool:
    for resolved in _candidate_template_dirs():
        if resolved == target or not _templates_present(resolved):
            continue
        try:
            if target.exists() or target.is_symlink():
                if target.is_symlink() or target.is_file():
                    target.unlink()
                else:
                    shutil.rmtree(target)
            shutil.copytree(resolved, target, dirs_exist_ok=True)
            return _templates_present(target)
        except OSError:
            continue
    return False


def _templates_present(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    for pattern in ("*.yaml", "*.yml"):
        try:
            if next(path.rglob(pattern), None) is not None:
                return True
        except OSError:
            return False
    return False


def _candidate_template_dirs() -> list[Path]:
    home_candidates = {Path.home()}
    try:
        home_candidates.add(Path(pwd.getpwuid(os.getuid()).pw_dir))
    except (KeyError, AttributeError, OSError):
        pass

    candidates: list[Path] = []
    for home in home_candidates:
        candidates.extend(
            [
                home / ".neonape" / "nuclei-templates",
                home / "nuclei-templates",
                home / "Desktop" / "python" / "nuclei-templates",
            ]
        )
    candidates.append(Path("/opt/homebrew/share/nuclei-templates"))
    return candidates


def _display_path(path: Path) -> str:
    try:
        return f"~/{path.relative_to(Path.home())}"
    except ValueError:
        return str(path)
