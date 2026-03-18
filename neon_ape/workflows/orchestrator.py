from __future__ import annotations

from datetime import date
from pathlib import Path
import platform
import shutil
import subprocess


def is_macos() -> bool:
    return platform.system() == "Darwin"


def build_daily_report_dir(target: str, base_dir: Path | None = None) -> Path:
    root = (base_dir or (Path.home() / "NeonApe-Reports")).expanduser()
    safe_target = "".join(char if char.isalnum() or char in {"-", ".", "_"} else "_" for char in target).strip("_") or "target"
    return root / f"{date.today().isoformat()}-{safe_target}"


def copy_daily_reports(target: str, report_files: list[Path], *, base_dir: Path | None = None) -> Path:
    destination = build_daily_report_dir(target, base_dir=base_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for report_file in report_files:
        if report_file.exists():
            shutil.copy2(report_file, destination / report_file.name)
    return destination


def speak_completion(highest_risk: int, *, checklist_complete: bool = False) -> list[str]:
    if checklist_complete:
        lines = [
            f"Adam reconnaissance and MAGI checklist complete. Highest risk score is {highest_risk}.",
            "Daily report folder created.",
        ]
    else:
        lines = [
            "Adam reconnaissance complete.",
            f"Highest risk score is {highest_risk}.",
            "Daily report folder created.",
        ]
    if not is_macos():
        return lines
    for line in lines:
        subprocess.run(["say", "-v", "Daniel", line], check=False)
    return lines


def speak_autoresearch_completion(start_score: float, end_score: float, *, persisted: bool = False) -> list[str]:
    lines = [f"Autoresearch complete. Skill improved from {round(start_score, 2)} percent to {round(end_score, 2)} percent."]
    if persisted:
        lines.append("Skill improved and saved permanently. New version active.")
    if not is_macos():
        return lines
    for line in lines:
        subprocess.run(["say", "-v", "Daniel", line], check=False)
    return lines


def open_in_finder(path: Path) -> None:
    if not is_macos():
        return
    subprocess.run(["open", str(path)], check=False)
