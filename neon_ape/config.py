from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from shutil import which
import tomllib
from typing import Any


PROJECT_DISCOVERY_TOOLS = (
    "subfinder",
    "httpx",
    "naabu",
    "nuclei",
    "dnsx",
    "katana",
    "uncover",
    "assetfinder",
    "amass",
)

COMMON_RECON_TOOLS = (
    "nmap",
    "whois",
    "dig",
    "gobuster",
    "dirb",
    "nikto",
    "sqlmap",
    "msfconsole",
)


@dataclass(slots=True)
class AppConfig:
    app_name: str
    config_path: Path
    install_root: Path
    bin_dir: Path
    launcher_path: Path
    data_dir: Path
    db_path: Path
    log_path: Path
    checklist_path: Path
    schema_path: Path
    scan_dir: Path
    privacy_mode: bool
    theme_name: str

    @classmethod
    def default(cls) -> "AppConfig":
        package_dir = Path(__file__).resolve().parent
        project_root = package_dir.parent
        config_path = _default_config_path()
        file_config = _load_config_file(config_path)
        install_root = Path(os.environ.get("NEONAPE_INSTALL_ROOT", file_config.get("install_root", "~/.local/share/neonape"))).expanduser()
        bin_dir = Path(os.environ.get("NEONAPE_BIN_DIR", file_config.get("bin_dir", "~/.local/bin"))).expanduser()
        data_dir = Path(os.environ.get("NEONAPE_DATA_DIR", file_config.get("data_dir", "~/.neon_ape"))).expanduser()
        privacy_mode = _as_bool(file_config.get("privacy_mode", True))
        theme_name = str(file_config.get("theme_name", "eva")).strip() or "eva"
        return cls(
            app_name="Neon Ape",
            config_path=config_path,
            install_root=install_root,
            bin_dir=bin_dir,
            launcher_path=bin_dir / "neonape",
            data_dir=data_dir,
            db_path=data_dir / "neon_ape.db",
            log_path=data_dir / "neon_ape.log",
            checklist_path=project_root / "neon_ape" / "checklists" / "neon_ape_checklist.json",
            schema_path=project_root / "neon_ape" / "db" / "schema.sql",
            scan_dir=data_dir / "scans",
            privacy_mode=privacy_mode,
            theme_name=theme_name,
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.scan_dir.mkdir(parents=True, exist_ok=True)


def detect_installed_tools() -> dict[str, str]:
    detected: dict[str, str] = {}
    for tool in (*COMMON_RECON_TOOLS, *PROJECT_DISCOVERY_TOOLS):
        path = which(tool)
        if path:
            detected[tool] = path
    return detected


def detect_package_manager() -> str | None:
    for manager in ("apt-get", "pacman", "brew"):
        if which(manager):
            return manager
    return None


def load_user_config(path: Path | None = None) -> dict[str, str | bool]:
    return _load_config_file(path or _default_config_path())


def save_user_config(values: dict[str, str | bool], path: Path | None = None) -> Path:
    target = path or _default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[neonape]"]
    for key, value in values.items():
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            rendered = f"\"{str(value)}\""
        lines.append(f"{key} = {rendered}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def update_user_config(key: str, value: str, path: Path | None = None) -> Path:
    config_path = path or _default_config_path()
    current = _load_config_file(config_path)
    normalized = _normalize_config_value(key, value)
    current[key] = normalized
    return save_user_config(current, config_path)


def _default_config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
    return base / "neonape" / "config.toml"


def _load_config_file(path: Path) -> dict[str, str | bool]:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    neonape_config = payload.get("neonape", {})
    return neonape_config if isinstance(neonape_config, dict) else {}


def _normalize_config_value(key: str, value: str) -> str | bool:
    if key == "privacy_mode":
        return _as_bool(value)
    return value.strip()


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)
