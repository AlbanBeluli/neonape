from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from shutil import which


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
    install_root: Path
    bin_dir: Path
    launcher_path: Path
    data_dir: Path
    db_path: Path
    log_path: Path
    checklist_path: Path
    schema_path: Path
    scan_dir: Path

    @classmethod
    def default(cls) -> "AppConfig":
        package_dir = Path(__file__).resolve().parent
        project_root = package_dir.parent
        install_root = Path(os.environ.get("NEONAPE_INSTALL_ROOT", "~/.local/share/neonape")).expanduser()
        bin_dir = Path(os.environ.get("NEONAPE_BIN_DIR", "~/.local/bin")).expanduser()
        data_dir = Path.home() / ".neon_ape"
        return cls(
            app_name="Neon Ape",
            install_root=install_root,
            bin_dir=bin_dir,
            launcher_path=bin_dir / "neonape",
            data_dir=data_dir,
            db_path=data_dir / "neon_ape.db",
            log_path=data_dir / "neon_ape.log",
            checklist_path=project_root / "neon_ape" / "checklists" / "oscp_black_book_mvp.json",
            schema_path=project_root / "neon_ape" / "db" / "schema.sql",
            scan_dir=data_dir / "scans",
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
