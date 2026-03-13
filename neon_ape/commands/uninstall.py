from __future__ import annotations

import shutil
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from neon_ape.config import AppConfig
from neon_ape.ui.theme import section_style


def run_uninstall(
    console: Console,
    config: AppConfig,
    *,
    assume_yes: bool,
    purge_data: bool,
) -> None:
    targets = [
        f"launcher: {config.launcher_path}",
        f"install root: {config.install_root}",
    ]
    if purge_data:
        targets.append(f"runtime data: {config.data_dir}")

    console.print(
        Panel.fit(
            "\n".join(targets),
            title="Uninstall Neon Ape",
            style=section_style("orange"),
        )
    )

    if not assume_yes:
        try:
            response = input("Proceed with uninstall? [y/N]: ").strip().lower()
        except EOFError:
            console.print("[bold red]Uninstall aborted. Re-run with `neonape uninstall --yes`.[/bold red]")
            return
        if response not in {"y", "yes"}:
            console.print("[bold yellow]Uninstall cancelled.[/bold yellow]")
            return

    remove_path(config.launcher_path)
    remove_path(config.install_root)
    if purge_data:
        remove_path(config.data_dir)

    console.print("[bold green]Neon Ape uninstalled.[/bold green]")


def remove_path(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
        return
    shutil.rmtree(path)
