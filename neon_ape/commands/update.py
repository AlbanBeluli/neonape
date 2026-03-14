from __future__ import annotations

from pathlib import Path
import subprocess

from rich.console import Console
from rich.panel import Panel

from neon_ape.config import AppConfig
from neon_ape.ui.theme import section_style


def run_update(
    console: Console,
    config: AppConfig,
    *,
    assume_yes: bool,
) -> None:
    update_script = config.install_root / "update.sh"
    console.print(
        Panel.fit(
            f"[bold]Installer root:[/bold] {config.install_root}\n"
            f"[bold]Update script:[/bold] {update_script}",
            title="Update Neon Ape",
            style=section_style("accent"),
        )
    )

    if not update_script.exists():
        console.print(
            "[bold red]Installed update script was not found.[/bold red] "
            "Reinstall Neon Ape with the installer first."
        )
        return

    if not assume_yes:
        try:
            response = input("Proceed with update? [y/N]: ").strip().lower()
        except EOFError:
            console.print("[bold red]Update aborted. Re-run with `neonape update --yes`.[/bold red]")
            return
        if response not in {"y", "yes"}:
            console.print("[bold yellow]Update cancelled.[/bold yellow]")
            return

    completed = subprocess.run(
        [str(update_script)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.stdout.strip():
        console.print(completed.stdout.strip())
    if completed.returncode != 0:
        if completed.stderr.strip():
            console.print(f"[bold red]{completed.stderr.strip()}[/bold red]")
        console.print(f"[bold red]Update failed with exit code {completed.returncode}.[/bold red]")
        return
    console.print("[bold green]Neon Ape update completed.[/bold green]")
