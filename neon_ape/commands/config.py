from __future__ import annotations

from rich.console import Console
from rich.table import Table

from neon_ape.config import AppConfig, load_user_config, save_user_config, update_user_config


ALLOWED_KEYS = {"data_dir", "privacy_mode", "theme_name", "install_root", "bin_dir", "obsidian_vault_path"}


def run_config_command(
    console: Console,
    config: AppConfig,
    *,
    action: str,
    key: str | None = None,
    value: str | None = None,
) -> None:
    if action == "show":
        current = load_user_config(config.config_path)
        merged = {
            "config_path": str(config.config_path),
            "data_dir": str(config.data_dir),
            "privacy_mode": config.privacy_mode,
            "theme_name": config.theme_name,
            "install_root": str(config.install_root),
            "bin_dir": str(config.bin_dir),
            "obsidian_vault_path": str(config.obsidian_vault_path) if config.obsidian_vault_path else "",
        }
        merged.update(current)
        console.print(_build_config_table(merged))
        return

    if action == "init":
        current = load_user_config(config.config_path)
        if not current:
            save_user_config(
                {
                    "data_dir": str(config.data_dir),
                    "privacy_mode": config.privacy_mode,
                    "theme_name": config.theme_name,
                    "install_root": str(config.install_root),
                    "bin_dir": str(config.bin_dir),
                    "obsidian_vault_path": str(config.obsidian_vault_path) if config.obsidian_vault_path else "",
                },
                config.config_path,
            )
        console.print(f"[bold green]Config initialized at[/bold green] {config.config_path}")
        return

    if action == "set":
        if not key or value is None:
            console.print("[bold red]Both `key` and `value` are required for `neonape config set`.[/bold red]")
            return
        if key not in ALLOWED_KEYS:
            console.print(
                f"[bold red]Unsupported config key:[/bold red] {key}. "
                f"Allowed keys: {', '.join(sorted(ALLOWED_KEYS))}"
            )
            return
        config_path = update_user_config(key, value, config.config_path)
        console.print(f"[bold green]Updated[/bold green] {key} in {config_path}")
        return

    console.print("[bold red]Unsupported config action.[/bold red]")


def _build_config_table(values: dict[str, object]) -> Table:
    table = Table(title="Neon Ape Config", expand=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for key in ("config_path", "data_dir", "privacy_mode", "theme_name", "install_root", "bin_dir", "obsidian_vault_path"):
        table.add_row(key, str(values.get(key, "-")))
    return table
