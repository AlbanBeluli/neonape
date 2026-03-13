from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt

from neon_ape.commands.db import run_db_view
from neon_ape.commands.tools import (
    run_chained_recon_workflow,
    run_checklist_step,
    run_nmap,
    run_projectdiscovery_tool,
)
from neon_ape.commands.transfer import run_export
from neon_ape.db.repository import checklist_summary, list_checklist_items, recent_scans
from neon_ape.ui.layout import build_checklist_table, build_interactive_actions, build_main_menu
from neon_ape.ui.views import build_landing_panel, build_quickstart_table, build_scans_table, build_status_table


def run_interactive_shell(
    console: Console,
    connection,
    *,
    config,
    detected_tools: dict[str, str],
    show_targets: bool,
    current_profile: str,
) -> None:
    profile = current_profile
    while True:
        checklist = checklist_summary(connection)
        checklist_items = list_checklist_items(connection)
        _render_home(console, connection, config, detected_tools, checklist, checklist_items, show_targets=show_targets)

        choice = Prompt.ask(
            "[bold cyan]Select action[/bold cyan]",
            choices=["1", "2", "3", "4", "5", "6", "7", "q"],
            default="1",
        )
        if choice == "1":
            console.print(build_checklist_table(checklist_items))
            continue
        if choice == "2":
            profile = _prompt_checklist_step(console, connection, checklist_items, detected_tools, config.scan_dir, profile)
            continue
        if choice == "3":
            _prompt_single_tool(console, connection, detected_tools, config.scan_dir)
            continue
        if choice == "4":
            _prompt_chained_workflow(console, connection, config.scan_dir)
            continue
        if choice == "5":
            _prompt_db_view(console, connection, checklist_items, show_targets=show_targets)
            continue
        if choice == "6":
            _prompt_export(console, connection)
            continue
        if choice == "7":
            console.clear()
            continue
        console.print("[bold green]Session closed.[/bold green]")
        return


def _render_home(
    console: Console,
    connection,
    config,
    detected_tools: dict[str, str],
    checklist: dict[str, str | int],
    checklist_items: list[dict[str, str | int | None]],
    *,
    show_targets: bool,
) -> None:
    console.print(build_main_menu())
    console.print(build_status_table(checklist, config.db_path, detected_tools))
    console.print(build_landing_panel(config.data_dir, checklist_items))
    console.print(build_quickstart_table())
    console.print(build_interactive_actions())
    console.print(
        build_scans_table(
            recent_scans(connection, limit=5),
            mask_targets=config.privacy_mode and not show_targets,
        )
    )


def _prompt_checklist_step(
    console: Console,
    connection,
    checklist_items: list[dict[str, str | int | None]],
    detected_tools: dict[str, str],
    scan_dir: Path,
    profile: str,
) -> str:
    console.print(build_checklist_table(checklist_items))
    step_value = Prompt.ask("[bold cyan]Checklist step[/bold cyan]")
    target = Prompt.ask("[bold cyan]Target[/bold cyan]")
    try:
        step_order = int(step_value)
    except ValueError:
        console.print("[bold red]Checklist step must be a number.[/bold red]")
        return profile
    profile, _ = run_checklist_step(
        console,
        connection,
        checklist_step=step_order,
        target=target,
        detected_tools=detected_tools,
        scan_dir=scan_dir,
        profile=profile,
    )
    return profile


def _prompt_single_tool(
    console: Console,
    connection,
    detected_tools: dict[str, str],
    scan_dir: Path,
) -> None:
    tool_name = Prompt.ask(
        "[bold cyan]Tool[/bold cyan]",
        choices=["nmap", "subfinder", "dnsx", "httpx", "naabu", "nuclei"],
        default="nmap",
    )
    target = Prompt.ask("[bold cyan]Target[/bold cyan]")
    if tool_name == "nmap":
        profile = Prompt.ask(
            "[bold cyan]Nmap profile[/bold cyan]",
            choices=["host_discovery", "service_scan", "aggressive"],
            default="service_scan",
        )
        run_nmap(console, connection, target=target, profile=profile, scan_dir=scan_dir)
        return
    if tool_name not in detected_tools:
        console.print(f"[bold red]{tool_name} is not installed or not on PATH.[/bold red]")
        return
    run_projectdiscovery_tool(console, connection, tool_name=tool_name, target=target, scan_dir=scan_dir)


def _prompt_chained_workflow(console: Console, connection, scan_dir: Path) -> None:
    target = Prompt.ask("[bold cyan]Workflow target domain[/bold cyan]")
    run_chained_recon_workflow(console, connection, target=target, scan_dir=scan_dir)


def _prompt_db_view(
    console: Console,
    connection,
    checklist_items: list[dict[str, str | int | None]],
    *,
    show_targets: bool,
) -> None:
    view = Prompt.ask(
        "[bold cyan]DB view[/bold cyan]",
        choices=["tables", "checklist", "scans", "findings"],
        default="scans",
    )
    limit = 20
    if view in {"scans", "findings"}:
        limit = int(Prompt.ask("[bold cyan]Limit[/bold cyan]", default="20"))
    run_db_view(
        console,
        connection,
        view,
        checklist_items,
        limit=limit,
        show_targets=show_targets,
    )


def _prompt_export(console: Console, connection) -> None:
    entity = Prompt.ask("[bold cyan]Export entity[/bold cyan]", choices=["scans", "findings"], default="scans")
    output = Path(Prompt.ask("[bold cyan]Output file[/bold cyan]", default=f"{entity}.json"))
    export_format = Prompt.ask("[bold cyan]Format[/bold cyan]", choices=["json", "csv"], default="json")
    limit = int(Prompt.ask("[bold cyan]Limit[/bold cyan]", default="50"))
    run_export(
        console,
        connection,
        entity=entity,
        output=output,
        export_format=export_format,
        limit=limit,
    )
