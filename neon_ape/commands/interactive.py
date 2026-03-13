from __future__ import annotations

from getpass import getpass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from neon_ape.commands.db import run_db_view
from neon_ape.commands.notes import run_add_note, run_list_notes, run_view_note
from neon_ape.commands.tools import (
    run_chained_recon_workflow,
    run_checklist_step,
    run_nmap,
    run_projectdiscovery_tool,
)
from neon_ape.commands.transfer import run_export
from neon_ape.db.repository import checklist_summary, list_checklist_items, list_note_headers, recent_scans
from neon_ape.ui.layout import build_checklist_table, build_interactive_actions, build_main_menu
from neon_ape.ui.views import build_landing_panel, build_quickstart_table, build_scans_table, build_status_table
from neon_ape.ui.theme import section_style


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
    last_summary: str | None = None
    while True:
        console.clear()
        checklist = checklist_summary(connection)
        checklist_items = list_checklist_items(connection)
        _render_home(
            console,
            connection,
            config,
            detected_tools,
            checklist,
            checklist_items,
            show_targets=show_targets,
            last_summary=last_summary,
        )

        choice = Prompt.ask(
            "[bold cyan]Select action[/bold cyan]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "q"],
            default="1",
        )
        if choice == "1":
            console.print(build_checklist_table(checklist_items))
            _pause(console)
            continue
        if choice == "2":
            profile, last_summary = _prompt_checklist_step(console, connection, checklist_items, detected_tools, config.scan_dir, profile)
            continue
        if choice == "3":
            last_summary = _prompt_single_tool(console, connection, detected_tools, config.scan_dir)
            continue
        if choice == "4":
            last_summary = _prompt_chained_workflow(console, connection, config.scan_dir)
            continue
        if choice == "5":
            _prompt_db_view(console, connection, checklist_items, show_targets=show_targets)
            last_summary = "Viewed database information."
            continue
        if choice == "6":
            _prompt_export(console, connection)
            last_summary = "Export completed."
            continue
        if choice == "7":
            last_summary = _prompt_notes(console, connection, config)
            continue
        if choice == "8":
            last_summary = "Screen refreshed."
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
    last_summary: str | None,
) -> None:
    console.print(build_main_menu())
    console.print(build_status_table(checklist, config.db_path, detected_tools))
    console.print(build_landing_panel(config.data_dir, checklist_items))
    if last_summary:
        console.print(Panel.fit(last_summary, title="Last Action", style=section_style("accent")))
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
) -> tuple[str, str]:
    console.print(build_checklist_table(checklist_items))
    step_value = Prompt.ask("[bold cyan]Checklist step[/bold cyan]")
    target = Prompt.ask("[bold cyan]Target[/bold cyan]")
    try:
        step_order = int(step_value)
    except ValueError:
        console.print("[bold red]Checklist step must be a number.[/bold red]")
        _pause(console)
        return profile, "Checklist step input was invalid."
    profile, _ = run_checklist_step(
        console,
        connection,
        checklist_step=step_order,
        target=target,
        detected_tools=detected_tools,
        scan_dir=scan_dir,
        profile=profile,
    )
    updated = checklist_summary(connection)
    _pause(console)
    return profile, (
        f"Checklist step {step_order} processed. Progress: "
        f"{updated.get('complete_count', 0)}/{updated.get('item_count', 0)} complete."
    )


def _prompt_single_tool(
    console: Console,
    connection,
    detected_tools: dict[str, str],
    scan_dir: Path,
) -> str:
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
        success = run_nmap(console, connection, target=target, profile=profile, scan_dir=scan_dir)
        _pause(console)
        return f"Ran nmap:{profile} against {target}. Status: {'success' if success else 'failed'}."
    if tool_name not in detected_tools:
        console.print(f"[bold red]{tool_name} is not installed or not on PATH.[/bold red]")
        _pause(console)
        return f"{tool_name} is not installed."
    success = run_projectdiscovery_tool(console, connection, tool_name=tool_name, target=target, scan_dir=scan_dir)
    _pause(console)
    return f"Ran {tool_name} against {target}. Status: {'success' if success else 'failed'}."


def _prompt_chained_workflow(console: Console, connection, scan_dir: Path) -> str:
    workflow = Prompt.ask(
        "[bold cyan]Workflow[/bold cyan]",
        choices=["pd_chain", "pd_web_chain"],
        default="pd_chain",
    )
    target = Prompt.ask("[bold cyan]Workflow target domain[/bold cyan]")
    success = run_chained_recon_workflow(console, connection, target=target, scan_dir=scan_dir, workflow_name=workflow)
    _pause(console)
    return f"Ran {workflow} for {target}. Status: {'success' if success else 'failed'}."


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
    _pause(console)


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
    _pause(console)


def _prompt_notes(console: Console, connection, config) -> str:
    action = Prompt.ask("[bold cyan]Notes[/bold cyan]", choices=["list", "add", "view"], default="list")
    if action == "list":
        notes = list_note_headers(connection)
        run_list_notes(console, notes)
        _pause(console)
        return f"Viewed {len(notes)} encrypted note headers."
    passphrase = getpass("Notes passphrase: ")
    if action == "add":
        target = Prompt.ask("[bold cyan]Target[/bold cyan]", default="")
        title = Prompt.ask("[bold cyan]Title[/bold cyan]")
        body = Prompt.ask("[bold cyan]Body[/bold cyan]")
        note_id = run_add_note(console, connection, passphrase=passphrase, title=title, body=body, target=target or None)
        _pause(console)
        return f"Stored encrypted note #{note_id}."
    notes = list_note_headers(connection)
    run_list_notes(console, notes)
    note_id = int(Prompt.ask("[bold cyan]Note ID[/bold cyan]"))
    run_view_note(console, connection, passphrase=passphrase, note_id=note_id)
    _pause(console)
    return f"Viewed note #{note_id}."


def _pause(console: Console) -> None:
    console.input("[bold cyan]Press Enter to continue[/bold cyan]")
