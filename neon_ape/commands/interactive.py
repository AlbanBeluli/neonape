from __future__ import annotations

from getpass import getpass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from neon_ape.commands.db import run_db_view
from neon_ape.commands.notes import run_add_note, run_list_notes, run_view_note
from neon_ape.commands.review import run_review
from neon_ape.commands.tools import (
    run_chained_recon_workflow,
    run_checklist_step,
    run_gobuster,
    run_nmap,
    run_projectdiscovery_tool,
)
from neon_ape.commands.transfer import run_export
from neon_ape.db.repository import checklist_summary, list_checklist_items, list_note_headers, recent_scans
from neon_ape.ui.layout import build_checklist_table, build_interactive_actions, build_main_menu
from neon_ape.ui.views import build_landing_panel, build_missing_tools_panel, build_quickstart_table, build_scans_table, build_status_table, build_welcome_panel
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
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "q"],
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
            last_summary = _prompt_review(console, connection)
            continue
        if choice == "9":
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
    scans = recent_scans(connection, limit=5)
    console.print(build_main_menu())
    console.print(build_status_table(checklist, config.db_path, detected_tools))
    if not scans:
        console.print(build_welcome_panel())
    console.print(build_landing_panel(config.data_dir, checklist_items))
    if last_summary:
        console.print(Panel.fit(last_summary, title="Last Action", style=section_style("accent")))
    console.print(build_quickstart_table())
    console.print(build_interactive_actions())
    console.print(
        build_scans_table(
            scans,
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
    step_value = _ask_text(console, "Checklist step")
    if step_value is None:
        return profile, "Returned from checklist step selection."
    target = _ask_text(console, "Target")
    if target is None:
        return profile, "Returned from checklist step selection."
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
        choices=["nmap", "subfinder", "assetfinder", "amass", "dnsx", "httpx", "naabu", "nuclei", "katana", "gobuster", "b"],
        default="nmap",
    )
    if tool_name == "b":
        return "Returned from tool selection."
    target = _ask_text(console, "Target")
    if target is None:
        return "Returned from tool selection."
    if tool_name == "nmap":
        profile = Prompt.ask(
            "[bold cyan]Nmap profile[/bold cyan]",
            choices=["host_discovery", "service_scan", "aggressive", "b"],
            default="service_scan",
        )
        if profile == "b":
            return "Returned from tool selection."
        success = run_nmap(console, connection, target=target, profile=profile, scan_dir=scan_dir)
        _pause(console)
        return f"Ran nmap:{profile} against {target}. Status: {'success' if success else 'failed'}."
    if tool_name not in detected_tools:
        console.print(build_missing_tools_panel([tool_name]))
        _pause(console)
        return f"{tool_name} is not installed."
    if tool_name == "gobuster":
        success = run_gobuster(console, connection, target=target, scan_dir=scan_dir)
        _pause(console)
        return f"Ran gobuster against {target}. Status: {'success' if success else 'failed'}."
    success = run_projectdiscovery_tool(console, connection, tool_name=tool_name, target=target, scan_dir=scan_dir)
    _pause(console)
    return f"Ran {tool_name} against {target}. Status: {'success' if success else 'failed'}."


def _prompt_chained_workflow(console: Console, connection, scan_dir: Path) -> str:
    workflow = Prompt.ask(
        "[bold cyan]Workflow[/bold cyan]",
        choices=["pd_chain", "pd_web_chain", "light_recon", "deep_recon", "js_web_chain", "b"],
        default="pd_chain",
    )
    if workflow == "b":
        return "Returned from workflow selection."
    target = _ask_text(console, "Workflow target domain")
    if target is None:
        return "Returned from workflow selection."
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
        choices=["tables", "checklist", "scans", "findings", "domain", "b"],
        default="scans",
    )
    if view == "b":
        return
    limit = 20
    domain_target = None
    if view == "domain":
        domain_target = _ask_text(console, "Domain or target")
        if domain_target is None:
            return
    if view in {"scans", "findings", "domain"}:
        limit_value = _ask_text(console, "Limit", default="20")
        if limit_value is None:
            return
        try:
            limit = int(limit_value)
        except ValueError:
            console.print("[bold red]Limit must be a number.[/bold red]")
            _pause(console)
            return
    run_db_view(
        console,
        connection,
        view,
        checklist_items,
        limit=limit,
        domain_target=domain_target,
        show_targets=show_targets,
    )
    _pause(console)


def _prompt_export(console: Console, connection) -> None:
    entity = Prompt.ask("[bold cyan]Export entity[/bold cyan]", choices=["scans", "findings", "b"], default="scans")
    if entity == "b":
        return
    output_value = _ask_text(console, "Output file", default=f"{entity}.json")
    if output_value is None:
        return
    output = Path(output_value)
    export_format = Prompt.ask("[bold cyan]Format[/bold cyan]", choices=["json", "csv", "b"], default="json")
    if export_format == "b":
        return
    limit_value = _ask_text(console, "Limit", default="50")
    if limit_value is None:
        return
    try:
        limit = int(limit_value)
    except ValueError:
        console.print("[bold red]Limit must be a number.[/bold red]")
        _pause(console)
        return
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
    action = Prompt.ask("[bold cyan]Notes[/bold cyan]", choices=["list", "add", "view", "b"], default="list")
    if action == "b":
        return "Returned from notes menu."
    if action == "list":
        notes = list_note_headers(connection)
        run_list_notes(console, notes)
        _pause(console)
        return f"Viewed {len(notes)} encrypted note headers."
    passphrase = _ask_secret("Notes passphrase")
    if passphrase is None:
        return "Returned from notes menu."
    if action == "add":
        target = _ask_text(console, "Target", default="")
        if target is None:
            return "Returned from notes menu."
        title = _ask_text(console, "Title")
        if title is None:
            return "Returned from notes menu."
        body = _ask_text(console, "Body")
        if body is None:
            return "Returned from notes menu."
        note_id = run_add_note(console, connection, passphrase=passphrase, title=title, body=body, target=target or None)
        _pause(console)
        return f"Stored encrypted note #{note_id}."
    notes = list_note_headers(connection)
    run_list_notes(console, notes)
    note_id_value = _ask_text(console, "Note ID")
    if note_id_value is None:
        return "Returned from notes menu."
    try:
        note_id = int(note_id_value)
    except ValueError:
        console.print("[bold red]Note ID must be a number.[/bold red]")
        _pause(console)
        return "Note view input was invalid."
    run_view_note(console, connection, passphrase=passphrase, note_id=note_id)
    _pause(console)
    return f"Viewed note #{note_id}."


def _prompt_review(console: Console, connection) -> str:
    target = _ask_text(console, "Review target")
    if target is None:
        return "Returned from review summary."
    limit_value = _ask_text(console, "Limit", default="20")
    if limit_value is None:
        return "Returned from review summary."
    try:
        limit = int(limit_value)
    except ValueError:
        console.print("[bold red]Limit must be a number.[/bold red]")
        _pause(console)
        return "Review limit input was invalid."
    run_review(console, connection, target=target, limit=limit)
    _pause(console)
    return f"Reviewed {target}."


def _pause(console: Console) -> None:
    console.input("[bold cyan]Press Enter to continue[/bold cyan]")


def _ask_text(console: Console, label: str, default: str | None = None) -> str | None:
    value = console.input(f"[bold cyan]{label}[/bold cyan] (or `b` to go back){_default_suffix(default)}: ").strip()
    if not value and default is not None:
        return default
    if value.lower() in {"b", "back"}:
        return None
    return value


def _ask_secret(label: str) -> str | None:
    value = getpass(f"{label} (or b to go back): ").strip()
    if value.lower() in {"b", "back"}:
        return None
    return value


def _default_suffix(default: str | None) -> str:
    if default is None:
        return ""
    return f" [default: {default}]"
