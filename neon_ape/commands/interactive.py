from __future__ import annotations

from getpass import getpass
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from neon_ape.commands.config import run_config_command
from neon_ape.commands.db import run_db_view
from neon_ape.commands.notes import run_add_note, run_list_notes, run_view_note
from neon_ape.commands.review import run_review
from neon_ape.commands.update import run_update
from neon_ape.commands.tools import (
    run_chained_recon_workflow,
    run_checklist_step,
    run_gobuster,
    run_nmap,
    run_projectdiscovery_tool,
)
from neon_ape.commands.transfer import run_export
from neon_ape.db.repository import checklist_summary, list_checklist_items, list_note_headers, recent_scans
from neon_ape.obsidian_sync import resolve_vault_path, run_sync as run_obsidian_sync
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
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "q"],
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
            last_summary = _prompt_review(console, connection, config)
            continue
        if choice == "9":
            last_summary = "Screen refreshed."
            continue
        if choice == "10":
            last_summary = _prompt_config(console, config)
            continue
        if choice == "11":
            last_summary = _prompt_update(console, config)
            continue
        if choice == "12":
            last_summary = _prompt_obsidian_sync(console, config)
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
        choices=["tables", "checklist", "scans", "findings", "inventory", "reviews", "notes", "domain", "b"],
        default="scans",
    )
    if view == "b":
        return
    limit = 20
    domain_target = None
    severity = None
    if view == "domain":
        domain_target = _ask_text(console, "Domain or target")
        if domain_target is None:
            return
    if view in {"inventory", "reviews", "notes"}:
        domain_target = _ask_text(console, "Filter target", default="")
        if domain_target is None:
            return
        domain_target = domain_target or None
    if view == "reviews":
        severity = _ask_text(console, "Severity", default="")
        if severity is None:
            return
        severity = severity or None
    if view in {"scans", "findings", "inventory", "reviews", "notes", "domain"}:
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
        finding_type=severity,
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


def _prompt_review(console: Console, connection, config) -> str:
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
    llm_triage = Prompt.ask("[bold cyan]Local LLM triage[/bold cyan]", choices=["y", "n"], default="n") == "y"
    web_paths_only = Prompt.ask("[bold cyan]Focus on Angel Eyes web exposure review[/bold cyan]", choices=["y", "n"], default="y") == "y"
    llm_provider = config.llm_provider
    llm_model = config.llm_model
    if llm_triage:
        llm_provider = Prompt.ask("[bold cyan]LLM provider[/bold cyan]", choices=["cline", "ollama"], default=config.llm_provider)
        if llm_provider == "ollama":
            llm_model_value = _ask_text(console, "LLM model", default=config.llm_model)
            if llm_model_value is None:
                return "Returned from review summary."
            llm_model = llm_model_value
    run_review(
        console,
        connection,
        target=target,
        limit=limit,
        llm_triage=llm_triage,
        llm_provider=llm_provider,
        llm_model=llm_model,
        web_paths_only=web_paths_only,
    )
    _pause(console)
    suffix = f" with local triage via {llm_provider}:{llm_model if llm_provider == 'ollama' else 'cline'}" if llm_triage else ""
    focus = " (Angel Eyes)" if web_paths_only else ""
    return f"Reviewed {target}{focus}{suffix}."


def _prompt_config(console: Console, config) -> str:
    action = Prompt.ask("[bold cyan]Config[/bold cyan]", choices=["show", "init", "set", "b"], default="show")
    if action == "b":
        return "Returned from config menu."
    if action in {"show", "init"}:
        run_config_command(console, config, action=action)
        _pause(console)
        return f"Config {action} completed."
    key = _ask_text(console, "Config key")
    if key is None:
        return "Returned from config menu."
    value = _ask_text(console, "Config value")
    if value is None:
        return "Returned from config menu."
    run_config_command(console, config, action="set", key=key, value=value)
    _pause(console)
    return f"Updated config key `{key}`."


def _prompt_update(console: Console, config) -> str:
    action = Prompt.ask("[bold cyan]Update Neon Ape now?[/bold cyan]", choices=["y", "n"], default="n")
    if action != "y":
        return "Update cancelled."
    run_update(console, config, assume_yes=True)
    _pause(console)
    return "Triggered install-managed update."


def _prompt_obsidian_sync(console: Console, config) -> str:
    target_note = _ask_text(console, "Target note", default="Pentests/example.com/Target.md")
    if target_note is None:
        return "Returned from Obsidian sync."
    resolved_vault = resolve_vault_path(None, config)
    if resolved_vault is None:
        console.print(
            Panel.fit(
                "No Obsidian vault could be resolved.\n\n"
                "Set one once with:\n"
                "`neonape config set obsidian_vault_path \"/path/to/your vault\"`\n\n"
                "or rerun this action and enter the vault path directly,\n"
                "or launch Neon Ape from inside an existing Obsidian vault.",
                title="Obsidian Vault Needed",
                style=section_style("orange"),
            )
        )
        _pause(console)
        return "Obsidian sync needs a configured or discoverable vault path."
    console.print(
        Panel.fit(
            f"Using Obsidian vault:\n{resolved_vault}\n\n"
            "Interactive sync uses safe defaults:\n"
            "- dry-run preview\n"
            "- no workflow execution\n"
            "- no note auto-open",
            title="Obsidian Sync",
            style=section_style("accent"),
        )
    )
    status = run_obsidian_sync(
        SimpleNamespace(
            vault_path=None,
            target_note=target_note,
            notes_passphrase=None,
            limit=200,
            open=False,
            dry_run=True,
            skip_run=True,
        ),
        console=console,
    )
    _pause(console)
    return f"Obsidian preview {'completed' if status == 0 else 'failed'} for `{target_note}`."


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
