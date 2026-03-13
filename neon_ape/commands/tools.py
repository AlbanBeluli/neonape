from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from neon_ape.db.repository import get_checklist_item, mark_checklist_item_status, record_scan
from neon_ape.services.validation import validate_target
from neon_ape.tools.nmap import build_nmap_command, execute_nmap, parse_nmap_xml, render_command_preview
from neon_ape.tools.projectdiscovery import (
    build_projectdiscovery_command,
    execute_projectdiscovery,
    parse_projectdiscovery_output,
)
from neon_ape.ui.theme import section_style
from neon_ape.ui.views import build_tool_output_table


def run_checklist_step(
    console: Console,
    connection,
    *,
    checklist_step: int,
    target: str,
    detected_tools: dict[str, str],
    scan_dir: Path,
    profile: str,
) -> tuple[str, str | None]:
    item = get_checklist_item(connection, checklist_step)
    if item is None:
        console.print(f"[bold red]Checklist step {checklist_step} was not found.[/bold red]")
        return profile, None

    action_tool = item.get("action_tool")
    action_profile = item.get("action_profile")
    if not action_tool:
        console.print(
            Panel.fit(
                f"[bold]Step:[/bold] {item['step_order']} {item['title']}\n"
                f"[bold]Guide:[/bold] {item['guide_text']}\n"
                f"[bold]Example:[/bold] {item['example_command']}",
                title="MAGI Checklist",
                style=section_style("accent"),
            )
        )
        console.print("[bold yellow]This checklist item is documentation-only and has no attached tool action.[/bold yellow]")
        return profile, None

    if action_tool not in detected_tools:
        console.print(f"[bold red]{action_tool} is not installed or not on PATH.[/bold red]")
        return profile, None

    console.print(
        Panel.fit(
            f"[bold]Step:[/bold] {item['step_order']} {item['title']}\n"
            f"[bold]Section:[/bold] {item['section_name']}\n"
            f"[bold]Guide:[/bold] {item['guide_text']}\n"
            f"[bold]Example:[/bold] {item['example_command']}",
            title="MAGI Checklist",
            style=section_style("accent"),
        )
    )

    step_profile = str(action_profile or profile)
    if action_tool == "nmap":
        success = run_nmap(console, connection, target=target, profile=step_profile, scan_dir=scan_dir)
        mark_step_outcome(console, connection, checklist_step, success)
        return step_profile, action_tool

    success = run_projectdiscovery_tool(console, connection, tool_name=str(action_tool), target=target, scan_dir=scan_dir)
    mark_step_outcome(console, connection, checklist_step, success)
    return profile, str(action_tool)


def run_nmap(
    console: Console,
    connection,
    *,
    target: str,
    profile: str,
    scan_dir: Path,
) -> bool:
    validated_target = validate_target(target)
    output_xml = scan_dir / f"{validated_target.replace('/', '_')}_{profile}.xml"
    command = build_nmap_command(validated_target, profile, output_xml)

    console.print(
        Panel.fit(
            f"[bold]Profile:[/bold] {profile}\n[bold]Target:[/bold] {validated_target}\n"
            f"[bold]Command:[/bold] {render_command_preview(command)}",
            title="Eva Unit Scanner",
            style=section_style("green"),
        )
    )

    result = execute_nmap(command, validated_target)
    findings = parse_nmap_xml(output_xml)
    record_scan(connection, result, findings)
    console.print(build_tool_output_table("nmap", findings))
    console.print(f"[bold green]nmap exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
    return result.exit_code == 0


def run_projectdiscovery_tool(
    console: Console,
    connection,
    *,
    tool_name: str,
    target: str,
    scan_dir: Path,
) -> bool:
    output_path = scan_dir / f"{tool_name}_{target.replace('/', '_')}.jsonl"
    validated_target, command = build_projectdiscovery_command(tool_name, target, output_path)

    console.print(
        Panel.fit(
            f"[bold]Tool:[/bold] {tool_name}\n[bold]Target:[/bold] {validated_target}\n"
            f"[bold]Command:[/bold] {render_command_preview(command)}",
            title="Angel Enumeration",
            style=section_style("orange"),
        )
    )

    result = execute_projectdiscovery(command, tool_name, validated_target, output_path)
    findings = parse_projectdiscovery_output(tool_name, output_path)
    record_scan(connection, result, findings)
    console.print(build_tool_output_table(tool_name, findings))
    console.print(f"[bold green]{tool_name} exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
    return result.exit_code == 0


def mark_step_outcome(console: Console, connection, step_order: int, success: bool) -> None:
    status = "complete" if success else "in_progress"
    mark_checklist_item_status(connection, step_order, status)
    label = "completed" if success else "left in progress"
    console.print(f"[bold cyan]Checklist step {step_order} {label}.[/bold cyan]")
