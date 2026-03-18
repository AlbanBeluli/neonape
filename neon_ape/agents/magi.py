from __future__ import annotations

import sys

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt

from neon_ape.commands.tools import run_checklist_step
from neon_ape.db.repository import checklist_summary, get_checklist_item, list_checklist_items, mark_checklist_item_status
from neon_ape.ui.layout import build_magi_execution_table


def run_magi_checklist(
    console: Console,
    connection,
    *,
    config,
    detected_tools: dict[str, str],
    target: str,
    auto: bool = False,
    prompt_manual: bool = True,
    silent_completed: bool = False,
) -> bool:
    items = list_checklist_items(connection)
    if not items:
        return False

    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold orange3]{task.description}[/bold orange3]"),
        BarColumn(bar_width=28, style="red", complete_style="orange3"),
        console=console,
    ) as progress:
        task = progress.add_task("MAGI is synchronizing...", total=len(items))
        for item in items:
            step_order = int(item.get("step_order", 0) or 0)
            current = next((entry for entry in list_checklist_items(connection) if int(entry.get("step_order", 0) or 0) == step_order), item)
            progress.update(task, description=f"MAGI step {step_order}: {item.get('title', '')}")
            if not silent_completed:
                console.print(build_magi_execution_table(list_checklist_items(connection), active_step=step_order))
            if str(current.get("status", "todo")) == "done":
                if not silent_completed:
                    console.print(f"[bold green]Checklist step {step_order} already done from existing evidence.[/bold green]")
                progress.advance(task)
                continue

            action = _choose_action(console, current, auto=auto, prompt_manual=prompt_manual)
            if action == "run":
                _, action_tool = run_checklist_step(
                    console,
                    connection,
                    checklist_step=step_order,
                    target=target,
                    detected_tools=detected_tools,
                    scan_dir=config.scan_dir,
                    profile="service_scan",
                    auto_setup=auto,
                )
                updated = get_checklist_item(connection, step_order) or {}
                if str(updated.get("status", "todo")) not in {"done"}:
                    mark_checklist_item_status(connection, step_order, "todo")
                if action_tool is None and not current.get("action_tool"):
                    mark_checklist_item_status(connection, step_order, "done")
                    console.print(f"[bold cyan]Checklist step {step_order} completed.[/bold cyan]")
            elif action == "done":
                mark_checklist_item_status(connection, step_order, "done")
                if not silent_completed:
                    console.print(f"[bold cyan]Checklist step {step_order} marked done.[/bold cyan]")
            else:
                mark_checklist_item_status(connection, step_order, "todo")
                if not silent_completed:
                    console.print(f"[bold yellow]Checklist step {step_order} left as todo.[/bold yellow]")
            progress.advance(task)

    summary = checklist_summary(connection)
    complete = int(summary.get("complete_count", 0) or 0)
    total = int(summary.get("item_count", 0) or 0)
    console.print(f"[bold orange3]MAGI status:[/bold orange3] {complete}/{total} done")
    if complete == total and total > 0:
        console.print("[bold green]MAGI Checklist complete.[/bold green]")
        return True
    return False


def _choose_action(console: Console, item: dict[str, object], *, auto: bool, prompt_manual: bool) -> str:
    is_manual = not item.get("action_tool")
    if auto:
        if is_manual:
            if prompt_manual and sys.stdin.isatty():
                return "done" if Confirm.ask(
                    f"Mark manual MAGI step {item.get('step_order')} done?",
                    default=True,
                ) else "skip"
            return "done"
        return "run"

    default_choice = "run"
    prompt = "Run now?"
    choices = ["run", "skip", "done"]
    if not sys.stdin.isatty():
        return default_choice
    console.print(
        f"[bold red]MELCHIOR[/bold red] recommends: [bold]{item.get('title', '')}[/bold]\n"
        f"[bold orange3]Command:[/bold orange3] {item.get('example_command', '-')}"
    )
    return Prompt.ask(
        f"[bold cyan]{prompt}[/bold cyan]",
        choices=choices,
        default=default_choice,
        show_choices=True,
    )
