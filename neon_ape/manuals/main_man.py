from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from neon_ape.manuals.adam_man import build_adam_manual
from neon_ape.manuals.checklist_man import build_checklist_manual
from neon_ape.ui.ascii import ADAM_BANNER


def render_manual(console: Console, *, topic: str = "main") -> None:
    if topic == "adam":
        console.print(build_adam_manual())
        return
    if topic == "checklist":
        console.print(build_checklist_manual())
        return
    console.print(build_main_manual())


def build_main_manual() -> Panel:
    content = Group(
        Panel.fit(
            f"{ADAM_BANNER}\n\n[bold magenta]NEON APE OPERATOR MANUAL[/bold magenta]\n"
            "[bold orange3]Eva-grade local operator workflow for Adam, MAGI, Angel Eyes, and encrypted reporting.[/bold orange3]",
            title="Manual Header",
            style="bold magenta",
        ),
        _section_name_synopsis(),
        _section_description(),
        _section_adam(),
        _section_commands(),
        _section_examples(),
        _section_voice_and_reports(),
        _section_security(),
        _section_tips(),
    )
    return Panel(content, title="Operator Manual", border_style="magenta")


def _section_name_synopsis() -> Group:
    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold magenta", no_wrap=True)
    body.add_column()
    body.add_row("NAME", "neonape - local-only Evangelion-inspired recon and review console")
    body.add_row("SYNOPSIS", "neonape adam --target example.com")
    body.add_row("", "neonape man adam")
    body.add_row("", "neonape man checklist")
    return Group(Rule("NAME / SYNOPSIS", style="magenta"), body)


def _section_description() -> Group:
    return Group(
        Rule("DESCRIPTION", style="magenta"),
        Panel.fit(
            "Neon Ape keeps the workflow local: Adam orchestrates recon, Angel Eyes scores sensitive web paths, "
            "MAGI tracks checklist progress, and the report/export flow stays on disk under your control.\n\n"
            "Use this manual as the operator entrypoint. Use the dedicated Adam and checklist pages when you need narrower guidance.",
            border_style="orange3",
        ),
    )


def _section_adam() -> Group:
    return Group(
        Rule("MOST IMPORTANT COMMAND", style="magenta"),
        Panel.fit(
            "[bold red]neonape adam --target example.com[/bold red]\n"
            "Runs Adam end-to-end: subdomain discovery, live host review, web path analysis, Angel Eyes triage, "
            "Obsidian export, MAGI checklist sequencing, and macOS voice/report handling.",
            title="Adam",
            border_style="red",
        ),
    )


def _section_commands() -> Group:
    table = Table(title="Available Commands", expand=False)
    table.add_column("Group", style="bold magenta")
    table.add_column("Command")
    table.add_column("Purpose")
    table.add_row("Adam", "`neonape adam` / `neonape man adam`", "Run Adam or open Adam-specific operator docs")
    table.add_row("Workflows", "`neonape --workflow pd_web_chain --target example.com`", "Run chained recon quickly")
    table.add_row("Review / Angel Eyes", "`neonape review --target example.com --web-paths`", "See sensitive path scoring and review output")
    table.add_row("MAGI Checklist", "`neonape man checklist` / `neonape --show-checklist --init-only`", "Learn or inspect checklist state and actions")
    table.add_row("Database", "`neonape db domain --target example.com`", "Inspect all stored evidence for a target")
    table.add_row("Utilities", "`neonape man` / `neonape update --yes`", "Open the manual or refresh the install")
    return Group(Rule("AVAILABLE COMMANDS", style="magenta"), table)


def _section_examples() -> Group:
    table = Table(title="Detailed Examples", expand=False)
    table.add_column("Scenario", style="bold magenta")
    table.add_column("Command")
    table.add_row("1. Adam full run", "`neonape adam --target stoic.ee`")
    table.add_row("2. Adam operator docs", "`neonape man adam`")
    table.add_row("3. MAGI checklist docs", "`neonape man checklist`")
    table.add_row("4. Angel Eyes review", "`neonape review --target example.com --web-paths`")
    table.add_row("5. Daily report follow-up", "`neonape obsidian --target-note Pentests/example.com/Target.md --skip-run`")
    table.add_row("6. Stored evidence lookup", "`neonape db domain --target example.com`")
    return Group(Rule("DETAILED EXAMPLES", style="magenta"), table)


def _section_voice_and_reports() -> Group:
    return Group(
        Rule("VOICE & REPORTS", style="magenta"),
        Panel.fit(
            "On macOS, Adam can speak completion lines with Daniel and create a daily report folder under "
            "`~/NeonApe-Reports/YYYY-MM-DD-target/`.\n\n"
            "Exports include:\n"
            "- `Findings.md`\n"
            "- `Sensitive-Paths.md`\n"
            "- `Review-Summary.md`\n"
            "- optional Finder open prompt at the end of Adam",
            border_style="orange3",
        ),
    )


def _section_security() -> Group:
    return Group(
        Rule("SECURITY", style="magenta"),
        Panel.fit(
            "Neon Ape is local-only by design.\n"
            "- SQLite-backed local storage\n"
            "- encrypted notes and secrets\n"
            "- subprocess calls use `shell=False`\n"
            "- validated targets and bounded tool wrappers\n"
            "- no exposed HTTP service and no outbound telemetry layer",
            border_style="red",
        ),
    )


def _section_tips() -> Group:
    tips = Table.grid(padding=(0, 1))
    tips.add_column(style="bold magenta", no_wrap=True)
    tips.add_column()
    tips.add_row("1.", "Start with `neonape adam --target example.com` unless you need a narrower workflow.")
    tips.add_row("2.", "Use `neonape man adam` when onboarding an operator to Adam’s end-to-end flow.")
    tips.add_row("3.", "Use `neonape man checklist` to understand MAGI step execution and status handling.")
    tips.add_row("4.", "Use `neonape db domain --target example.com` to verify what was actually stored.")
    tips.add_row("5.", "Set an Obsidian vault once with `neonape config set obsidian_vault_path <path>`.")
    return Group(Rule("TIPS & BEST PRACTICES", style="magenta"), tips)
