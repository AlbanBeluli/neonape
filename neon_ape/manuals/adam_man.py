from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from neon_ape.ui.ascii import ADAM_BANNER, MISSION_COMPLETE_BANNER


def build_adam_manual() -> Panel:
    content = Group(
        Panel.fit(
            f"{ADAM_BANNER}\n\n[bold red]ADAM OPERATOR MANUAL[/bold red]\n"
            "[bold orange3]The First Angel: autonomous recon, Angel Eyes review, Obsidian sync, MAGI follow-through.[/bold orange3]",
            title="Adam",
            style="bold red",
        ),
        _adam_synopsis(),
        _adam_flow(),
        _adam_live_steps(),
        _adam_autoresearch(),
        _adam_voice(),
        _adam_examples(),
        _adam_best_practices(),
    )
    return Panel(content, title="Operator Manual: Adam", border_style="red")


def _adam_synopsis() -> Group:
    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold red", no_wrap=True)
    body.add_column()
    body.add_row("NAME", "neonape man adam - dedicated Adam workflow manual")
    body.add_row("RUN", "neonape adam --target example.com")
    body.add_row("RESULT", "Daily report folder + Obsidian export + PDF + MAGI checklist status")
    return Group(Rule("NAME / SYNOPSIS", style="red"), body)


def _adam_flow() -> Group:
    table = Table(title="Adam Workflow", expand=False)
    table.add_column("Stage", style="bold red")
    table.add_column("Action")
    table.add_row("1", "subfinder discovers scoped subdomains")
    table.add_row("2", "httpx validates live web targets")
    table.add_row("3", "katana crawls reachable paths")
    table.add_row("4", "gobuster reviews exposed directories and sensitive paths")
    table.add_row("5", "nuclei runs a bounded live triage pass")
    table.add_row("6", "Angel Eyes scores web exposure risk")
    table.add_row("7", "LLM triage writes defensive review context")
    table.add_row("8", "Obsidian export writes the markdown report set")
    table.add_row("9", "MAGI checklist prompts run/skip/done decisions")
    return Group(Rule("WORKFLOW", style="red"), table)


def _adam_live_steps() -> Group:
    return Group(
        Rule("LIVE STEPS", style="red"),
        Panel.fit(
            "Adam streams progress live with Rich progress bars and Eva-style stage text.\n\n"
            "Typical live messages:\n"
            "- `Adam is awakening Unit-01...`\n"
            "- `Hunting Angels across example.com...`\n"
            "- `Discovering subdomains`\n"
            "- `Analyzing the Paths`\n"
            "- `Loading MAGI checklist sequence...`",
            border_style="orange3",
        ),
    )


def _adam_voice() -> Group:
    return Group(
        Rule("VOICE & DAILY REPORTS", style="red"),
        Panel.fit(
            f"{MISSION_COMPLETE_BANNER}\n\n"
            "On macOS, Adam uses Daniel for completion voice lines and offers to open the daily report folder in Finder.\n\n"
            "Daily report location:\n"
            "`~/NeonApe-Reports/YYYY-MM-DD-target/`\n\n"
            "Copied artifacts:\n"
            "- `Findings.md`\n"
            "- `Sensitive-Paths.md`\n"
            "- `Review-Summary.md`\n"
            "- `*.pdf` when `--pdf` is used",
            border_style="red",
        ),
    )


def _adam_autoresearch() -> Group:
    table = Table(title="Autoresearch Integration", expand=False)
    table.add_column("Mode", style="bold red")
    table.add_column("Command")
    table.add_column("Result")
    table.add_row("Standalone", "`neonape autoresearch --target magi-checklist`", "Researches one Neon Ape skill and writes backup/improved snapshots + changelog")
    table.add_row("Adam-assisted", "`neonape adam --autoresearch --target example.com`", "Runs Adam first, then autoresearches MAGI Checklist or Angel Eyes")
    table.add_row("Explicit skill", "`neonape adam --autoresearch --autoresearch-target angel-eyes --target example.com`", "Forces Adam to refine a specific post-run skill area")
    table.add_row("Headless", "`neonape autoresearch --target angel-eyes --headless --rounds 100`", "Uses stored defaults, suppresses voice, and sends a macOS terminal-notifier completion message")
    table.add_row("PDF output", "`neonape autoresearch --target angel-eyes --auto --test-target example.com --pdf`", "Writes a PDF summary into the daily report folder")
    return Group(
        Rule("AUTORESEARCH", style="red"),
        table,
        Panel.fit(
            "Autoresearch runs a bounded local loop with an objective evaluation harness: host discovery, sensitive path coverage, top-risk visibility, duplicate grouping, persistence, and export quality.\n\n"
            "The dashboard shows both subjective criteria scores and weighted objective oracle scores, plus a live sparkline graph for each series.\n\n"
            "Persistent skills live under `~/.neonape/skills/<skill>/` with `current.json`, `history/`, and `changelog.md`.\n\n"
            "Use `neonape skill list`, `neonape skill diff <skill>`, and `neonape skill use <skill> --version <timestamp>` to inspect or roll back versions.",
            border_style="orange3",
        ),
    )


def _adam_examples() -> Group:
    table = Table(title="Adam Examples", expand=False)
    table.add_column("Scenario", style="bold red")
    table.add_column("Command")
    table.add_row("Full run", "`neonape adam --target example.com`")
    table.add_row("Full run + PDF", "`neonape adam --target example.com --pdf`")
    table.add_row("Prompt for target", "`neonape adam`")
    table.add_row("Adam + autoresearch", "`neonape adam --autoresearch --target example.com`")
    table.add_row("Headless autoresearch", "`neonape autoresearch --target magi-checklist --rounds 50 --auto`")
    table.add_row("Objective harness", "`neonape autoresearch --target angel-eyes --headless --rounds 50`")
    table.add_row("Status", "`neonape status`")
    table.add_row("Review saved results after run", "`neonape db domain --target example.com`")
    table.add_row("Re-open the docs", "`neonape man adam`")
    return Group(Rule("EXAMPLES", style="red"), table)


def _adam_best_practices() -> Group:
    tips = Table.grid(padding=(0, 1))
    tips.add_column(style="bold red", no_wrap=True)
    tips.add_column()
    tips.add_row("1.", "Use Adam as the primary entrypoint when you want the full local reporting loop.")
    tips.add_row("2.", "Let Adam seed MAGI steps it already completed so you only decide on remaining work.")
    tips.add_row("3.", "Use `--autoresearch` when you want Adam to refine MAGI Checklist or Angel Eyes after a real run.")
    tips.add_row("4.", "Check Obsidian export paths and the daily report folder at the final mission screen.")
    return Group(Rule("BEST PRACTICES", style="red"), tips)
