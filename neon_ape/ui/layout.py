from rich.panel import Panel
from rich.table import Table


def build_main_menu() -> Table:
    table = Table(title="Main Menu", expand=False)
    table.add_column("Section", style="bold")
    table.add_column("Purpose")
    table.add_row("Eva Unit Scanner", "Authorized active scanning and service review")
    table.add_row("Angel Enumeration", "Passive recon, DNS, WHOIS, and note capture")
    table.add_row("MAGI Checklist", "Phase-based workflow with progress tracking")
    table.add_row("AT Field Protector", "Encryption, storage, and local safety checks")
    table.add_row("Entry Plug Scripts", "Restricted custom Python automation")
    return table


def build_checklist_table(items: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="MAGI Checklist", expand=False)
    table.add_column("Step", style="bold")
    table.add_column("Section")
    table.add_column("Title")
    table.add_column("Action")
    table.add_column("Status")
    for item in items:
        action = item.get("action_tool") or "-"
        profile = item.get("action_profile") or "-"
        action_label = action if profile == "-" else f"{action}:{profile}"
        table.add_row(
            str(item.get("step_order", "")),
            str(item.get("section_name", "")),
            str(item.get("title", "")),
            action_label,
            str(item.get("status", "pending")),
        )
    return table


def build_interactive_actions() -> Table:
    table = Table(title="Interactive Actions", expand=False)
    table.add_column("Key", style="bold")
    table.add_column("Action")
    table.add_row("1", "Show checklist")
    table.add_row("2", "Run checklist step")
    table.add_row("3", "Run a single tool")
    table.add_row("4", "Run chained recon workflow")
    table.add_row("5", "Open DB views")
    table.add_row("6", "Export scans or findings")
    table.add_row("7", "Encrypted notes")
    table.add_row("8", "Review summary")
    table.add_row("9", "Refresh screen")
    table.add_row("10", "Config")
    table.add_row("11", "Update Neon Ape")
    table.add_row("12", "Obsidian sync")
    table.add_row("q", "Exit")
    return table


def build_angel_eyes_panel(summary: dict[str, object]) -> Panel:
    items = summary.get("items", []) if isinstance(summary, dict) else []
    grouped = summary.get("grouped", {}) if isinstance(summary, dict) else {}
    counts = {
        "Secrets": len(grouped.get("Secrets", [])) if isinstance(grouped, dict) else 0,
        "Logs": len(grouped.get("Logs", [])) if isinstance(grouped, dict) else 0,
        "Repo Metadata": len(grouped.get("Repo Metadata", [])) if isinstance(grouped, dict) else 0,
        "Server Config": len(grouped.get("Server Config", [])) if isinstance(grouped, dict) else 0,
    }
    highest = max((int(item.get("risk_score", 0) or 0) for item in items), default=0) if isinstance(items, list) else 0
    body = (
        f"[bold]Flagged Paths:[/bold] {len(items) if isinstance(items, list) else 0}\n"
        f"[bold red]Secrets:[/bold red] {counts['Secrets']}\n"
        f"[bold yellow]Logs:[/bold yellow] {counts['Logs']}\n"
        f"[bold magenta]Repo Metadata:[/bold magenta] {counts['Repo Metadata']}\n"
        f"[bold cyan]Server Config:[/bold cyan] {counts['Server Config']}\n"
        f"[bold]Highest Risk:[/bold] {highest}\n"
        "[italic]Generate review to produce defensive triage from Angel Eyes evidence.[/italic]"
    )
    return Panel.fit(body, title="Angel Eyes - Web Exposure Review", style="bold magenta")
