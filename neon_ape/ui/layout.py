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
