from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from neon_ape.ui.theme import section_style


def display_runtime_path(path: Path) -> str:
    home = Path.home()
    try:
        return f"~/{path.relative_to(home)}"
    except ValueError:
        return path.name


def build_status_table(checklist: dict[str, str | int], db_path: Path, detected_tools: dict[str, str]) -> Table:
    table = Table(title="AT Field Status", expand=False)
    table.add_column("Signal", style="bold")
    table.add_column("Value")
    table.add_row(
        "Checklist Progress",
        f"{checklist.get('complete_count', 0)}/{checklist.get('item_count', 0)}",
    )
    table.add_row("Runtime Data", "local-only")
    table.add_row("Detected Tools", str(len(detected_tools)))
    return table


def build_findings_table(findings: list[dict[str, str]]) -> Table:
    table = Table(title="Scan Findings", expand=False)
    table.add_column("Type", style="bold")
    table.add_column("Host/Key")
    table.add_column("Value")
    if not findings:
        table.add_row("info", "-", "No parsed findings")
        return table
    for finding in findings:
        table.add_row(
            finding.get("type", "unknown"),
            finding.get("host", finding.get("key", "-")),
            finding.get("value", "-"),
        )
    return table


def build_tool_output_table(tool_name: str, findings: list[dict[str, str]]) -> Table:
    if tool_name == "httpx":
        return build_httpx_table(findings)
    if tool_name == "naabu":
        return build_naabu_table(findings)
    if tool_name == "dnsx":
        return build_dnsx_table(findings)
    if tool_name == "nuclei":
        return build_nuclei_table(findings)
    return build_findings_table(findings)


def build_httpx_table(findings: list[dict[str, str]]) -> Table:
    table = Table(title="HTTPX Findings", expand=False)
    table.add_column("URL", style="bold")
    table.add_column("Code")
    table.add_column("Title")
    table.add_column("Tech")
    table.add_column("Server")
    table.add_column("IP")
    if not findings:
        table.add_row("-", "-", "-", "-", "-", "-")
        return table
    for finding in findings:
        table.add_row(
            finding.get("host", "-"),
            finding.get("status_code", "-"),
            finding.get("title", "-"),
            finding.get("technologies", "-"),
            finding.get("webserver", "-"),
            finding.get("ip", "-"),
        )
    return table


def build_dnsx_table(findings: list[dict[str, str]]) -> Table:
    table = Table(title="DNSX Findings", expand=False)
    table.add_column("Host", style="bold")
    table.add_column("Record")
    table.add_column("Value")
    if not findings:
        table.add_row("-", "-", "-")
        return table
    for finding in findings:
        table.add_row(
            finding.get("host", "-"),
            finding.get("record_type", finding.get("key", "-")),
            finding.get("value", "-"),
        )
    return table


def build_naabu_table(findings: list[dict[str, str]]) -> Table:
    table = Table(title="Naabu Findings", expand=False)
    table.add_column("Host", style="bold")
    table.add_column("Port")
    table.add_column("Proto")
    if not findings:
        table.add_row("-", "-", "-")
        return table
    for finding in findings:
        table.add_row(
            finding.get("host", "-"),
            finding.get("key", "-"),
            finding.get("value", "-"),
        )
    return table


def build_nuclei_table(findings: list[dict[str, str]]) -> Table:
    table = Table(title="Nuclei Findings", expand=False)
    table.add_column("Matched", style="bold")
    table.add_column("Severity")
    table.add_column("Template")
    table.add_column("Name")
    if not findings:
        table.add_row("-", "-", "-", "-")
        return table
    for finding in findings:
        table.add_row(
            finding.get("host", "-"),
            finding.get("severity", "-"),
            finding.get("template_id", finding.get("key", "-")),
            finding.get("name", "-"),
        )
    return table


def build_tables_table(tables: list[str]) -> Table:
    table = Table(title="Database Tables", expand=False)
    table.add_column("Table", style="bold")
    if not tables:
        table.add_row("-")
        return table
    for name in tables:
        table.add_row(name)
    return table


def build_landing_panel(data_dir: Path, checklist_items: list[dict[str, str | int | None]]) -> Panel:
    complete = sum(1 for item in checklist_items if item.get("status") == "complete")
    pending_items = [item for item in checklist_items if item.get("status") != "complete"]
    next_steps = "\n".join(
        f"{item.get('step_order')}. {item.get('title')}"
        for item in pending_items[:3]
    ) or "All checklist items completed."
    body = (
        f"[bold green]Ready.[/bold green] Runtime data lives under [bold]{display_runtime_path(data_dir)}[/bold]\n"
        f"[bold]Checklist progress:[/bold] {complete}/{len(checklist_items)} complete\n"
        f"[bold]Next steps:[/bold]\n{next_steps}"
    )
    return Panel.fit(body, title="Launch Overview", style=section_style("green"))


def build_quickstart_table() -> Table:
    table = Table(title="Quick Start", expand=False)
    table.add_column("Action", style="bold")
    table.add_column("Command")
    table.add_row("Open interactive shell", "neonape")
    table.add_row("Show checklist", "neonape --show-checklist --init-only")
    table.add_row("Run next recon step", "neonape --checklist-step 2 --target example.com")
    table.add_row("Run chained recon", "neonape --workflow pd_chain --target example.com")
    table.add_row("Inspect scans", "neonape db scans")
    table.add_row("Inspect findings", "neonape db findings")
    table.add_row("Show targets", "neonape --show-targets")
    table.add_row("Uninstall", "neonape uninstall")
    return table


def build_scans_table(scans: list[dict[str, str | int | None]], *, mask_targets: bool = False) -> Table:
    table = Table(title="Recent Scans", expand=False)
    table.add_column("ID", style="bold")
    table.add_column("Tool")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Finished")
    if not scans:
        table.add_row("-", "-", "-", "-", "-")
        return table
    for scan in scans:
        table.add_row(
            str(scan.get("id", "-")),
            str(scan.get("tool_name", "-")),
            _mask_target(str(scan.get("target", "-"))) if mask_targets else str(scan.get("target", "-")),
            str(scan.get("status", "-")),
            str(scan.get("finished_at", "-")),
        )
    return table


def build_recent_findings_table(findings: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="Recent Findings", expand=False)
    table.add_column("ID", style="bold")
    table.add_column("Run")
    table.add_column("Type")
    table.add_column("Key")
    table.add_column("Value")
    if not findings:
        table.add_row("-", "-", "-", "-", "-")
        return table
    for finding in findings:
        table.add_row(
            str(finding.get("id", "-")),
            str(finding.get("scan_run_id", "-")),
            str(finding.get("finding_type", "-")),
            str(finding.get("key", "-")),
            str(finding.get("value", "-")),
        )
    return table


def build_notes_table(notes: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="Encrypted Notes", expand=False)
    table.add_column("ID", style="bold")
    table.add_column("Target")
    table.add_column("Title")
    table.add_column("Updated")
    if not notes:
        table.add_row("-", "-", "-", "-")
        return table
    for note in notes:
        table.add_row(
            str(note.get("id", "-")),
            str(note.get("target", "-") or "-"),
            str(note.get("title", "-")),
            str(note.get("updated_at", "-")),
        )
    return table


def build_domain_summary_panel(target: str, overview: dict[str, list[dict[str, str | int | None]]]) -> Panel:
    body = (
        f"[bold]Query:[/bold] {target}\n"
        f"[bold]Scans:[/bold] {len(overview.get('scans', []))}\n"
        f"[bold]Findings:[/bold] {len(overview.get('findings', []))}\n"
        f"[bold]Inventory:[/bold] {len(overview.get('inventory', []))}\n"
        f"[bold]Review Matches:[/bold] {len(overview.get('reviews', []))}\n"
        f"[bold]Notes:[/bold] {len(overview.get('notes', []))}"
    )
    return Panel.fit(body, title="Domain Overview", style=section_style("accent"))


def build_inventory_table(rows: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="Service Inventory", expand=False)
    table.add_column("Host", style="bold")
    table.add_column("Port")
    table.add_column("Proto")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")
    if not rows:
        table.add_row("-", "-", "-", "-", "-", "-")
        return table
    for row in rows:
        table.add_row(
            str(row.get("host", "-")),
            str(row.get("port", "-")),
            str(row.get("protocol", "-")),
            str(row.get("service_name", "-") or "-"),
            str(row.get("product", "-") or "-"),
            str(row.get("version", "-") or "-"),
        )
    return table


def build_review_findings_table(rows: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="Review Matches", expand=False)
    table.add_column("Host", style="bold")
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("Key")
    table.add_column("Title")
    if not rows:
        table.add_row("-", "-", "-", "-", "-")
        return table
    for row in rows:
        table.add_row(
            str(row.get("host", "-")),
            str(row.get("severity", "-")),
            str(row.get("source_tool", "-")),
            str(row.get("finding_key", "-")),
            str(row.get("title", "-")),
        )
    return table


def build_review_summary_panel(target: str, overview: dict[str, list[dict[str, str | int | None]]]) -> Panel:
    severities = [str(item.get("severity", "")).lower() for item in overview.get("reviews", [])]
    critical = sum(1 for value in severities if value == "critical")
    high = sum(1 for value in severities if value == "high")
    medium = sum(1 for value in severities if value == "medium")
    body = (
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Inventory Entries:[/bold] {len(overview.get('inventory', []))}\n"
        f"[bold]Critical:[/bold] {critical}\n"
        f"[bold]High:[/bold] {high}\n"
        f"[bold]Medium:[/bold] {medium}"
    )
    return Panel.fit(body, title="Smart Review", style=section_style("orange"))


def _mask_target(value: str) -> str:
    if value in {"", "-"}:
        return value
    if len(value) <= 6:
        return "***"
    return f"{value[:2]}***{value[-2:]}"
