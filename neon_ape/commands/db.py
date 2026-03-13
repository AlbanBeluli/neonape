from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from neon_ape.db.repository import list_tables, normalize_batch_history_labels, recent_findings, recent_scans
from neon_ape.ui.layout import build_checklist_table
from neon_ape.ui.views import build_recent_findings_table, build_scans_table, build_tables_table, display_runtime_path


def run_db_view(
    console: Console,
    connection,
    db_command: str | None,
    checklist_items: list[dict[str, str | int | None]],
    *,
    limit: int = 20,
    tool_name: str | None = None,
    finding_type: str | None = None,
    as_json: bool = False,
    show_targets: bool = False,
) -> None:
    if db_command == "tables":
        tables = list_tables(connection)
        _emit(console, tables, build_tables_table(tables), as_json=as_json)
        return
    if db_command == "checklist":
        _emit(console, checklist_items, build_checklist_table(checklist_items), as_json=as_json)
        return
    if db_command == "scans":
        scans = recent_scans(connection, limit=limit, tool_name=tool_name)
        sanitized = _sanitize_scans(scans, show_targets=show_targets)
        _emit(console, sanitized, build_scans_table(sanitized, mask_targets=not show_targets), as_json=as_json)
        return
    if db_command == "findings":
        findings = recent_findings(connection, limit=limit, finding_type=finding_type)
        _emit(console, findings, build_recent_findings_table(findings), as_json=as_json)
        return
    if db_command == "cleanup-history":
        result = normalize_batch_history_labels(connection)
        console.print(
            "[bold green]History cleanup complete.[/bold green] "
            f"scan_runs={result['scan_runs_updated']}, tool_history={result['tool_history_updated']}"
        )
        return
    console.print("[bold red]Unsupported db command.[/bold red]")


def _emit(console: Console, payload, table, *, as_json: bool) -> None:
    if as_json:
        console.print_json(json.dumps(payload))
        return
    console.print(table)


def _sanitize_scans(scans: list[dict[str, str | int | None]], *, show_targets: bool) -> list[dict[str, str | int | None]]:
    sanitized: list[dict[str, str | int | None]] = []
    for scan in scans:
        item = dict(scan)
        raw_output_path = item.get("raw_output_path")
        if isinstance(raw_output_path, str) and raw_output_path:
            item["raw_output_path"] = display_runtime_path(Path(raw_output_path))
        if not show_targets:
            item["target"] = _mask_target(str(item.get("target", "-")))
        sanitized.append(item)
    return sanitized


def _mask_target(value: str) -> str:
    if value in {"", "-"}:
        return value
    if len(value) <= 6:
        return "***"
    return f"{value[:2]}***{value[-2:]}"
