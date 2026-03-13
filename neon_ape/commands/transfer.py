from __future__ import annotations

import csv
import json
from pathlib import Path

from rich.console import Console

from neon_ape.db.repository import export_scan_bundle, import_scan_bundle, recent_findings


def run_export(
    console: Console,
    connection,
    *,
    entity: str,
    output: Path,
    export_format: str,
    limit: int,
    tool_name: str | None = None,
    finding_type: str | None = None,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if entity == "scans":
        bundles = export_scan_bundle(connection, limit=limit, tool_name=tool_name)
        with output.open("w", encoding="utf-8", newline="") as handle:
            if export_format == "json":
                json.dump(bundles, handle, indent=2)
            else:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["id", "tool_name", "target", "command_line", "status", "raw_output_path", "finished_at"],
                )
                writer.writeheader()
                for bundle in bundles:
                    writer.writerow(bundle["scan"])
        console.print(f"[bold green]Exported {len(bundles)} scans to {output}[/bold green]")
        return

    findings = recent_findings(connection, limit=limit, finding_type=finding_type)
    with output.open("w", encoding="utf-8", newline="") as handle:
        if export_format == "json":
            json.dump(findings, handle, indent=2)
        else:
            writer = csv.DictWriter(
                handle,
                fieldnames=["id", "scan_run_id", "finding_type", "key", "value"],
            )
            writer.writeheader()
            writer.writerows(findings)
    console.print(f"[bold green]Exported {len(findings)} findings to {output}[/bold green]")


def run_import(console: Console, connection, *, entity: str, input_path: Path) -> None:
    if entity != "scans":
        console.print("[bold red]Only `neonape import scans` is currently supported.[/bold red]")
        return
    with input_path.open("r", encoding="utf-8") as handle:
        bundles = json.load(handle)
    if not isinstance(bundles, list):
        raise ValueError("Expected a JSON list of scan bundles")
    imported = import_scan_bundle(connection, bundles)
    console.print(f"[bold green]Imported {imported} scans from {input_path}[/bold green]")
