from __future__ import annotations

import json

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from neon_ape.db.repository import review_overview
from neon_ape.services.llm_triage import run_local_triage
from neon_ape.ui.layout import build_angel_eyes_panel
from neon_ape.ui.views import build_angel_eyes_table, build_inventory_table, build_llm_triage_panel, build_review_findings_table, build_review_summary_panel, build_web_path_table


def run_review(
    console: Console,
    connection,
    *,
    target: str,
    limit: int = 50,
    as_json: bool = False,
    llm_triage: bool = False,
    llm_provider: str = "cline",
    llm_model: str = "qwen3.5:4b",
    web_paths_only: bool = False,
) -> None:
    overview = review_overview(connection, target, limit=limit)
    if as_json:
        console.print_json(json.dumps({"target": target, **overview}))
        return
    console.print(build_review_summary_panel(target, overview))
    console.print(build_angel_eyes_panel(overview["angel_eyes"]))
    for category in ("Secrets", "Logs", "Repo Metadata", "Server Config"):
        console.print(build_angel_eyes_table(overview["angel_eyes"]["grouped"].get(category, []), category))
    if not web_paths_only:
        console.print(build_web_path_table(overview["web_paths"]["katana"], "katana"))
        console.print(build_web_path_table(overview["web_paths"]["gobuster"], "gobuster"))
        console.print(build_inventory_table(overview["inventory"]))
        console.print(build_review_findings_table(overview["reviews"]))
    if llm_triage:
        try:
            with Progress(
                SpinnerColumn(style="bold magenta"),
                TextColumn("[bold cyan]Eva Unit-01 synchronization... Angel Eyes generating review[/bold cyan]"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("triage", total=None)
                triage = run_local_triage(target=target, overview=overview, provider=llm_provider, model=llm_model)
        except RuntimeError as exc:
            console.print(f"[bold red]{exc}[/bold red]")
            return
        label = llm_model if llm_provider == "ollama" else "cline"
        console.print(build_llm_triage_panel(triage, f"{llm_provider}:{label}"))
