from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt

from neon_ape.commands.review import run_review
from neon_ape.commands.tools import (
    _discover_subdomains,
    _unique_targets,
    run_gobuster,
    run_projectdiscovery_batch_tool,
)
from neon_ape.db.repository import review_overview
from neon_ape.obsidian_sync import resolve_vault_path, run_sync as run_obsidian_sync, sanitize_target_name
from neon_ape.ui.layout import build_adam_completion_panel, build_adam_intro_panel
from neon_ape.workflows.orchestrator import copy_daily_reports, is_macos, open_in_finder, speak_completion
ADAM_REQUIRED_TOOLS = ("subfinder", "httpx", "katana", "gobuster", "nuclei")


def run_adam(
    console: Console,
    connection,
    *,
    config,
    detected_tools: dict[str, str],
    target: str | None = None,
) -> bool:
    console.print(build_adam_intro_panel())
    active_target = (target or "").strip()
    if not active_target:
        active_target = Prompt.ask("[bold red]Target domain[/bold red]")
    if not active_target:
        console.print("[bold red]Adam needs a target domain.[/bold red]")
        return False

    missing = [tool for tool in ADAM_REQUIRED_TOOLS if tool not in detected_tools]
    if missing:
        console.print(f"[bold red]Adam cannot proceed. Missing tools:[/bold red] {', '.join(missing)}")
        return False

    console.print(f"[bold orange3]Hunting Angels across {active_target}...[/bold orange3]")
    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold orange3]{task.description}[/bold orange3]"),
        BarColumn(bar_width=28, style="red", complete_style="orange3"),
        console=console,
    ) as progress:
        task = progress.add_task("Adam is awakening Unit-01...", total=6)

        progress.update(task, description="Discovering subdomains")
        subdomains = _discover_subdomains(console, connection, target=active_target, scan_dir=config.scan_dir, workflow_name="pd_web_chain")
        progress.advance(task)
        if not subdomains:
            console.print("[bold red]Adam found no subdomains to continue with.[/bold red]")
            return False

        progress.update(task, description="Probing live HTTP targets")
        httpx_success, httpx_findings = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="httpx",
            targets=subdomains,
            scan_dir=config.scan_dir,
            workflow_name=f"{active_target}_adam_httpx",
            history_target=f"adam:{active_target}:httpx",
        )
        progress.advance(task)
        if not httpx_success:
            return False

        live_http_targets = _unique_targets(finding.get("host", "") for finding in httpx_findings if finding.get("host"))
        if not live_http_targets:
            console.print("[bold red]Adam found no live web targets.[/bold red]")
            return False

        progress.update(task, description="Crawling reachable web paths")
        katana_success, katana_findings = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="katana",
            targets=live_http_targets,
            scan_dir=config.scan_dir,
            workflow_name=f"{active_target}_adam_katana",
            history_target=f"adam:{active_target}:katana",
        )
        progress.advance(task)
        if not katana_success:
            return False

        progress.update(task, description="Enumerating exposed directories")
        gobuster_success = True
        for http_target in live_http_targets:
            if not run_gobuster(console, connection, target=http_target, scan_dir=config.scan_dir, interactive_retry=False):
                gobuster_success = False
        progress.advance(task)
        if not gobuster_success:
            console.print("[bold yellow]Adam completed with partial gobuster failures.[/bold yellow]")

        progress.update(task, description="Launching nuclei review")
        nuclei_targets = _unique_targets(finding.get("host", "") for finding in katana_findings if finding.get("host")) or live_http_targets
        nuclei_success, _ = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="nuclei",
            targets=nuclei_targets,
            scan_dir=config.scan_dir,
            workflow_name=f"{active_target}_adam_nuclei",
            history_target=f"adam:{active_target}:nuclei",
        )
        progress.advance(task)
        if not nuclei_success:
            console.print("[bold yellow]Adam completed with partial nuclei results.[/bold yellow]")

        progress.update(task, description="Analyzing the Paths")
        run_review(
            console,
            connection,
            target=active_target,
            limit=50,
            llm_triage=True,
            llm_provider=config.llm_provider,
            llm_model=config.llm_model,
            web_paths_only=True,
            llm_progress=False,
        )
        progress.advance(task)

    vault_path = resolve_vault_path(None, config)
    if vault_path is None:
        console.print("[bold yellow]Adam could not resolve an Obsidian vault. Export skipped.[/bold yellow]")
        return True

    console.print("[bold orange3]Synchronizing with Obsidian...[/bold orange3]")
    status = run_obsidian_sync(
        SimpleNamespace(
            vault_path=str(vault_path),
            target_note=active_target,
            notes_passphrase=None,
            limit=200,
            open=False,
            dry_run=False,
            skip_run=True,
        ),
        console=console,
    )
    if status != 0:
        console.print("[bold red]Adam finished recon, but Obsidian export failed.[/bold red]")
        return False

    overview = review_overview(connection, active_target, limit=100)
    highest_risk = max((int(item.get("risk_score", 0) or 0) for item in overview.get("angel_eyes", {}).get("items", [])), default=0)
    target_dir = Path(vault_path) / "Pentests" / sanitize_target_name(active_target)
    findings_path = target_dir / "Findings.md"
    sensitive_paths_path = target_dir / "Sensitive-Paths.md"
    review_summary_path = target_dir / "Review-Summary.md"
    daily_report_dir = copy_daily_reports(active_target, [findings_path, sensitive_paths_path, review_summary_path])
    spoken_lines = speak_completion(highest_risk)
    if is_macos():
        console.print("[bold orange3]Daniel voice notification:[/bold orange3]")
        for line in spoken_lines:
            console.print(f"- {line}")

    console.print(
        build_adam_completion_panel(
            target=active_target,
            highest_risk=highest_risk,
            findings_path=findings_path,
            sensitive_paths_path=sensitive_paths_path,
            review_summary_path=review_summary_path,
            daily_report_dir=daily_report_dir,
        )
    )
    console.print(f"[bold cyan]Daily report folder:[/bold cyan] {daily_report_dir}")
    _offer_open_results(console, findings_path, sensitive_paths_path, review_summary_path, daily_report_dir)
    return True


def _offer_open_results(
    console: Console,
    findings_path: Path,
    sensitive_paths_path: Path,
    review_summary_path: Path,
    daily_report_dir: Path,
) -> None:
    if is_macos():
        if not sys.stdin.isatty():
            console.print("[bold cyan]Press Enter to open the daily report folder in Finder[/bold cyan]")
            return
        console.input("[bold cyan]Press Enter to open the daily report folder in Finder[/bold cyan]")
        open_in_finder(daily_report_dir)
        return

    opener = shutil.which("xdg-open")
    if not opener:
        return
    command_hint = (
        f"xdg-open '{findings_path}'\n"
        f"xdg-open '{sensitive_paths_path}'\n"
        f"xdg-open '{review_summary_path}'"
    )
    if not sys.stdin.isatty():
        console.print(f"[bold cyan]Open results:[/bold cyan]\n{command_hint}")
        return
    answer = console.input("[bold cyan]Open exported review files with xdg-open?[/bold cyan] [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        console.print(f"[bold cyan]Open results later with:[/bold cyan]\n{command_hint}")
        return
    for path in (findings_path, sensitive_paths_path, review_summary_path):
        subprocess.run([opener, str(path)], check=False)
