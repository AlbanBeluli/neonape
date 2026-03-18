from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt

from neon_ape.agents.autoresearch import run_autoresearch
from neon_ape.commands.review import run_review
from neon_ape.commands.tools import (
    _discover_subdomains,
    _unique_targets,
    run_checklist_step,
    run_gobuster,
    run_projectdiscovery_batch_tool,
)
from neon_ape.db.repository import checklist_summary, get_checklist_item, list_checklist_items, mark_checklist_item_status, record_scan, review_overview
from neon_ape.obsidian_sync import resolve_vault_path, run_sync as run_obsidian_sync, sanitize_target_name
from neon_ape.reports.pdf_generator import generate_pdf_report
from neon_ape.tools.base import ToolResult, run_command
from neon_ape.tools.projectdiscovery import parse_projectdiscovery_output
from neon_ape.ui.layout import build_adam_completion_panel, build_adam_intro_panel, build_magi_execution_table
from neon_ape.workflows.orchestrator import build_daily_report_dir, copy_daily_reports, is_macos, open_in_finder, speak_completion
ADAM_REQUIRED_TOOLS = ("subfinder", "httpx", "katana", "gobuster", "nuclei")
ADAM_NUCLEI_TIMEOUT = 180
ADAM_NUCLEI_SEVERITIES = "medium,high,critical"


def run_adam(
    console: Console,
    connection,
    *,
    config,
    detected_tools: dict[str, str],
    target: str | None = None,
    pdf_enabled: bool = False,
    autoresearch_enabled: bool = False,
    autoresearch_target: str | None = None,
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
        nuclei_targets = live_http_targets[:2]
        nuclei_success, _ = _run_adam_nuclei_review(
            console,
            connection,
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
    overview = review_overview(connection, active_target, limit=100)
    highest_risk = max((int(item.get("risk_score", 0) or 0) for item in overview.get("angel_eyes", {}).get("items", [])), default=0)
    if vault_path is None:
        console.print("[bold yellow]Adam could not resolve an Obsidian vault. Export will fall back to a local daily report folder.[/bold yellow]")
        daily_report_dir = build_daily_report_dir(active_target)
        daily_report_dir.mkdir(parents=True, exist_ok=True)
        findings_path = daily_report_dir / "Findings.md"
        sensitive_paths_path = daily_report_dir / "Sensitive-Paths.md"
        review_summary_path = daily_report_dir / "Review-Summary.md"
        _write_report_placeholder(findings_path, "Findings", active_target, highest_risk)
        _write_report_placeholder(sensitive_paths_path, "Sensitive Paths", active_target, highest_risk)
        _write_report_placeholder(review_summary_path, "Review Summary", active_target, highest_risk)
    else:
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
        target_dir = Path(vault_path) / "Pentests" / sanitize_target_name(active_target)
        findings_path = target_dir / "Findings.md"
        sensitive_paths_path = target_dir / "Sensitive-Paths.md"
        review_summary_path = target_dir / "Review-Summary.md"
        daily_report_dir = copy_daily_reports(active_target, [findings_path, sensitive_paths_path, review_summary_path])

    pdf_path: Path | None = None
    if pdf_enabled:
        pdf_path = daily_report_dir / f"{sanitize_target_name(active_target)}-adam-report.pdf"
        pdf_sections = [
            ("Findings", _read_report_section(findings_path)),
            ("Sensitive Paths", _read_report_section(sensitive_paths_path)),
            ("Review Summary", _read_report_section(review_summary_path)),
        ]
        generate_pdf_report(
            pdf_path,
            title="Neon Ape Adam Report",
            subtitle=f"Target: {active_target}",
            summary_rows=(
                ("Target", active_target),
                ("Highest Risk", str(highest_risk)),
                ("Daily Folder", str(daily_report_dir)),
            ),
            sections=pdf_sections,
        )

    _seed_adam_completed_steps(connection)
    console.print("[bold orange3]Loading MAGI checklist sequence...[/bold orange3]")
    checklist_success = _run_magi_checklist(
        console,
        connection,
        config=config,
        detected_tools=detected_tools,
        target=active_target,
    )
    if autoresearch_enabled:
        research_skill = autoresearch_target or ("angel-eyes" if highest_risk > 0 else "magi-checklist")
        console.print(f"[bold orange3]Adam is beginning autoresearch on {research_skill}. Persistent skill storage will be updated if the score improves enough.[/bold orange3]")
        run_autoresearch(
            console,
            config=config,
            skill_target=research_skill,
            daily_report_dir=daily_report_dir,
            auto=True,
        )
    spoken_lines = speak_completion(highest_risk, checklist_complete=checklist_success)
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
    if pdf_path is not None:
        console.print(f"[bold cyan]PDF report:[/bold cyan] {pdf_path}")
    _offer_open_results(console, findings_path, sensitive_paths_path, review_summary_path, daily_report_dir)
    return True


def _write_report_placeholder(path: Path, title: str, target: str, highest_risk: int) -> None:
    path.write_text(
        f"# {title}\n\n"
        f"- Target: `{target}`\n"
        f"- Highest risk score observed: `{highest_risk}`\n"
        "- Obsidian export was unavailable, so Adam wrote this local fallback artifact.\n",
        encoding="utf-8",
    )


def _read_report_section(path: Path) -> str:
    if not path.exists():
        return "Not available."
    return path.read_text(encoding="utf-8")[:4000]


def _seed_adam_completed_steps(connection) -> None:
    for step_order in (4, 7, 11, 12, 13):
        mark_checklist_item_status(connection, step_order, "done")


def _run_magi_checklist(
    console: Console,
    connection,
    *,
    config,
    detected_tools: dict[str, str],
    target: str,
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
            items = list_checklist_items(connection)
            console.print(build_magi_execution_table(items, active_step=step_order))
            if str(current.get("status", "todo")) == "done":
                console.print(f"[bold green]Checklist step {step_order} already done from Adam workflow evidence.[/bold green]")
                progress.advance(task)
                continue
            action = _prompt_checklist_action(console, current)
            if action == "run":
                _, action_tool = run_checklist_step(
                    console,
                    connection,
                    checklist_step=step_order,
                    target=target,
                    detected_tools=detected_tools,
                    scan_dir=config.scan_dir,
                    profile="service_scan",
                )
                updated = get_checklist_item(connection, step_order) or {}
                if str(updated.get("status", "todo")) not in {"done"}:
                    mark_checklist_item_status(connection, step_order, "todo")
                if action_tool is None and not item.get("action_tool"):
                    mark_checklist_item_status(connection, step_order, "done")
                    console.print(f"[bold cyan]Checklist step {step_order} completed.[/bold cyan]")
            elif action == "done":
                mark_checklist_item_status(connection, step_order, "done")
                console.print(f"[bold cyan]Checklist step {step_order} marked done.[/bold cyan]")
            elif action == "skip":
                mark_checklist_item_status(connection, step_order, "todo")
                console.print(f"[bold yellow]Checklist step {step_order} left as todo.[/bold yellow]")
            progress.advance(task)

    summary = checklist_summary(connection)
    console.print(
        f"[bold orange3]MAGI status:[/bold orange3] "
        f"{summary.get('complete_count', 0)}/{summary.get('item_count', 0)} done"
    )
    return int(summary.get("complete_count", 0) or 0) == int(summary.get("item_count", 0) or 0)


def _prompt_checklist_action(console: Console, item: dict[str, object]) -> str:
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


def _run_adam_nuclei_review(
    console: Console,
    connection,
    *,
    targets: list[str],
    scan_dir: Path,
    workflow_name: str,
    history_target: str,
) -> tuple[bool, list[dict[str, str]]]:
    normalized_targets = _unique_targets(targets)
    if not normalized_targets:
        return False, []
    output_path = scan_dir / f"nuclei_{workflow_name}.jsonl"
    input_path = scan_dir / f"nuclei_{workflow_name}.input.txt"
    input_path.write_text("\n".join(normalized_targets) + "\n", encoding="utf-8")
    command = [
        "nuclei",
        "-jsonl",
        "-severity",
        ADAM_NUCLEI_SEVERITIES,
        "-rl",
        "20",
        "-timeout",
        "5",
        "-l",
        str(input_path),
        "-o",
        str(output_path),
    ]
    console.print(
        f"[bold orange3]Adam is constraining nuclei for live orchestration:[/bold orange3] "
        f"{', '.join(normalized_targets)}"
    )
    try:
        result = run_command(
            "nuclei",
            history_target,
            command,
            timeout=ADAM_NUCLEI_TIMEOUT,
            raw_output_path=str(output_path),
        )
    finally:
        input_path.unlink(missing_ok=True)
    findings = parse_projectdiscovery_output("nuclei", output_path)
    record_scan(
        connection,
        ToolResult(
            tool_name="nuclei",
            target=history_target,
            command=command,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            raw_output_path=str(output_path),
        ),
        findings,
    )
    console.print(f"[bold green]nuclei exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold yellow]{result.stderr}[/bold yellow]")
    return result.exit_code == 0, findings
