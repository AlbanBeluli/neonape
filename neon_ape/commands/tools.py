from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel

from neon_ape.config import detect_installed_tools
from neon_ape.commands.setup_tools import offer_missing_tool_setup
from neon_ape.db.repository import get_checklist_item, mark_checklist_item_status, record_scan
from neon_ape.services.validation import validate_target
from neon_ape.tools.base import ToolResult
from neon_ape.tools.web_paths import correlate_sensitive_paths, grouped_sensitive_paths
from neon_ape.tools.nmap import build_nmap_command, execute_nmap, parse_nmap_xml, render_command_preview
from neon_ape.tools.passive_recon import execute_passive_recon
from neon_ape.tools.projectdiscovery import (
    build_projectdiscovery_batch_command,
    build_projectdiscovery_command,
    execute_projectdiscovery,
    parse_projectdiscovery_output,
)
from neon_ape.tools.web_enum import build_gobuster_command, execute_gobuster, parse_gobuster_output
from neon_ape.ui.layout import build_angel_eyes_panel
from neon_ape.ui.theme import section_style
from neon_ape.ui.views import build_angel_eyes_table, build_missing_tools_panel, build_tool_output_table


def run_checklist_step(
    console: Console,
    connection,
    *,
    checklist_step: int,
    target: str,
    detected_tools: dict[str, str],
    scan_dir: Path,
    profile: str,
) -> tuple[str, str | None]:
    item = get_checklist_item(connection, checklist_step)
    if item is None:
        console.print(f"[bold red]Checklist step {checklist_step} was not found.[/bold red]")
        return profile, None

    action_tool = item.get("action_tool")
    action_profile = item.get("action_profile")
    if not action_tool:
        console.print(
            Panel.fit(
                f"[bold]Step:[/bold] {item['step_order']} {item['title']}\n"
                f"[bold]Guide:[/bold] {item['guide_text']}\n"
                f"[bold]Example:[/bold] {item['example_command']}",
                title="MAGI Checklist",
                style=section_style("accent"),
            )
        )
        console.print("[bold yellow]This checklist item is documentation-only and has no attached tool action.[/bold yellow]")
        return profile, None

    if action_tool not in detected_tools:
        console.print(build_missing_tools_panel([str(action_tool)]))
        if not offer_missing_tool_setup(console, missing_tools=[str(action_tool)]):
            return profile, None
        detected_tools.clear()
        detected_tools.update(detect_installed_tools())
        if action_tool not in detected_tools:
            console.print(build_missing_tools_panel([str(action_tool)]))
            return profile, None

    console.print(
        Panel.fit(
            f"[bold]Step:[/bold] {item['step_order']} {item['title']}\n"
            f"[bold]Section:[/bold] {item['section_name']}\n"
            f"[bold]Guide:[/bold] {item['guide_text']}\n"
            f"[bold]Example:[/bold] {item['example_command']}",
            title="MAGI Checklist",
            style=section_style("accent"),
        )
    )

    step_profile = str(action_profile or profile)
    if action_tool == "workflow":
        workflow_tools = {
            "pd_chain": {"subfinder", "httpx", "naabu"},
            "pd_web_chain": {"subfinder", "httpx", "nuclei"},
            "light_recon": {"assetfinder", "subfinder", "httpx"},
            "deep_recon": {"assetfinder", "subfinder", "amass", "dnsx", "httpx", "naabu", "nuclei"},
            "js_web_chain": {"subfinder", "httpx", "katana", "nuclei"},
        }
        missing_tools = sorted(tool for tool in workflow_tools.get(step_profile, set()) if tool not in detected_tools)
        if missing_tools:
            console.print(build_missing_tools_panel(missing_tools))
            if not offer_missing_tool_setup(console, missing_tools=missing_tools):
                return profile, action_tool
            detected_tools.clear()
            detected_tools.update(detect_installed_tools())
            missing_tools = sorted(tool for tool in workflow_tools.get(step_profile, set()) if tool not in detected_tools)
            if missing_tools:
                console.print(build_missing_tools_panel(missing_tools))
                return profile, action_tool
        success = run_chained_recon_workflow(
            console,
            connection,
            target=target,
            scan_dir=scan_dir,
            workflow_name=step_profile,
        )
        mark_step_outcome(console, connection, checklist_step, success)
        return profile, action_tool

    if action_tool == "nmap":
        success = run_nmap(console, connection, target=target, profile=step_profile, scan_dir=scan_dir)
        mark_step_outcome(console, connection, checklist_step, success)
        return step_profile, action_tool

    if action_tool == "passive_recon":
        success = run_passive_recon(console, connection, target=target, profile=step_profile)
        mark_step_outcome(console, connection, checklist_step, success)
        return step_profile, action_tool

    if action_tool == "gobuster":
        success = run_gobuster(console, connection, target=target, scan_dir=scan_dir)
        mark_step_outcome(console, connection, checklist_step, success)
        return profile, action_tool

    success = run_projectdiscovery_tool(console, connection, tool_name=str(action_tool), target=target, scan_dir=scan_dir)
    mark_step_outcome(console, connection, checklist_step, success)
    return profile, str(action_tool)


def run_nmap(
    console: Console,
    connection,
    *,
    target: str,
    profile: str,
    scan_dir: Path,
) -> bool:
    try:
        validated_target = validate_target(target)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return False
    output_xml = scan_dir / f"{validated_target.replace('/', '_')}_{profile}.xml"
    command = build_nmap_command(validated_target, profile, output_xml)

    console.print(
        Panel.fit(
            f"[bold]Profile:[/bold] {profile}\n[bold]Target:[/bold] {validated_target}\n"
            f"[bold]Command:[/bold] {render_command_preview(command)}",
            title="Eva Unit Scanner",
            style=section_style("green"),
        )
    )

    result = execute_nmap(command, validated_target)
    findings = parse_nmap_xml(output_xml)
    record_scan(connection, result, findings)
    console.print(build_tool_output_table("nmap", findings))
    console.print(f"[bold green]nmap exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
    return result.exit_code == 0


def run_projectdiscovery_tool(
    console: Console,
    connection,
    *,
    tool_name: str,
    target: str,
    scan_dir: Path,
) -> bool:
    output_path = scan_dir / f"{tool_name}_{target.replace('/', '_')}.jsonl"
    try:
        validated_target, command = build_projectdiscovery_command(tool_name, target, output_path)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return False

    console.print(
        Panel.fit(
            f"[bold]Tool:[/bold] {tool_name}\n[bold]Target:[/bold] {validated_target}\n"
            f"[bold]Command:[/bold] {render_command_preview(command)}",
            title="Angel Enumeration",
            style=section_style("orange"),
        )
    )

    result = execute_projectdiscovery(command, tool_name, validated_target, output_path)
    findings = parse_projectdiscovery_output(tool_name, output_path)
    record_scan(connection, result, findings)
    console.print(build_tool_output_table(tool_name, findings))
    _render_angel_eyes(console, tool_name, findings)
    console.print(f"[bold green]{tool_name} exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
    return result.exit_code == 0


def run_passive_recon(
    console: Console,
    connection,
    *,
    target: str,
    profile: str,
) -> bool:
    try:
        validated_target = validate_target(target)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return False

    command_preview = {
        "whois_lookup": f"python -m neon_ape.tools.passive_recon whois {validated_target}",
        "dns_a_records": f"python -m neon_ape.tools.passive_recon dns-a {validated_target}",
    }.get(profile, profile)
    console.print(
        Panel.fit(
            f"[bold]Profile:[/bold] {profile}\n[bold]Target:[/bold] {validated_target}\n"
            f"[bold]Command:[/bold] {command_preview}",
            title="Angel Enumeration",
            style=section_style("orange"),
        )
    )
    try:
        result, findings = execute_passive_recon(profile, validated_target)
    except Exception as exc:  # noqa: BLE001 - deliberate local guard for terminal UX
        result = ToolResult(
            tool_name="passive_recon",
            target=validated_target,
            command=["passive_recon", profile, validated_target],
            stdout="",
            stderr=str(exc),
            exit_code=1,
            raw_output_path="",
        )
        findings = []
    record_scan(connection, result, findings)
    console.print(build_tool_output_table("passive_recon", findings))
    console.print(f"[bold green]passive_recon exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
    return result.exit_code == 0


def run_gobuster(
    console: Console,
    connection,
    *,
    target: str,
    scan_dir: Path,
    interactive_retry: bool = True,
) -> bool:
    output_path = scan_dir / f"gobuster_{_safe_name(target)}.txt"
    try:
        validated_target, command = build_gobuster_command(target, output_path)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return False

    console.print(
        Panel.fit(
            f"[bold]Tool:[/bold] gobuster\n[bold]Target:[/bold] {validated_target}\n"
            f"[bold]Command:[/bold] {render_command_preview(command)}",
            title="Eva Unit Scanner",
            style=section_style("green"),
        )
    )

    result = execute_gobuster(command, validated_target, output_path)
    findings = parse_gobuster_output(output_path)
    record_scan(connection, result, findings)
    console.print(build_tool_output_table("gobuster", findings))
    _render_angel_eyes(console, "gobuster", findings)
    console.print(f"[bold green]gobuster exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
        hint = _gobuster_wildcard_hint(result.stderr, validated_target)
        if hint:
            console.print(hint)
        details = _gobuster_wildcard_details(result.stderr)
        should_retry = False
        if details:
            should_retry = _prompt_gobuster_retry(console, details["content_length"]) if interactive_retry else True
        if details and should_retry:
            console.print(
                f"[bold cyan]Retrying gobuster with --exclude-length {details['content_length']}...[/bold cyan]"
            )
            retry_validated_target, retry_command = build_gobuster_command(
                target,
                output_path,
                exclude_length=details["content_length"],
            )
            console.print(
                Panel.fit(
                    f"[bold]Tool:[/bold] gobuster\n[bold]Target:[/bold] {retry_validated_target}\n"
                    f"[bold]Command:[/bold] {render_command_preview(retry_command)}",
                    title="Eva Unit Scanner Retry",
                    style=section_style("green"),
                )
            )
            retry_result = execute_gobuster(retry_command, retry_validated_target, output_path)
            retry_findings = parse_gobuster_output(output_path)
            record_scan(connection, retry_result, retry_findings)
            console.print(build_tool_output_table("gobuster", retry_findings))
            _render_angel_eyes(console, "gobuster", retry_findings)
            console.print(f"[bold green]gobuster retry exit code:[/bold green] {retry_result.exit_code}")
            if retry_result.exit_code != 0 and retry_result.stderr:
                console.print(f"[bold red]{retry_result.stderr}[/bold red]")
            return retry_result.exit_code == 0
    return result.exit_code == 0


def run_projectdiscovery_batch_tool(
    console: Console,
    connection,
    *,
    tool_name: str,
    targets: list[str],
    scan_dir: Path,
    workflow_name: str | None = None,
    history_target: str | None = None,
) -> tuple[bool, list[dict[str, str]]]:
    normalized_targets = _unique_targets(targets)
    output_path = scan_dir / f"{tool_name}_{_safe_name(workflow_name or normalized_targets[0])}.jsonl"
    try:
        validated_targets, command, input_path = build_projectdiscovery_batch_command(tool_name, normalized_targets, output_path)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return False, []

    console.print(
        Panel.fit(
            f"[bold]Tool:[/bold] {tool_name}\n"
            f"[bold]Targets:[/bold] {len(validated_targets)}\n"
            f"[bold]Command:[/bold] {render_command_preview(command)}",
            title="Angel Enumeration",
            style=section_style("orange"),
        )
    )

    result = execute_projectdiscovery(
        command,
        tool_name,
        history_target or _default_batch_history_target(tool_name, workflow_name, validated_targets),
        output_path,
    )
    findings = parse_projectdiscovery_output(tool_name, output_path)
    record_scan(connection, result, findings)
    console.print(build_tool_output_table(tool_name, findings))
    _render_angel_eyes(console, tool_name, findings)
    console.print(f"[bold green]{tool_name} exit code:[/bold green] {result.exit_code}")
    if result.exit_code != 0 and result.stderr:
        console.print(f"[bold red]{result.stderr}[/bold red]")
    input_path.unlink(missing_ok=True)
    return result.exit_code == 0, findings


def run_chained_recon_workflow(
    console: Console,
    connection,
    *,
    target: str,
    scan_dir: Path,
    workflow_name: str = "pd_chain",
) -> bool:
    if workflow_name not in {"pd_chain", "pd_web_chain", "light_recon", "deep_recon", "js_web_chain"}:
        console.print(f"[bold red]Unsupported workflow:[/bold red] {workflow_name}")
        return False

    workflow_label = {
        "pd_chain": "subfinder -> httpx -> naabu",
        "pd_web_chain": "subfinder -> httpx -> nuclei",
        "light_recon": "assetfinder + subfinder -> httpx",
        "deep_recon": "assetfinder + subfinder + amass -> dnsx -> httpx -> naabu -> nuclei",
        "js_web_chain": "subfinder -> httpx -> katana -> nuclei",
    }[workflow_name]
    console.print(
        Panel.fit(
            f"[bold]Workflow:[/bold] {workflow_label}\n[bold]Seed target:[/bold] {target}",
            title="MAGI Chained Recon",
            style=section_style("accent"),
        )
    )

    subdomains = _discover_subdomains(console, connection, target=target, scan_dir=scan_dir, workflow_name=workflow_name)
    if workflow_name in {"pd_chain", "pd_web_chain", "js_web_chain"} and not subdomains:
        return False
    if not subdomains:
        console.print("[bold yellow]No subdomains found. Falling back to the provided target for HTTP probing.[/bold yellow]")
        subdomains = [target]

    if workflow_name == "deep_recon":
        dns_success = run_projectdiscovery_tool(console, connection, tool_name="dnsx", target=target, scan_dir=scan_dir)
        if not dns_success:
            return False

    httpx_success, httpx_findings = run_projectdiscovery_batch_tool(
        console,
        connection,
        tool_name="httpx",
        targets=subdomains,
        scan_dir=scan_dir,
        workflow_name=f"{target}_workflow_httpx",
        history_target=f"{workflow_name}:{target}:httpx",
    )
    if not httpx_success:
        return False

    live_http_targets = _unique_targets(
        finding.get("host", "")
        for finding in httpx_findings
        if finding.get("host")
    )
    live_hosts = _unique_targets(
        _extract_host(finding.get("host", ""))
        for finding in httpx_findings
        if finding.get("host")
    )
    if not live_hosts:
        console.print("[bold yellow]No live HTTP targets found for the next workflow stage.[/bold yellow]")
        return True

    if workflow_name in {"pd_chain", "deep_recon"}:
        naabu_success, _ = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="naabu",
            targets=live_hosts,
            scan_dir=scan_dir,
            workflow_name=f"{target}_workflow_naabu",
            history_target=f"{workflow_name}:{target}:naabu",
        )
        if not naabu_success or workflow_name == "pd_chain":
            return naabu_success
        nuclei_success, _ = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="nuclei",
            targets=live_http_targets,
            scan_dir=scan_dir,
            workflow_name=f"{target}_workflow_nuclei",
            history_target=f"{workflow_name}:{target}:nuclei",
        )
        return nuclei_success

    if workflow_name == "js_web_chain":
        katana_success, katana_findings = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="katana",
            targets=live_http_targets,
            scan_dir=scan_dir,
            workflow_name=f"{target}_workflow_katana",
            history_target=f"{workflow_name}:{target}:katana",
        )
        if not katana_success:
            return False
        katana_targets = _unique_targets(finding.get("host", "") for finding in katana_findings if finding.get("host"))
        if not katana_targets:
            katana_targets = live_http_targets
        nuclei_success, _ = run_projectdiscovery_batch_tool(
            console,
            connection,
            tool_name="nuclei",
            targets=katana_targets,
            scan_dir=scan_dir,
            workflow_name=f"{target}_workflow_nuclei",
            history_target=f"{workflow_name}:{target}:nuclei",
        )
        return nuclei_success

    nuclei_success, _ = run_projectdiscovery_batch_tool(
        console,
        connection,
        tool_name="nuclei",
        targets=live_http_targets,
        scan_dir=scan_dir,
        workflow_name=f"{target}_workflow_nuclei",
        history_target=f"{workflow_name}:{target}:nuclei",
    )
    return nuclei_success


def mark_step_outcome(console: Console, connection, step_order: int, success: bool) -> None:
    status = "done" if success else "in_progress"
    mark_checklist_item_status(connection, step_order, status)
    label = "completed" if success else "left in progress"
    console.print(f"[bold cyan]Checklist step {step_order} {label}.[/bold cyan]")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "run"


def _extract_host(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.hostname or parsed.netloc
    return value


def _unique_targets(values) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def _default_batch_history_target(tool_name: str, workflow_name: str | None, validated_targets: list[str]) -> str:
    if workflow_name:
        return f"batch:{tool_name}:{workflow_name}"
    if len(validated_targets) == 1:
        return validated_targets[0]
    return f"batch:{tool_name}:{len(validated_targets)}_targets"


def _gobuster_wildcard_hint(stderr: str, target: str) -> str | None:
    details = _gobuster_wildcard_details(stderr)
    if details is None:
        return None

    return (
        "[bold yellow]Gobuster hit a wildcard-style response.[/bold yellow] "
        f"The target returns HTTP {details['status_code']} for random paths with length {details['content_length']}. "
        f"Retry manually with a filtered command such as "
        f"`gobuster dir -u {target} -w <wordlist> --exclude-length {details['content_length']}` "
        f"or adjust the blocked status codes."
    )


def _gobuster_wildcard_details(stderr: str) -> dict[str, str] | None:
    lowered = stderr.lower()
    if "matches the provided options for non existing urls" not in lowered:
        return None
    status_match = re.search(r"=>\s*(\d{3})\s*\(Length:\s*(\d+)\)", stderr)
    if not status_match:
        return None
    status_code, content_length = status_match.groups()
    return {"status_code": status_code, "content_length": content_length}


def _prompt_gobuster_retry(console: Console, exclude_length: str) -> bool:
    answer = console.input(
        "[bold cyan]Retry gobuster with "
        f"`--exclude-length {exclude_length}`?[/bold cyan] [y/N]: "
    ).strip().lower()
    return answer in {"y", "yes"}


def _render_angel_eyes(console: Console, tool_name: str, findings: list[dict[str, str]]) -> None:
    if tool_name not in {"gobuster", "katana", "httpx", "nuclei"}:
        return
    rows = [
        {
            "tool_name": tool_name,
            "finding_type": finding.get("type", ""),
            "key": finding.get("key", ""),
            "value": finding.get("value", ""),
            "category": finding.get("category", ""),
            "risk_score": finding.get("risk_score", 0),
            "metadata": finding,
        }
        for finding in findings
        if finding.get("category")
    ]
    if not rows:
        return
    items = correlate_sensitive_paths(rows)
    grouped = grouped_sensitive_paths(items)
    console.print(build_angel_eyes_panel({"items": items, "grouped": grouped}))
    for category in ("Secrets", "Logs", "Repo Metadata", "Server Config"):
        if grouped.get(category):
            console.print(build_angel_eyes_table(grouped[category], category))


def _discover_subdomains(
    console: Console,
    connection,
    *,
    target: str,
    scan_dir: Path,
    workflow_name: str,
) -> list[str]:
    tools = ["subfinder"]
    if workflow_name in {"light_recon", "deep_recon"}:
        tools.insert(0, "assetfinder")
    if workflow_name == "deep_recon":
        tools.append("amass")

    collected: list[str] = []
    for tool_name in tools:
        success = run_projectdiscovery_tool(console, connection, tool_name=tool_name, target=target, scan_dir=scan_dir)
        if not success and tool_name == "subfinder":
            return []
        output_path = scan_dir / f"{tool_name}_{target.replace('/', '_')}.jsonl"
        findings = parse_projectdiscovery_output(tool_name, output_path)
        collected.extend(
            finding.get("host", "")
            for finding in findings
            if finding.get("host")
        )
    return _unique_targets(collected)
