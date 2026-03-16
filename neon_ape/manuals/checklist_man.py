from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table


def build_checklist_manual() -> Panel:
    content = Group(
        Panel.fit(
            "[bold magenta]MAGI CHECKLIST OPERATOR MANUAL[/bold magenta]\n"
            "[bold orange3]How Neon Ape tracks practical steps, runs attached actions, and preserves status in local storage.[/bold orange3]",
            title="MAGI",
            style="bold magenta",
        ),
        _checklist_synopsis(),
        _checklist_structure(),
        _checklist_actions(),
        _checklist_nmap(),
        _checklist_examples(),
        _checklist_best_practices(),
    )
    return Panel(content, title="Operator Manual: MAGI Checklist", border_style="magenta")


def _checklist_synopsis() -> Group:
    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold magenta", no_wrap=True)
    body.add_column()
    body.add_row("NAME", "neonape man checklist - dedicated MAGI checklist manual")
    body.add_row("VIEW", "neonape --show-checklist --init-only")
    body.add_row("RUN STEP", "neonape --checklist-step 9 --target 192.168.1.10")
    return Group(Rule("NAME / SYNOPSIS", style="magenta"), body)


def _checklist_structure() -> Group:
    table = Table(title="Checklist Structure", expand=False)
    table.add_column("Section", style="bold magenta")
    table.add_column("Purpose")
    table.add_row("Angel Enumeration", "Passive recon, WHOIS, DNS, and subdomain collection")
    table.add_row("Eva Unit Scanner", "Host discovery, port scanning, HTTP probing, service review")
    table.add_row("Service Enumeration", "Nuclei checks and follow-up service context")
    table.add_row("Web Path Review", "Angel Eyes-backed review of sensitive paths and exposed assets")
    table.add_row("MAGI Checklist", "Documentation, validation, and progress tracking")
    return Group(Rule("STRUCTURE", style="magenta"), table)


def _checklist_actions() -> Group:
    table = Table(title="Interactive Actions", expand=False)
    table.add_column("Status", style="bold magenta")
    table.add_column("Meaning")
    table.add_row("todo", "Step still needs work or was intentionally skipped for later")
    table.add_row("done", "Step is complete and timestamped in the local database")
    table.add_row("Run now?", "Execute the attached tool wrapper or mark the step manually")
    return Group(
        Rule("RUN NOW? + STATUS", style="magenta"),
        table,
        Panel.fit(
            "MAGI prompts offer `run`, `skip`, or `done`.\n"
            "Tool-backed steps execute their safe wrappers. Manual steps can still be marked done without running a command.",
            border_style="orange3",
        ),
    )


def _checklist_nmap() -> Group:
    table = Table(title="Nmap Wrapper Profiles", expand=False)
    table.add_column("Profile", style="bold magenta")
    table.add_column("Wrapper")
    table.add_row("host_discovery", "`nmap -sn <target>`")
    table.add_row("service_scan", "`nmap -sV <target>`")
    table.add_row("aggressive", "`nmap -A -T4 <target>`")
    return Group(
        Rule("NMAP WRAPPERS", style="magenta"),
        table,
        Panel.fit(
            "The checklist uses Neon Ape’s XML-backed Nmap wrappers so service results persist into the DB and later review layers.",
            border_style="red",
        ),
    )


def _checklist_examples() -> Group:
    table = Table(title="Checklist Examples", expand=False)
    table.add_column("Scenario", style="bold magenta")
    table.add_column("Command")
    table.add_row("View checklist", "`neonape --show-checklist --init-only`")
    table.add_row("Run WHOIS step", "`neonape --checklist-step 2 --target example.com`")
    table.add_row("Run host discovery", "`neonape --checklist-step 6 --target 192.168.1.0/24`")
    table.add_row("Run service scan", "`neonape --checklist-step 9 --target 192.168.1.10`")
    table.add_row("Review stored status", "`neonape db checklist`")
    return Group(Rule("EXAMPLES", style="magenta"), table)


def _checklist_best_practices() -> Group:
    tips = Table.grid(padding=(0, 1))
    tips.add_column(style="bold magenta", no_wrap=True)
    tips.add_column()
    tips.add_row("1.", "Use checklist steps when you want persistence and guidance, not just raw tool output.")
    tips.add_row("2.", "Prefer MAGI for host discovery and service enumeration so the DB stays coherent.")
    tips.add_row("3.", "Mark manual validation and reporting steps done once you have actually reviewed the evidence.")
    return Group(Rule("BEST PRACTICES", style="magenta"), tips)
