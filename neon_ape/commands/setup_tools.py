from __future__ import annotations

from collections.abc import Sequence
import platform
import subprocess
from shutil import which

from rich.console import Console
from rich.prompt import Confirm


SUPPORTED_TOOLS = (
    "passive_recon",
    "whois",
    "dig",
    "nmap",
    "ffuf",
    "gobuster",
    "amass",
    "subfinder",
    "httpx",
    "naabu",
    "nuclei",
    "dnsx",
    "katana",
    "assetfinder",
)

BREW_PACKAGES = {
    "whois": "whois",
    "dig": "bind",
    "nmap": "nmap",
    "ffuf": "ffuf",
    "gobuster": "gobuster",
    "amass": "amass",
    "assetfinder": "assetfinder",
    "subfinder": "projectdiscovery/tap/subfinder",
    "httpx": "projectdiscovery/tap/httpx",
    "naabu": "projectdiscovery/tap/naabu",
    "nuclei": "projectdiscovery/tap/nuclei",
    "dnsx": "projectdiscovery/tap/dnsx",
    "katana": "projectdiscovery/tap/katana",
}

APT_PACKAGES = {
    "whois": "whois",
    "dig": "dnsutils",
    "nmap": "nmap",
    "ffuf": "ffuf",
    "gobuster": "gobuster",
    "amass": "amass",
}


def _expand_missing_tools(tools: Sequence[str]) -> list[str]:
    expanded: list[str] = []
    for tool in tools:
        if tool == "passive_recon":
            expanded.extend(["whois", "dig"])
        else:
            expanded.append(tool)
    return list(dict.fromkeys(expanded))


def find_missing_tools(tools: Sequence[str] | None = None) -> list[str]:
    wanted = _expand_missing_tools(tools or SUPPORTED_TOOLS)
    return [tool for tool in wanted if which(tool) is None]


def _build_install_plan(missing_tools: Sequence[str]) -> tuple[list[str], list[str], str | None]:
    system = platform.system()
    plan: list[str] = []
    unmanaged: list[str] = []
    package_map = BREW_PACKAGES if system == "Darwin" else APT_PACKAGES if system == "Linux" else {}
    manager = "brew" if system == "Darwin" and which("brew") else "apt-get" if system == "Linux" and which("apt-get") else None

    if manager is None:
        return [], list(_expand_missing_tools(missing_tools)), None

    for tool in _expand_missing_tools(missing_tools):
        package = package_map.get(tool)
        if package is None:
            unmanaged.append(tool)
            continue
        if package not in plan:
            plan.append(package)
    return plan, unmanaged, manager


def run_tool_setup(
    console: Console,
    *,
    assume_yes: bool = False,
    missing_tools: Sequence[str] | None = None,
) -> bool:
    detected_missing = find_missing_tools(missing_tools)
    if not detected_missing:
        console.print("[bold green]All managed recon tools already appear to be installed.[/bold green]")
        return True

    packages, unmanaged, manager = _build_install_plan(detected_missing)
    if manager is None:
        console.print("[bold red]No supported package manager was detected. Supported: Homebrew on macOS, apt-get on Linux.[/bold red]")
        if unmanaged:
            console.print(f"[bold yellow]Manual install still required for:[/bold yellow] {', '.join(unmanaged)}")
        return False

    console.print(
        f"[bold]Package manager:[/bold] {manager}\n"
        f"[bold]Missing tools:[/bold] {', '.join(detected_missing)}\n"
        f"[bold]Packages to install:[/bold] {', '.join(packages) if packages else '-'}"
    )
    if unmanaged:
        console.print(
            f"[bold yellow]No automatic package mapping for:[/bold yellow] {', '.join(unmanaged)}"
        )

    if not packages:
        return False

    if not assume_yes and not Confirm.ask("Install missing recon tools now?", default=True):
        console.print("[bold yellow]Tool setup cancelled.[/bold yellow]")
        return False

    command = ["brew", "install", *packages] if manager == "brew" else ["sudo", "apt-get", "install", "-y", *packages]
    completed = subprocess.run(command, capture_output=True, text=True, check=False, shell=False)
    if completed.returncode == 0:
        console.print("[bold green]Tool setup completed.[/bold green]")
        if unmanaged:
            console.print(
                f"[bold yellow]Still unmanaged:[/bold yellow] {', '.join(unmanaged)}"
            )
        return True

    error_text = completed.stderr.strip() or completed.stdout.strip() or f"{manager} exited with {completed.returncode}"
    console.print(f"[bold red]{error_text}[/bold red]")
    return False


def offer_missing_tool_setup(
    console: Console,
    *,
    missing_tools: Sequence[str],
    assume_yes: bool = False,
) -> bool:
    expanded = _expand_missing_tools(missing_tools)
    label = ", ".join(missing_tools)
    console.print(
        f"[bold yellow]Tool '{label}' not found.[/bold yellow] "
        "Run `neonape setup tools --yes` automatically?"
    )
    if assume_yes or Confirm.ask("Run automatic tool setup?", default=True):
        return run_tool_setup(console, assume_yes=True, missing_tools=expanded)
    return False
