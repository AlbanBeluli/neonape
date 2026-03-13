from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pathlib import Path
import shutil

from neon_ape.config import AppConfig, detect_installed_tools
from neon_ape.db.repository import (
    get_checklist_item,
    checklist_summary,
    initialize_database,
    list_tables,
    list_checklist_items,
    mark_checklist_item_status,
    record_scan,
    recent_findings,
    recent_scans,
    seed_checklist_from_file,
)
from neon_ape.services.logging_utils import configure_logger
from neon_ape.services.storage import connect
from neon_ape.services.validation import validate_target
from neon_ape.tools.nmap import build_nmap_command, execute_nmap, parse_nmap_xml, render_command_preview
from neon_ape.tools.projectdiscovery import (
    build_projectdiscovery_command,
    execute_projectdiscovery,
    parse_projectdiscovery_output,
)
from neon_ape.ui.ascii import EVA_BANNER
from neon_ape.ui.layout import build_checklist_table, build_main_menu
from neon_ape.ui.theme import APP_TITLE, section_style


class NeonApeApp:
    """Top-level local terminal application shell."""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.console = Console()
        self.config = config or AppConfig.default()
        self.logger = None
        self.command: str | None = None
        self.db_command: str | None = None
        self.uninstall_yes = False
        self.uninstall_purge_data = False
        self.target: str | None = None
        self.profile = "service_scan"
        self.run_nmap = False
        self.init_only = False
        self.tool: str | None = None
        self.checklist_step: int | None = None
        self.show_checklist = False

    def run(self) -> None:
        if self.command == "uninstall":
            self._run_uninstall()
            return

        self.config.ensure_directories()
        self.logger = configure_logger(self.config.log_path)
        connection = connect(self.config.db_path)
        initialize_database(connection, self.config.schema_path)
        seed_checklist_from_file(connection, self.config.checklist_path)
        checklist = checklist_summary(connection)
        checklist_items = list_checklist_items(connection)
        detected_tools = detect_installed_tools()

        self.console.print(Panel.fit(EVA_BANNER, title=APP_TITLE, style=section_style("accent")))
        self.console.print(build_main_menu())
        self.console.print(self._build_status_table(checklist, detected_tools))

        if self.command == "db":
            self._run_db_view(connection, checklist_items)
            return

        if self.show_checklist or self.checklist_step:
            self.console.print(build_checklist_table(checklist_items))

        if self.init_only or (not self.run_nmap and not self.tool and not self.checklist_step):
            self.console.print(
                "[bold green]Storage initialized.[/bold green] "
                "Use `neonape --target <host> --run-nmap` or "
                "`neonape --tool <name> --target <host>` to execute a tool workflow."
            )
            return

        if not self.target:
            self.console.print("[bold red]A target is required when running a tool workflow.[/bold red]")
            return

        if self.checklist_step is not None:
            self._run_checklist_step(connection, detected_tools)
            return

        if self.run_nmap:
            if "nmap" not in detected_tools:
                self.console.print("[bold red]nmap is not installed or not on PATH.[/bold red]")
                return
            self._run_nmap(connection)
            return

        if self.tool:
            if self.tool not in detected_tools:
                self.console.print(f"[bold red]{self.tool} is not installed or not on PATH.[/bold red]")
                return
            self._run_projectdiscovery_tool(connection)

    def _run_uninstall(self) -> None:
        targets = [
            f"launcher: {self.config.launcher_path}",
            f"install root: {self.config.install_root}",
        ]
        if self.uninstall_purge_data:
            targets.append(f"runtime data: {self.config.data_dir}")

        self.console.print(
            Panel.fit(
                "\n".join(targets),
                title="Uninstall Neon Ape",
                style=section_style("orange"),
            )
        )

        if not self.uninstall_yes:
            try:
                response = input("Proceed with uninstall? [y/N]: ").strip().lower()
            except EOFError:
                self.console.print("[bold red]Uninstall aborted. Re-run with `neonape uninstall --yes`.[/bold red]")
                return
            if response not in {"y", "yes"}:
                self.console.print("[bold yellow]Uninstall cancelled.[/bold yellow]")
                return

        self._remove_path(self.config.launcher_path)
        self._remove_path(self.config.install_root)
        if self.uninstall_purge_data:
            self._remove_path(self.config.data_dir)

        self.console.print("[bold green]Neon Ape uninstalled.[/bold green]")

    def _remove_path(self, path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
            return
        shutil.rmtree(path)

    def _run_db_view(self, connection, checklist_items: list[dict[str, str | int | None]]) -> None:
        if self.db_command == "tables":
            self.console.print(self._build_tables_table(list_tables(connection)))
            return
        if self.db_command == "checklist":
            self.console.print(build_checklist_table(checklist_items))
            return
        if self.db_command == "scans":
            self.console.print(self._build_scans_table(recent_scans(connection)))
            return
        if self.db_command == "findings":
            self.console.print(self._build_recent_findings_table(recent_findings(connection)))
            return
        self.console.print("[bold red]Unsupported db command.[/bold red]")

    def _run_checklist_step(self, connection, detected_tools: dict[str, str]) -> None:
        item = get_checklist_item(connection, self.checklist_step or 0)
        if item is None:
            self.console.print(f"[bold red]Checklist step {self.checklist_step} was not found.[/bold red]")
            return

        action_tool = item.get("action_tool")
        action_profile = item.get("action_profile")
        if not action_tool:
            self.console.print(
                Panel.fit(
                    f"[bold]Step:[/bold] {item['step_order']} {item['title']}\n"
                    f"[bold]Guide:[/bold] {item['guide_text']}\n"
                    f"[bold]Example:[/bold] {item['example_command']}",
                    title="MAGI Checklist",
                    style=section_style("accent"),
                )
            )
            self.console.print("[bold yellow]This checklist item is documentation-only and has no attached tool action.[/bold yellow]")
            return

        if action_tool not in detected_tools:
            self.console.print(f"[bold red]{action_tool} is not installed or not on PATH.[/bold red]")
            return

        self.console.print(
            Panel.fit(
                f"[bold]Step:[/bold] {item['step_order']} {item['title']}\n"
                f"[bold]Section:[/bold] {item['section_name']}\n"
                f"[bold]Guide:[/bold] {item['guide_text']}\n"
                f"[bold]Example:[/bold] {item['example_command']}",
                title="MAGI Checklist",
                style=section_style("accent"),
            )
        )

        if action_tool == "nmap":
            self.profile = str(action_profile or "service_scan")
            success = self._run_nmap(connection)
            self._mark_step_outcome(connection, item["step_order"], success)
            return

        self.tool = str(action_tool)
        success = self._run_projectdiscovery_tool(connection)
        self._mark_step_outcome(connection, item["step_order"], success)

    def _run_nmap(self, connection) -> bool:
        validated_target = validate_target(self.target or "")
        output_xml = self.config.scan_dir / f"{validated_target.replace('/', '_')}_{self.profile}.xml"
        command = build_nmap_command(validated_target, self.profile, output_xml)

        self.console.print(
            Panel.fit(
                f"[bold]Profile:[/bold] {self.profile}\n[bold]Target:[/bold] {validated_target}\n"
                f"[bold]Command:[/bold] {render_command_preview(command)}",
                title="Eva Unit Scanner",
                style=section_style("green"),
            )
        )

        result = execute_nmap(command, validated_target)
        findings = parse_nmap_xml(output_xml)
        record_scan(connection, result, findings)
        self.console.print(self._build_tool_output_table("nmap", findings))
        self.console.print(f"[bold green]nmap exit code:[/bold green] {result.exit_code}")
        return result.exit_code == 0

    def _run_projectdiscovery_tool(self, connection) -> bool:
        tool_name = self.tool or ""
        output_path = self.config.scan_dir / f"{tool_name}_{(self.target or '').replace('/', '_')}.jsonl"
        validated_target, command = build_projectdiscovery_command(tool_name, self.target or "", output_path)

        self.console.print(
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
        self.console.print(self._build_tool_output_table(tool_name, findings))
        self.console.print(f"[bold green]{tool_name} exit code:[/bold green] {result.exit_code}")
        return result.exit_code == 0

    def _mark_step_outcome(self, connection, step_order: int, success: bool) -> None:
        status = "complete" if success else "in_progress"
        mark_checklist_item_status(connection, step_order, status)
        label = "completed" if success else "left in progress"
        self.console.print(f"[bold cyan]Checklist step {step_order} {label}.[/bold cyan]")

    def _build_status_table(self, checklist: dict[str, str | int], detected_tools: dict[str, str]) -> Table:
        table = Table(title="AT Field Status", expand=False)
        table.add_column("Signal", style="bold")
        table.add_column("Value")
        table.add_row("Checklist Items", str(checklist.get("item_count", 0)))
        table.add_row("Database", self._display_runtime_path(self.config.db_path))
        table.add_row("Detected Tools", ", ".join(sorted(detected_tools)) or "None")
        return table

    def _build_findings_table(self, findings: list[dict[str, str]]) -> Table:
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

    def _build_tool_output_table(self, tool_name: str, findings: list[dict[str, str]]) -> Table:
        if tool_name == "httpx":
            return self._build_httpx_table(findings)
        if tool_name == "dnsx":
            return self._build_dnsx_table(findings)
        return self._build_findings_table(findings)

    def _build_httpx_table(self, findings: list[dict[str, str]]) -> Table:
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

    def _build_dnsx_table(self, findings: list[dict[str, str]]) -> Table:
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

    def _build_tables_table(self, tables: list[str]) -> Table:
        table = Table(title="Database Tables", expand=False)
        table.add_column("Table", style="bold")
        if not tables:
            table.add_row("-")
            return table
        for name in tables:
            table.add_row(name)
        return table

    def _build_scans_table(self, scans: list[dict[str, str | int | None]]) -> Table:
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
                str(scan.get("target", "-")),
                str(scan.get("status", "-")),
                str(scan.get("finished_at", "-")),
            )
        return table

    def _build_recent_findings_table(self, findings: list[dict[str, str | int | None]]) -> Table:
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

    def _display_runtime_path(self, path: Path) -> str:
        home = Path.home()
        try:
            return f"~/{path.relative_to(home)}"
        except ValueError:
            return path.name
