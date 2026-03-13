from pathlib import Path
from rich.panel import Panel
from rich.console import Console

from neon_ape.config import AppConfig, detect_installed_tools
from neon_ape.db.repository import (
    checklist_summary,
    initialize_database,
    list_checklist_items,
    recent_scans,
    seed_checklist_from_file,
)
from neon_ape.commands.db import run_db_view
from neon_ape.commands.tools import run_checklist_step, run_nmap, run_projectdiscovery_tool
from neon_ape.commands.transfer import run_export, run_import
from neon_ape.commands.uninstall import run_uninstall
from neon_ape.services.logging_utils import configure_logger
from neon_ape.services.storage import connect
from neon_ape.ui.ascii import EVA_BANNER
from neon_ape.ui.layout import build_checklist_table, build_main_menu
from neon_ape.ui.theme import APP_TITLE, section_style
from neon_ape.ui.views import build_landing_panel, build_quickstart_table, build_scans_table, build_status_table


class NeonApeApp:
    """Top-level local terminal application shell."""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.console = Console()
        self.config = config or AppConfig.default()
        self.logger = None
        self.command: str | None = None
        self.db_command: str | None = None
        self.db_limit = 20
        self.db_tool: str | None = None
        self.db_finding_type: str | None = None
        self.db_json_output = False
        self.export_entity: str | None = None
        self.export_output: str | None = None
        self.export_format = "json"
        self.import_entity: str | None = None
        self.import_input: str | None = None
        self.uninstall_yes = False
        self.uninstall_purge_data = False
        self.target: str | None = None
        self.profile = "service_scan"
        self.run_nmap = False
        self.init_only = False
        self.tool: str | None = None
        self.checklist_step: int | None = None
        self.show_checklist = False
        self.show_targets = False

    def run(self) -> None:
        if self.command == "uninstall":
            run_uninstall(
                self.console,
                self.config,
                assume_yes=self.uninstall_yes,
                purge_data=self.uninstall_purge_data,
            )
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
        self.console.print(build_status_table(checklist, self.config.db_path, detected_tools))

        if self.command == "db":
            run_db_view(
                self.console,
                connection,
                self.db_command,
                checklist_items,
                limit=self.db_limit,
                tool_name=self.db_tool,
                finding_type=self.db_finding_type,
                as_json=self.db_json_output,
                show_targets=self.show_targets,
            )
            return

        if self.command == "export":
            run_export(
                self.console,
                connection,
                entity=str(self.export_entity),
                output=Path(str(self.export_output)),
                export_format=self.export_format,
                limit=self.db_limit,
                tool_name=self.db_tool,
                finding_type=self.db_finding_type,
            )
            return

        if self.command == "import":
            run_import(
                self.console,
                connection,
                entity=str(self.import_entity),
                input_path=Path(str(self.import_input)),
            )
            return

        if self.show_checklist or self.checklist_step:
            self.console.print(build_checklist_table(checklist_items))

        if self.init_only or (not self.run_nmap and not self.tool and not self.checklist_step):
            self.console.print(build_landing_panel(self.config.data_dir, checklist_items))
            self.console.print(build_quickstart_table())
            self.console.print(
                build_scans_table(
                    recent_scans(connection, limit=5),
                    mask_targets=self.config.privacy_mode and not self.show_targets,
                )
            )
            return

        if not self.target:
            self.console.print("[bold red]A target is required when running a tool workflow.[/bold red]")
            return

        if self.checklist_step is not None:
            self.profile, self.tool = run_checklist_step(
                self.console,
                connection,
                checklist_step=self.checklist_step,
                target=self.target,
                detected_tools=detected_tools,
                scan_dir=self.config.scan_dir,
                profile=self.profile,
            )
            return

        if self.run_nmap:
            if "nmap" not in detected_tools:
                self.console.print("[bold red]nmap is not installed or not on PATH.[/bold red]")
                return
            run_nmap(
                self.console,
                connection,
                target=self.target,
                profile=self.profile,
                scan_dir=self.config.scan_dir,
            )
            return

        if self.tool:
            if self.tool not in detected_tools:
                self.console.print(f"[bold red]{self.tool} is not installed or not on PATH.[/bold red]")
                return
            run_projectdiscovery_tool(
                self.console,
                connection,
                tool_name=self.tool,
                target=self.target,
                scan_dir=self.config.scan_dir,
            )
