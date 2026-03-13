from pathlib import Path
from getpass import getpass
from rich.panel import Panel
from rich.console import Console

from neon_ape.commands.notes import run_add_note, run_notes_listing, run_view_note
from neon_ape.commands.review import run_review
from neon_ape.config import AppConfig, detect_installed_tools
from neon_ape.db.repository import (
    checklist_summary,
    initialize_database,
    list_checklist_items,
    recent_scans,
    seed_checklist_from_file,
)
from neon_ape.commands.db import run_db_view
from neon_ape.commands.interactive import run_interactive_shell
from neon_ape.commands.tools import run_chained_recon_workflow, run_checklist_step, run_nmap, run_projectdiscovery_tool
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
        self.review_target: str | None = None
        self.review_limit = 50
        self.review_json_output = False
        self.db_limit = 20
        self.db_tool: str | None = None
        self.db_finding_type: str | None = None
        self.db_domain_target: str | None = None
        self.db_json_output = False
        self.export_entity: str | None = None
        self.export_output: str | None = None
        self.export_format = "json"
        self.import_entity: str | None = None
        self.import_input: str | None = None
        self.notes_command: str | None = None
        self.note_title: str | None = None
        self.note_body: str | None = None
        self.note_target: str | None = None
        self.note_id: int | None = None
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
        self.workflow: str | None = None

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
        interactive_mode = not any((self.command, self.run_nmap, self.tool, self.checklist_step, self.workflow, self.init_only))

        self.console.print(Panel.fit(EVA_BANNER, title=APP_TITLE, style=section_style("accent")))
        if not interactive_mode:
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
                domain_target=self.db_domain_target,
                as_json=self.db_json_output,
                show_targets=self.show_targets,
            )
            return

        if self.command == "review":
            run_review(
                self.console,
                connection,
                target=str(self.review_target),
                limit=self.review_limit,
                as_json=self.review_json_output,
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

        if self.command == "notes":
            if self.notes_command == "list":
                run_notes_listing(self.console, connection, target=self.note_target)
                return
            passphrase = getpass("Notes passphrase: ")
            if self.notes_command == "add":
                run_add_note(
                    self.console,
                    connection,
                    passphrase=passphrase,
                    title=str(self.note_title),
                    body=str(self.note_body),
                    target=self.note_target,
                )
                return
            if self.notes_command == "view":
                run_view_note(
                    self.console,
                    connection,
                    passphrase=passphrase,
                    note_id=int(self.note_id),
                )
                return

        if self.show_checklist or self.checklist_step:
            self.console.print(build_checklist_table(checklist_items))

        if self.init_only:
            self.console.print(build_landing_panel(self.config.data_dir, checklist_items))
            self.console.print(build_quickstart_table())
            self.console.print(
                build_scans_table(
                    recent_scans(connection, limit=5),
                    mask_targets=self.config.privacy_mode and not self.show_targets,
                )
            )
            return

        if interactive_mode:
            run_interactive_shell(
                self.console,
                connection,
                config=self.config,
                detected_tools=detected_tools,
                show_targets=self.show_targets,
                current_profile=self.profile,
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
            return

        if self.workflow == "pd_chain":
            required_tools = {"subfinder", "httpx", "naabu"}
            missing_tools = sorted(tool for tool in required_tools if tool not in detected_tools)
            if missing_tools:
                self.console.print(f"[bold red]Missing workflow tools:[/bold red] {', '.join(missing_tools)}")
                return
            run_chained_recon_workflow(
                self.console,
                connection,
                target=self.target,
                scan_dir=self.config.scan_dir,
                workflow_name=self.workflow,
            )
            return

        if self.workflow == "pd_web_chain":
            required_tools = {"subfinder", "httpx", "nuclei"}
            missing_tools = sorted(tool for tool in required_tools if tool not in detected_tools)
            if missing_tools:
                self.console.print(f"[bold red]Missing workflow tools:[/bold red] {', '.join(missing_tools)}")
                return
            run_chained_recon_workflow(
                self.console,
                connection,
                target=self.target,
                scan_dir=self.config.scan_dir,
                workflow_name=self.workflow,
            )
