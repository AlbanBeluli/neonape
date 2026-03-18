from pathlib import Path
from getpass import getpass
from types import SimpleNamespace
from rich.panel import Panel
from rich.console import Console

from neon_ape.agents.adam import run_adam
from neon_ape.agents.autoresearch import run_autoresearch
from neon_ape.manuals.main_man import render_manual
from neon_ape.commands.notes import run_add_note, run_notes_listing, run_view_note
from neon_ape.commands.config import run_config_command
from neon_ape.commands.review import run_review
from neon_ape.commands.update import run_update
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
from neon_ape.commands.tools import run_chained_recon_workflow, run_checklist_step, run_gobuster, run_nmap, run_projectdiscovery_tool
from neon_ape.commands.transfer import run_export, run_import
from neon_ape.commands.uninstall import run_uninstall
from neon_ape.obsidian_sync import run_sync as run_obsidian_sync
from neon_ape.services.logging_utils import configure_logger
from neon_ape.services.storage import connect
from neon_ape.skills.manager import diff_skill, list_skills as list_saved_skills, skills_root, use_skill_version
from neon_ape.ui.ascii import EVA_BANNER
from neon_ape.ui.layout import build_checklist_table, build_main_menu
from neon_ape.ui.theme import APP_TITLE, section_style
from neon_ape.ui.views import build_landing_panel, build_missing_tools_panel, build_quickstart_table, build_scans_table, build_status_table, build_welcome_panel
from rich.table import Table


class NeonApeApp:
    """Top-level local terminal application shell."""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.console = Console()
        self.config = config or AppConfig.default()
        self.logger = None
        self.command: str | None = None
        self.manual_topic: str | None = None
        self.db_command: str | None = None
        self.config_action: str | None = None
        self.config_key: str | None = None
        self.config_value: str | None = None
        self.review_target: str | None = None
        self.review_limit = 50
        self.review_json_output = False
        self.review_llm_triage = False
        self.review_llm_provider: str | None = None
        self.review_llm_model: str | None = None
        self.review_web_paths_only = False
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
        self.update_yes = False
        self.obsidian_vault_path: str | None = None
        self.obsidian_target_note: str | None = None
        self.obsidian_notes_passphrase: str | None = None
        self.obsidian_limit = 200
        self.obsidian_open = False
        self.obsidian_dry_run = False
        self.obsidian_skip_run = False
        self.target: str | None = None
        self.profile = "service_scan"
        self.run_nmap = False
        self.init_only = False
        self.tool: str | None = None
        self.checklist_step: int | None = None
        self.show_checklist = False
        self.show_targets = False
        self.workflow: str | None = None
        self.adam_target: str | None = None
        self.adam_autoresearch = False
        self.adam_autoresearch_target: str | None = None
        self.autoresearch_target: str | None = None
        self.autoresearch_questions: list[str] = []
        self.autoresearch_scenarios: list[str] = []
        self.autoresearch_iterations = 6
        self.autoresearch_baseline_runs = 8
        self.autoresearch_overnight = False
        self.skill_command: str | None = None
        self.skill_name: str | None = None
        self.skill_version: str | None = None

    def run(self) -> None:
        if self.command == "man":
            render_manual(self.console, topic=self.manual_topic or "main")
            return

        if self.command == "uninstall":
            run_uninstall(
                self.console,
                self.config,
                assume_yes=self.uninstall_yes,
                purge_data=self.uninstall_purge_data,
            )
            return

        if self.command == "update":
            run_update(
                self.console,
                self.config,
                assume_yes=self.update_yes,
            )
            return

        if self.command == "config":
            run_config_command(
                self.console,
                self.config,
                action=str(self.config_action),
                key=self.config_key,
                value=self.config_value,
            )
            return

        if self.command == "obsidian":
            status = run_obsidian_sync(
                SimpleNamespace(
                    vault_path=self.obsidian_vault_path,
                    target_note=self.obsidian_target_note,
                    notes_passphrase=self.obsidian_notes_passphrase,
                    limit=self.obsidian_limit,
                    open=self.obsidian_open,
                    dry_run=self.obsidian_dry_run,
                    skip_run=self.obsidian_skip_run,
                ),
                console=self.console,
            )
            if status != 0:
                raise SystemExit(status)
            return

        if self.command == "adam":
            self.config.ensure_directories()
            self.logger = configure_logger(self.config.log_path)
            connection = connect(self.config.db_path)
            initialize_database(connection, self.config.schema_path)
            seed_checklist_from_file(connection, self.config.checklist_path)
            detected_tools = detect_installed_tools()
            success = run_adam(
                self.console,
                connection,
                config=self.config,
                detected_tools=detected_tools,
                target=self.adam_target,
                autoresearch_enabled=self.adam_autoresearch,
                autoresearch_target=self.adam_autoresearch_target,
            )
            if not success:
                raise SystemExit(1)
            return

        if self.command == "autoresearch":
            self.config.ensure_directories()
            self.logger = configure_logger(self.config.log_path)
            success = run_autoresearch(
                self.console,
                config=self.config,
                skill_target=self.autoresearch_target,
                questions=self.autoresearch_questions,
                scenarios=self.autoresearch_scenarios,
                overnight=self.autoresearch_overnight,
                iterations=self.autoresearch_iterations,
                baseline_runs=self.autoresearch_baseline_runs,
            )
            if not success:
                raise SystemExit(1)
            return

        if self.command == "skill":
            self.config.ensure_directories()
            self.logger = configure_logger(self.config.log_path)
            if self.skill_command == "list":
                rows = list_saved_skills()
                table = Table(title="Persistent Skills", expand=False)
                table.add_column("Skill", style="bold magenta")
                table.add_column("Label")
                table.add_column("Score")
                table.add_column("Last Improved")
                table.add_column("Store")
                for row in rows:
                    table.add_row(
                        str(row.get("skill", "-")),
                        str(row.get("label", "-")),
                        str(row.get("score", "-")),
                        str(row.get("last_improved", "-")),
                        str(skills_root()),
                    )
                if not rows:
                    self.console.print(f"[bold yellow]No persistent skills saved yet.[/bold yellow] Store: {skills_root()}")
                else:
                    self.console.print(table)
                return
            if self.skill_command == "diff":
                try:
                    content = diff_skill(str(self.skill_name))
                except ValueError as exc:
                    self.console.print(f"[bold red]{exc}[/bold red]")
                    return
                self.console.print(
                    Panel.fit(
                        content,
                        title=f"Skill Diff: {self.skill_name}",
                        style=section_style("accent"),
                    )
                )
                return
            if self.skill_command == "use":
                try:
                    active = use_skill_version(str(self.skill_name), str(self.skill_version))
                except ValueError as exc:
                    self.console.print(f"[bold red]{exc}[/bold red]")
                    return
                self.console.print(
                    Panel.fit(
                        f"[bold]Skill:[/bold] {active.get('skill')}\n"
                        f"[bold]Activated:[/bold] {active.get('activated_at')}\n"
                        f"[bold]Score:[/bold] {active.get('score')}",
                        title="Skill Activated",
                        style=section_style("accent"),
                    )
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
        machine_output_mode = (self.command == "db" and self.db_json_output) or (self.command == "review" and self.review_json_output)

        if not machine_output_mode:
            self.console.print(Panel.fit(EVA_BANNER, title=APP_TITLE, style=section_style("accent")))
        if not interactive_mode and not machine_output_mode:
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
                llm_triage=self.review_llm_triage,
                llm_provider=self.review_llm_provider or self.config.llm_provider,
                llm_model=self.review_llm_model or self.config.llm_model,
                web_paths_only=self.review_web_paths_only,
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
            self.console.print(build_welcome_panel())
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
                self.console.print(build_missing_tools_panel(["nmap"]))
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
                self.console.print(build_missing_tools_panel([self.tool]))
                return
            if self.tool == "gobuster":
                run_gobuster(
                    self.console,
                    connection,
                    target=self.target,
                    scan_dir=self.config.scan_dir,
                )
                return
            run_projectdiscovery_tool(
                self.console,
                connection,
                tool_name=self.tool,
                target=self.target,
                scan_dir=self.config.scan_dir,
            )
            return

        if self.workflow:
            workflow_tools = {
                "pd_chain": {"subfinder", "httpx", "naabu"},
                "pd_web_chain": {"subfinder", "httpx", "nuclei"},
                "light_recon": {"assetfinder", "subfinder", "httpx"},
                "deep_recon": {"assetfinder", "subfinder", "amass", "dnsx", "httpx", "naabu", "nuclei"},
                "js_web_chain": {"subfinder", "httpx", "katana", "nuclei"},
            }
            missing_tools = sorted(tool for tool in workflow_tools.get(self.workflow, set()) if tool not in detected_tools)
            if missing_tools:
                self.console.print(build_missing_tools_panel(missing_tools))
                return
            run_chained_recon_workflow(
                self.console,
                connection,
                target=self.target,
                scan_dir=self.config.scan_dir,
                workflow_name=self.workflow,
            )
            return
