from pathlib import Path

from neon_ape.cli import build_parser
from neon_ape.app import NeonApeApp
from neon_ape.config import AppConfig


def test_parse_db_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["db", "tables"])
    assert args.command == "db"
    assert args.db_command == "tables"


def test_parse_config_set_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["config", "set", "privacy_mode", "false"])
    assert args.command == "config"
    assert args.config_action == "set"
    assert args.key == "privacy_mode"
    assert args.value == "false"


def test_parse_uninstall_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["uninstall", "--purge-data", "--yes"])
    assert args.command == "uninstall"
    assert args.purge_data is True
    assert args.yes is True


def test_parse_update_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["update", "--yes"])
    assert args.command == "update"
    assert args.yes is True


def test_parse_tool_command_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tool", "httpx", "--target", "https://example.com"])
    assert args.tool == "httpx"
    assert args.target == "https://example.com"


def test_parse_nuclei_tool_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tool", "nuclei", "--target", "https://example.com"])
    assert args.tool == "nuclei"
    assert args.target == "https://example.com"


def test_parse_katana_tool_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tool", "katana", "--target", "https://example.com"])
    assert args.tool == "katana"
    assert args.target == "https://example.com"


def test_parse_gobuster_tool_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tool", "gobuster", "--target", "https://example.com"])
    assert args.tool == "gobuster"
    assert args.target == "https://example.com"


def test_parse_assetfinder_tool_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tool", "assetfinder", "--target", "example.com"])
    assert args.tool == "assetfinder"
    assert args.target == "example.com"


def test_parse_show_targets_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--show-targets"])
    assert args.show_targets is True


def test_parse_db_scan_filters() -> None:
    parser = build_parser()
    args = parser.parse_args(["db", "scans", "--limit", "5", "--tool", "httpx", "--json"])
    assert args.command == "db"
    assert args.db_command == "scans"
    assert args.limit == 5
    assert args.tool == "httpx"
    assert args.json is True


def test_parse_db_domain_view() -> None:
    parser = build_parser()
    args = parser.parse_args(["db", "domain", "--target", "example.com", "--limit", "10"])
    assert args.command == "db"
    assert args.db_command == "domain"
    assert args.domain_target == "example.com"
    assert args.limit == 10


def test_parse_db_inventory_view() -> None:
    parser = build_parser()
    args = parser.parse_args(["db", "inventory", "--target", "example.com", "--limit", "10", "--json"])
    assert args.command == "db"
    assert args.db_command == "inventory"
    assert args.domain_target == "example.com"
    assert args.limit == 10
    assert args.json is True


def test_parse_db_reviews_view() -> None:
    parser = build_parser()
    args = parser.parse_args(["db", "reviews", "--target", "example.com", "--severity", "high"])
    assert args.command == "db"
    assert args.db_command == "reviews"
    assert args.domain_target == "example.com"
    assert args.finding_type == "high"


def test_parse_obsidian_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["obsidian", "--target-note", "Pentests/example.com/Target.md", "--dry-run", "--skip-run"])
    assert args.command == "obsidian"
    assert args.target_note == "Pentests/example.com/Target.md"
    assert args.dry_run is True
    assert args.skip_run is True


def test_parse_review_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["review", "--target", "example.com", "--limit", "25", "--json"])
    assert args.command == "review"
    assert args.target == "example.com"
    assert args.limit == 25
    assert args.json is True


def test_parse_review_llm_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["review", "--target", "example.com", "--llm-triage", "--llm-model", "llama3.2:3b"])
    assert args.command == "review"
    assert args.llm_triage is True
    assert args.llm_model == "llama3.2:3b"


def test_parse_export_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["export", "scans", "--output", "scans.json", "--format", "json", "--limit", "10"])
    assert args.command == "export"
    assert args.export_entity == "scans"
    assert args.output == "scans.json"
    assert args.export_format == "json"
    assert args.limit == 10


def test_parse_workflow_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--workflow", "pd_chain", "--target", "example.com"])
    assert args.workflow == "pd_chain"
    assert args.target == "example.com"


def test_parse_web_workflow_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--workflow", "pd_web_chain", "--target", "example.com"])
    assert args.workflow == "pd_web_chain"
    assert args.target == "example.com"


def test_parse_deep_recon_workflow_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--workflow", "deep_recon", "--target", "example.com"])
    assert args.workflow == "deep_recon"
    assert args.target == "example.com"


def test_parse_notes_add_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["notes", "add", "--title", "Login", "--body", "Panel observed", "--target", "app.example.com"])
    assert args.command == "notes"
    assert args.notes_command == "add"
    assert args.title == "Login"
    assert args.body == "Panel observed"


def test_db_json_mode_avoids_banner_output(tmp_path, monkeypatch) -> None:
    output: list[str] = []

    class StubConsole:
        def print(self, message) -> None:
            output.append(str(message))

        def print_json(self, message: str) -> None:
            output.append(message)

    config = AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=Path(__file__).resolve().parents[1] / "neon_ape" / "db" / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=None,
    )
    checklist_path = Path(__file__).resolve().parents[1] / "neon_ape" / "checklists" / "neon_ape_checklist.json"
    config.checklist_path = checklist_path  # type: ignore[misc]
    monkeypatch.setattr("neon_ape.app.configure_logger", lambda path: None)

    app = NeonApeApp(config=config)
    app.console = StubConsole()
    app.command = "db"
    app.db_command = "tables"
    app.db_json_output = True
    app.run()

    assert output
    assert not any("Neon Ape" in line for line in output[:-1])
