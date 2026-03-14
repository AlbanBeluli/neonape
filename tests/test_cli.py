from neon_ape.cli import build_parser


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
