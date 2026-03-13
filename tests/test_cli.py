from neon_ape.cli import build_parser


def test_parse_db_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["db", "tables"])
    assert args.command == "db"
    assert args.db_command == "tables"


def test_parse_uninstall_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["uninstall", "--purge-data", "--yes"])
    assert args.command == "uninstall"
    assert args.purge_data is True
    assert args.yes is True


def test_parse_tool_command_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tool", "httpx", "--target", "https://example.com"])
    assert args.tool == "httpx"
    assert args.target == "https://example.com"


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


def test_parse_export_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["export", "scans", "--output", "scans.json", "--format", "json", "--limit", "10"])
    assert args.command == "export"
    assert args.export_entity == "scans"
    assert args.output == "scans.json"
    assert args.export_format == "json"
    assert args.limit == 10
