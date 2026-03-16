from __future__ import annotations

import argparse

from neon_ape.app import NeonApeApp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neonape",
        description="Neon Ape local terminal dashboard for checklist-driven recon workflows.",
        epilog=(
            "Examples:\n"
            "  neonape\n"
            "  neonape --show-checklist --init-only\n"
            "  neonape --workflow pd_chain --target example.com\n"
            "  neonape --workflow pd_web_chain --target example.com\n"
            "  neonape --workflow light_recon --target example.com\n"
            "  neonape --workflow deep_recon --target example.com\n"
            "  neonape --workflow js_web_chain --target example.com\n"
            "  neonape --checklist-step 2 --target example.com\n"
            "  neonape --checklist-step 3 --target example.com\n"
            "  neonape --checklist-step 4 --target 192.168.1.10\n"
            "  neonape --checklist-step 5 --target https://example.com\n"
            "  neonape --checklist-step 6 --target 192.168.1.10\n"
            "  neonape --target 192.168.1.10 --run-nmap --profile service_scan\n"
            "  neonape --target 192.168.1.0/24 --run-nmap --profile host_discovery\n"
            "  neonape --tool subfinder --target example.com\n"
            "  neonape --tool dnsx --target example.com\n"
            "  neonape --tool httpx --target https://example.com\n"
            "  neonape --tool naabu --target 192.168.1.10\n\n"
            "  neonape --tool nuclei --target https://example.com\n\n"
            "  neonape --tool assetfinder --target example.com\n"
            "  neonape --tool amass --target example.com\n"
            "  neonape --tool katana --target https://example.com\n"
            "  neonape --tool gobuster --target https://example.com\n\n"
            "Database views:\n"
            "  neonape db tables\n"
            "  neonape db checklist\n"
            "  neonape db scans\n"
            "  neonape db findings\n"
            "  neonape db inventory\n"
            "  neonape db reviews\n"
            "  neonape db notes\n"
            "  neonape db domain --target example.com\n"
            "  neonape db cleanup-history\n\n"
            "Review:\n"
            "  neonape review --target example.com\n\n"
            "  neonape review --target example.com --llm-triage\n"
            "  neonape review --target example.com --llm-triage --llm-model llama3.2:3b\n\n"
            "  neonape review --target example.com --llm-triage --llm-provider cline\n\n"
            "Maintenance:\n"
            "  neonape update\n"
            "  neonape update --yes\n"
            "  neonape uninstall\n"
            "  neonape uninstall --purge-data --yes\n\n"
            "Config:\n"
            "  neonape config show\n"
            "  neonape config init\n"
            "  neonape config set privacy_mode false\n"
            "  neonape config set theme_name eva\n"
            "  neonape config set obsidian_vault_path ~/Documents/Obsidian\n\n"
            "  neonape config set llm_provider cline\n"
            "  neonape config set llm_model qwen3.5:4b\n\n"
            "Obsidian:\n"
            "  neonape obsidian --target-note Pentests/example.com/Target.md\n"
            "  neonape obsidian --target-note Pentests/example.com/Target.md --dry-run\n\n"
            "Transfer:\n"
            "  neonape export scans --output scans.json\n"
            "  neonape export findings --format csv --output findings.csv\n"
            "  neonape import scans --input scans.json\n\n"
            "Notes:\n"
            "  neonape notes list\n"
            "  neonape notes add --title \"Login panel\" --body \"Observed admin portal\" --target app.example.com\n"
            "  neonape notes view --id 1\n\n"
            "Nmap profiles:\n"
            "  host_discovery  nmap -sn <target>\n"
            "  service_scan    nmap -sV <target>\n"
            "  aggressive      nmap -A -T4 <target>\n\n"
            "ProjectDiscovery wrappers:\n"
            "  subfinder  passive subdomain discovery for domains\n"
            "  dnsx       DNS A/AAAA/CNAME/NS/MX/TXT resolution for domains\n"
            "  httpx      HTTP probing for URLs or hosts\n"
            "  naabu      top-100 TCP port probing for hosts or IPs\n"
            "  nuclei     HTTP template checks with JSONL findings\n\n"
            "  assetfinder passive subdomain discovery for domains\n"
            "  amass      passive amass subdomain enumeration\n"
            "  katana     JSONL web crawl for reachable HTTP targets\n"
            "  gobuster   directory brute forcing with safe defaults\n\n"
            "Chained workflows:\n"
            "  pd_chain      subfinder -> httpx -> naabu\n"
            "  pd_web_chain  subfinder -> httpx -> nuclei\n"
            "  light_recon   assetfinder + subfinder -> httpx\n"
            "  deep_recon    assetfinder + subfinder + amass -> dnsx -> httpx -> naabu -> nuclei\n"
            "  js_web_chain  subfinder -> httpx -> katana -> nuclei"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
    update_parser = subparsers.add_parser("update", help="Refresh an install-managed Neon Ape copy in place.")
    update_parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    config_parser = subparsers.add_parser("config", help="Show or update Neon Ape user config.")
    config_subparsers = config_parser.add_subparsers(dest="config_action", required=True)
    config_subparsers.add_parser("show", help="Show the effective Neon Ape config.")
    config_subparsers.add_parser("init", help="Write a starter config file if one does not exist.")
    config_set = config_subparsers.add_parser("set", help="Set a config key in ~/.config/neonape/config.toml.")
    config_set.add_argument("key", help="Config key to change.")
    config_set.add_argument("value", help="New value for the config key.")
    obsidian_parser = subparsers.add_parser("obsidian", help="Sync Neon Ape data into an Obsidian vault.")
    obsidian_parser.add_argument("--vault-path", help="Absolute path to the vault root. Falls back to config or current vault.")
    obsidian_parser.add_argument("--target-note", required=True, help="Path to the source Markdown note relative to the vault.")
    obsidian_parser.add_argument("--notes-passphrase", help="Optional passphrase used to decrypt Neon Ape notes.")
    obsidian_parser.add_argument("--limit", type=int, default=200, help="Maximum number of rows to pull from the Neon Ape domain view.")
    obsidian_parser.add_argument("--open", action="store_true", help="Try to open the synced target note in Obsidian.")
    obsidian_parser.add_argument("--dry-run", action="store_true", help="Preview generated paths and content without writing.")
    obsidian_parser.add_argument("--skip-run", action="store_true", help="Skip running a new workflow and only export local data.")

    review_parser = subparsers.add_parser("review", help="Show normalized service inventory and local review matches for a target.")
    review_parser.add_argument("--target", required=True, help="Domain, host, or target string to review.")
    review_parser.add_argument("--limit", type=int, default=50, help="Maximum number of rows per section to show.")
    review_parser.add_argument("--json", action="store_true", help="Emit JSON instead of Rich tables.")
    review_parser.add_argument("--llm-triage", action="store_true", help="Run local findings triage through Ollama after the standard review tables.")
    review_parser.add_argument("--llm-provider", choices=("ollama", "cline"), help="Choose the local LLM provider for triage.")
    review_parser.add_argument("--llm-model", help="Override the configured local Ollama model for this run.")
    db_parser = subparsers.add_parser("db", help="Inspect stored SQLite data through built-in read-only views.")
    db_subparsers = db_parser.add_subparsers(dest="db_command", required=True)
    db_tables_parser = db_subparsers.add_parser("tables", help="List Neon Ape database tables.")
    db_tables_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_checklist_parser = db_subparsers.add_parser("checklist", help="Show checklist step status and attached actions.")
    db_checklist_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_scans_parser = db_subparsers.add_parser("scans", help="Show recent scan runs.")
    db_scans_parser.add_argument("--limit", type=int, default=20, help="Maximum number of scan rows to show.")
    db_scans_parser.add_argument("--tool", help="Filter scans by tool name.")
    db_scans_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_findings_parser = db_subparsers.add_parser("findings", help="Show recent parsed findings.")
    db_findings_parser.add_argument("--limit", type=int, default=50, help="Maximum number of finding rows to show.")
    db_findings_parser.add_argument("--type", dest="finding_type", help="Filter findings by finding type.")
    db_findings_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_inventory_parser = db_subparsers.add_parser("inventory", help="Show normalized service inventory entries.")
    db_inventory_parser.add_argument("--limit", type=int, default=50, help="Maximum number of inventory rows to show.")
    db_inventory_parser.add_argument("--target", dest="domain_target", help="Optional host or target filter.")
    db_inventory_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_reviews_parser = db_subparsers.add_parser("reviews", help="Show normalized review matches.")
    db_reviews_parser.add_argument("--limit", type=int, default=50, help="Maximum number of review rows to show.")
    db_reviews_parser.add_argument("--target", dest="domain_target", help="Optional host or target filter.")
    db_reviews_parser.add_argument("--severity", dest="finding_type", choices=("medium", "high", "critical"), help="Optional severity filter.")
    db_reviews_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_notes_parser = db_subparsers.add_parser("notes", help="Show encrypted note headers.")
    db_notes_parser.add_argument("--limit", type=int, default=50, help="Maximum number of note rows to show.")
    db_notes_parser.add_argument("--target", dest="domain_target", help="Optional target or title filter.")
    db_notes_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a Rich table.")
    db_domain_parser = db_subparsers.add_parser("domain", help="Show stored scans, findings, and notes that match a domain or target string.")
    db_domain_parser.add_argument("--target", dest="domain_target", required=True, help="Domain or target string to search for.")
    db_domain_parser.add_argument("--limit", type=int, default=50, help="Maximum number of rows per section to show.")
    db_domain_parser.add_argument("--json", action="store_true", help="Emit JSON instead of Rich tables.")
    db_subparsers.add_parser(
        "cleanup-history",
        help="Rewrite older chained httpx/naabu history rows to the newer stable workflow labels.",
    )
    uninstall_parser = subparsers.add_parser("uninstall", help="Remove the installed Neon Ape command and private install.")
    uninstall_parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    uninstall_parser.add_argument(
        "--purge-data",
        action="store_true",
        help="Also remove runtime data under ~/.neon_ape.",
    )
    export_parser = subparsers.add_parser("export", help="Export scans or findings from the local database.")
    export_subparsers = export_parser.add_subparsers(dest="export_entity", required=True)
    export_scans = export_subparsers.add_parser("scans", help="Export scan history.")
    export_scans.add_argument("--output", required=True, help="Output file path.")
    export_scans.add_argument("--format", dest="export_format", choices=("json", "csv"), default="json")
    export_scans.add_argument("--limit", type=int, default=100)
    export_scans.add_argument("--tool", help="Filter scans by tool name.")
    export_findings = export_subparsers.add_parser("findings", help="Export findings.")
    export_findings.add_argument("--output", required=True, help="Output file path.")
    export_findings.add_argument("--format", dest="export_format", choices=("json", "csv"), default="json")
    export_findings.add_argument("--limit", type=int, default=100)
    export_findings.add_argument("--type", dest="finding_type", help="Filter findings by type.")

    import_parser = subparsers.add_parser("import", help="Import supported export bundles into the local database.")
    import_subparsers = import_parser.add_subparsers(dest="import_entity", required=True)
    import_scans = import_subparsers.add_parser("scans", help="Import a previously exported scan bundle.")
    import_scans.add_argument("--input", required=True, help="Input JSON file path.")

    notes_parser = subparsers.add_parser("notes", help="Manage encrypted local notes.")
    notes_subparsers = notes_parser.add_subparsers(dest="notes_command", required=True)
    notes_list = notes_subparsers.add_parser("list", help="List encrypted note headers.")
    notes_list.add_argument("--target", help="Filter notes by target.")
    notes_add = notes_subparsers.add_parser("add", help="Add an encrypted note.")
    notes_add.add_argument("--title", required=True, help="Short note title.")
    notes_add.add_argument("--body", required=True, help="Note body text.")
    notes_add.add_argument("--target", help="Optional target label.")
    notes_view = notes_subparsers.add_parser("view", help="Decrypt and display a note.")
    notes_view.add_argument("--id", dest="note_id", required=True, type=int, help="Note identifier.")

    parser.add_argument(
        "--target",
        help="Validated target hostname, domain, URL, IP, or CIDR depending on the selected action.",
    )
    parser.add_argument(
        "--profile",
        default="service_scan",
        choices=("host_discovery", "service_scan", "aggressive"),
        help="Nmap command profile: host_discovery (-sn), service_scan (-sV), or aggressive (-A -T4).",
    )
    parser.add_argument(
        "--run-nmap",
        action="store_true",
        help="Execute the safe nmap workflow for the provided target.",
    )
    parser.add_argument(
        "--tool",
        choices=("subfinder", "assetfinder", "amass", "httpx", "naabu", "dnsx", "nuclei", "katana", "gobuster"),
        help="Execute a supported recon or web-enumeration tool with safe defaults.",
    )
    parser.add_argument(
        "--workflow",
        choices=("pd_chain", "pd_web_chain", "light_recon", "deep_recon", "js_web_chain"),
        help="Execute a chained workflow. Supports pd_chain, pd_web_chain, light_recon, deep_recon, and js_web_chain.",
    )
    parser.add_argument(
        "--checklist-step",
        type=int,
        help="Execute the action attached to a checklist step for the provided target.",
    )
    parser.add_argument(
        "--show-checklist",
        action="store_true",
        help="Display checklist items and any attached actions.",
    )
    parser.add_argument(
        "--init-only",
        action="store_true",
        help="Initialize storage and seed checklists without running tools.",
    )
    parser.add_argument(
        "--show-targets",
        action="store_true",
        help="Show full targets in landing views instead of masking them.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    app = NeonApeApp()
    app.command = args.command
    app.config_action = getattr(args, "config_action", None)
    app.config_key = getattr(args, "key", None)
    app.config_value = getattr(args, "value", None)
    app.review_target = getattr(args, "target", None) if args.command == "review" else None
    app.review_limit = getattr(args, "limit", 50) if args.command == "review" else 50
    app.review_json_output = getattr(args, "json", False) if args.command == "review" else False
    app.review_llm_triage = getattr(args, "llm_triage", False) if args.command == "review" else False
    app.review_llm_provider = getattr(args, "llm_provider", None) if args.command == "review" else None
    app.review_llm_model = getattr(args, "llm_model", None) if args.command == "review" else None
    app.db_command = getattr(args, "db_command", None)
    app.db_limit = getattr(args, "limit", 20)
    app.db_tool = getattr(args, "tool", None)
    app.db_finding_type = getattr(args, "finding_type", None)
    app.db_domain_target = getattr(args, "domain_target", None)
    app.db_json_output = getattr(args, "json", False)
    app.export_entity = getattr(args, "export_entity", None)
    app.export_output = getattr(args, "output", None)
    app.export_format = getattr(args, "export_format", "json")
    app.import_entity = getattr(args, "import_entity", None)
    app.import_input = getattr(args, "input", None)
    app.notes_command = getattr(args, "notes_command", None)
    app.note_title = getattr(args, "title", None)
    app.note_body = getattr(args, "body", None)
    app.note_target = getattr(args, "target", None) if args.command == "notes" else None
    app.note_id = getattr(args, "note_id", None)
    app.uninstall_yes = getattr(args, "yes", False)
    app.uninstall_purge_data = getattr(args, "purge_data", False)
    app.update_yes = getattr(args, "yes", False) if args.command == "update" else False
    app.obsidian_vault_path = getattr(args, "vault_path", None)
    app.obsidian_target_note = getattr(args, "target_note", None)
    app.obsidian_notes_passphrase = getattr(args, "notes_passphrase", None)
    app.obsidian_limit = getattr(args, "limit", 200) if args.command == "obsidian" else 200
    app.obsidian_open = getattr(args, "open", False) if args.command == "obsidian" else False
    app.obsidian_dry_run = getattr(args, "dry_run", False) if args.command == "obsidian" else False
    app.obsidian_skip_run = getattr(args, "skip_run", False) if args.command == "obsidian" else False
    app.target = args.target
    app.profile = args.profile
    app.run_nmap = args.run_nmap
    app.init_only = args.init_only
    app.tool = args.tool
    app.workflow = args.workflow
    app.checklist_step = args.checklist_step
    app.show_checklist = args.show_checklist
    app.show_targets = args.show_targets
    app.run()
    return 0
