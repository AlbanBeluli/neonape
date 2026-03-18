from __future__ import annotations

import argparse

from neon_ape.app import NeonApeApp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neonape",
        description=(
            "Neon Ape is a local-only Evangelion-inspired operator console for Adam-driven recon, "
            "MAGI checklists, Angel Eyes web review, and encrypted reporting."
        ),
        epilog=(
            "Recommended:\n"
            "  neonape adam --target example.com\n\n"
            "Status:\n"
            "  neonape status\n\n"
            "Manuals:\n"
            "  neonape man\n"
            "  neonape man adam\n"
            "  neonape man checklist\n\n"
            "Adam:\n"
            "  neonape adam\n"
            "  neonape adam --target example.com\n"
            "  neonape adam --target example.com --pdf\n"
            "  neonape adam --autoresearch --target example.com\n\n"
            "Autoresearch:\n"
            "  neonape autoresearch --target magi-checklist --auto\n"
            "  neonape autoresearch --target angel-eyes --auto --test-target stoic.ee --pdf\n"
            "  neonape autoresearch --target angel-eyes --headless --rounds 100\n\n"
            "Skills:\n"
            "  neonape skill list\n"
            "  neonape skill diff magi-checklist\n"
            "  neonape skill use magi-checklist --version 2026-03-18\n\n"
            "Setup:\n"
            "  neonape setup notifications\n\n"
            "  neonape setup tools --yes\n\n"
            "Workflows:\n"
            "  neonape --workflow pd_web_chain --target example.com\n"
            "  neonape --workflow light_recon --target example.com\n"
            "  neonape --workflow deep_recon --target example.com\n"
            "  neonape --show-checklist --init-only\n\n"
            "Review:\n"
            "  neonape review --target example.com --web-paths\n"
            "  neonape review --target example.com --llm-triage\n"
            "  neonape obsidian --target-note Pentests/example.com/Target.md --dry-run\n\n"
            "Database:\n"
            "  neonape db domain --target example.com\n"
            "  neonape db reviews --target example.com --severity high\n"
            "  neonape db checklist\n\n"
            "Maintenance:\n"
            "  neonape update --yes\n"
            "  neonape uninstall --purge-data --yes"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("status", help="Show persistent skill health and overall Neon Ape status.")
    man_parser = subparsers.add_parser("man", help="Open the Neon Ape operator manual.")
    man_subparsers = man_parser.add_subparsers(dest="man_topic")
    man_subparsers.add_parser("adam", help="Open the dedicated Adam manual.")
    man_subparsers.add_parser("checklist", help="Open the dedicated MAGI checklist manual.")
    update_parser = subparsers.add_parser("update", help="Refresh an install-managed Neon Ape copy in place.")
    update_parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    setup_parser = subparsers.add_parser("setup", help="Install optional local operator dependencies.")
    setup_subparsers = setup_parser.add_subparsers(dest="setup_command", required=True)
    setup_notifications = setup_subparsers.add_parser("notifications", help="Install terminal-notifier on macOS via Homebrew.")
    setup_notifications.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    setup_tools = setup_subparsers.add_parser("tools", help="Install managed local recon tools such as whois, dig, nmap, and gobuster.")
    setup_tools.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    config_parser = subparsers.add_parser("config", help="Show or update Neon Ape user config.")
    config_subparsers = config_parser.add_subparsers(dest="config_action", required=True)
    config_subparsers.add_parser("show", help="Show the effective Neon Ape config.")
    config_subparsers.add_parser("init", help="Write a starter config file if one does not exist.")
    config_set = config_subparsers.add_parser("set", help="Set a config key in ~/.config/neonape/config.toml.")
    config_set.add_argument("key", help="Config key to change.")
    config_set.add_argument("value", help="New value for the config key.")
    adam_parser = subparsers.add_parser("adam", help="Run Adam, the autonomous web review orchestrator.")
    adam_parser.add_argument("--target", help="Seed domain for Adam. If omitted, Neon Ape prompts for a domain.")
    adam_parser.add_argument("--pdf", action="store_true", help="Generate a PDF report in the daily report folder when Adam completes.")
    adam_parser.add_argument("--autoresearch", action="store_true", help="Run autoresearch against MAGI Checklist or Angel Eyes after Adam finishes recon.")
    adam_parser.add_argument("--autoresearch-target", choices=("magi-checklist", "angel-eyes", "nmap-wrappers", "ui-panels", "prompt-templates", "triage-prompt", "adam-workflow"), help="Optional explicit skill for Adam's autoresearch phase.")
    autoresearch_parser = subparsers.add_parser("autoresearch", help="Run the local autoresearch loop against a Neon Ape skill.")
    autoresearch_parser.add_argument("--target", choices=("magi-checklist", "angel-eyes", "nmap-wrappers", "ui-panels", "prompt-templates", "triage-prompt", "adam-workflow"), help="Skill target to improve.")
    autoresearch_parser.add_argument("--question", action="append", default=[], help="Yes/no research question. Can be repeated up to six times.")
    autoresearch_parser.add_argument("--scenario", action="append", default=[], help="Test scenario. Can be repeated up to five times.")
    autoresearch_parser.add_argument("--iterations", type=int, default=6, help="Number of tiny-change iterations to evaluate.")
    autoresearch_parser.add_argument("--rounds", type=int, help="Alias for --iterations.")
    autoresearch_parser.add_argument("--baseline-runs", type=int, default=8, help="How many scoring runs to average for baseline and candidates.")
    autoresearch_parser.add_argument("--test-target", action="append", default=[], help="Optional safe test target label for the objective harness. Can be repeated.")
    autoresearch_parser.add_argument("--pdf", action="store_true", help="Generate a PDF report in the daily report folder when autoresearch completes.")
    autoresearch_parser.add_argument("--auto", action="store_true", help="Use stored default questions and scenarios with no interactive prompts.")
    autoresearch_parser.add_argument("--headless", action="store_true", help="Enable auto mode, suppress voice, and send a terminal-notifier message on macOS.")
    autoresearch_parser.add_argument("--no-voice", action="store_true", help="Suppress Daniel voice lines for this autoresearch run.")
    autoresearch_parser.add_argument("--dry-run", action="store_true", help="Run scoring and diff generation without persisting a new active version.")
    autoresearch_parser.add_argument("--overnight", action="store_true", help="Label the run as an overnight autonomous session in the dashboard and changelog.")
    skill_parser = subparsers.add_parser("skill", help="Inspect or switch persistent Neon Ape skill versions.")
    skill_subparsers = skill_parser.add_subparsers(dest="skill_command", required=True)
    skill_subparsers.add_parser("list", help="List saved skills and their active versions.")
    skill_diff = skill_subparsers.add_parser("diff", help="Show the current diff against the previous saved version.")
    skill_diff.add_argument("skill_name", help="Skill name to diff.")
    skill_use = skill_subparsers.add_parser("use", help="Switch the active version to a saved history snapshot.")
    skill_use.add_argument("skill_name", help="Skill name to activate.")
    skill_use.add_argument("--version", required=True, help="History version prefix such as 2026-03-18.")
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
    review_parser.add_argument("--llm-triage", action="store_true", help="Run local findings triage after the standard review tables.")
    review_parser.add_argument("--llm-provider", choices=("ollama", "cline"), help="Choose the local LLM provider for triage.")
    review_parser.add_argument("--llm-model", help="Override the configured local Ollama model for this run.")
    review_parser.add_argument("--web-paths", action="store_true", help="Focus the review output on Angel Eyes sensitive path analysis.")
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
    app.manual_topic = (getattr(args, "man_topic", None) or "main") if args.command == "man" else None
    app.config_action = getattr(args, "config_action", None)
    app.config_key = getattr(args, "key", None)
    app.config_value = getattr(args, "value", None)
    app.review_target = getattr(args, "target", None) if args.command == "review" else None
    app.review_limit = getattr(args, "limit", 50) if args.command == "review" else 50
    app.review_json_output = getattr(args, "json", False) if args.command == "review" else False
    app.review_llm_triage = getattr(args, "llm_triage", False) if args.command == "review" else False
    app.review_llm_provider = getattr(args, "llm_provider", None) if args.command == "review" else None
    app.review_llm_model = getattr(args, "llm_model", None) if args.command == "review" else None
    app.review_web_paths_only = getattr(args, "web_paths", False) if args.command == "review" else False
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
    app.setup_command = getattr(args, "setup_command", None) if args.command == "setup" else None
    app.setup_yes = getattr(args, "yes", False) if args.command == "setup" else False
    app.obsidian_vault_path = getattr(args, "vault_path", None)
    app.obsidian_target_note = getattr(args, "target_note", None)
    app.obsidian_notes_passphrase = getattr(args, "notes_passphrase", None)
    app.obsidian_limit = getattr(args, "limit", 200) if args.command == "obsidian" else 200
    app.obsidian_open = getattr(args, "open", False) if args.command == "obsidian" else False
    app.obsidian_dry_run = getattr(args, "dry_run", False) if args.command == "obsidian" else False
    app.obsidian_skip_run = getattr(args, "skip_run", False) if args.command == "obsidian" else False
    app.adam_target = getattr(args, "target", None) if args.command == "adam" else None
    app.adam_pdf = getattr(args, "pdf", False) if args.command == "adam" else False
    app.adam_autoresearch = getattr(args, "autoresearch", False) if args.command == "adam" else False
    app.adam_autoresearch_target = getattr(args, "autoresearch_target", None) if args.command == "adam" else None
    app.autoresearch_target = getattr(args, "target", None) if args.command == "autoresearch" else None
    app.autoresearch_questions = getattr(args, "question", []) if args.command == "autoresearch" else []
    app.autoresearch_scenarios = getattr(args, "scenario", []) if args.command == "autoresearch" else []
    app.autoresearch_iterations = ((getattr(args, "rounds", None) or getattr(args, "iterations", 6)) if args.command == "autoresearch" else 6)
    app.autoresearch_baseline_runs = getattr(args, "baseline_runs", 8) if args.command == "autoresearch" else 8
    app.autoresearch_test_targets = getattr(args, "test_target", []) if args.command == "autoresearch" else []
    app.autoresearch_pdf = getattr(args, "pdf", False) if args.command == "autoresearch" else False
    app.autoresearch_auto = getattr(args, "auto", False) if args.command == "autoresearch" else False
    app.autoresearch_headless = getattr(args, "headless", False) if args.command == "autoresearch" else False
    app.autoresearch_no_voice = getattr(args, "no_voice", False) if args.command == "autoresearch" else False
    app.autoresearch_dry_run = getattr(args, "dry_run", False) if args.command == "autoresearch" else False
    app.autoresearch_overnight = getattr(args, "overnight", False) if args.command == "autoresearch" else False
    app.skill_command = getattr(args, "skill_command", None) if args.command == "skill" else None
    app.skill_name = getattr(args, "skill_name", None) if args.command == "skill" else None
    app.skill_version = getattr(args, "version", None) if args.command == "skill" else None
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
