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
            "Database views:\n"
            "  neonape db tables\n"
            "  neonape db checklist\n"
            "  neonape db scans\n"
            "  neonape db findings\n\n"
            "Maintenance:\n"
            "  neonape uninstall\n"
            "  neonape uninstall --purge-data --yes\n\n"
            "Transfer:\n"
            "  neonape export scans --output scans.json\n"
            "  neonape export findings --format csv --output findings.csv\n"
            "  neonape import scans --input scans.json\n\n"
            "Nmap profiles:\n"
            "  host_discovery  nmap -sn <target>\n"
            "  service_scan    nmap -sV <target>\n"
            "  aggressive      nmap -A -T4 <target>\n\n"
            "ProjectDiscovery wrappers:\n"
            "  subfinder  passive subdomain discovery for domains\n"
            "  dnsx       DNS A/AAAA/CNAME/NS/MX/TXT resolution for domains\n"
            "  httpx      HTTP probing for URLs or hosts\n"
            "  naabu      top-100 TCP port probing for hosts or IPs"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
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
        choices=("subfinder", "httpx", "naabu", "dnsx"),
        help="Execute a supported ProjectDiscovery tool with safe defaults.",
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
    app.db_command = getattr(args, "db_command", None)
    app.db_limit = getattr(args, "limit", 20)
    app.db_tool = getattr(args, "tool", None)
    app.db_finding_type = getattr(args, "finding_type", None)
    app.db_json_output = getattr(args, "json", False)
    app.export_entity = getattr(args, "export_entity", None)
    app.export_output = getattr(args, "output", None)
    app.export_format = getattr(args, "export_format", "json")
    app.import_entity = getattr(args, "import_entity", None)
    app.import_input = getattr(args, "input", None)
    app.uninstall_yes = getattr(args, "yes", False)
    app.uninstall_purge_data = getattr(args, "purge_data", False)
    app.target = args.target
    app.profile = args.profile
    app.run_nmap = args.run_nmap
    app.init_only = args.init_only
    app.tool = args.tool
    app.checklist_step = args.checklist_step
    app.show_checklist = args.show_checklist
    app.show_targets = args.show_targets
    app.run()
    return 0
