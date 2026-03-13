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
    db_subparsers.add_parser("tables", help="List Neon Ape database tables.")
    db_subparsers.add_parser("checklist", help="Show checklist step status and attached actions.")
    db_subparsers.add_parser("scans", help="Show recent scan runs.")
    db_subparsers.add_parser("findings", help="Show recent parsed findings.")

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
    return parser


def main() -> int:
    args = build_parser().parse_args()
    app = NeonApeApp()
    app.command = args.command
    app.db_command = getattr(args, "db_command", None)
    app.target = args.target
    app.profile = args.profile
    app.run_nmap = args.run_nmap
    app.init_only = args.init_only
    app.tool = args.tool
    app.checklist_step = args.checklist_step
    app.show_checklist = args.show_checklist
    app.run()
    return 0
