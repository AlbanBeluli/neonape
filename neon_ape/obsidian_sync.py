from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from cryptography.fernet import InvalidToken
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import yaml

from neon_ape.config import AppConfig
from neon_ape.services.crypto import decrypt_text, derive_key
from neon_ape.services.storage import connect


DEFAULT_TEMPLATE = """---
target: "example.com"
scope: "in-scope subdomains only"
checklist: "pd_web_chain"
---

# Target Notes

## Objective

## Scope Notes

## Hypotheses

## Follow-Up
"""

MAX_OVERVIEW_BYTES = 5_000_000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m neon_ape.obsidian_sync",
        description="Sync Neon Ape workflow outputs into an Obsidian vault.",
    )
    parser.add_argument("--vault-path", required=True, help="Absolute path to the Obsidian vault root.")
    parser.add_argument(
        "--target-note",
        required=True,
        help="Path to the source Markdown note relative to the vault, for example Pentests/example.com/Target.md",
    )
    parser.add_argument(
        "--notes-passphrase",
        help="Optional passphrase used to decrypt Neon Ape notes for inclusion in Notes.md.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum number of rows to pull from the Neon Ape domain view.",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Try to open the synced target note in Obsidian after writing files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview generated paths and content without writing into the vault or opening Obsidian.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    console = Console()
    vault_path = Path(args.vault_path).expanduser().resolve()
    target_note = vault_path / args.target_note

    if not vault_path.exists():
        console.print(f"[bold red]Vault path does not exist:[/bold red] {vault_path}")
        return 1
    if not target_note.exists():
        console.print(f"[bold red]Target note does not exist:[/bold red] {target_note}")
        return 1

    obsidian_path = shutil.which("obsidian")
    if not obsidian_path:
        console.print(
            Panel.fit(
                "Obsidian CLI was not found on PATH.\n"
                "The sync can still write Markdown, Canvas, and scan artifacts into the vault.\n"
                "Install the `obsidian` command if you want Neon Ape to open the results automatically.",
                title="Obsidian CLI",
                style="bold yellow",
            )
        )

    try:
        frontmatter, body = parse_frontmatter(target_note.read_text(encoding="utf-8"))
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return 1

    target = str(frontmatter.get("target", "")).strip()
    checklist = str(frontmatter.get("checklist", "pd_web_chain")).strip() or "pd_web_chain"
    scope = str(frontmatter.get("scope", "unspecified")).strip() or "unspecified"
    if not target:
        console.print("[bold red]Frontmatter is missing required `target`.[/bold red]")
        return 1

    template_path = vault_path / "Pentests" / "Templates" / "Pentest-Target.md"
    ensure_template(template_path)

    target_dir = vault_path / "Pentests" / sanitize_target_name(target)
    scans_dir = target_dir / "Scans"
    screenshots_dir = target_dir / "Screenshots"
    for path in (target_dir, scans_dir, screenshots_dir):
        path.mkdir(parents=True, exist_ok=True)

    target_markdown = build_target_index(frontmatter, body)

    if not args.dry_run:
        write_target_index(target_dir / "Target.md", frontmatter, body)

    try:
        if not args.dry_run:
            run_workflow(console, checklist=checklist, target=target)
    except RuntimeError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return 1
    overview = fetch_domain_overview(console, target=target, limit=args.limit)
    if overview is None:
        return 1

    config = AppConfig.default()
    notes = decrypt_notes_for_target(
        config.db_path,
        target=target,
        passphrase=args.notes_passphrase,
    )
    copied_artifacts = [] if args.dry_run else copy_scan_artifacts(overview.get("scans", []), scans_dir)

    findings_md = render_findings_markdown(target, scope, checklist, overview)
    notes_md = render_notes_markdown(target, notes, overview.get("notes", []), bool(args.notes_passphrase))
    canvas = build_attack_canvas(target, overview)

    if args.dry_run:
        console.print(build_summary_table(target, checklist, scope, target_dir, preview_scan_artifacts(overview.get("scans", [])), notes, dry_run=True))
        console.print(
            Panel.fit(
                f"[bold]Would write:[/bold]\n"
                f"- {target_dir / 'Target.md'}\n"
                f"- {target_dir / 'Findings.md'}\n"
                f"- {target_dir / 'Notes.md'}\n"
                f"- {target_dir / 'Attack-Chain.canvas'}\n"
                f"- {scans_dir}\n"
                f"- {screenshots_dir}\n\n"
                f"[bold]Target.md preview:[/bold]\n{target_markdown[:1200]}",
                title="Obsidian Dry Run",
                style="bold yellow",
            )
        )
        return 0

    (target_dir / "Findings.md").write_text(findings_md, encoding="utf-8")
    (target_dir / "Notes.md").write_text(notes_md, encoding="utf-8")
    (target_dir / "Attack-Chain.canvas").write_text(json.dumps(canvas, indent=2), encoding="utf-8")

    console.print(build_summary_table(target, checklist, scope, target_dir, copied_artifacts, notes, dry_run=False))
    if args.open:
        open_in_obsidian(console, obsidian_path, target_dir / "Target.md")
    return 0


def parse_frontmatter(markdown: str) -> tuple[dict[str, Any], str]:
    if not markdown.startswith("---\n"):
        raise ValueError("Target note is missing YAML frontmatter.")
    parts = markdown.split("\n---\n", 1)
    if len(parts) != 2:
        raise ValueError("Target note frontmatter is not closed with `---`.")
    raw_frontmatter = parts[0][4:]
    body = parts[1]
    data = yaml.safe_load(raw_frontmatter) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML frontmatter must be a key/value mapping.")
    return data, body


def ensure_template(template_path: Path) -> None:
    if template_path.exists():
        return
    template_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.write_text(DEFAULT_TEMPLATE, encoding="utf-8")


def sanitize_target_name(target: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", ".", "_"} else "_" for char in target).strip("_") or "target"


def write_target_index(path: Path, frontmatter: dict[str, Any], body: str) -> None:
    path.write_text(build_target_index(frontmatter, body), encoding="utf-8")


def build_target_index(frontmatter: dict[str, Any], body: str) -> str:
    merged = {
        "target": frontmatter.get("target", ""),
        "scope": frontmatter.get("scope", ""),
        "checklist": frontmatter.get("checklist", ""),
    }
    return f"---\n{yaml.safe_dump(merged, sort_keys=False).strip()}\n---\n\n{body.strip()}\n"


def run_workflow(console: Console, *, checklist: str, target: str) -> None:
    command = ["neonape", "--workflow", checklist, "--target", target]
    console.print(
        Panel.fit(
            f"[bold]Workflow:[/bold] {checklist}\n[bold]Target:[/bold] {target}\n[bold]Command:[/bold] {' '.join(command)}",
            title="Neon Ape -> Obsidian",
            style="bold cyan",
        )
    )
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Neon Ape workflow timed out after 1800 seconds")
    if completed.stdout.strip():
        console.print(completed.stdout.strip())
    if completed.returncode != 0:
        if completed.stderr.strip():
            console.print(f"[bold red]{completed.stderr.strip()}[/bold red]")
        raise RuntimeError(f"Neon Ape workflow failed with exit code {completed.returncode}")


def fetch_domain_overview(console: Console, *, target: str, limit: int) -> dict[str, Any] | None:
    command = ["neonape", "db", "domain", "--target", target, "--limit", str(limit), "--json"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    except subprocess.TimeoutExpired:
        console.print("[bold red]Neon Ape domain overview timed out. Try a smaller `--limit` value.[/bold red]")
        return None
    if completed.returncode != 0:
        if completed.stderr.strip():
            console.print(f"[bold red]{completed.stderr.strip()}[/bold red]")
        else:
            console.print("[bold red]Failed to read Neon Ape domain overview.[/bold red]")
        return None
    if len(completed.stdout.encode("utf-8")) > MAX_OVERVIEW_BYTES:
        console.print(
            "[bold red]Neon Ape domain overview is too large for a single sync pass.[/bold red] "
            "Re-run with a smaller `--limit` value."
        )
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        console.print("[bold red]Neon Ape domain overview did not return valid JSON.[/bold red]")
        return None


def decrypt_notes_for_target(db_path: Path, *, target: str, passphrase: str | None) -> list[dict[str, str]]:
    connection = connect(db_path)
    try:
        pattern = f"%{target}%"
        rows = connection.execute(
            """
            SELECT id, target, title, ciphertext, created_at, updated_at
            FROM notes
            WHERE COALESCE(target, '') LIKE ?
               OR title LIKE ?
            ORDER BY updated_at DESC, id DESC
            """,
            (pattern, pattern),
        ).fetchall()
        if not passphrase:
            return [{"id": str(row["id"]), "target": str(row["target"] or "-"), "title": str(row["title"]), "body": ""} for row in rows]

        decrypted: list[dict[str, str]] = []
        for row in rows:
            try:
                raw = base64.urlsafe_b64decode(bytes(row["ciphertext"]))
                salt = raw[:16]
                ciphertext = raw[16:]
                key = derive_key(passphrase, salt)
                plaintext = decrypt_text(ciphertext, key)
            except (ValueError, InvalidToken):
                plaintext = "[Unable to decrypt note with provided passphrase]"
            decrypted.append(
                {
                    "id": str(row["id"]),
                    "target": str(row["target"] or "-"),
                    "title": str(row["title"]),
                    "body": plaintext,
                }
            )
        return decrypted
    finally:
        connection.close()


def copy_scan_artifacts(scans: list[dict[str, Any]], destination: Path) -> list[str]:
    copied: list[str] = []
    for scan in scans:
        raw_output_path = str(scan.get("raw_output_path", "") or "")
        if not raw_output_path:
            continue
        source = Path(os.path.expanduser(raw_output_path))
        if not source.exists() or not source.is_file():
            continue
        target = destination / source.name
        shutil.copy2(source, target)
        copied.append(target.name)
    return sorted(set(copied))


def preview_scan_artifacts(scans: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for scan in scans:
        raw_output_path = str(scan.get("raw_output_path", "") or "")
        if raw_output_path:
            names.append(Path(os.path.expanduser(raw_output_path)).name)
    return sorted(set(names))


def render_findings_markdown(target: str, scope: str, checklist: str, overview: dict[str, Any]) -> str:
    lines = [
        f"# Findings for {target}",
        "",
        f"- Scope: `{scope}`",
        f"- Workflow: `{checklist}`",
        "",
        "## Review Matches",
        "",
        render_markdown_table(
            ["Title", "Severity", "Source", "Matched"],
            [
                [
                    str(item.get("title", "-")),
                    str(item.get("severity", "-")),
                    str(item.get("source_tool", "-")),
                    str(item.get("host", "-")),
                ]
                for item in overview.get("reviews", [])
            ],
        ),
        "",
        "## Service Inventory",
        "",
        render_markdown_table(
            ["Host", "Port", "Service", "Product", "Version"],
            [
                [
                    str(item.get("host", "-")),
                    str(item.get("port", "-")),
                    str(item.get("service_name", "-")),
                    str(item.get("product", "-")),
                    str(item.get("version", "-")),
                ]
                for item in overview.get("inventory", [])
            ],
        ),
        "",
        "## Web Paths",
        "",
        "### Katana",
        "",
        render_markdown_table(
            ["Path", "Source"],
            [[str(item.get("host", "-")), str(item.get("value", "-"))] for item in overview.get("web_paths", {}).get("katana", [])],
        ),
        "",
        "### Gobuster",
        "",
        render_markdown_table(
            ["Path", "Status"],
            [[str(item.get("host", "-")), str(item.get("value", "-"))] for item in overview.get("web_paths", {}).get("gobuster", [])],
        ),
        "",
        "## Raw Findings",
        "",
        render_markdown_table(
            ["Type", "Key", "Value"],
            [
                [
                    str(item.get("finding_type", "-")),
                    str(item.get("key", "-")),
                    str(item.get("value", "-")),
                ]
                for item in overview.get("findings", [])
            ],
        ),
    ]
    return "\n".join(lines).strip() + "\n"


def render_notes_markdown(
    target: str,
    notes: list[dict[str, str]],
    note_headers: list[dict[str, Any]],
    has_passphrase: bool,
) -> str:
    lines = [f"# Notes for {target}", ""]
    if not note_headers:
        lines.append("No saved Neon Ape notes matched this target.")
        return "\n".join(lines) + "\n"
    if not has_passphrase:
        lines.extend(
            [
                "> Note bodies are encrypted. Re-run this sync with `--notes-passphrase` to include decrypted content.",
                "",
            ]
        )
    for note in notes:
        lines.extend(
            [
                f"## {note['title']}",
                "",
                f"- Note ID: `{note['id']}`",
                f"- Target: `{note['target']}`",
                "",
            ]
        )
        if note["body"]:
            lines.extend([note["body"], ""])
    return "\n".join(lines).strip() + "\n"


def render_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        rows = [["-" for _ in headers]]
    header_row = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join("---" for _ in headers) + " |"
    body_rows = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header_row, separator, *body_rows])


def build_attack_canvas(target: str, overview: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    base_node_id = "target-root"
    nodes.append(
        {
            "id": base_node_id,
            "type": "text",
            "text": f"Target\\n{target}",
            "x": 0,
            "y": 0,
            "width": 260,
            "height": 100,
        }
    )
    y = 180
    for index, finding in enumerate(overview.get("reviews", [])[:12], start=1):
        node_id = f"review-{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "text",
                "text": f"{finding.get('severity', 'info').upper()}\\n{finding.get('title', '-')}\n{finding.get('host', '-')}",
                "x": 320,
                "y": y,
                "width": 320,
                "height": 120,
            }
        )
        edges.append({"id": f"edge-{index}", "fromNode": base_node_id, "toNode": node_id})
        y += 150
    return {"nodes": nodes, "edges": edges}


def build_summary_table(
    target: str,
    checklist: str,
    scope: str,
    target_dir: Path,
    copied_artifacts: list[str],
    notes: list[dict[str, str]],
    *,
    dry_run: bool,
) -> Table:
    table = Table(title="Obsidian Sync", expand=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Target", target)
    table.add_row("Workflow", checklist)
    table.add_row("Scope", scope)
    table.add_row("Vault Output", str(target_dir))
    table.add_row("Copied Scans", str(len(copied_artifacts)))
    table.add_row("Notes", str(len(notes)))
    table.add_row("Dry Run", str(dry_run))
    return table


def open_in_obsidian(console: Console, obsidian_path: str | None, note_path: Path) -> None:
    if not obsidian_path:
        return
    commands = (
        [obsidian_path, "open", str(note_path)],
        [obsidian_path, str(note_path)],
    )
    for command in commands:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode == 0:
            console.print(f"[bold green]Opened in Obsidian:[/bold green] {note_path}")
            return
    console.print(
        "[bold yellow]Obsidian CLI is installed, but Neon Ape could not auto-open the note with the local command syntax.[/bold yellow]"
    )


if __name__ == "__main__":
    raise SystemExit(main())
