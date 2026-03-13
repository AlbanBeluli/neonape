from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from neon_ape.tools.base import ToolResult


def initialize_database(connection: sqlite3.Connection, schema_path: Path) -> None:
    with schema_path.open("r", encoding="utf-8") as handle:
        connection.executescript(handle.read())
    _ensure_checklist_action_columns(connection)
    connection.commit()


def _ensure_checklist_action_columns(connection: sqlite3.Connection) -> None:
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(checklist_items)").fetchall()
    }
    if "action_tool" not in columns:
        try:
            connection.execute("ALTER TABLE checklist_items ADD COLUMN action_tool TEXT")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
    if "action_profile" not in columns:
        try:
            connection.execute("ALTER TABLE checklist_items ADD COLUMN action_profile TEXT")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise


def seed_checklist_from_file(connection: sqlite3.Connection, checklist_path: Path) -> None:
    with checklist_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    existing = connection.execute(
        "SELECT id FROM checklists WHERE slug = ?",
        (payload["slug"],),
    ).fetchone()
    if existing:
        checklist_id = existing["id"]
        connection.execute(
            "UPDATE checklists SET title = ?, description = ? WHERE id = ?",
            (payload["title"], payload["description"], checklist_id),
        )
        connection.execute("DELETE FROM checklist_items WHERE checklist_id = ?", (checklist_id,))
    else:
        cursor = connection.execute(
            "INSERT INTO checklists (slug, title, description) VALUES (?, ?, ?)",
            (payload["slug"], payload["title"], payload["description"]),
        )
        checklist_id = cursor.lastrowid

    for item in payload["items"]:
        connection.execute(
            """
            INSERT INTO checklist_items (
                checklist_id, step_order, section_name, title, guide_text, example_command, action_tool, action_profile
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checklist_id,
                item["step_order"],
                item["section_name"],
                item["title"],
                item["guide_text"],
                item["example_command"],
                item.get("action_tool"),
                item.get("action_profile"),
            ),
        )
    connection.commit()


def checklist_summary(connection: sqlite3.Connection) -> dict[str, str | int]:
    row = connection.execute(
        """
        SELECT c.title, COUNT(ci.id) AS item_count
        FROM checklists c
        LEFT JOIN checklist_items ci ON ci.checklist_id = c.id
        GROUP BY c.id
        ORDER BY c.id
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return {"title": "Unseeded", "item_count": 0}
    return {"title": row["title"], "item_count": row["item_count"]}


def checklist_item_count(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COUNT(*) AS count FROM checklist_items").fetchone()
    return int(row["count"]) if row is not None else 0


def list_checklist_items(connection: sqlite3.Connection) -> list[dict[str, str | int | None]]:
    rows = connection.execute(
        """
        SELECT
            step_order,
            section_name,
            title,
            guide_text,
            example_command,
            action_tool,
            action_profile,
            status
        FROM checklist_items
        ORDER BY step_order
        """
    ).fetchall()
    return [dict(row) for row in rows]


def get_checklist_item(connection: sqlite3.Connection, step_order: int) -> dict[str, str | int | None] | None:
    row = connection.execute(
        """
        SELECT
            step_order,
            section_name,
            title,
            guide_text,
            example_command,
            action_tool,
            action_profile,
            status
        FROM checklist_items
        WHERE step_order = ?
        """,
        (step_order,),
    ).fetchone()
    return dict(row) if row is not None else None


def mark_checklist_item_status(
    connection: sqlite3.Connection,
    step_order: int,
    status: str,
) -> None:
    completed_at = "CURRENT_TIMESTAMP" if status == "complete" else "NULL"
    connection.execute(
        f"""
        UPDATE checklist_items
        SET status = ?, completed_at = {completed_at}
        WHERE step_order = ?
        """,
        (status, step_order),
    )
    connection.commit()


def record_scan(
    connection: sqlite3.Connection,
    result: ToolResult,
    findings: list[dict[str, str]],
) -> None:
    cursor = connection.execute(
        """
        INSERT INTO scan_runs (tool_name, target, command_line, status, raw_output_path, finished_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            result.tool_name,
            result.target,
            " ".join(result.command),
            "success" if result.exit_code == 0 else "failed",
            result.raw_output_path,
        ),
    )
    scan_run_id = cursor.lastrowid
    for finding in findings:
        connection.execute(
            """
            INSERT INTO scan_findings (scan_run_id, finding_type, key, value, metadata_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                finding.get("type", "unknown"),
                finding.get("key", finding.get("host", finding.get("value", ""))),
                finding.get("value", ""),
                json.dumps(finding, sort_keys=True),
            ),
        )
    connection.execute(
        """
        INSERT INTO tool_history (tool_name, target, arguments_json, exit_code)
        VALUES (?, ?, ?, ?)
        """,
        (
            result.tool_name,
            result.target,
            json.dumps(result.command),
            result.exit_code,
        ),
    )
    connection.commit()


def list_tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return [str(row["name"]) for row in rows]


def recent_scans(connection: sqlite3.Connection, limit: int = 20) -> list[dict[str, str | int | None]]:
    rows = connection.execute(
        """
        SELECT id, tool_name, target, status, raw_output_path, finished_at
        FROM scan_runs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def recent_findings(connection: sqlite3.Connection, limit: int = 50) -> list[dict[str, str | int | None]]:
    rows = connection.execute(
        """
        SELECT id, scan_run_id, finding_type, key, value
        FROM scan_findings
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]
