from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def ensure_scan_findings_columns(connection: sqlite3.Connection) -> None:
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(scan_findings)").fetchall()
    }
    if "category" not in columns:
        connection.execute("ALTER TABLE scan_findings ADD COLUMN category TEXT")
    if "risk_score" not in columns:
        connection.execute("ALTER TABLE scan_findings ADD COLUMN risk_score INTEGER")
