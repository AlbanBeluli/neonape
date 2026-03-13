from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlparse

from neon_ape.tools.base import ToolResult


def initialize_database(connection: sqlite3.Connection, schema_path: Path) -> None:
    with schema_path.open("r", encoding="utf-8") as handle:
        connection.executescript(handle.read())
    _ensure_checklist_action_columns(connection)
    _backfill_intelligence(connection)
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
        SELECT
            c.title,
            COUNT(ci.id) AS item_count,
            SUM(CASE WHEN ci.status = 'complete' THEN 1 ELSE 0 END) AS complete_count
        FROM checklists c
        LEFT JOIN checklist_items ci ON ci.checklist_id = c.id
        GROUP BY c.id
        ORDER BY c.id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return {"title": "Unseeded", "item_count": 0, "complete_count": 0}
    return {"title": row["title"], "item_count": row["item_count"], "complete_count": row["complete_count"] or 0}


def checklist_item_count(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM checklist_items
        WHERE checklist_id = (SELECT id FROM checklists ORDER BY id DESC LIMIT 1)
        """
    ).fetchone()
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
        WHERE checklist_id = (SELECT id FROM checklists ORDER BY id DESC LIMIT 1)
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
        WHERE checklist_id = (SELECT id FROM checklists ORDER BY id DESC LIMIT 1)
          AND step_order = ?
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
        WHERE checklist_id = (SELECT id FROM checklists ORDER BY id DESC LIMIT 1)
          AND step_order = ?
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
    _ingest_inventory_and_reviews(connection, scan_run_id, result.tool_name, findings)
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


def recent_scans(
    connection: sqlite3.Connection,
    limit: int = 20,
    tool_name: str | None = None,
) -> list[dict[str, str | int | None]]:
    query = """
        SELECT id, tool_name, target, status, raw_output_path, finished_at
        FROM scan_runs
    """
    params: list[str | int] = []
    if tool_name:
        query += " WHERE tool_name = ?"
        params.append(tool_name)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = connection.execute(query, tuple(params)).fetchall()
    return [dict(row) for row in rows]


def recent_findings(
    connection: sqlite3.Connection,
    limit: int = 50,
    finding_type: str | None = None,
) -> list[dict[str, str | int | None]]:
    query = """
        SELECT id, scan_run_id, finding_type, key, value
        FROM scan_findings
    """
    params: list[str | int] = []
    if finding_type:
        query += " WHERE finding_type = ?"
        params.append(finding_type)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = connection.execute(query, tuple(params)).fetchall()
    return [dict(row) for row in rows]


def domain_overview(
    connection: sqlite3.Connection,
    target: str,
    *,
    limit: int = 50,
) -> dict[str, list[dict[str, str | int | None]]]:
    pattern = f"%{target}%"
    scans = connection.execute(
        """
        SELECT id, tool_name, target, status, raw_output_path, finished_at
        FROM scan_runs
        WHERE target LIKE ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (pattern, limit),
    ).fetchall()
    findings = connection.execute(
        """
        SELECT sf.id, sf.scan_run_id, sf.finding_type, sf.key, sf.value
        FROM scan_findings sf
        LEFT JOIN scan_runs sr ON sr.id = sf.scan_run_id
        WHERE sr.target LIKE ?
           OR sf.key LIKE ?
           OR sf.value LIKE ?
           OR sf.metadata_json LIKE ?
        ORDER BY sf.id DESC
        LIMIT ?
        """,
        (pattern, pattern, pattern, pattern, limit),
    ).fetchall()
    notes = connection.execute(
        """
        SELECT id, target, title, created_at, updated_at
        FROM notes
        WHERE COALESCE(target, '') LIKE ?
           OR title LIKE ?
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
        """,
        (pattern, pattern, limit),
    ).fetchall()
    inventory = connection.execute(
        """
        SELECT id, scan_run_id, host, port, protocol, service_name, product, version, source_tool
        FROM service_inventory
        WHERE host LIKE ?
           OR COALESCE(product, '') LIKE ?
           OR COALESCE(version, '') LIKE ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (pattern, pattern, pattern, limit),
    ).fetchall()
    reviews = connection.execute(
        """
        SELECT id, scan_run_id, host, source_tool, finding_key, title, severity, confidence, recommendation
        FROM review_findings
        WHERE host LIKE ?
           OR title LIKE ?
           OR recommendation LIKE ?
           OR evidence_json LIKE ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (pattern, pattern, pattern, pattern, limit),
    ).fetchall()
    return {
        "scans": [dict(row) for row in scans],
        "findings": [dict(row) for row in findings],
        "notes": [dict(row) for row in notes],
        "inventory": _dedupe_inventory_rows([dict(row) for row in inventory]),
        "reviews": _dedupe_review_rows([dict(row) for row in reviews]),
    }


def review_overview(
    connection: sqlite3.Connection,
    target: str,
    *,
    limit: int = 50,
) -> dict[str, list[dict[str, str | int | None]]]:
    overview = domain_overview(connection, target, limit=limit)
    return {"inventory": overview["inventory"], "reviews": overview["reviews"]}


def store_note(
    connection: sqlite3.Connection,
    *,
    target: str | None,
    title: str,
    ciphertext: bytes,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO notes (target, title, ciphertext, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (target, title, ciphertext),
    )
    connection.commit()
    return int(cursor.lastrowid)


def list_note_headers(connection: sqlite3.Connection, target: str | None = None) -> list[dict[str, str | int | None]]:
    query = """
        SELECT id, target, title, created_at, updated_at
        FROM notes
    """
    params: list[str] = []
    if target:
        query += " WHERE target = ?"
        params.append(target)
    query += " ORDER BY updated_at DESC, id DESC"
    rows = connection.execute(query, tuple(params)).fetchall()
    return [dict(row) for row in rows]


def get_note(connection: sqlite3.Connection, note_id: int) -> dict[str, object] | None:
    row = connection.execute(
        """
        SELECT id, target, title, ciphertext, created_at, updated_at
        FROM notes
        WHERE id = ?
        """,
        (note_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def normalize_batch_history_labels(connection: sqlite3.Connection) -> dict[str, int]:
    scan_updates = 0
    history_updates = 0

    scan_rows = connection.execute(
        """
        SELECT id, tool_name, target, raw_output_path
        FROM scan_runs
        WHERE tool_name IN ('httpx', 'naabu')
        """
    ).fetchall()
    for row in scan_rows:
        new_target = _normalized_history_target(
            str(row["tool_name"]),
            str(row["target"]),
            str(row["raw_output_path"] or ""),
        )
        if new_target and new_target != row["target"]:
            connection.execute(
                "UPDATE scan_runs SET target = ? WHERE id = ?",
                (new_target, row["id"]),
            )
            scan_updates += 1

    history_rows = connection.execute(
        """
        SELECT id, tool_name, target, arguments_json
        FROM tool_history
        WHERE tool_name IN ('httpx', 'naabu')
        """
    ).fetchall()
    for row in history_rows:
        artifact_hint = _extract_output_path_from_arguments(row["arguments_json"])
        new_target = _normalized_history_target(
            str(row["tool_name"]),
            str(row["target"] or ""),
            artifact_hint,
        )
        if new_target and new_target != row["target"]:
            connection.execute(
                "UPDATE tool_history SET target = ? WHERE id = ?",
                (new_target, row["id"]),
            )
            history_updates += 1

    connection.commit()
    return {"scan_runs_updated": scan_updates, "tool_history_updated": history_updates}


def _ingest_inventory_and_reviews(
    connection: sqlite3.Connection,
    scan_run_id: int,
    tool_name: str,
    findings: list[dict[str, str]],
) -> None:
    inventory_ids = _insert_inventory_records(connection, scan_run_id, tool_name, findings)
    _insert_review_records(connection, scan_run_id, tool_name, findings, inventory_ids)


def _insert_inventory_records(
    connection: sqlite3.Connection,
    scan_run_id: int,
    tool_name: str,
    findings: list[dict[str, str]],
) -> dict[tuple[str, str, str, str, str], int]:
    inventory_ids: dict[tuple[str, str, str, str, str], int] = {}
    for record in _inventory_records(tool_name, findings):
        cursor = connection.execute(
            """
            INSERT INTO service_inventory (
                scan_run_id, host, port, protocol, service_name, product, version, source_tool
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                record["host"],
                record["port"],
                record["protocol"],
                record["service_name"],
                record["product"],
                record["version"],
                tool_name,
            ),
        )
        marker = (
            str(record["host"]),
            str(record["port"]),
            str(record["protocol"]),
            str(record["product"]),
            str(record["version"]),
        )
        inventory_ids[marker] = int(cursor.lastrowid)
    return inventory_ids


def _insert_review_records(
    connection: sqlite3.Connection,
    scan_run_id: int,
    tool_name: str,
    findings: list[dict[str, str]],
    inventory_ids: dict[tuple[str, str, str, str, str], int],
) -> None:
    for review in _review_records(tool_name, findings, inventory_ids):
        connection.execute(
            """
            INSERT INTO review_findings (
                scan_run_id, inventory_id, host, source_tool, finding_key, title, severity, confidence, recommendation, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                review.get("inventory_id"),
                review["host"],
                tool_name,
                review["finding_key"],
                review["title"],
                review["severity"],
                review["confidence"],
                review["recommendation"],
                json.dumps(review["evidence"], sort_keys=True),
            ),
        )


def _backfill_intelligence(connection: sqlite3.Connection) -> None:
    scan_rows = connection.execute(
        """
        SELECT
            sr.id,
            sr.tool_name,
            EXISTS(SELECT 1 FROM service_inventory si WHERE si.scan_run_id = sr.id) AS has_inventory,
            EXISTS(SELECT 1 FROM review_findings rf WHERE rf.scan_run_id = sr.id) AS has_reviews
        FROM scan_runs sr
        ORDER BY sr.id ASC
        """
    ).fetchall()
    for scan in scan_rows:
        findings_rows = connection.execute(
            """
            SELECT metadata_json
            FROM scan_findings
            WHERE scan_run_id = ?
            ORDER BY id ASC
            """,
            (scan["id"],),
        ).fetchall()
        findings: list[dict[str, str]] = []
        for row in findings_rows:
            try:
                payload = json.loads(row["metadata_json"])
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                findings.append({str(key): str(value) for key, value in payload.items()})
        if findings:
            inventory_ids: dict[tuple[str, str, str, str, str], int] = {}
            if not int(scan["has_inventory"]):
                inventory_ids = _insert_inventory_records(connection, int(scan["id"]), str(scan["tool_name"]), findings)
            else:
                for existing in connection.execute(
                    """
                    SELECT id, host, port, protocol, product, version
                    FROM service_inventory
                    WHERE scan_run_id = ?
                    """,
                    (scan["id"],),
                ).fetchall():
                    inventory_ids[
                        (
                            str(existing["host"]),
                            str(existing["port"]),
                            str(existing["protocol"]),
                            str(existing["product"] or ""),
                            str(existing["version"] or ""),
                        )
                    ] = int(existing["id"])
            if not int(scan["has_reviews"]):
                _insert_review_records(connection, int(scan["id"]), str(scan["tool_name"]), findings, inventory_ids)


def _inventory_records(tool_name: str, findings: list[dict[str, str]]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for finding in findings:
        record: dict[str, object] | None = None
        if tool_name == "nmap" and finding.get("type") == "port":
            record = {
                "host": finding.get("host", ""),
                "port": _to_int(finding.get("key")),
                "protocol": finding.get("protocol", ""),
                "service_name": finding.get("service_name", ""),
                "product": finding.get("product", ""),
                "version": finding.get("version", ""),
            }
        elif tool_name == "httpx" and finding.get("type") == "http_service":
            host = _http_host(finding.get("host", ""))
            record = {
                "host": host,
                "port": _to_int(finding.get("port")),
                "protocol": finding.get("scheme", "http"),
                "service_name": "http",
                "product": finding.get("product", ""),
                "version": finding.get("version", ""),
            }
        if not record or not record["host"]:
            continue
        marker = (
            str(record["host"]),
            str(record["port"]),
            str(record["protocol"]),
            str(record["product"]),
            str(record["version"]),
        )
        if marker in seen:
            continue
        seen.add(marker)
        records.append(record)
    return records


def _review_records(
    tool_name: str,
    findings: list[dict[str, str]],
    inventory_ids: dict[tuple[str, str, str, str, str], int],
) -> list[dict[str, object]]:
    reviews: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()

    if tool_name in {"nmap", "httpx"}:
        for record in _inventory_records(tool_name, findings):
            match = _match_known_service_risk(str(record["product"]), str(record["version"]))
            if not match:
                continue
            marker = (
                str(record["host"]),
                match["finding_key"],
                match["severity"],
            )
            if marker in seen:
                continue
            seen.add(marker)
            inventory_id = inventory_ids.get(
                (
                    str(record["host"]),
                    str(record["port"]),
                    str(record["protocol"]),
                    str(record["product"]),
                    str(record["version"]),
                )
            )
            reviews.append(
                {
                    "inventory_id": inventory_id,
                    "host": str(record["host"]),
                    "finding_key": match["finding_key"],
                    "title": match["title"],
                    "severity": match["severity"],
                    "confidence": "medium",
                    "recommendation": match["recommendation"],
                    "evidence": record,
                }
            )

    if tool_name == "nuclei":
        for finding in findings:
            if finding.get("type") != "nuclei_finding":
                continue
            severity = str(finding.get("severity", "info")).lower()
            if severity not in {"medium", "high", "critical"}:
                continue
            marker = (finding.get("host", ""), finding.get("key", ""), severity)
            if marker in seen:
                continue
            seen.add(marker)
            reviews.append(
                {
                    "inventory_id": None,
                    "host": finding.get("host", ""),
                    "finding_key": finding.get("template_id", finding.get("key", "")),
                    "title": finding.get("name", finding.get("value", "Nuclei finding")),
                    "severity": severity,
                    "confidence": "high",
                    "recommendation": "Prioritize manual validation, patch review, and exposure reduction for this template match.",
                    "evidence": finding,
                }
            )
    return reviews


def _match_known_service_risk(product: str, version: str) -> dict[str, str] | None:
    normalized_product = product.lower().strip()
    normalized_version = version.strip()
    if "apache" in normalized_product and normalized_version in {"2.4.49", "2.4.50"}:
        return {
            "finding_key": f"apache-httpd-{normalized_version}",
            "title": f"Apache httpd {normalized_version} requires urgent review",
            "severity": "high",
            "recommendation": "Review current patch level and exposure immediately. This version family is widely scrutinized and should be upgraded promptly after manual validation.",
        }
    if normalized_product == "openssl" and normalized_version == "1.0.1":
        return {
            "finding_key": "openssl-1.0.1",
            "title": "OpenSSL 1.0.1 requires manual review",
            "severity": "high",
            "recommendation": "Confirm exact patch level and replace this legacy OpenSSL branch where possible after manual validation.",
        }
    return None


def _to_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _http_host(value: str) -> str:
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname
    return value


def _dedupe_inventory_rows(rows: list[dict[str, str | int | None]]) -> list[dict[str, str | int | None]]:
    unique: dict[tuple[str, str, str, str, str], dict[str, str | int | None]] = {}
    for row in rows:
        marker = (
            str(row.get("host", "")),
            str(row.get("port", "")),
            str(row.get("protocol", "")),
            str(row.get("product", "")),
            str(row.get("version", "")),
        )
        current = unique.get(marker)
        if current is None or int(row.get("id", 0) or 0) > int(current.get("id", 0) or 0):
            unique[marker] = row
    return sorted(unique.values(), key=lambda item: int(item.get("id", 0) or 0), reverse=True)


def _dedupe_review_rows(rows: list[dict[str, str | int | None]]) -> list[dict[str, str | int | None]]:
    unique: dict[tuple[str, str, str, str], dict[str, str | int | None]] = {}
    for row in rows:
        marker = (
            str(row.get("host", "")),
            str(row.get("source_tool", "")),
            str(row.get("finding_key", "")),
            str(row.get("severity", "")),
        )
        current = unique.get(marker)
        if current is None or int(row.get("id", 0) or 0) > int(current.get("id", 0) or 0):
            unique[marker] = row
    return sorted(unique.values(), key=lambda item: int(item.get("id", 0) or 0), reverse=True)


def export_scan_bundle(
    connection: sqlite3.Connection,
    limit: int = 100,
    tool_name: str | None = None,
) -> list[dict[str, object]]:
    query = """
        SELECT id, tool_name, target, command_line, status, raw_output_path, finished_at
        FROM scan_runs
    """
    params: list[str | int] = []
    if tool_name:
        query += " WHERE tool_name = ?"
        params.append(tool_name)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    scans = [dict(row) for row in connection.execute(query, tuple(params)).fetchall()]

    bundles: list[dict[str, object]] = []
    for scan in scans:
        findings = connection.execute(
            """
            SELECT finding_type, key, value, metadata_json
            FROM scan_findings
            WHERE scan_run_id = ?
            ORDER BY id ASC
            """,
            (scan["id"],),
        ).fetchall()
        bundles.append(
            {
                "scan": scan,
                "findings": [dict(row) for row in findings],
            }
        )
    return bundles


def import_scan_bundle(connection: sqlite3.Connection, bundles: list[dict[str, object]]) -> int:
    imported = 0
    for bundle in bundles:
        scan = bundle.get("scan", {})
        findings = bundle.get("findings", [])
        cursor = connection.execute(
            """
            INSERT INTO scan_runs (tool_name, target, command_line, status, raw_output_path, finished_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan.get("tool_name", "imported"),
                scan.get("target", ""),
                scan.get("command_line", ""),
                scan.get("status", "success"),
                scan.get("raw_output_path", ""),
                scan.get("finished_at"),
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
                    finding.get("finding_type", "imported"),
                    finding.get("key", ""),
                    finding.get("value", ""),
                    finding.get("metadata_json", "{}"),
                ),
            )
        imported += 1
    connection.commit()
    return imported


def _normalized_history_target(tool_name: str, current_target: str, artifact_hint: str) -> str | None:
    if current_target.startswith("pd_chain:") or current_target.startswith("batch:"):
        return None

    workflow_target = _workflow_history_target(tool_name, artifact_hint)
    if workflow_target:
        return workflow_target

    targets = [item.strip() for item in current_target.split(",") if item.strip()]
    if len(targets) > 1:
        return f"batch:{tool_name}:{len(targets)}_targets"
    return None


def _workflow_history_target(tool_name: str, artifact_hint: str) -> str | None:
    name = Path(artifact_hint).name if artifact_hint else ""
    if not name:
        return None
    pattern = re.compile(rf"^{re.escape(tool_name)}_(.+)_workflow_{re.escape(tool_name)}\.(jsonl|input\.txt)$")
    match = pattern.match(name)
    if not match:
        return None
    seed = match.group(1)
    return f"pd_chain:{seed}:{tool_name}"


def _extract_output_path_from_arguments(arguments_json: str) -> str:
    try:
        arguments = json.loads(arguments_json)
    except json.JSONDecodeError:
        return ""
    if not isinstance(arguments, list):
        return ""
    for item in arguments:
        token = str(item)
        if token.endswith(".jsonl") or token.endswith(".input.txt"):
            return token
    return ""
