import sqlite3
from pathlib import Path

from neon_ape.db.repository import (
    export_scan_bundle,
    get_checklist_item,
    import_scan_bundle,
    initialize_database,
    list_checklist_items,
    list_tables,
    mark_checklist_item_status,
    recent_findings,
    recent_scans,
    record_scan,
    seed_checklist_from_file,
)
from neon_ape.tools.base import ToolResult


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    return connection


def test_seed_checklist_and_status_update() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")
    seed_checklist_from_file(connection, root / "neon_ape" / "checklists" / "oscp_black_book_mvp.json")

    items = list_checklist_items(connection)
    assert len(items) >= 1
    assert get_checklist_item(connection, 1)["title"] == "Validate target scope"

    mark_checklist_item_status(connection, 1, "complete")
    assert get_checklist_item(connection, 1)["status"] == "complete"


def test_record_scan_persists_scan_and_findings() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")
    seed_checklist_from_file(connection, root / "neon_ape" / "checklists" / "oscp_black_book_mvp.json")

    result = ToolResult(
        tool_name="httpx",
        target="https://example.com",
        command=["httpx", "-json"],
        stdout="",
        stderr="",
        exit_code=0,
        raw_output_path="/tmp/httpx.jsonl",
    )
    findings = [{"type": "http_service", "host": "https://example.com", "key": "https://example.com", "value": "200"}]

    record_scan(connection, result, findings)

    scans = recent_scans(connection, limit=1)
    stored_findings = recent_findings(connection, limit=1)
    assert scans[0]["tool_name"] == "httpx"
    assert scans[0]["raw_output_path"] == "/tmp/httpx.jsonl"
    assert stored_findings[0]["finding_type"] == "http_service"


def test_recent_queries_support_filters() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")
    seed_checklist_from_file(connection, root / "neon_ape" / "checklists" / "oscp_black_book_mvp.json")

    record_scan(
        connection,
        ToolResult(tool_name="httpx", target="a", command=["httpx"], exit_code=0),
        [{"type": "http_service", "host": "a", "key": "a", "value": "200"}],
    )
    record_scan(
        connection,
        ToolResult(tool_name="dnsx", target="b", command=["dnsx"], exit_code=0),
        [{"type": "dns_record", "host": "b", "key": "A", "value": "1.1.1.1"}],
    )

    assert len(recent_scans(connection, limit=10, tool_name="httpx")) == 1
    assert len(recent_findings(connection, limit=10, finding_type="dns_record")) == 1


def test_export_and_import_scan_bundle_roundtrip() -> None:
    root = Path(__file__).resolve().parents[1]
    source = _connection()
    initialize_database(source, root / "neon_ape" / "db" / "schema.sql")
    seed_checklist_from_file(source, root / "neon_ape" / "checklists" / "oscp_black_book_mvp.json")
    record_scan(
        source,
        ToolResult(tool_name="httpx", target="a", command=["httpx"], exit_code=0),
        [{"type": "http_service", "host": "a", "key": "a", "value": "200"}],
    )

    bundle = export_scan_bundle(source, limit=10)

    target = _connection()
    initialize_database(target, root / "neon_ape" / "db" / "schema.sql")
    imported = import_scan_bundle(target, bundle)

    assert imported == 1
    assert len(recent_scans(target, limit=10)) == 1
    assert len(recent_findings(target, limit=10)) == 1


def test_list_tables_returns_expected_schema_tables() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")
    tables = list_tables(connection)
    assert "checklists" in tables
    assert "scan_runs" in tables
