import sqlite3
from pathlib import Path

from neon_ape.db.repository import (
    domain_overview,
    export_scan_bundle,
    get_checklist_item,
    get_note,
    import_scan_bundle,
    initialize_database,
    list_checklist_items,
    list_note_headers,
    list_tables,
    mark_checklist_item_status,
    normalize_batch_history_labels,
    recent_findings,
    recent_inventory,
    recent_note_headers,
    recent_review_findings,
    recent_scans,
    record_scan,
    review_overview,
    seed_checklist_from_file,
    store_note,
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
    seed_checklist_from_file(connection, root / "neon_ape" / "checklists" / "neon_ape_checklist.json")

    items = list_checklist_items(connection)
    assert len(items) >= 1
    assert get_checklist_item(connection, 1)["title"] == "Validate target scope"

    mark_checklist_item_status(connection, 1, "complete")
    assert get_checklist_item(connection, 1)["status"] == "complete"


def test_record_scan_persists_scan_and_findings() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")
    seed_checklist_from_file(connection, root / "neon_ape" / "checklists" / "neon_ape_checklist.json")

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
    seed_checklist_from_file(connection, root / "neon_ape" / "checklists" / "neon_ape_checklist.json")

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
    seed_checklist_from_file(source, root / "neon_ape" / "checklists" / "neon_ape_checklist.json")
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


def test_normalize_batch_history_labels_rewrites_old_chained_rows() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    connection.execute(
        """
        INSERT INTO scan_runs (tool_name, target, command_line, status, raw_output_path, finished_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            "httpx",
            "ops.stoic.ee,www.stoic.ee",
            "httpx -l ~/.neon_ape/scans/httpx_stoic.ee_workflow_httpx.input.txt -o ~/.neon_ape/scans/httpx_stoic.ee_workflow_httpx.jsonl",
            "success",
            str(root / "httpx_stoic.ee_workflow_httpx.jsonl"),
        ),
    )
    connection.execute(
        """
        INSERT INTO tool_history (tool_name, target, arguments_json, exit_code)
        VALUES (?, ?, ?, ?)
        """,
        (
            "naabu",
            "ops.stoic.ee,www.stoic.ee",
            '["naabu","-list","/tmp/naabu_stoic.ee_workflow_naabu.input.txt","-o","/tmp/naabu_stoic.ee_workflow_naabu.jsonl"]',
            0,
        ),
    )
    connection.commit()

    result = normalize_batch_history_labels(connection)

    updated_scan = connection.execute("SELECT target FROM scan_runs").fetchone()
    updated_history = connection.execute("SELECT target FROM tool_history").fetchone()
    assert result == {"scan_runs_updated": 1, "tool_history_updated": 1}
    assert updated_scan["target"] == "pd_chain:stoic.ee:httpx"
    assert updated_history["target"] == "pd_chain:stoic.ee:naabu"


def test_domain_overview_collects_scans_findings_and_notes() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    record_scan(
        connection,
        ToolResult(tool_name="httpx", target="pd_web_chain:stoic.ee:httpx", command=["httpx"], exit_code=0),
        [{"type": "http_service", "host": "https://www.stoic.ee", "key": "https://www.stoic.ee", "value": "200"}],
    )
    store_note(connection, target="stoic.ee", title="Portal", ciphertext=b"encrypted")

    overview = domain_overview(connection, "stoic.ee", limit=10)

    assert len(overview["scans"]) == 1
    assert len(overview["findings"]) == 1
    assert len(overview["notes"]) == 1
    assert len(overview["inventory"]) == 1


def test_recent_inventory_reviews_and_notes_support_filters() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    record_scan(
        connection,
        ToolResult(tool_name="httpx", target="pd_web_chain:example.com:httpx", command=["httpx"], exit_code=0),
        [
            {
                "type": "http_service",
                "host": "https://app.example.com",
                "key": "https://app.example.com",
                "value": "200",
                "product": "Apache httpd",
                "version": "2.4.49",
                "scheme": "https",
                "port": "443",
            }
        ],
    )
    store_note(connection, target="example.com", title="Portal", ciphertext=b"encrypted")

    inventory = recent_inventory(connection, limit=10, target="example.com")
    reviews = recent_review_findings(connection, limit=10, target="example.com", severity="high")
    notes = recent_note_headers(connection, limit=10, target="example.com")

    assert len(inventory) == 1
    assert inventory[0]["product"] == "Apache httpd"
    assert len(reviews) == 1
    assert reviews[0]["severity"] == "high"
    assert len(notes) == 1


def test_domain_and_review_overview_include_katana_and_gobuster_paths() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    record_scan(
        connection,
        ToolResult(tool_name="katana", target="https://app.example.com", command=["katana"], exit_code=0),
        [{"type": "web_path", "host": "https://app.example.com/app.js", "key": "https://app.example.com/app.js", "value": "crawl"}],
    )
    record_scan(
        connection,
        ToolResult(tool_name="gobuster", target="https://app.example.com", command=["gobuster"], exit_code=0),
        [{"type": "web_path", "host": "/admin", "key": "/admin", "value": "301"}],
    )

    domain = domain_overview(connection, "app.example.com", limit=20)
    review = review_overview(connection, "app.example.com", limit=20)

    assert len(domain["web_paths"]["katana"]) == 1
    assert len(domain["web_paths"]["gobuster"]) == 1
    assert domain["web_paths"]["katana"][0]["host"] == "https://app.example.com/app.js"
    assert domain["web_paths"]["gobuster"][0]["host"] == "/admin"
    assert len(review["web_paths"]["katana"]) == 1
    assert len(review["web_paths"]["gobuster"]) == 1


def test_record_scan_creates_review_entries_for_risky_services_and_nuclei() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    record_scan(
        connection,
        ToolResult(tool_name="nmap", target="10.10.10.10", command=["nmap"], exit_code=0),
        [
            {
                "type": "port",
                "host": "10.10.10.10",
                "key": "80",
                "value": "http Apache httpd 2.4.49 (open)",
                "service_name": "http",
                "product": "Apache httpd",
                "version": "2.4.49",
                "protocol": "tcp",
            }
        ],
    )
    record_scan(
        connection,
        ToolResult(tool_name="nuclei", target="https://example.com", command=["nuclei"], exit_code=0),
        [
            {
                "type": "nuclei_finding",
                "host": "https://example.com/login",
                "key": "exposed-login",
                "template_id": "exposed-login",
                "name": "Exposed Login",
                "severity": "high",
                "value": "high Exposed Login",
            }
        ],
    )

    overview = review_overview(connection, "example.com", limit=10)
    apache_overview = review_overview(connection, "10.10.10.10", limit=10)

    assert len(apache_overview["inventory"]) == 1
    assert any(item["finding_key"] == "apache-httpd-2.4.49" for item in apache_overview["reviews"])
    assert any(item["finding_key"] == "exposed-login" for item in overview["reviews"])


def test_review_overview_deduplicates_repeated_inventory_and_review_rows() -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    repeated_finding = [
        {
            "type": "port",
            "host": "10.10.10.10",
            "key": "80",
            "value": "http Apache httpd 2.4.49 (open)",
            "service_name": "http",
            "product": "Apache httpd",
            "version": "2.4.49",
            "protocol": "tcp",
        }
    ]
    record_scan(connection, ToolResult(tool_name="nmap", target="10.10.10.10", command=["nmap"], exit_code=0), repeated_finding)
    record_scan(connection, ToolResult(tool_name="nmap", target="10.10.10.10", command=["nmap"], exit_code=0), repeated_finding)

    overview = review_overview(connection, "10.10.10.10", limit=20)

    assert len(overview["inventory"]) == 1
    assert len(overview["reviews"]) == 1
