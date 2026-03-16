from pathlib import Path

from neon_ape.ui.views import (
    build_angel_eyes_table,
    build_domain_summary_panel,
    build_naabu_table,
    build_nuclei_table,
    build_recent_findings_table,
    build_review_summary_panel,
    build_scans_table,
    build_status_table,
    build_web_path_table,
)


def test_build_scans_table_masks_targets_when_requested() -> None:
    table = build_scans_table(
        [{"id": 1, "tool_name": "httpx", "target": "example.com", "status": "success", "finished_at": "now"}],
        mask_targets=True,
    )
    cells = table.columns[2]._cells
    assert cells == ["ex***om"]


def test_build_status_table_hides_db_path() -> None:
    table = build_status_table({"item_count": 7, "complete_count": 3}, Path("/tmp/example.db"), {"nmap": "/usr/bin/nmap"})
    assert table.columns[1]._cells == ["3/7", "local-only", "1"]


def test_build_recent_findings_table_renders_rows() -> None:
    table = build_recent_findings_table(
        [{"id": 1, "scan_run_id": 3, "finding_type": "dns_record", "key": "A", "value": "1.1.1.1"}]
    )
    assert table.columns[2]._cells == ["dns_record"]


def test_build_nuclei_table_renders_match_metadata() -> None:
    table = build_nuclei_table(
        [{"host": "https://example.com", "severity": "high", "template_id": "panel", "name": "Exposed Panel"}]
    )
    assert table.columns[1]._cells == ["[red]high[/red]"]


def test_build_naabu_table_renders_port_numbers() -> None:
    table = build_naabu_table(
        [{"host": "www.example.com", "key": "443", "value": "tcp"}]
    )
    assert table.columns[1]._cells == ["443"]


def test_build_katana_web_path_table_renders_paths() -> None:
    table = build_web_path_table(
        [{"host": "https://example.com/app.js", "value": "crawl"}],
        "katana",
    )
    assert table.columns[0]._cells == ["https://example.com/app.js"]
    assert table.columns[1]._cells == ["crawl"]


def test_build_gobuster_web_path_table_renders_status() -> None:
    table = build_web_path_table(
        [{"host": "/admin", "value": "301"}],
        "gobuster",
    )
    assert table.columns[0]._cells == ["/admin"]
    assert table.columns[1]._cells == ["301"]


def test_domain_and_review_summary_panels_include_web_path_counts() -> None:
    overview = {
        "scans": [],
        "findings": [],
        "notes": [],
        "inventory": [],
        "reviews": [],
        "angel_eyes": {"items": [{"path": "/.env", "risk_score": 95}], "grouped": {}},
        "web_paths": {"katana": [{"host": "a", "value": "crawl"}], "gobuster": [{"host": "/admin", "value": "301"}]},
    }
    domain_panel = build_domain_summary_panel("example.com", overview)
    review_panel = build_review_summary_panel("example.com", overview)
    assert "Katana Paths" in str(domain_panel.renderable)
    assert "Gobuster Paths" in str(domain_panel.renderable)
    assert "Katana Paths" in str(review_panel.renderable)
    assert "Gobuster Paths" in str(review_panel.renderable)
    assert "Angel Eyes" in str(review_panel.renderable)


def test_build_angel_eyes_table_renders_risk_and_sources() -> None:
    table = build_angel_eyes_table(
        [
            {
                "host": "app.example.com",
                "path": "/.env",
                "status": "200",
                "length": 42,
                "source_tools": ["gobuster", "nuclei"],
                "risk_score": 95,
            }
        ],
        "Secrets",
    )
    assert table.columns[1]._cells == ["/.env"]
    assert table.columns[4]._cells == ["gobuster,nuclei"]
