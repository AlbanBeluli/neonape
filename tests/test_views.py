from pathlib import Path

from neon_ape.ui.views import (
    build_naabu_table,
    build_nuclei_table,
    build_recent_findings_table,
    build_scans_table,
    build_status_table,
)


def test_build_scans_table_masks_targets_when_requested() -> None:
    table = build_scans_table(
        [{"id": 1, "tool_name": "httpx", "target": "example.com", "status": "success", "finished_at": "now"}],
        mask_targets=True,
    )
    cells = table.columns[2]._cells
    assert cells == ["ex***om"]


def test_build_status_table_hides_db_path() -> None:
    table = build_status_table({"item_count": 7}, Path("/tmp/example.db"), {"nmap": "/usr/bin/nmap"})
    assert table.columns[1]._cells == ["7", "local-only", "1"]


def test_build_recent_findings_table_renders_rows() -> None:
    table = build_recent_findings_table(
        [{"id": 1, "scan_run_id": 3, "finding_type": "dns_record", "key": "A", "value": "1.1.1.1"}]
    )
    assert table.columns[2]._cells == ["dns_record"]


def test_build_nuclei_table_renders_match_metadata() -> None:
    table = build_nuclei_table(
        [{"host": "https://example.com", "severity": "high", "template_id": "panel", "name": "Exposed Panel"}]
    )
    assert table.columns[1]._cells == ["high"]


def test_build_naabu_table_renders_port_numbers() -> None:
    table = build_naabu_table(
        [{"host": "www.example.com", "key": "443", "value": "tcp"}]
    )
    assert table.columns[1]._cells == ["443"]
