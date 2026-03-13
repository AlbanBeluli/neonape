from pathlib import Path

from neon_ape.ui.views import build_scans_table, build_status_table


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
