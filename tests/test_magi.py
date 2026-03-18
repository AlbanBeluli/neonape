import sqlite3
from pathlib import Path

from rich.console import Console

from neon_ape.agents.magi import run_magi_checklist
from neon_ape.db.repository import get_checklist_item, initialize_database, mark_checklist_item_status, seed_checklist_from_file


def test_run_magi_checklist_auto_completes_manual_steps(tmp_path: Path, monkeypatch) -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    schema_path = Path(__file__).resolve().parents[1] / "neon_ape" / "db" / "schema.sql"
    checklist_path = Path(__file__).resolve().parents[1] / "neon_ape" / "checklists" / "neon_ape_checklist.json"
    initialize_database(connection, schema_path)
    seed_checklist_from_file(connection, checklist_path)

    def _fake_run_checklist_step(*args, **kwargs):
        mark_checklist_item_status(connection, int(kwargs["checklist_step"]), "done")
        return "service_scan", str(get_checklist_item(connection, int(kwargs["checklist_step"]))["action_tool"])

    monkeypatch.setattr("neon_ape.agents.magi.run_checklist_step", _fake_run_checklist_step)

    class Config:
        scan_dir = tmp_path / "scans"

    console = Console(record=True)
    success = run_magi_checklist(
        console,
        connection,
        config=Config(),
        detected_tools={"passive_recon": "builtin", "nmap": "/usr/bin/nmap", "subfinder": "/bin/subfinder", "dnsx": "/bin/dnsx", "httpx": "/bin/httpx", "naabu": "/bin/naabu", "nuclei": "/bin/nuclei"},
        target="example.com",
        auto=True,
        prompt_manual=False,
    )

    assert success is True
    assert get_checklist_item(connection, 1)["status"] == "done"
    assert get_checklist_item(connection, 14)["status"] == "done"
