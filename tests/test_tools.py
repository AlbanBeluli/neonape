from pathlib import Path

from rich.console import Console

from neon_ape.commands.tools import _default_batch_history_target, _gobuster_wildcard_details, _gobuster_wildcard_hint, run_gobuster


def test_default_batch_history_target_prefers_workflow_name() -> None:
    label = _default_batch_history_target("httpx", "stoic.ee_workflow_httpx", ["www.stoic.ee", "ops.stoic.ee"])
    assert label == "batch:httpx:stoic.ee_workflow_httpx"


def test_default_batch_history_target_uses_count_for_multi_target_batch() -> None:
    label = _default_batch_history_target("naabu", None, ["www.stoic.ee", "ops.stoic.ee"])
    assert label == "batch:naabu:2_targets"


def test_gobuster_wildcard_hint_extracts_length_and_status() -> None:
    stderr = (
        "Error: the server returns a status code that matches the provided options for non existing urls. "
        "https://stoic.ee/random => 200 (Length: 24824). To continue please exclude the status code or the length"
    )
    hint = _gobuster_wildcard_hint(stderr, "https://stoic.ee")
    assert hint is not None
    assert "HTTP 200" in hint
    assert "24824" in hint
    assert "--exclude-length 24824" in hint


def test_gobuster_wildcard_details_extracts_fields() -> None:
    stderr = (
        "Error: the server returns a status code that matches the provided options for non existing urls. "
        "https://stoic.ee/random => 200 (Length: 24824). To continue please exclude the status code or the length"
    )
    details = _gobuster_wildcard_details(stderr)
    assert details == {"status_code": "200", "content_length": "24824"}


def test_run_gobuster_falls_back_to_legacy_gobuster(monkeypatch, tmp_path) -> None:
    console = Console(record=True)
    calls: list[str] = []

    monkeypatch.setattr("neon_ape.commands.tools.run_ffuf", lambda *args, **kwargs: calls.append("ffuf") or False)
    monkeypatch.setattr("neon_ape.commands.tools.build_gobuster_command", lambda *args, **kwargs: ("https://example.com", ["gobuster"]))
    monkeypatch.setattr(
        "neon_ape.commands.tools.execute_gobuster",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "tool_name": "gobuster",
                "target": "https://example.com",
                "command": ["gobuster"],
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "raw_output_path": str(Path(tmp_path) / "gobuster.txt"),
            },
        )(),
    )
    monkeypatch.setattr("neon_ape.commands.tools.parse_gobuster_output", lambda *args, **kwargs: [])
    monkeypatch.setattr("neon_ape.commands.tools.record_scan", lambda *args, **kwargs: None)
    monkeypatch.setattr("neon_ape.commands.tools.build_tool_output_table", lambda *args, **kwargs: "")
    monkeypatch.setattr("neon_ape.commands.tools._render_angel_eyes", lambda *args, **kwargs: None)

    success = run_gobuster(console, object(), target="example.com", scan_dir=tmp_path)
    assert success is True
    assert calls == ["ffuf"]
    assert "Falling back to legacy Gobuster flow" in console.export_text()
