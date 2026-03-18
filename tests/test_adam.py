from pathlib import Path

from rich.console import Console

from neon_ape.agents import adam as adam_module
from neon_ape.config import AppConfig


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=None,
    )


def test_run_adam_continues_without_obsidian_and_runs_autoresearch(tmp_path, monkeypatch) -> None:
    console = Console(record=True)
    config = _config(tmp_path)
    config.scan_dir.mkdir(parents=True, exist_ok=True)
    called: dict[str, object] = {}

    monkeypatch.setattr(adam_module, "_discover_subdomains", lambda *args, **kwargs: ["www.example.com"])
    monkeypatch.setattr(
        adam_module,
        "run_projectdiscovery_batch_tool",
        lambda *args, **kwargs: (
            True,
            [{"host": "https://www.example.com"}] if kwargs.get("tool_name") == "httpx" else [],
        ),
    )
    monkeypatch.setattr(adam_module, "run_gobuster", lambda *args, **kwargs: True)
    monkeypatch.setattr(adam_module, "_run_adam_nuclei_review", lambda *args, **kwargs: (True, []))
    monkeypatch.setattr(adam_module, "run_review", lambda *args, **kwargs: None)
    monkeypatch.setattr(adam_module, "resolve_vault_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(adam_module, "_seed_adam_completed_steps", lambda *args, **kwargs: None)
    monkeypatch.setattr(adam_module, "_run_magi_checklist", lambda *args, **kwargs: True)
    monkeypatch.setattr(adam_module, "build_daily_report_dir", lambda *args, **kwargs: tmp_path / "reports")
    monkeypatch.setattr(
        adam_module,
        "review_overview",
        lambda *args, **kwargs: {"angel_eyes": {"items": [{"risk_score": 88}]}}
    )
    monkeypatch.setattr(
        adam_module,
        "run_autoresearch",
        lambda *args, **kwargs: called.setdefault("skill", kwargs.get("skill_target")) or True,
    )
    monkeypatch.setattr(adam_module, "speak_completion", lambda *args, **kwargs: ["done"])
    monkeypatch.setattr(adam_module, "_offer_open_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(adam_module, "is_macos", lambda: False)

    success = adam_module.run_adam(
        console,
        connection=object(),
        config=config,
        detected_tools={tool: f"/usr/bin/{tool}" for tool in adam_module.ADAM_REQUIRED_TOOLS},
        target="example.com",
        autoresearch_enabled=True,
    )

    assert success is True
    assert called["skill"] == "angel-eyes"
    output = console.export_text()
    assert "fall back to a local daily" in output.lower()
    assert "report folder" in output.lower()
    assert "Adam is beginning autoresearch on angel-eyes" in output
