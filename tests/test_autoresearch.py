from pathlib import Path

from rich.console import Console

from neon_ape.agents.autoresearch import SKILL_REGISTRY, run_autoresearch
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


def test_autoresearch_generates_daily_artifacts(tmp_path, monkeypatch) -> None:
    console = Console(record=True)
    config = _config(tmp_path)
    output_dir = tmp_path / "reports"
    monkeypatch.setattr("neon_ape.agents.autoresearch.is_macos", lambda: False)

    success = run_autoresearch(
        console,
        config=config,
        skill_target="magi-checklist",
        questions=["Does it stay practical?"],
        scenarios=["A new operator must continue from MAGI quickly."],
        iterations=2,
        baseline_runs=2,
        daily_report_dir=output_dir,
        silent_voice=True,
    )

    assert success is True
    assert (output_dir / "magi-checklist.backup.json").exists()
    assert (output_dir / "magi-checklist.improved.json").exists()
    assert (output_dir / "autoresearch-changelog.md").exists()
    assert (output_dir / "autoresearch-summary.json").exists()


def test_autoresearch_supported_skill_registry_contains_expected_targets() -> None:
    assert "magi-checklist" in SKILL_REGISTRY
    assert "angel-eyes" in SKILL_REGISTRY
    assert "adam-workflow" in SKILL_REGISTRY
