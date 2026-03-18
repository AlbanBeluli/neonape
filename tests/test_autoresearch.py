from pathlib import Path

from rich.console import Console

from neon_ape.agents.autoresearch import SKILL_REGISTRY, run_autoresearch
from neon_ape.config import AppConfig
from neon_ape.skills.manager import load_current_skill


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
    skills_dir = tmp_path / "skills"
    monkeypatch.setenv("NEONAPE_SKILLS_DIR", str(skills_dir))
    monkeypatch.setattr("neon_ape.agents.autoresearch.is_macos", lambda: False)
    sample_sets = iter(([50.0, 50.0], [53.5, 53.5], [53.5, 53.5]))
    monkeypatch.setattr("neon_ape.agents.autoresearch._score_samples", lambda *args, **kwargs: next(sample_sets))
    objective_sets = iter(
        (
            {"score": 48.61, "oracles": {"host discovery success": 48.61}},
            {"score": 53.85, "oracles": {"host discovery success": 53.85}},
            {"score": 53.85, "oracles": {"host discovery success": 53.85}},
        )
    )
    monkeypatch.setattr(
        "neon_ape.agents.autoresearch.evaluate_skill_objectively",
        lambda *args, **kwargs: next(objective_sets),
    )

    success = run_autoresearch(
        console,
        config=config,
        skill_target="magi-checklist",
        questions=["Does it stay practical?"],
        scenarios=["A new operator must continue from MAGI quickly."],
        iterations=2,
        baseline_runs=2,
        silent_voice=True,
    )

    assert success is True
    skill_root = skills_dir / "magi-checklist"
    assert (skill_root / "current.json").exists()
    assert (skill_root / "changelog.md").exists()
    assert (skill_root / "history").exists()
    output = console.export_text()
    assert "Skill improved and saved permanently. New version active." in output
    current = load_current_skill("magi-checklist", root=skills_dir)
    assert current is not None
    assert len(current["default_questions"]) >= 1
    assert len(current["default_scenarios"]) >= 1


def test_autoresearch_supported_skill_registry_contains_expected_targets() -> None:
    assert "magi-checklist" in SKILL_REGISTRY
    assert "angel-eyes" in SKILL_REGISTRY
    assert "adam-workflow" in SKILL_REGISTRY
    assert "triage-prompt" in SKILL_REGISTRY


def test_autoresearch_headless_skips_voice_and_reports_notifier(tmp_path, monkeypatch) -> None:
    console = Console(record=True)
    config = _config(tmp_path)
    skills_dir = tmp_path / "skills"
    monkeypatch.setenv("NEONAPE_SKILLS_DIR", str(skills_dir))
    monkeypatch.setattr("neon_ape.agents.autoresearch.is_macos", lambda: True)
    monkeypatch.setattr("neon_ape.agents.autoresearch.which", lambda name: "/usr/local/bin/terminal-notifier" if name == "terminal-notifier" else None)
    monkeypatch.setattr("neon_ape.agents.autoresearch._score_samples", lambda *args, **kwargs: [50.0, 53.5])
    monkeypatch.setattr(
        "neon_ape.agents.autoresearch.evaluate_skill_objectively",
        lambda *args, **kwargs: {"score": 55.0, "oracles": {"host discovery success": 55.0}},
    )
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        class Result:
            returncode = 0
            stdout = ""
            stderr = ""
        return Result()

    monkeypatch.setattr("neon_ape.agents.autoresearch.subprocess.run", fake_run)

    success = run_autoresearch(
        console,
        config=config,
        skill_target="angel-eyes",
        iterations=1,
        baseline_runs=2,
        auto=True,
        headless=True,
    )

    assert success is True
    assert any(command[0] == "/usr/local/bin/terminal-notifier" for command in calls)
    output = console.export_text()
    assert "macOS notification:" in output
    assert "Daniel voice notification" not in output


def test_autoresearch_dry_run_does_not_persist_new_version(tmp_path, monkeypatch) -> None:
    console = Console(record=True)
    config = _config(tmp_path)
    skills_dir = tmp_path / "skills"
    monkeypatch.setenv("NEONAPE_SKILLS_DIR", str(skills_dir))
    monkeypatch.setattr("neon_ape.agents.autoresearch.is_macos", lambda: False)
    sample_sets = iter(([50.0, 50.0], [55.0, 55.0], [55.0, 55.0]))
    monkeypatch.setattr("neon_ape.agents.autoresearch._score_samples", lambda *args, **kwargs: next(sample_sets))
    objective_sets = iter(
        (
            {"score": 48.0, "oracles": {"host discovery success": 48.0}},
            {"score": 55.5, "oracles": {"host discovery success": 55.5}},
            {"score": 55.5, "oracles": {"host discovery success": 55.5}},
        )
    )
    monkeypatch.setattr(
        "neon_ape.agents.autoresearch.evaluate_skill_objectively",
        lambda *args, **kwargs: next(objective_sets),
    )

    success = run_autoresearch(
        console,
        config=config,
        skill_target="magi-checklist",
        auto=True,
        iterations=2,
        baseline_runs=2,
        dry_run=True,
        silent_voice=True,
    )

    assert success is True
    current = load_current_skill("magi-checklist", root=skills_dir)
    assert current is None
    assert "Dry run complete. Active version unchanged." in console.export_text()
