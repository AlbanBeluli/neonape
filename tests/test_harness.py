from pathlib import Path

from neon_ape.config import AppConfig
from neon_ape.evaluation.harness import built_in_targets, evaluate_skill_objectively, render_sparkline

REPO_ROOT = Path(__file__).resolve().parents[1]


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
        checklist_path=REPO_ROOT / "neon_ape" / "checklists" / "neon_ape_checklist.json",
        schema_path=REPO_ROOT / "neon_ape" / "db" / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=tmp_path / "Obsidian Vault",
    )


def test_built_in_targets_returns_safe_fixture_labels() -> None:
    targets = built_in_targets("angel-eyes")
    assert len(targets) >= 3
    assert targets[0].endswith(".local")


def test_evaluate_skill_objectively_returns_weighted_score_and_creates_exports(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("NEONAPE_HOME", str(tmp_path / ".neonape"))
    config = _config(tmp_path)
    report = evaluate_skill_objectively(
        skill_name="angel-eyes",
        candidate_text=(
            "subfinder httpx live host angel eyes high-risk .env .git highest risk risk score "
            "grouped duplicate source tool database saved persist Findings.md Sensitive-Paths.md Review-Summary.md"
        ),
        config=config,
    )
    assert report["score"] > 50
    assert report["export_detected"] is True
    assert report["db_done_count"] > 0
    oracle_scores = report["oracle_scores"]
    assert oracle_scores["host_discovery_success"] > 0
    assert oracle_scores["export_quality"] > 0
    assert (tmp_path / "Obsidian Vault" / "Pentests" / "fixture-web-001.local" / "Findings.md").exists()


def test_evaluate_skill_objectively_supports_explicit_real_target(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("NEONAPE_HOME", str(tmp_path / ".neonape"))
    config = _config(tmp_path)
    report = evaluate_skill_objectively(
        skill_name="angel-eyes",
        candidate_text="angel eyes highest risk grouped duplicate source tool",
        config=config,
        test_targets=["stoic.ee"],
    )
    assert report["targets"] == ["stoic.ee"]
    assert report["export_detected"] is True
    assert report["oracle_scores"]["export_quality"] > 0


def test_render_sparkline_returns_blocks() -> None:
    sparkline = render_sparkline([10, 20, 30, 25, 35])
    assert len(sparkline) == 5
