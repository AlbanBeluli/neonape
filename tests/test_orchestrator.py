from pathlib import Path

from neon_ape.workflows.orchestrator import build_daily_report_dir, copy_daily_reports, speak_autoresearch_completion


def test_build_daily_report_dir_uses_target_slug(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("neon_ape.workflows.orchestrator.Path.home", lambda: tmp_path)
    path = build_daily_report_dir("example.com")
    assert path.parent == tmp_path / "NeonApe-Reports"
    assert path.name.endswith("-example.com")


def test_copy_daily_reports_copies_existing_files(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    findings = source / "Findings.md"
    findings.write_text("findings", encoding="utf-8")
    review = source / "Review-Summary.md"
    review.write_text("review", encoding="utf-8")

    destination = copy_daily_reports("example.com", [findings, review], base_dir=tmp_path / "reports")

    assert (destination / "Findings.md").read_text(encoding="utf-8") == "findings"
    assert (destination / "Review-Summary.md").read_text(encoding="utf-8") == "review"


def test_speak_autoresearch_completion_includes_persist_notice() -> None:
    lines = speak_autoresearch_completion(51.2, 56.8, persisted=True)
    assert "Autoresearch complete." in lines[0]
    assert "Skill improved and saved permanently. New version active." in lines[1]


def test_speak_autoresearch_completion_without_persist_notice() -> None:
    lines = speak_autoresearch_completion(51.2, 51.9, persisted=False)
    assert len(lines) == 1
