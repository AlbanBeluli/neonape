from pathlib import Path

from neon_ape.skills.manager import (
    diff_skill,
    initialize_skill_state,
    list_skills,
    save_improved_skill,
    use_skill_version,
)


def test_skill_manager_persists_current_and_history(tmp_path) -> None:
    state = initialize_skill_state(
        skill_name="magi-checklist",
        label="MAGI Checklist",
        source_path=Path("/tmp/source.json"),
        content='{"name": "baseline"}',
        root=tmp_path,
        score=50.0,
    )
    assert state["skill"] == "magi-checklist"

    saved, backup = save_improved_skill(
        skill_name="magi-checklist",
        label="MAGI Checklist",
        source_path=Path("/tmp/source.json"),
        previous_content='{"name": "baseline"}',
        new_content='{"name": "improved"}',
        previous_score=50.0,
        new_score=55.0,
        questions=["Does it stay practical?"],
        scenarios=["Operator resumes from MAGI."],
        kept_changes=[{"iteration": 1, "change": "Clarify command previews."}],
        discarded_changes=[],
        root=tmp_path,
    )

    assert saved["score"] == 55.0
    assert backup is not None
    assert backup.exists()
    rows = list_skills(root=tmp_path)
    assert rows[0]["skill"] == "magi-checklist"
    assert "improved" in diff_skill("magi-checklist", root=tmp_path)


def test_use_skill_version_switches_current(tmp_path) -> None:
    initialize_skill_state(
        skill_name="angel-eyes",
        label="Angel Eyes",
        source_path=Path("/tmp/source.py"),
        content="baseline",
        root=tmp_path,
        score=60.0,
    )
    _, backup = save_improved_skill(
        skill_name="angel-eyes",
        label="Angel Eyes",
        source_path=Path("/tmp/source.py"),
        previous_content="baseline",
        new_content="improved",
        previous_score=60.0,
        new_score=63.5,
        questions=[],
        scenarios=[],
        kept_changes=[],
        discarded_changes=[],
        root=tmp_path,
    )
    active = use_skill_version("angel-eyes", backup.stem[:10], root=tmp_path)
    assert active["content"] == "baseline"
