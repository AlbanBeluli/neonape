from __future__ import annotations

from datetime import UTC, datetime
from difflib import unified_diff
import json
import os
from pathlib import Path
from typing import Any


def skills_root() -> Path:
    override = os.environ.get("NEONAPE_SKILLS_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".neonape" / "skills"


def ensure_skills_root(root: Path | None = None) -> Path:
    target = root or skills_root()
    target.mkdir(parents=True, exist_ok=True)
    return target


def skill_dir(skill_name: str, *, root: Path | None = None) -> Path:
    return ensure_skills_root(root) / skill_name


def history_dir(skill_name: str, *, root: Path | None = None) -> Path:
    return skill_dir(skill_name, root=root) / "history"


def current_path(skill_name: str, *, root: Path | None = None) -> Path:
    return skill_dir(skill_name, root=root) / "current.json"


def changelog_path(skill_name: str, *, root: Path | None = None) -> Path:
    return skill_dir(skill_name, root=root) / "changelog.md"


def load_current_skill(skill_name: str, *, root: Path | None = None) -> dict[str, Any] | None:
    path = current_path(skill_name, root=root)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def initialize_skill_state(
    *,
    skill_name: str,
    label: str,
    source_path: Path,
    content: str,
    root: Path | None = None,
    score: float | None = None,
    default_questions: list[str] | None = None,
    default_scenarios: list[str] | None = None,
) -> dict[str, Any]:
    existing = load_current_skill(skill_name, root=root)
    if existing is not None:
        changed = False
        if default_questions and not existing.get("default_questions"):
            existing["default_questions"] = default_questions
            changed = True
        if default_scenarios and not existing.get("default_scenarios"):
            existing["default_scenarios"] = default_scenarios
            changed = True
        if changed:
            _write_current(skill_name, existing, root=root)
        return existing
    state = _build_state(
        skill_name=skill_name,
        label=label,
        source_path=source_path,
        content=content,
        score=score,
        improvement=0.0,
        activated_at=_timestamp(),
        default_questions=default_questions,
        default_scenarios=default_scenarios,
    )
    _write_current(skill_name, state, root=root)
    _append_changelog(
        skill_name,
        f"## {_timestamp()}\n- Initialized persistent skill snapshot from `{source_path}`.\n",
        root=root,
    )
    return state


def save_improved_skill(
    *,
    skill_name: str,
    label: str,
    source_path: Path,
    previous_content: str,
    new_content: str,
    previous_score: float,
    new_score: float,
    questions: list[str],
    scenarios: list[str],
    kept_changes: list[dict[str, Any]],
    discarded_changes: list[dict[str, Any]],
    default_questions: list[str] | None = None,
    default_scenarios: list[str] | None = None,
    root: Path | None = None,
) -> tuple[dict[str, Any], Path | None]:
    current = load_current_skill(skill_name, root=root)
    if current is not None:
        backup = dict(current)
    else:
        backup = _build_state(
            skill_name=skill_name,
            label=label,
            source_path=source_path,
            content=previous_content,
            score=previous_score,
            improvement=0.0,
            activated_at=_timestamp(),
            default_questions=default_questions,
            default_scenarios=default_scenarios,
        )
    backup_file = _write_history_backup(skill_name, backup, root=root)
    state = _build_state(
        skill_name=skill_name,
        label=label,
        source_path=source_path,
        content=new_content,
        score=new_score,
        improvement=round(new_score - previous_score, 2),
        activated_at=_timestamp(),
        questions=questions,
        scenarios=scenarios,
        kept_changes=kept_changes,
        discarded_changes=discarded_changes,
        default_questions=default_questions,
        default_scenarios=default_scenarios,
    )
    _write_current(skill_name, state, root=root)
    _append_changelog(
        skill_name,
        _changelog_entry(state, backup_file.name, kept_changes),
        root=root,
    )
    return state, backup_file


def list_skills(*, root: Path | None = None) -> list[dict[str, Any]]:
    base = ensure_skills_root(root)
    rows: list[dict[str, Any]] = []
    for folder in sorted(item for item in base.iterdir() if item.is_dir()):
        current = folder / "current.json"
        if not current.exists():
            continue
        payload = json.loads(current.read_text(encoding="utf-8"))
        rows.append(
            {
                "skill": payload.get("skill", folder.name),
                "label": payload.get("label", folder.name),
                "score": payload.get("score"),
                "last_improved": payload.get("activated_at", "-"),
                "source_path": payload.get("source_path", "-"),
            }
        )
    return rows


def diff_skill(skill_name: str, *, root: Path | None = None) -> str:
    current = load_current_skill(skill_name, root=root)
    previous = _latest_history_entry(skill_name, root=root)
    if current is None:
        raise ValueError(f"Skill not found: {skill_name}")
    if previous is None:
        return "No previous version found for this skill."
    current_lines = str(current.get("content", "")).splitlines()
    previous_lines = str(previous.get("content", "")).splitlines()
    diff = "\n".join(
        unified_diff(
            previous_lines,
            current_lines,
            fromfile=f"{skill_name}:previous",
            tofile=f"{skill_name}:current",
            lineterm="",
        )
    )
    return diff or "No content changes detected."


def use_skill_version(skill_name: str, version: str, *, root: Path | None = None) -> dict[str, Any]:
    selected_path = _find_history_version(skill_name, version, root=root)
    if selected_path is None:
        raise ValueError(f"No saved version matched '{version}' for skill {skill_name}.")
    selected = json.loads(selected_path.read_text(encoding="utf-8"))
    current = load_current_skill(skill_name, root=root)
    if current is not None:
        _write_history_backup(skill_name, current, root=root)
    selected["activated_at"] = _timestamp()
    _write_current(skill_name, selected, root=root)
    _append_changelog(
        skill_name,
        f"## {_timestamp()}\n- Switched active version to `{selected_path.name}`.\n",
        root=root,
    )
    return selected


def describe_skill_structure(skill_name: str, *, root: Path | None = None) -> list[str]:
    folder = skill_dir(skill_name, root=root)
    history = history_dir(skill_name, root=root)
    lines = [
        str(folder),
        f"{folder / 'current.json'}",
        f"{folder / 'changelog.md'}",
        f"{history}/",
    ]
    if history.exists():
        lines.extend(str(item) for item in sorted(history.iterdir()))
    return lines


def update_skill_defaults(
    skill_name: str,
    *,
    default_questions: list[str],
    default_scenarios: list[str],
    root: Path | None = None,
) -> dict[str, Any]:
    current = load_current_skill(skill_name, root=root)
    if current is None:
        raise ValueError(f"Skill not found: {skill_name}")
    current["default_questions"] = default_questions
    current["default_scenarios"] = default_scenarios
    _write_current(skill_name, current, root=root)
    _append_changelog(
        skill_name,
        f"## {_timestamp()}\n- Stored default autoresearch questions and scenarios for headless runs.\n",
        root=root,
    )
    return current


def _build_state(
    *,
    skill_name: str,
    label: str,
    source_path: Path,
    content: str,
    score: float | None,
    improvement: float,
    activated_at: str,
    questions: list[str] | None = None,
    scenarios: list[str] | None = None,
    kept_changes: list[dict[str, Any]] | None = None,
    discarded_changes: list[dict[str, Any]] | None = None,
    default_questions: list[str] | None = None,
    default_scenarios: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "skill": skill_name,
        "label": label,
        "source_path": str(source_path),
        "content": content,
        "score": score,
        "improvement": improvement,
        "activated_at": activated_at,
        "questions": questions or [],
        "scenarios": scenarios or [],
        "default_questions": default_questions or [],
        "default_scenarios": default_scenarios or [],
        "kept_changes": kept_changes or [],
        "discarded_changes": discarded_changes or [],
    }


def _write_current(skill_name: str, payload: dict[str, Any], *, root: Path | None = None) -> None:
    target_dir = skill_dir(skill_name, root=root)
    target_dir.mkdir(parents=True, exist_ok=True)
    history_dir(skill_name, root=root).mkdir(parents=True, exist_ok=True)
    current_path(skill_name, root=root).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_history_backup(skill_name: str, payload: dict[str, Any], *, root: Path | None = None) -> Path:
    history = history_dir(skill_name, root=root)
    history.mkdir(parents=True, exist_ok=True)
    filename = f"{_timestamp_for_file()}.json"
    destination = history / filename
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination


def _append_changelog(skill_name: str, text: str, *, root: Path | None = None) -> None:
    target = changelog_path(skill_name, root=root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text(f"# {skill_name} changelog\n\n", encoding="utf-8")
    with target.open("a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def _latest_history_entry(skill_name: str, *, root: Path | None = None) -> dict[str, Any] | None:
    history = history_dir(skill_name, root=root)
    if not history.exists():
        return None
    entries = sorted(history.glob("*.json"))
    if not entries:
        return None
    return json.loads(entries[-1].read_text(encoding="utf-8"))


def _find_history_version(skill_name: str, version: str, *, root: Path | None = None) -> Path | None:
    history = history_dir(skill_name, root=root)
    if not history.exists():
        return None
    matches = sorted(path for path in history.glob("*.json") if path.stem.startswith(version))
    return matches[-1] if matches else None


def _changelog_entry(state: dict[str, Any], backup_name: str, kept_changes: list[dict[str, Any]]) -> str:
    lines = [
        f"## {_timestamp()}",
        f"- Activated new version with score `{state.get('score')}` and improvement `{state.get('improvement')}`.",
        f"- Previous active version saved as `{backup_name}`.",
    ]
    if kept_changes:
        lines.append("- Kept changes:")
        lines.extend(f"  - Iteration {item['iteration']}: {item['change']}" for item in kept_changes)
    return "\n".join(lines) + "\n"


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _timestamp_for_file() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
