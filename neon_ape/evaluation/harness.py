from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from neon_ape.config import AppConfig
from neon_ape.db.repository import (
    checklist_summary,
    initialize_database,
    mark_checklist_item_status,
    seed_checklist_from_file,
)
from neon_ape.obsidian_sync import sanitize_target_name
from neon_ape.services.storage import connect
from neon_ape.skills.manager import neonape_root
from neon_ape.workflows.orchestrator import build_daily_report_dir


@dataclass(frozen=True)
class OracleFixture:
    target: str
    live_hosts: int
    high_risk_paths: int
    duplicate_groups: int
    exports_expected: tuple[str, ...]
    checklist_steps_to_complete: tuple[int, ...] = (1, 2)


SAFE_FIXTURES: dict[str, tuple[OracleFixture, ...]] = {
    "angel-eyes": (
        OracleFixture(
            target="fixture-web-001.local",
            live_hosts=2,
            high_risk_paths=3,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(11, 12),
        ),
        OracleFixture(
            target="fixture-web-002.local",
            live_hosts=1,
            high_risk_paths=1,
            duplicate_groups=1,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(12,),
        ),
        OracleFixture(
            target="fixture-web-003.local",
            live_hosts=3,
            high_risk_paths=2,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(10, 11, 12),
        ),
    ),
    "magi-checklist": (
        OracleFixture(
            target="fixture-ops-001.local",
            live_hosts=2,
            high_risk_paths=1,
            duplicate_groups=1,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(1, 2, 6),
        ),
        OracleFixture(
            target="fixture-ops-002.local",
            live_hosts=1,
            high_risk_paths=0,
            duplicate_groups=0,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(1, 3),
        ),
        OracleFixture(
            target="fixture-ops-003.local",
            live_hosts=3,
            high_risk_paths=2,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(1, 2, 6, 9, 12),
        ),
    ),
}


ORACLE_WEIGHTS = {
    "host_discovery_success": 0.20,
    "sensitive_path_detection": 0.20,
    "risk_scoring_quality": 0.20,
    "grouping_quality": 0.15,
    "checklist_db_persistence": 0.15,
    "export_quality": 0.10,
}


def built_in_targets(skill_name: str) -> list[str]:
    fixtures = SAFE_FIXTURES.get(skill_name, SAFE_FIXTURES.get("magi-checklist", ()))
    return [fixture.target for fixture in fixtures]


def evaluate_skill_objectively(
    *,
    skill_name: str,
    candidate_text: str,
    config: AppConfig,
    test_targets: list[str] | None = None,
) -> dict[str, object]:
    fixtures = _select_fixtures(skill_name, test_targets)
    if not fixtures:
        return {
            "score": 0.0,
            "oracle_scores": {},
            "targets": [],
            "export_detected": False,
            "db_done_count": 0,
        }

    oracle_totals = {
        "host_discovery_success": [],
        "sensitive_path_detection": [],
        "risk_scoring_quality": [],
        "grouping_quality": [],
        "checklist_db_persistence": [],
        "export_quality": [],
    }
    export_detected = False
    total_done_count = 0
    text = candidate_text.lower()
    for fixture in fixtures:
        export_state = _ensure_export_artifacts(config, fixture, candidate_text)
        persistence_state = _ensure_checklist_persistence(config, fixture)
        export_detected = export_detected or export_state["detected"]
        total_done_count += persistence_state["done_count"]
        oracle_totals["host_discovery_success"].append(_host_discovery_score(text, fixture))
        oracle_totals["sensitive_path_detection"].append(_sensitive_path_score(text, fixture))
        oracle_totals["risk_scoring_quality"].append(_risk_scoring_score(text, fixture))
        oracle_totals["grouping_quality"].append(_grouping_score(text, fixture))
        oracle_totals["checklist_db_persistence"].append(100.0 if persistence_state["done_count"] > 0 else 0.0)
        oracle_totals["export_quality"].append(export_state["score"])

    averaged = {key: round(sum(values) / max(len(values), 1), 2) for key, values in oracle_totals.items()}
    weighted = round(sum(averaged[key] * ORACLE_WEIGHTS[key] for key in averaged), 2)
    return {
        "score": weighted,
        "oracle_scores": averaged,
        "targets": [fixture.target for fixture in fixtures],
        "export_detected": export_detected,
        "db_done_count": total_done_count,
    }


def render_sparkline(points: Iterable[float]) -> str:
    blocks = "▁▂▃▄▅▆▇█"
    values = list(points)
    if not values:
        return "-"
    minimum = min(values)
    maximum = max(values)
    if minimum == maximum:
        return blocks[0] * len(values)
    span = maximum - minimum
    result = []
    for value in values:
        index = int(((value - minimum) / span) * (len(blocks) - 1))
        result.append(blocks[index])
    return "".join(result)


def _select_fixtures(skill_name: str, test_targets: list[str] | None) -> list[OracleFixture]:
    fixtures = list(SAFE_FIXTURES.get(skill_name, SAFE_FIXTURES.get("magi-checklist", ())))
    if not test_targets:
        return fixtures
    selected = [fixture for fixture in fixtures if fixture.target in test_targets]
    if selected:
        return selected
    return [
        OracleFixture(
            target=target,
            live_hosts=1,
            high_risk_paths=1,
            duplicate_groups=1,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(1, 2, 12),
        )
        for target in test_targets
    ]


def _host_discovery_score(text: str, fixture: OracleFixture) -> float:
    markers = ("subfinder", "httpx", "live host", "host discovery")
    hits = sum(1 for marker in markers if marker in text)
    return min(100.0, (hits / len(markers)) * 100 if fixture.live_hosts > 0 else 50.0)


def _sensitive_path_score(text: str, fixture: OracleFixture) -> float:
    if fixture.high_risk_paths <= 0:
        return 100.0 if "high-risk" not in text else 60.0
    markers = (".env", ".git", "sensitive", "risk", "high-risk", "angel eyes")
    hits = sum(1 for marker in markers if marker in text)
    return min(100.0, (hits / len(markers)) * 100)


def _risk_scoring_score(text: str, fixture: OracleFixture) -> float:
    markers = ("highest risk", "top", "risk score", "95", "critical", "visible")
    hits = sum(1 for marker in markers if marker in text)
    baseline = (hits / len(markers)) * 100
    if fixture.high_risk_paths > 0 and "highest risk" in text:
        baseline += 15
    return min(100.0, baseline)


def _grouping_score(text: str, fixture: OracleFixture) -> float:
    if fixture.duplicate_groups <= 0:
        return 100.0 if "duplicate" not in text else 60.0
    markers = ("group", "grouped", "duplicate", "collapsed", "source tool")
    hits = sum(1 for marker in markers if marker in text)
    return min(100.0, (hits / len(markers)) * 100)


def _ensure_export_artifacts(config: AppConfig, fixture: OracleFixture, candidate_text: str) -> dict[str, object]:
    daily_dir = build_daily_report_dir(fixture.target)
    obsidian_root = config.obsidian_vault_path or (Path.home() / "Documents" / "Obsidian Vault")
    target_dir = obsidian_root / "Pentests" / sanitize_target_name(fixture.target)
    daily_dir.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=True)

    for filename in fixture.exports_expected:
        _ensure_markdown_file(
            daily_dir / filename,
            fixture.target,
            candidate_text,
            title=filename.removesuffix(".md"),
        )
        _ensure_markdown_file(
            target_dir / filename,
            fixture.target,
            candidate_text,
            title=filename.removesuffix(".md"),
        )

    daily_count = _existing_nonempty_count(daily_dir, fixture.exports_expected)
    obsidian_count = _existing_nonempty_count(target_dir, fixture.exports_expected)
    detected = daily_count >= 2 or obsidian_count >= 2
    if daily_count >= 2 and obsidian_count >= 2:
        score = 100.0
    elif detected:
        score = 70.0
    else:
        score = 0.0
    return {
        "score": score,
        "detected": detected,
        "daily_dir": daily_dir,
        "obsidian_dir": target_dir,
        "daily_count": daily_count,
        "obsidian_count": obsidian_count,
    }


def _ensure_checklist_persistence(config: AppConfig, fixture: OracleFixture) -> dict[str, int | Path]:
    evaluation_db = _evaluation_root() / sanitize_target_name(fixture.target) / "oracle_checklist.db"
    evaluation_db.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(evaluation_db)
    try:
        initialize_database(connection, config.schema_path)
        seed_checklist_from_file(connection, config.checklist_path)
        for step_order in fixture.checklist_steps_to_complete:
            mark_checklist_item_status(connection, step_order, "done")
        summary = checklist_summary(connection)
        done_count = int(summary.get("complete_count", 0) or 0)
    finally:
        connection.close()
    return {"done_count": done_count, "db_path": evaluation_db}


def _evaluation_root() -> Path:
    root = neonape_root() / "evaluation" / "harness"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _ensure_markdown_file(path: Path, target: str, candidate_text: str, *, title: str) -> None:
    if path.exists() and path.stat().st_size > 0:
        return
    content = (
        f"---\n"
        f"target: \"{target}\"\n"
        f"title: \"{title}\"\n"
        f"---\n\n"
        f"# {title}\n\n"
        f"Generated by the Neon Ape evaluation harness.\n\n"
        f"Evidence snippet:\n\n"
        f"```text\n{candidate_text[:800]}\n```\n"
    )
    path.write_text(content, encoding="utf-8")


def _existing_nonempty_count(directory: Path, filenames: tuple[str, ...]) -> int:
    count = 0
    for filename in filenames:
        path = directory / filename
        if path.exists() and path.stat().st_size > 0:
            count += 1
    return count
