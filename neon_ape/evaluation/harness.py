from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class OracleFixture:
    target: str
    live_hosts: int
    high_risk_paths: int
    duplicate_groups: int
    exports_expected: tuple[str, ...]


SAFE_FIXTURES: dict[str, tuple[OracleFixture, ...]] = {
    "angel-eyes": (
        OracleFixture(
            target="fixture-web-001.local",
            live_hosts=2,
            high_risk_paths=3,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
        ),
        OracleFixture(
            target="fixture-web-002.local",
            live_hosts=1,
            high_risk_paths=1,
            duplicate_groups=1,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
        ),
        OracleFixture(
            target="fixture-web-003.local",
            live_hosts=3,
            high_risk_paths=2,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
        ),
    ),
    "magi-checklist": (
        OracleFixture(
            target="fixture-ops-001.local",
            live_hosts=2,
            high_risk_paths=1,
            duplicate_groups=1,
            exports_expected=("Findings.md", "Review-Summary.md"),
        ),
        OracleFixture(
            target="fixture-ops-002.local",
            live_hosts=1,
            high_risk_paths=0,
            duplicate_groups=0,
            exports_expected=("Findings.md", "Review-Summary.md"),
        ),
        OracleFixture(
            target="fixture-ops-003.local",
            live_hosts=3,
            high_risk_paths=2,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
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
    test_targets: list[str] | None = None,
) -> dict[str, object]:
    fixtures = _select_fixtures(skill_name, test_targets)
    if not fixtures:
        return {"score": 0.0, "oracle_scores": {}, "targets": []}

    oracle_totals = {
        "host_discovery_success": [],
        "sensitive_path_detection": [],
        "risk_scoring_quality": [],
        "grouping_quality": [],
        "checklist_db_persistence": [],
        "export_quality": [],
    }
    text = candidate_text.lower()
    for fixture in fixtures:
        oracle_totals["host_discovery_success"].append(_host_discovery_score(text, fixture))
        oracle_totals["sensitive_path_detection"].append(_sensitive_path_score(text, fixture))
        oracle_totals["risk_scoring_quality"].append(_risk_scoring_score(text, fixture))
        oracle_totals["grouping_quality"].append(_grouping_score(text, fixture))
        oracle_totals["checklist_db_persistence"].append(_persistence_score(text, fixture, skill_name))
        oracle_totals["export_quality"].append(_export_score(text, fixture))

    averaged = {key: round(sum(values) / max(len(values), 1), 2) for key, values in oracle_totals.items()}
    weighted = round(sum(averaged[key] * ORACLE_WEIGHTS[key] for key in averaged), 2)
    return {
        "score": weighted,
        "oracle_scores": averaged,
        "targets": [fixture.target for fixture in fixtures],
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
    return [OracleFixture(target=target, live_hosts=1, high_risk_paths=1, duplicate_groups=1, exports_expected=("Findings.md", "Review-Summary.md")) for target in test_targets]


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


def _persistence_score(text: str, fixture: OracleFixture, skill_name: str) -> float:
    markers = ("status", "done", "todo", "database", "saved", "persist")
    if skill_name == "angel-eyes":
        markers = ("database", "saved", "persist", "review", "history")
    hits = sum(1 for marker in markers if marker in text)
    return min(100.0, (hits / len(markers)) * 100)


def _export_score(text: str, fixture: OracleFixture) -> float:
    hits = sum(1 for marker in fixture.exports_expected if marker.lower() in text)
    if not fixture.exports_expected:
        return 100.0
    return min(100.0, (hits / len(fixture.exports_expected)) * 100)
