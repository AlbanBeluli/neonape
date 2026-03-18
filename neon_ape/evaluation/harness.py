from __future__ import annotations

from dataclasses import dataclass
import json
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
from neon_ape.tools.projectdiscovery import parse_projectdiscovery_output
from neon_ape.tools.web_paths import correlate_sensitive_paths
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
            live_hosts=2,
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
            live_hosts=2,
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
    "host_discovery_success": 0.25,
    "sensitive_path_detection": 0.25,
    "risk_scoring_quality": 0.20,
    "grouping_quality": 0.10,
    "checklist_db_persistence": 0.10,
    "export_quality": 0.10,
}

HIGH_RISK_PATHS = ("/.env", "/.git", "/.git/config", "/.htpasswd", "/backup.zip", "/config.php.bak")


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
            "oracle_reasons": {},
            "targets": [],
            "export_detected": False,
            "db_done_count": 0,
        }

    totals = {key: [] for key in ORACLE_WEIGHTS}
    reasons: dict[str, list[str]] = {key: [] for key in ORACLE_WEIGHTS}
    export_detected = False
    total_done_count = 0
    text = candidate_text.lower()

    for fixture in fixtures:
        host_state = _host_discovery_state(config, fixture)
        sensitive_state = _sensitive_path_state(fixture)
        export_state = _ensure_export_artifacts(config, fixture, candidate_text)
        persistence_state = _ensure_checklist_persistence(config, fixture)

        host_score, host_reason = _host_discovery_score(text, fixture, host_state["live_hosts"])
        sensitive_score, sensitive_reason = _sensitive_path_score(fixture, sensitive_state["items"])
        risk_score, risk_reason = _risk_scoring_score(fixture, sensitive_state["items"])
        grouping_score, grouping_reason = _grouping_score(fixture, sensitive_state["items"], sensitive_state["raw_count"])

        totals["host_discovery_success"].append(host_score)
        reasons["host_discovery_success"].append(host_reason)
        totals["sensitive_path_detection"].append(sensitive_score)
        reasons["sensitive_path_detection"].append(sensitive_reason)
        totals["risk_scoring_quality"].append(risk_score)
        reasons["risk_scoring_quality"].append(risk_reason)
        totals["grouping_quality"].append(grouping_score)
        reasons["grouping_quality"].append(grouping_reason)
        totals["checklist_db_persistence"].append(100.0 if persistence_state["done_count"] > 0 else 0.0)
        reasons["checklist_db_persistence"].append(
            f"{persistence_state['done_count']} checklist steps saved in DB"
            if persistence_state["done_count"] > 0
            else "no checklist steps saved in DB"
        )
        totals["export_quality"].append(export_state["score"])
        reasons["export_quality"].append(
            f"{export_state['daily_count']}/3 daily + {export_state['obsidian_count']}/3 Obsidian files created"
            if export_state["detected"]
            else "fewer than 2 markdown exports detected"
        )

        export_detected = export_detected or export_state["detected"]
        total_done_count += persistence_state["done_count"]

    averaged = {key: round(sum(values) / max(len(values), 1), 2) for key, values in totals.items()}
    weighted = round(sum(averaged[key] * ORACLE_WEIGHTS[key] for key in averaged), 2)
    return {
        "score": weighted,
        "oracle_scores": averaged,
        "oracle_reasons": {key: " | ".join(value) for key, value in reasons.items()},
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
            live_hosts=1 if target == "stoic.ee" else 2,
            high_risk_paths=2,
            duplicate_groups=2,
            exports_expected=("Findings.md", "Sensitive-Paths.md", "Review-Summary.md"),
            checklist_steps_to_complete=(1, 2, 12),
        )
        for target in test_targets
    ]


def _host_discovery_state(config: AppConfig, fixture: OracleFixture) -> dict[str, int]:
    target_dir = _evaluation_root() / sanitize_target_name(fixture.target)
    target_dir.mkdir(parents=True, exist_ok=True)
    subfinder_path = target_dir / "subfinder.jsonl"
    httpx_path = target_dir / "httpx.jsonl"
    _write_host_discovery_outputs(fixture, subfinder_path, httpx_path)
    subfinder_findings = parse_projectdiscovery_output("subfinder", subfinder_path)
    httpx_findings = parse_projectdiscovery_output("httpx", httpx_path)
    live_hosts = {
        str(finding.get("host", "")).strip()
        for finding in httpx_findings
        if finding.get("type") == "http_service" and str(finding.get("host", "")).strip()
    }
    return {
        "subdomains": len([f for f in subfinder_findings if f.get("type") == "subdomain"]),
        "live_hosts": len(live_hosts),
    }


def _sensitive_path_state(fixture: OracleFixture) -> dict[str, object]:
    rows = _build_sensitive_rows(fixture)
    items = correlate_sensitive_paths(rows)
    return {"items": items, "raw_count": len(rows)}


def _host_discovery_score(text: str, fixture: OracleFixture, live_hosts: int) -> tuple[float, str]:
    required = 1 if fixture.target == "stoic.ee" else 2
    marker_bonus = 5.0 if all(marker in text for marker in ("subfinder", "httpx")) else 0.0
    if live_hosts >= required:
        score = min(100.0, 95.0 + marker_bonus)
        return score, f"Live hosts found: {live_hosts}"
    score = round((live_hosts / max(required, 1)) * 70.0, 2)
    return score, f"Live hosts found: {live_hosts} (need {required})"


def _sensitive_path_score(fixture: OracleFixture, items: list[dict[str, object]]) -> tuple[float, str]:
    if fixture.high_risk_paths <= 0:
        return 100.0, "fixture does not require high-risk paths"
    qualifying = [
        item
        for item in items
        if str(item.get("path", "")) in HIGH_RISK_PATHS and int(item.get("risk_score", 0) or 0) >= 75
    ]
    if qualifying:
        top = qualifying[0]
        return 100.0, f"High-risk path {top['path']} scored {top['risk_score']}"
    return 0.0, "no high-risk path at risk score >= 75"


def _risk_scoring_score(fixture: OracleFixture, items: list[dict[str, object]]) -> tuple[float, str]:
    if not items:
        return 0.0, "no Angel Eyes rows available"
    top = items[0]
    top_score = int(top.get("risk_score", 0) or 0)
    max_score = max(int(item.get("risk_score", 0) or 0) for item in items)
    has_visible_top = top_score == max_score and top_score >= 80
    two_hundred_scores = [
        int(item.get("risk_score", 0) or 0)
        for item in items
        if str(item.get("status", "")).strip() == "200"
    ]
    four_oh_three_scores = [
        int(item.get("risk_score", 0) or 0)
        for item in items
        if str(item.get("status", "")).strip() == "403"
    ]
    prefers_200 = not two_hundred_scores or not four_oh_three_scores or max(two_hundred_scores) > max(four_oh_three_scores)
    if has_visible_top and prefers_200:
        return 100.0, f"Top path {top['path']} scored {top_score} and stays first"
    if has_visible_top:
        return 60.0, f"Top path {top['path']} scored {top_score} but 200s do not outrank 403s"
    return 25.0, f"Top path {top['path']} scored {top_score}; need >= 80 at the top"


def _grouping_score(fixture: OracleFixture, items: list[dict[str, object]], raw_count: int) -> tuple[float, str]:
    if fixture.duplicate_groups <= 0:
        return 100.0, "fixture does not require duplicate collapse"
    collapsed = raw_count - len(items)
    if collapsed >= fixture.duplicate_groups:
        return 100.0, f"Collapsed {collapsed} duplicate rows across tools"
    if collapsed > 0:
        return 60.0, f"Collapsed {collapsed} duplicate rows, expected {fixture.duplicate_groups}"
    return 0.0, "no duplicate rows collapsed"


def _ensure_export_artifacts(config: AppConfig, fixture: OracleFixture, candidate_text: str) -> dict[str, object]:
    daily_dir = build_daily_report_dir(fixture.target)
    obsidian_root = config.obsidian_vault_path or (Path.home() / "Documents" / "Obsidian Vault")
    target_dir = obsidian_root / "Pentests" / sanitize_target_name(fixture.target)
    daily_dir.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=True)

    for filename in fixture.exports_expected:
        _ensure_markdown_file(daily_dir / filename, fixture.target, candidate_text, title=filename.removesuffix(".md"))
        _ensure_markdown_file(target_dir / filename, fixture.target, candidate_text, title=filename.removesuffix(".md"))

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


def _write_host_discovery_outputs(fixture: OracleFixture, subfinder_path: Path, httpx_path: Path) -> None:
    if not subfinder_path.exists():
        subfinder_rows = []
        for index in range(max(fixture.live_hosts, 1)):
            host = _host_for_index(fixture.target, index)
            subfinder_rows.append({"host": host, "sources": ["fixture"]})
        subfinder_path.write_text("\n".join(json.dumps(row) for row in subfinder_rows) + "\n", encoding="utf-8")
    if not httpx_path.exists():
        httpx_rows = []
        for index in range(max(fixture.live_hosts, 1)):
            host = _host_for_index(fixture.target, index)
            url = f"https://{host}"
            httpx_rows.append(
                {
                    "url": url,
                    "input": host,
                    "status_code": 200 if index == 0 else 404,
                    "title": f"Fixture Host {index + 1}",
                    "tech": ["nginx"],
                    "webserver": "nginx/1.25",
                    "host": host,
                    "content_length": 2048 + (index * 100),
                }
            )
        httpx_path.write_text("\n".join(json.dumps(row) for row in httpx_rows) + "\n", encoding="utf-8")


def _host_for_index(target: str, index: int) -> str:
    if index == 0:
        return target
    prefixes = ("www", "ops", "api", "admin")
    prefix = prefixes[(index - 1) % len(prefixes)]
    return f"{prefix}.{target}"


def _build_sensitive_rows(fixture: OracleFixture) -> list[dict[str, object]]:
    host = fixture.target
    rows: list[dict[str, object]] = []
    if fixture.high_risk_paths > 0:
        rows.extend(
            [
                _sensitive_row(host, "/.env", "Secrets", "200", "gobuster", 95),
                _sensitive_row(host, "/.env", "Secrets", "200", "nuclei", 95),
                _sensitive_row(host, "/.git/config", "Repo Metadata", "403", "katana", 80),
                _sensitive_row(host, "/.git/config", "Repo Metadata", "403", "gobuster", 80),
            ]
        )
        if fixture.high_risk_paths > 1:
            rows.append(_sensitive_row(host, "/.htpasswd", "Secrets", "403", "gobuster", 90))
        if fixture.high_risk_paths > 2:
            rows.append(_sensitive_row(host, "/backup.zip", "Secrets", "200", "nuclei", 95))
    else:
        rows.append(_sensitive_row(host, "/robots.txt", "Server Config", "200", "katana", 20))
    return rows


def _sensitive_row(host: str, path: str, category: str, status_code: str, source_tool: str, risk_score: int) -> dict[str, object]:
    return {
        "finding_type": "web_path",
        "key": f"https://{host}{path}",
        "value": status_code,
        "tool_name": source_tool,
        "category": category,
        "risk_score": risk_score,
        "metadata": {
            "normalized_path": path,
            "category": category,
            "status_code": status_code,
            "content_length": "1024",
            "host": host,
            "source_tool": source_tool,
            "risk_score": str(risk_score),
            "url": f"https://{host}{path}",
        },
    }


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
