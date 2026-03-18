from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from statistics import mean
import json
import sys

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from neon_ape.skills.manager import (
    describe_skill_structure,
    diff_skill,
    initialize_skill_state,
    save_improved_skill,
)
from neon_ape.workflows.orchestrator import is_macos, speak_autoresearch_completion

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class SkillProfile:
    name: str
    label: str
    source_path: Path
    default_questions: tuple[str, ...]
    default_scenarios: tuple[str, ...]
    mutation_bank: tuple[str, ...]
    keyword_bank: tuple[str, ...]


SKILL_REGISTRY: dict[str, SkillProfile] = {
    "magi-checklist": SkillProfile(
        name="magi-checklist",
        label="MAGI Checklist",
        source_path=REPO_ROOT / "neon_ape" / "checklists" / "neon_ape_checklist.json",
        default_questions=(
            "Does the checklist stay practical for recon and review operators?",
            "Does every step make the next action obvious?",
            "Does the checklist preserve status cleanly in the local database?",
        ),
        default_scenarios=(
            "A new operator needs to understand host discovery and service enumeration quickly.",
            "An Adam run finishes and the operator needs to continue manual validation from MAGI.",
            "A reviewer checks whether the stored checklist state matches the guided workflow.",
        ),
        mutation_bank=(
            "Clarify that each step should reference the exact wrapper or command preview shown in Neon Ape.",
            "Emphasize persistence: every guided step should map to stored evidence or a deliberate manual review decision.",
            "Tighten the operator language so the sequence feels procedural instead of descriptive.",
            "Surface the highest-value recon and review steps earlier in the narrative.",
        ),
        keyword_bank=("checklist", "magi", "status", "step", "review", "run now", "database"),
    ),
    "angel-eyes": SkillProfile(
        name="angel-eyes",
        label="Angel Eyes",
        source_path=REPO_ROOT / "neon_ape" / "tools" / "web_paths.py",
        default_questions=(
            "Does Angel Eyes clearly rank sensitive paths by evidence and risk?",
            "Does the review language stay defensive and operator-focused?",
            "Does the output make it obvious which web exposures need manual review first?",
        ),
        default_scenarios=(
            "A target exposes .env and .git paths behind mixed 200 and 403 responses.",
            "A reviewer needs to explain why a blocked log file is still important.",
            "An Obsidian export should summarize only the highest-priority sensitive path evidence.",
        ),
        mutation_bank=(
            "Highlight that category, status, source tool, and risk score should always travel together.",
            "Make the review language explicitly defensive: prioritize validation and remediation, not attack framing.",
            "Favor grouped evidence that collapses duplicate paths across multiple source tools.",
            "Keep the highest-risk web exposure summary visible at the top of the operator output.",
        ),
        keyword_bank=("angel eyes", "sensitive", "risk", "category", "web", "review", "evidence"),
    ),
    "nmap-wrappers": SkillProfile(
        name="nmap-wrappers",
        label="Nmap Wrappers",
        source_path=REPO_ROOT / "neon_ape" / "tools" / "nmap.py",
        default_questions=(
            "Do the wrappers stay safe and predictable for local operator use?",
            "Do the profiles map cleanly to the intended scan intensity?",
            "Does the XML parsing preserve useful service evidence for later review?",
        ),
        default_scenarios=(
            "An operator wants a low-noise host discovery pass.",
            "A service scan should feed the review layer with product and version evidence.",
            "A stored scan needs to be understandable from the DB without reading raw XML.",
        ),
        mutation_bank=(
            "Prefer crisp profile descriptions that expose scan intensity and evidence flow.",
            "Reinforce that XML output is the persistence bridge into Neon Ape review features.",
            "Keep the operator mental model centered on safe profiles instead of raw flag memorization.",
        ),
        keyword_bank=("nmap", "xml", "profile", "service", "scan", "evidence"),
    ),
    "ui-panels": SkillProfile(
        name="ui-panels",
        label="UI Panels",
        source_path=REPO_ROOT / "neon_ape" / "ui" / "layout.py",
        default_questions=(
            "Do the panels make high-priority information obvious at a glance?",
            "Does the theme stay consistent with the Adam and Eva visual language?",
            "Does the operator always know the next action to take?",
        ),
        default_scenarios=(
            "A tired operator opens Neon Ape late at night and needs the main signal immediately.",
            "An Adam run finishes and the completion screen should point straight to the report artifacts.",
            "A MAGI step is active and the operator must see status without reading dense text blocks.",
        ),
        mutation_bank=(
            "Keep primary signal above ornament: the next action and current risk should dominate the layout.",
            "Use Eva-styled emphasis to distinguish operator guidance from stored evidence.",
            "Compress repeated wording so the visual system stays sharp during long sessions.",
        ),
        keyword_bank=("panel", "layout", "operator", "status", "signal", "summary"),
    ),
    "prompt-templates": SkillProfile(
        name="prompt-templates",
        label="Prompt Templates",
        source_path=REPO_ROOT / "neon_ape" / "services" / "llm_triage.py",
        default_questions=(
            "Do the prompts stay defensive and avoid offensive drift?",
            "Do they produce concise review output instead of generic prose?",
            "Do they preserve evidence and remediation focus?",
        ),
        default_scenarios=(
            "Angel Eyes finds a blocked .env and .git directory on a target.",
            "A service inventory contains an outdated Apache version that needs review wording.",
            "The operator needs a triage summary that fits cleanly into Obsidian.",
        ),
        mutation_bank=(
            "Require concise defensive phrasing and forbid speculative attack wording.",
            "Bias output toward evidence, manual validation, remediation, and data gaps.",
            "Make every section accountable to the observed findings instead of generic advice.",
        ),
        keyword_bank=("prompt", "triage", "review", "defensive", "remediation", "evidence"),
    ),
    "triage-prompt": SkillProfile(
        name="triage-prompt",
        label="Triage Prompt",
        source_path=REPO_ROOT / "neon_ape" / "services" / "llm_triage.py",
        default_questions=(
            "Do the prompts stay defensive and avoid offensive drift?",
            "Do they produce concise review output instead of generic prose?",
            "Do they preserve evidence and remediation focus?",
        ),
        default_scenarios=(
            "Angel Eyes finds a blocked .env and .git directory on a target.",
            "A service inventory contains an outdated Apache version that needs review wording.",
            "The operator needs a triage summary that fits cleanly into Obsidian.",
        ),
        mutation_bank=(
            "Require concise defensive phrasing and forbid speculative attack wording.",
            "Bias output toward evidence, manual validation, remediation, and data gaps.",
            "Make every section accountable to the observed findings instead of generic advice.",
        ),
        keyword_bank=("prompt", "triage", "review", "defensive", "remediation", "evidence"),
    ),
    "adam-workflow": SkillProfile(
        name="adam-workflow",
        label="Adam Workflow",
        source_path=REPO_ROOT / "neon_ape" / "agents" / "adam.py",
        default_questions=(
            "Does Adam remain a clean end-to-end operator workflow?",
            "Does each stage flow naturally into the next without surprise?",
            "Does the completion screen leave the operator with clear follow-up paths?",
        ),
        default_scenarios=(
            "A target completes recon and the operator needs exports, daily reports, and MAGI continuation.",
            "A partially failing nuclei or gobuster stage should still produce a usable operator flow.",
            "An Adam run with autoresearch should remain understandable instead of feeling bolted on.",
        ),
        mutation_bank=(
            "Keep Adam’s narrative sequential: recon, review, export, checklist, then refinement.",
            "Make partial-failure language calm and operational instead of alarming.",
            "Ensure the completion path always points to artifacts and the next human decision.",
        ),
        keyword_bank=("adam", "workflow", "report", "magi", "export", "completion"),
    ),
}


def run_autoresearch(
    console: Console,
    *,
    config,
    skill_target: str | None = None,
    questions: list[str] | None = None,
    scenarios: list[str] | None = None,
    overnight: bool = False,
    iterations: int = 6,
    baseline_runs: int = 8,
    daily_report_dir: Path | None = None,
    silent_voice: bool = False,
) -> bool:
    profile = _resolve_skill_profile(skill_target, console)
    if profile is None:
        return False

    active_questions = _collect_questions(console, profile, questions or [])
    active_scenarios = _collect_scenarios(console, profile, scenarios or [])
    original_text = profile.source_path.read_text(encoding="utf-8")
    persisted = initialize_skill_state(
        skill_name=profile.name,
        label=profile.label,
        source_path=profile.source_path,
        content=original_text,
        score=None,
    )
    baseline_text = str(persisted.get("content", original_text))
    baseline_samples = _score_samples(profile, baseline_text, active_questions, active_scenarios, runs=baseline_runs)
    baseline_score = round(mean(baseline_samples), 2)
    best_text = baseline_text
    best_score = baseline_score
    kept_changes: list[dict[str, object]] = []
    discarded_changes: list[dict[str, object]] = []
    mutation_log: list[dict[str, object]] = []

    with Live(_build_dashboard(profile, baseline_score, best_score, kept_changes, discarded_changes, active_questions, active_scenarios), console=console, refresh_per_second=4) as live:
        for iteration in range(1, max(iterations, 1) + 1):
            change_note = _choose_mutation(profile, best_text, iteration)
            candidate_text = _apply_tiny_change(best_text, profile, change_note, iteration)
            scores = _score_samples(profile, candidate_text, active_questions, active_scenarios, runs=baseline_runs)
            candidate_score = round(mean(scores), 2)
            entry = {
                "iteration": iteration,
                "change": change_note,
                "score": candidate_score,
                "delta": round(candidate_score - best_score, 2),
            }
            mutation_log.append(entry)
            if candidate_score > best_score:
                best_score = candidate_score
                best_text = candidate_text
                kept_changes.append(entry)
            else:
                discarded_changes.append(entry)
            live.update(
                _build_dashboard(
                    profile,
                    baseline_score,
                    best_score,
                    kept_changes,
                    discarded_changes,
                    active_questions,
                    active_scenarios,
                    iteration=iteration,
                    overnight=overnight,
                )
            )

    improvement = round(best_score - baseline_score, 2)
    saved_state = None
    backup_file = None
    diff_text = "No persisted skill update because improvement did not exceed 2.0%."
    if improvement > 2.0:
        saved_state, backup_file = save_improved_skill(
            skill_name=profile.name,
            label=profile.label,
            source_path=profile.source_path,
            previous_content=baseline_text,
            new_content=best_text,
            previous_score=baseline_score,
            new_score=best_score,
            questions=active_questions,
            scenarios=active_scenarios,
            kept_changes=kept_changes,
            discarded_changes=discarded_changes,
        )
        diff_text = diff_skill(profile.name)

    if not silent_voice:
        spoken_lines = speak_autoresearch_completion(baseline_score, best_score, persisted=improvement > 2.0)
        if is_macos():
            console.print("[bold orange3]Daniel voice notification:[/bold orange3]")
            for line in spoken_lines:
                console.print(f"- {line}")

    diff_panel = Panel.fit(
        diff_text if len(diff_text) < 3000 else diff_text[:3000] + "\n...",
        title="Skill Diff Summary",
        border_style="magenta",
    )
    console.print(diff_panel)
    console.print(
        Panel.fit(
            f"[bold magenta]Autoresearch complete[/bold magenta]\n"
            f"[bold]Skill:[/bold] {profile.label}\n"
            f"[bold]Baseline:[/bold] {baseline_score}%\n"
            f"[bold]Improved:[/bold] {best_score}%\n"
            f"[bold]Improvement delta:[/bold] {improvement}%\n"
            f"[bold]Current skill:[/bold] {describe_skill_structure(profile.name)[1]}\n"
            f"[bold]Backup:[/bold] {backup_file if backup_file else 'Not written'}\n"
            f"[bold]Changelog:[/bold] {describe_skill_structure(profile.name)[2]}\n"
            f"[bold]Status:[/bold] {'Skill improved and saved permanently. New version active.' if saved_state else 'Research complete, but active version unchanged.'}",
            title="Autoresearch",
            border_style="magenta",
        )
    )
    return True


def _resolve_skill_profile(skill_target: str | None, console: Console) -> SkillProfile | None:
    if not skill_target:
        if not sys.stdin.isatty():
            return SKILL_REGISTRY["magi-checklist"]
        prompt = ", ".join(sorted(SKILL_REGISTRY))
        answer = Prompt.ask("[bold magenta]Skill to improve[/bold magenta]", default="magi-checklist")
        skill_target = answer.strip()
        if not skill_target:
            skill_target = "magi-checklist"
    normalized = skill_target.strip().lower()
    profile = SKILL_REGISTRY.get(normalized)
    if profile is None:
        console.print(f"[bold red]Unsupported skill target:[/bold red] {skill_target}")
        console.print(f"[bold yellow]Supported values:[/bold yellow] {', '.join(sorted(SKILL_REGISTRY))}")
    return profile


def _collect_questions(console: Console, profile: SkillProfile, provided: list[str]) -> list[str]:
    if provided:
        return provided[:6]
    if not sys.stdin.isatty():
        return list(profile.default_questions)
    console.print("[bold magenta]Autoresearch checklist questions[/bold magenta] [dim](3-6 yes/no prompts)[/dim]")
    questions = []
    for index, default in enumerate(profile.default_questions, start=1):
        answer = console.input(f"Question {index} [{default}]: ").strip()
        questions.append(answer or default)
    while len(questions) < 6:
        answer = console.input("Add another yes/no question [Enter to stop]: ").strip()
        if not answer:
            break
        questions.append(answer)
    return questions


def _collect_scenarios(console: Console, profile: SkillProfile, provided: list[str]) -> list[str]:
    if provided:
        return provided[:5]
    if not sys.stdin.isatty():
        return list(profile.default_scenarios)
    console.print("[bold magenta]Autoresearch test scenarios[/bold magenta] [dim](3-5 cases)[/dim]")
    scenarios = []
    for index, default in enumerate(profile.default_scenarios, start=1):
        answer = console.input(f"Scenario {index} [{default}]: ").strip()
        scenarios.append(answer or default)
    while len(scenarios) < 5:
        answer = console.input("Add another scenario [Enter to stop]: ").strip()
        if not answer:
            break
        scenarios.append(answer)
    return scenarios


def _score_samples(
    profile: SkillProfile,
    candidate_text: str,
    questions: list[str],
    scenarios: list[str],
    *,
    runs: int,
) -> list[float]:
    base = _base_score(profile, candidate_text, questions, scenarios)
    scores: list[float] = []
    for index in range(runs):
        digest = sha256(f"{profile.name}|{index}|{candidate_text}|{'|'.join(questions)}|{'|'.join(scenarios)}".encode("utf-8")).hexdigest()
        jitter = (int(digest[:2], 16) % 5) - 2
        scores.append(max(0.0, min(100.0, round(base + jitter, 2))))
    return scores


def _base_score(profile: SkillProfile, candidate_text: str, questions: list[str], scenarios: list[str]) -> float:
    text = candidate_text.lower()
    keyword_hits = sum(1 for keyword in profile.keyword_bank if keyword in text)
    keyword_score = (keyword_hits / max(len(profile.keyword_bank), 1)) * 30
    question_score = sum(_question_alignment(text, question) for question in questions) / max(len(questions), 1) * 35
    scenario_score = sum(_scenario_alignment(text, scenario) for scenario in scenarios) / max(len(scenarios), 1) * 35
    return round(keyword_score + question_score + scenario_score, 2)


def _question_alignment(text: str, question: str) -> float:
    tokens = _meaningful_terms(question)
    if not tokens:
        return 0.5
    return sum(1 for token in tokens if token in text) / len(tokens)


def _scenario_alignment(text: str, scenario: str) -> float:
    tokens = _meaningful_terms(scenario)
    if not tokens:
        return 0.5
    return min(1.0, (sum(1 for token in tokens if token in text) + 1) / (len(tokens) + 1))


def _meaningful_terms(text: str) -> list[str]:
    terms = []
    for raw in text.lower().replace("/", " ").replace("-", " ").split():
        token = "".join(char for char in raw if char.isalnum() or char == ".")
        if len(token) >= 4:
            terms.append(token)
    return terms[:10]


def _choose_mutation(profile: SkillProfile, current_text: str, iteration: int) -> str:
    for change in profile.mutation_bank:
        if change.lower() not in current_text.lower():
            return change
    return profile.mutation_bank[(iteration - 1) % len(profile.mutation_bank)]


def _apply_tiny_change(current_text: str, profile: SkillProfile, change_note: str, iteration: int) -> str:
    if profile.source_path.suffix == ".json":
        payload = json.loads(current_text)
        if isinstance(payload, list):
            mutated = list(payload)
            mutated.append(
                {
                    "section_name": "Autoresearch",
                    "title": f"Iteration {iteration} refinement note",
                    "guide_text": change_note,
                    "status": "todo",
                }
            )
            return json.dumps(mutated, indent=2) + "\n"
        if isinstance(payload, dict):
            mutated = dict(payload)
            mutated["_autoresearch_note"] = {"iteration": iteration, "change": change_note}
            return json.dumps(mutated, indent=2) + "\n"
    comment = _comment_prefix(profile.source_path)
    return current_text.rstrip() + f"\n{comment} autoresearch iteration {iteration}: {change_note}{_comment_suffix(profile.source_path)}\n"


def _comment_prefix(path: Path) -> str:
    if path.suffix in {".py", ".sh"}:
        return "#"
    if path.suffix in {".md", ".txt"}:
        return "<!--"
    return "#"


def _comment_suffix(path: Path) -> str:
    if path.suffix in {".md", ".txt"}:
        return " -->"
    return ""


def _build_dashboard(
    profile: SkillProfile,
    baseline_score: float,
    best_score: float,
    kept_changes: list[dict[str, object]],
    discarded_changes: list[dict[str, object]],
    questions: list[str],
    scenarios: list[str],
    *,
    iteration: int = 0,
    overnight: bool = False,
) -> Group:
    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="bold magenta")
    stats.add_column()
    stats.add_row("Skill", profile.label)
    stats.add_row("Source", str(profile.source_path.relative_to(REPO_ROOT)))
    stats.add_row("Mode", "overnight autonomous loop" if overnight else "bounded local loop")
    stats.add_row("Iteration", str(iteration))
    stats.add_row("Baseline", f"{baseline_score}%")
    stats.add_row("Best", f"{best_score}%")
    stats.add_row("Kept", str(len(kept_changes)))
    stats.add_row("Discarded", str(len(discarded_changes)))

    score_table = Table(title="Score Chart", expand=False)
    score_table.add_column("Metric", style="bold magenta")
    score_table.add_column("Value")
    score_table.add_row("Baseline", f"{baseline_score}%")
    score_table.add_row("Current Best", f"{best_score}%")
    score_table.add_row("Improvement", f"{round(best_score - baseline_score, 2)}%")

    log_table = Table(title="Change Log", expand=False)
    log_table.add_column("Decision", style="bold")
    log_table.add_column("Iteration")
    log_table.add_column("Score")
    log_table.add_column("Change")
    for entry in kept_changes[-4:]:
        log_table.add_row("[bold green]kept[/bold green]", str(entry["iteration"]), f"{entry['score']}%", str(entry["change"]))
    for entry in discarded_changes[-4:]:
        log_table.add_row("[bold red]discarded[/bold red]", str(entry["iteration"]), f"{entry['score']}%", str(entry["change"]))
    if not kept_changes and not discarded_changes:
        log_table.add_row("-", "-", "-", "Awaiting first tiny change")

    prompts_table = Table(title="Operator Criteria", expand=False)
    prompts_table.add_column("Type", style="bold magenta")
    prompts_table.add_column("Prompt")
    for question in questions:
        prompts_table.add_row("Yes/No", question)
    for scenario in scenarios:
        prompts_table.add_row("Scenario", scenario)

    return Group(
        Panel.fit(stats, title="Autoresearch Dashboard", border_style="magenta"),
        score_table,
        log_table,
        prompts_table,
    )


def _build_changelog(
    profile: SkillProfile,
    baseline_score: float,
    best_score: float,
    questions: list[str],
    scenarios: list[str],
    kept_changes: list[dict[str, object]],
    discarded_changes: list[dict[str, object]],
) -> str:
    lines = [
        f"# Autoresearch Changelog: {profile.label}",
        "",
        f"- Skill: `{profile.name}`",
        f"- Source: `{profile.source_path.relative_to(REPO_ROOT)}`",
        f"- Baseline score: `{baseline_score}%`",
        f"- Final score: `{best_score}%`",
        "",
        "## Questions",
    ]
    lines.extend(f"- {item}" for item in questions)
    lines.extend(["", "## Scenarios"])
    lines.extend(f"- {item}" for item in scenarios)
    lines.extend(["", "## Kept changes"])
    if kept_changes:
        lines.extend(f"- Iteration {item['iteration']}: +{round(float(item['delta']), 2)} -> {item['change']}" for item in kept_changes)
    else:
        lines.append("- None kept")
    lines.extend(["", "## Discarded changes"])
    if discarded_changes:
        lines.extend(f"- Iteration {item['iteration']}: {round(float(item['delta']), 2)} -> {item['change']}" for item in discarded_changes)
    else:
        lines.append("- None discarded")
    return "\n".join(lines) + "\n"
