from neon_ape.evaluation.harness import built_in_targets, evaluate_skill_objectively, render_sparkline


def test_built_in_targets_returns_safe_fixture_labels() -> None:
    targets = built_in_targets("angel-eyes")
    assert len(targets) >= 3
    assert targets[0].endswith(".local")


def test_evaluate_skill_objectively_returns_weighted_score() -> None:
    report = evaluate_skill_objectively(
        skill_name="angel-eyes",
        candidate_text=(
            "subfinder httpx live host angel eyes high-risk .env .git highest risk risk score "
            "grouped duplicate source tool database saved persist Findings.md Sensitive-Paths.md Review-Summary.md"
        ),
    )
    assert report["score"] > 50
    oracle_scores = report["oracle_scores"]
    assert oracle_scores["host_discovery_success"] > 0
    assert oracle_scores["export_quality"] > 0


def test_render_sparkline_returns_blocks() -> None:
    sparkline = render_sparkline([10, 20, 30, 25, 35])
    assert len(sparkline) == 5
