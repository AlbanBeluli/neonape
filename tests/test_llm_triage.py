from neon_ape.services.llm_triage import run_local_triage


def test_run_local_triage_invokes_ollama(monkeypatch) -> None:
    class Result:
        returncode = 0
        stdout = "## Executive Summary\n\nReview complete."
        stderr = ""

    monkeypatch.setattr("neon_ape.services.llm_triage.ollama_available", lambda: True)
    monkeypatch.setattr("neon_ape.services.llm_triage.subprocess.run", lambda *args, **kwargs: Result())

    output = run_local_triage(
        target="example.com",
        overview={"inventory": [], "reviews": [], "web_paths": {"katana": [], "gobuster": []}},
        provider="ollama",
        model="qwen3.5:4b",
    )

    assert "Executive Summary" in output


def test_run_local_triage_raises_when_ollama_missing(monkeypatch) -> None:
    monkeypatch.setattr("neon_ape.services.llm_triage.ollama_available", lambda: False)

    try:
        run_local_triage(
            target="example.com",
            overview={"inventory": [], "reviews": [], "web_paths": {"katana": [], "gobuster": []}},
            provider="ollama",
            model="qwen3.5:4b",
        )
    except RuntimeError as exc:
        assert "ollama" in str(exc).lower()
    else:
        raise AssertionError("Expected RuntimeError when ollama is missing")


def test_run_local_triage_invokes_cline(monkeypatch) -> None:
    class Result:
        returncode = 0
        stdout = "## Executive Summary\n\nCline review complete."
        stderr = ""

    monkeypatch.setattr("neon_ape.services.llm_triage.cline_available", lambda: True)
    monkeypatch.setattr("neon_ape.services.llm_triage.subprocess.run", lambda *args, **kwargs: Result())

    output = run_local_triage(
        target="example.com",
        overview={"inventory": [], "reviews": [], "web_paths": {"katana": [], "gobuster": []}},
        provider="cline",
        model="qwen3.5:4b",
    )

    assert "Cline review complete" in output
