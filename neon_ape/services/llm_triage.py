from __future__ import annotations

import json
import subprocess
from shutil import which


def ollama_available() -> bool:
    return which("ollama") is not None


def run_local_triage(*, target: str, overview: dict[str, object], model: str, timeout: int = 180) -> str:
    if not ollama_available():
        raise RuntimeError("Local `ollama` was not found on PATH.")

    prompt = _build_triage_prompt(target=target, overview=overview)
    try:
        completed = subprocess.run(
            ["ollama", "run", model, prompt],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Ollama triage timed out after {timeout} seconds.") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise RuntimeError(stderr or f"Ollama triage failed with exit code {completed.returncode}.")

    result = completed.stdout.strip()
    if not result:
        raise RuntimeError("Ollama returned an empty triage result.")
    return result


def _build_triage_prompt(*, target: str, overview: dict[str, object]) -> str:
    payload = json.dumps(overview, indent=2, sort_keys=True)
    return (
        "You are a local security triage assistant embedded in Neon Ape.\n"
        "Summarize the supplied recon and review data for a human operator.\n"
        "Stay defensive and review-focused. Do not provide exploitation steps, foothold guidance, payloads, or attack chains.\n"
        "Return concise markdown with these sections:\n"
        "1. Executive Summary\n"
        "2. Highest-Priority Findings\n"
        "3. Manual Validation Priorities\n"
        "4. Remediation Focus\n"
        "5. Data Gaps\n\n"
        f"Target: {target}\n"
        f"Review data:\n{payload}\n"
    )
