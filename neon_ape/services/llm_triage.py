from __future__ import annotations

import json
import subprocess
import tempfile
from shutil import which


def ollama_available() -> bool:
    return which("ollama") is not None


def cline_available() -> bool:
    return which("cline") is not None


def run_local_triage(*, target: str, overview: dict[str, object], provider: str, model: str, timeout: int = 180) -> str:
    prompt = _build_triage_prompt(target=target, overview=overview)
    normalized_provider = provider.strip().lower()
    if normalized_provider == "ollama":
        return _run_ollama_triage(prompt=prompt, model=model, timeout=timeout)
    if normalized_provider == "cline":
        return _run_cline_triage(prompt=prompt, timeout=timeout)
    raise RuntimeError(f"Unsupported local LLM provider: {provider}")


def _run_ollama_triage(*, prompt: str, model: str, timeout: int) -> str:
    if not ollama_available():
        raise RuntimeError("Local `ollama` was not found on PATH.")
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


def _run_cline_triage(*, prompt: str, timeout: int) -> str:
    if not cline_available():
        raise RuntimeError("Local `cline` was not found on PATH.")
    try:
        with tempfile.TemporaryDirectory(prefix="neonape-cline-") as workspace:
            completed = subprocess.run(
                ["cline", prompt],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                cwd=workspace,
            )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Cline triage timed out after {timeout} seconds.") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise RuntimeError(stderr or f"Cline triage failed with exit code {completed.returncode}.")

    result = completed.stdout.strip()
    if not result:
        raise RuntimeError("Cline returned an empty triage result.")
    return result


def _build_triage_prompt(*, target: str, overview: dict[str, object]) -> str:
    payload = json.dumps(overview, indent=2, sort_keys=True)
    return (
        "You are a local security triage assistant embedded in Neon Ape.\n"
        "Summarize the supplied recon and review data for a human operator.\n"
        "Stay defensive and review-focused.\n"
        "Never use the words or phrases attack, bypass, exploit, foothold, payload, try to access, or attempt path traversal.\n"
        "Do not provide attack steps, exploit ideas, weaponization advice, or offensive sequencing.\n"
        "Use the exact markdown section headers below and no others:\n"
        "## 1. Executive Summary\n"
        "## 2. Highest-Priority Findings\n"
        "## 3. Manual Validation Checklist\n"
        "## 4. Remediation Focus\n"
        "## 5. Data Gaps\n"
        "For Highest-Priority Findings, include risk score and short evidence for each item.\n"
        "For Manual Validation Checklist, use only review-focused wording such as confirm, verify, review, inspect, compare, and document.\n\n"
        f"Target: {target}\n"
        f"Review data:\n{payload}\n"
    )
