from __future__ import annotations

import json
from pathlib import Path
import urllib.request
from urllib.parse import urlparse

from neon_ape.services.validation import validate_url_or_target
from neon_ape.tools.base import ToolResult, run_command
from neon_ape.tools.web_enum import DEFAULT_WORDLISTS
from neon_ape.tools.web_paths import enrich_web_path_findings


FFUF_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"


def build_ffuf_command(
    target: str,
    output_path: Path,
    *,
    wordlist_path: Path | None = None,
    threads: int = 50,
    rate: int = 100,
) -> tuple[str, list[str]]:
    validated = _normalize_ffuf_target(target)
    wordlist = ensure_ffuf_wordlist(wordlist_path or output_path.parent / "wordlists" / "common.txt")
    command = [
        "ffuf",
        "-u",
        f"{validated.rstrip('/')}/FUZZ",
        "-w",
        str(wordlist),
        "-t",
        str(threads),
        "-rate",
        str(rate),
        "-o",
        str(output_path),
        "-of",
        "jsonl",
    ]
    return validated, command


def ensure_ffuf_wordlist(preferred_path: Path) -> Path:
    for candidate in DEFAULT_WORDLISTS:
        resolved = Path(candidate).expanduser()
        if resolved.exists():
            return resolved
    preferred_path.parent.mkdir(parents=True, exist_ok=True)
    if preferred_path.exists() and preferred_path.stat().st_size > 0:
        return preferred_path
    try:
        with urllib.request.urlopen(FFUF_WORDLIST_URL, timeout=20) as response:
            data = response.read()
        preferred_path.write_bytes(data)
        return preferred_path
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            "No supported ffuf wordlist found and automatic download failed. "
            "Install SecLists or place Discovery/Web-Content/common.txt locally."
        ) from exc


def execute_ffuf(command: list[str], target: str, output_path: Path) -> ToolResult:
    return run_command("ffuf", target, command, timeout=300, raw_output_path=str(output_path))


def parse_ffuf_output(output_path: Path) -> list[dict[str, str]]:
    if not output_path.exists() or output_path.stat().st_size == 0:
        return []

    findings: list[dict[str, str]] = []
    raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw_text:
        return []

    lines = [line for line in raw_text.splitlines() if line.strip()]
    parsed_any = False
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        if isinstance(payload, dict) and isinstance(payload.get("results"), list):
            for item in payload["results"]:
                if isinstance(item, dict):
                    findings.append(_ffuf_result_to_finding(item))
            continue
        if isinstance(payload, dict):
            findings.append(_ffuf_result_to_finding(payload))

    if not parsed_any:
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, dict) and isinstance(payload.get("results"), list):
            for item in payload["results"]:
                if isinstance(item, dict):
                    findings.append(_ffuf_result_to_finding(item))

    return enrich_web_path_findings("ffuf", [finding for finding in findings if finding])


def _ffuf_result_to_finding(payload: dict[str, object]) -> dict[str, str]:
    url = str(payload.get("url", ""))
    input_value = payload.get("input")
    path_value = ""
    if isinstance(input_value, dict):
        path_value = str(input_value.get("FUZZ", ""))
    if not path_value:
        parsed = urlparse(url)
        path_value = parsed.path or str(payload.get("position", ""))
    if path_value and not path_value.startswith("/"):
        path_value = f"/{path_value}"
    status_code = str(payload.get("status", ""))
    content_length = str(payload.get("length", ""))
    words = str(payload.get("words", ""))
    lines = str(payload.get("lines", ""))
    value = f"{status_code} len={content_length} words={words} lines={lines}".strip()
    return {
        "type": "web_path",
        "host": path_value,
        "key": path_value,
        "value": value,
        "status_code": status_code,
        "content_length": content_length,
        "url": url,
    }


def _normalize_ffuf_target(target: str) -> str:
    validated = validate_url_or_target(target)
    parsed = urlparse(validated)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return validated
    return f"https://{validated}"
