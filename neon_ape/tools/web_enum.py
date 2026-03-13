from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from neon_ape.services.validation import validate_url_or_target
from neon_ape.tools.base import ToolResult, run_command


DEFAULT_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/Users/akira/SecLists/Discovery/Web-Content/common.txt",
    "/Users/akira/SecLists/Discovery/Web-Content/raft-small-words.txt",
    "/Users/akira/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/Users/akira/dirb/wordlists/common.txt",
)


def build_gobuster_command(target: str, output_path: Path, *, exclude_length: str | None = None) -> tuple[str, list[str]]:
    validated = _normalize_gobuster_target(target)
    wordlist = _detect_wordlist()
    if wordlist is None:
        raise ValueError(
            "No supported gobuster wordlist found. Install SecLists or dirb common wordlists, "
            "or place one in a standard path such as ~/SecLists/Discovery/Web-Content/common.txt."
        )
    command = [
        "gobuster",
        "dir",
        "-q",
        "-k",
        "-u",
        validated,
        "-w",
        wordlist,
        "-t",
        "10",
    ]
    if exclude_length:
        command.extend(["--exclude-length", exclude_length])
    command.extend(
        [
        "-o",
        str(output_path),
        ]
    )
    return validated, command


def execute_gobuster(command: list[str], target: str, output_path: Path) -> ToolResult:
    return run_command("gobuster", target, command, timeout=300, raw_output_path=str(output_path))


def parse_gobuster_output(output_path: Path) -> list[dict[str, str]]:
    if not output_path.exists():
        return []
    findings: list[dict[str, str]] = []
    with output_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("====") or line.startswith("Gobuster") or line.startswith("[") and "Progress" in line:
                continue
            if "Status:" not in line:
                continue
            path_part, status_part = line.split("Status:", 1)
            path_value = path_part.strip()
            status_value = status_part.strip()
            findings.append({"type": "web_path", "host": path_value, "key": path_value, "value": status_value})
    return findings


def _detect_wordlist() -> str | None:
    for candidate in DEFAULT_WORDLISTS:
        if Path(candidate).exists():
            return candidate
    return None


def _normalize_gobuster_target(target: str) -> str:
    validated = validate_url_or_target(target)
    parsed = urlparse(validated)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return validated
    return f"https://{validated}"
