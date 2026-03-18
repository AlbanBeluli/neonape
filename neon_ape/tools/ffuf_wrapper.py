from __future__ import annotations

import json
from pathlib import Path
import shutil
import urllib.request
from urllib.parse import urlparse

from neon_ape.services.validation import validate_url_or_target
from neon_ape.tools.base import ToolResult, run_command
from neon_ape.tools.web_enum import DEFAULT_WORDLISTS
from neon_ape.tools.web_paths import enrich_web_path_findings


FFUF_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
BUILTIN_FFUF_WORDLIST = """\
admin
login
.env
.git
.htaccess
.htpasswd
config.php
phpinfo.php
robots.txt
sitemap.xml
backup.zip
backup.tar.gz
uploads
api
dashboard
"""


def default_ffuf_wordlist_path() -> Path:
    return Path.home() / ".neonape" / "wordlists" / "common.txt"


def build_ffuf_command(
    target: str,
    output_path: Path,
    *,
    wordlist_path: Path | None = None,
    threads: int = 40,
    rate: int = 80,
) -> tuple[str, list[str]]:
    validated = _normalize_ffuf_target(target)
    wordlist = ensure_ffuf_wordlist(wordlist_path or default_ffuf_wordlist_path())
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
        "json",
    ]
    return validated, command


def ensure_ffuf_wordlist(preferred_path: Path | None = None) -> Path:
    target_path = preferred_path or default_ffuf_wordlist_path()
    target_path = target_path.expanduser()
    if target_path.exists() and target_path.stat().st_size > 0:
        return target_path

    for candidate in DEFAULT_WORDLISTS:
        resolved = Path(candidate).expanduser()
        if resolved.exists() and resolved.stat().st_size > 0:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(resolved, target_path)
            return target_path

    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(FFUF_WORDLIST_URL, timeout=20) as response:
            data = response.read()
        target_path.write_bytes(data)
        return target_path
    except Exception:  # noqa: BLE001
        target_path.write_text(BUILTIN_FFUF_WORDLIST, encoding="utf-8")
        return target_path


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
