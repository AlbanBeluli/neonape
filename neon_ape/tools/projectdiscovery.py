from __future__ import annotations

import json
from pathlib import Path

from neon_ape.tools.base import ToolResult, run_command
from neon_ape.services.validation import validate_domain, validate_target, validate_url_or_target


SUPPORTED_TOOLS = ("subfinder", "httpx", "naabu", "dnsx")


def build_projectdiscovery_command(tool_name: str, target: str, output_path: Path) -> tuple[str, list[str]]:
    if tool_name == "subfinder":
        validated = validate_domain(target)
        command = ["subfinder", "-silent", "-oJ", "-d", validated, "-o", str(output_path)]
        return validated, command

    if tool_name == "httpx":
        validated = validate_url_or_target(target)
        command = [
            "httpx",
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-ip",
            "-target",
            validated,
            "-o",
            str(output_path),
        ]
        return validated, command

    if tool_name == "naabu":
        validated = validate_target(target)
        command = ["naabu", "-silent", "-json", "-top-ports", "100", "-host", validated, "-o", str(output_path)]
        return validated, command

    if tool_name == "dnsx":
        validated = validate_domain(target)
        input_path = output_path.with_suffix(".input.txt")
        input_path.write_text(f"{validated}\n", encoding="utf-8")
        command = [
            "dnsx",
            "-silent",
            "-json",
            "-re",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-mx",
            "-txt",
            "-list",
            str(input_path),
            "-o",
            str(output_path),
        ]
        return validated, command

    raise ValueError(f"Unsupported ProjectDiscovery tool: {tool_name}")


def execute_projectdiscovery(command: list[str], tool_name: str, target: str, output_path: Path) -> ToolResult:
    cleanup_path = output_path.with_suffix(".input.txt") if tool_name == "dnsx" else None
    try:
        return run_command(tool_name, target, command, timeout=_timeout_for(tool_name), raw_output_path=str(output_path))
    finally:
        if cleanup_path is not None:
            cleanup_path.unlink(missing_ok=True)


def parse_projectdiscovery_output(tool_name: str, output_path: Path) -> list[dict[str, str]]:
    if not output_path.exists():
        return []

    findings: list[dict[str, str]] = []
    with output_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                findings.append({"type": "raw_output", "value": line})
                continue
            findings.extend(_parse_payload(tool_name, payload))
    return findings


def _parse_payload(tool_name: str, payload: dict[str, object]) -> list[dict[str, str]]:
    if tool_name == "subfinder":
        host = str(payload.get("host", ""))
        sources = payload.get("sources", [])
        value = ",".join(str(item) for item in sources) if isinstance(sources, list) else str(sources)
        return [{"type": "subdomain", "host": host, "key": host, "value": value or "discovered"}]

    if tool_name == "httpx":
        url = str(payload.get("url", payload.get("input", "")))
        status_code = str(payload.get("status_code", ""))
        title = str(payload.get("title", ""))
        tech = payload.get("tech", [])
        technologies = ",".join(str(item) for item in tech) if isinstance(tech, list) else str(tech)
        webserver = str(payload.get("webserver", ""))
        ip = str(payload.get("host", payload.get("ip", "")))
        content_type = str(payload.get("content_type", ""))
        value = " ".join(part for part in (status_code, title, technologies) if part).strip()
        return [
            {
                "type": "http_service",
                "host": url,
                "key": url,
                "value": value or "reachable",
                "status_code": status_code,
                "title": title,
                "technologies": technologies,
                "webserver": webserver,
                "ip": ip,
                "content_type": content_type,
            }
        ]

    if tool_name == "naabu":
        host = str(payload.get("host", payload.get("ip", "")))
        port = str(payload.get("port", ""))
        protocol = str(payload.get("protocol", "tcp"))
        return [{"type": "port", "host": host, "key": port, "value": protocol}]

    if tool_name == "dnsx":
        host = str(payload.get("host", ""))
        records: list[dict[str, str]] = []
        for record_type in ("a", "aaaa", "cname", "ns", "mx", "txt"):
            values = payload.get(record_type)
            if isinstance(values, list) and values:
                records.append(
                    {
                        "type": "dns_record",
                        "host": host,
                        "key": record_type.upper(),
                        "value": ",".join(str(value) for value in values),
                        "record_type": record_type.upper(),
                    }
                )
        if records:
            return records
        response = payload.get("raw")
        if response:
            return [{"type": "dns_record", "host": host, "key": "RAW", "value": str(response)}]
        return []

    return [{"type": "raw_output", "value": json.dumps(payload, sort_keys=True)}]


def _timeout_for(tool_name: str) -> int:
    if tool_name == "subfinder":
        return 180
    if tool_name == "httpx":
        return 120
    if tool_name == "naabu":
        return 180
    if tool_name == "dnsx":
        return 120
    return 300
