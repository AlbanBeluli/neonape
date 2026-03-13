from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from neon_ape.tools.base import ToolResult, run_command
from neon_ape.services.validation import validate_domain, validate_target, validate_url_or_target


SUPPORTED_TOOLS = ("subfinder", "httpx", "naabu", "dnsx", "nuclei", "assetfinder", "amass", "katana")


def build_projectdiscovery_command(tool_name: str, target: str, output_path: Path) -> tuple[str, list[str]]:
    if tool_name == "subfinder":
        validated = validate_domain(target)
        command = ["subfinder", "-oJ", "-d", validated, "-o", str(output_path)]
        return validated, command

    if tool_name == "assetfinder":
        validated = validate_domain(target)
        command = ["assetfinder", "--subs-only", validated]
        return validated, command

    if tool_name == "amass":
        validated = validate_domain(target)
        command = ["amass", "enum", "-passive", "-d", validated]
        return validated, command

    if tool_name == "httpx":
        validated = validate_url_or_target(target)
        command = _httpx_base_command() + ["-target", validated, "-o", str(output_path)]
        return validated, command

    if tool_name == "naabu":
        validated = validate_target(target)
        command = _naabu_base_command() + ["-host", validated, "-o", str(output_path)]
        return validated, command

    if tool_name == "dnsx":
        validated = validate_domain(target)
        input_path = output_path.with_suffix(".input.txt")
        input_path.write_text(f"{validated}\n", encoding="utf-8")
        command = [
            "dnsx",
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

    if tool_name == "nuclei":
        validated = validate_url_or_target(target)
        command = _nuclei_base_command() + ["-u", validated, "-o", str(output_path)]
        return validated, command

    if tool_name == "katana":
        validated = validate_url_or_target(target)
        command = ["katana", "-jsonl", "-u", validated, "-jc", "-o", str(output_path)]
        return validated, command

    raise ValueError(f"Unsupported ProjectDiscovery tool: {tool_name}")


def build_projectdiscovery_batch_command(
    tool_name: str,
    targets: list[str],
    output_path: Path,
) -> tuple[list[str], list[str], Path]:
    if tool_name not in {"httpx", "naabu", "nuclei", "katana"}:
        raise ValueError(f"Unsupported batch ProjectDiscovery tool: {tool_name}")

    if not targets:
        raise ValueError("At least one target is required")

    validated_targets = [_validate_batch_target(tool_name, target) for target in targets]
    input_path = output_path.with_suffix(".input.txt")
    input_path.write_text("\n".join(validated_targets) + "\n", encoding="utf-8")

    if tool_name == "httpx":
        command = _httpx_base_command() + ["-l", str(input_path), "-o", str(output_path)]
        return validated_targets, command, input_path

    if tool_name == "naabu":
        command = _naabu_base_command() + ["-list", str(input_path), "-o", str(output_path)]
        return validated_targets, command, input_path

    if tool_name == "nuclei":
        command = _nuclei_base_command() + ["-l", str(input_path), "-o", str(output_path)]
        return validated_targets, command, input_path

    command = ["katana", "-jsonl", "-list", str(input_path), "-jc", "-o", str(output_path)]
    return validated_targets, command, input_path


def execute_projectdiscovery(command: list[str], tool_name: str, target: str, output_path: Path) -> ToolResult:
    cleanup_path = output_path.with_suffix(".input.txt") if tool_name in {"dnsx", "httpx", "naabu", "nuclei", "katana"} else None
    try:
        result = run_command(tool_name, target, command, timeout=_timeout_for(tool_name), raw_output_path=str(output_path))
        if tool_name in {"assetfinder", "amass"} and result.stdout:
            output_path.write_text(result.stdout, encoding="utf-8")
        return result
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
                if tool_name == "assetfinder":
                    findings.append({"type": "subdomain", "host": line, "key": line, "value": "discovered"})
                    continue
                payload = json.loads(line)
            except json.JSONDecodeError:
                if tool_name == "amass":
                    candidate = line.strip()
                    if candidate and "." in candidate and " " not in candidate:
                        findings.append({"type": "subdomain", "host": candidate, "key": candidate, "value": "discovered"})
                        continue
                findings.append({"type": "raw_output", "value": line})
                continue
            findings.extend(_parse_payload(tool_name, payload))
    return _deduplicate_findings(findings)


def _parse_payload(tool_name: str, payload: dict[str, object]) -> list[dict[str, str]]:
    if tool_name == "subfinder":
        host = str(payload.get("host", ""))
        sources = payload.get("sources", [])
        value = ",".join(str(item) for item in sources) if isinstance(sources, list) else str(sources)
        return [{"type": "subdomain", "host": host, "key": host, "value": value or "discovered"}]

    if tool_name == "amass":
        host = str(payload.get("name", payload.get("host", "")))
        addresses = payload.get("addresses", [])
        ips = ",".join(str(item.get("ip", "")) for item in addresses if isinstance(item, dict) and item.get("ip"))
        return [{"type": "subdomain", "host": host, "key": host, "value": ips or "discovered"}] if host else []

    if tool_name == "httpx":
        url = str(payload.get("url", payload.get("input", "")))
        status_code = str(payload.get("status_code", ""))
        title = str(payload.get("title", ""))
        tech = payload.get("tech", [])
        technologies = ",".join(str(item) for item in tech) if isinstance(tech, list) else str(tech)
        webserver = str(payload.get("webserver", ""))
        ip = str(payload.get("host", payload.get("ip", "")))
        content_type = str(payload.get("content_type", ""))
        parsed = urlparse(url)
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else ""))
        scheme = parsed.scheme
        product, version = _split_product_version(webserver)
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
                "port": port,
                "scheme": scheme,
                "product": product,
                "version": version,
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

    if tool_name == "katana":
        url = str(payload.get("request", {}).get("endpoint", payload.get("url", payload.get("endpoint", ""))))
        source = str(payload.get("source", "crawl"))
        return [{"type": "web_path", "host": url, "key": url, "value": source or "discovered"}] if url else []

    if tool_name == "nuclei":
        template_id = str(payload.get("template-id", ""))
        info = payload.get("info", {})
        name = str(info.get("name", "")) if isinstance(info, dict) else ""
        severity = str(info.get("severity", payload.get("severity", "")))
        matched_at = str(payload.get("matched-at", payload.get("host", "")))
        extracted = payload.get("extracted-results", [])
        extracted_text = ",".join(str(item) for item in extracted) if isinstance(extracted, list) else str(extracted)
        value = " ".join(part for part in (severity, name, extracted_text) if part).strip()
        return [
            {
                "type": "nuclei_finding",
                "host": matched_at,
                "key": template_id or matched_at,
                "value": value or "template match",
                "template_id": template_id,
                "name": name,
                "severity": severity,
                "matcher_name": str(payload.get("matcher-name", "")),
                "curl_command": str(payload.get("curl-command", "")),
            }
        ]

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
    if tool_name == "nuclei":
        return 300
    if tool_name == "assetfinder":
        return 120
    if tool_name == "amass":
        return 240
    if tool_name == "katana":
        return 180
    return 300


def _httpx_base_command() -> list[str]:
    return [
        "httpx",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-ip",
    ]


def _naabu_base_command() -> list[str]:
    return ["naabu", "-json", "-top-ports", "100"]


def _nuclei_base_command() -> list[str]:
    return ["nuclei", "-jsonl", "-severity", "info,low,medium,high,critical"]


def _validate_batch_target(tool_name: str, target: str) -> str:
    if tool_name in {"httpx", "nuclei", "katana"}:
        return validate_url_or_target(target)
    return validate_target(target)


def _deduplicate_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    unique: list[dict[str, str]] = []
    for finding in findings:
        marker = tuple(sorted((str(key), str(value)) for key, value in finding.items()))
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(finding)
    return unique


def _split_product_version(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    if "/" not in value:
        return value.strip(), ""
    product, version = value.split("/", 1)
    return product.strip(), version.strip()
