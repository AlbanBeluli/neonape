from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from neon_ape.models import SensitivePath, normalize_web_path


def enrich_web_path_findings(tool_name: str, findings: list[dict[str, str]]) -> list[dict[str, str]]:
    enriched: list[dict[str, str]] = []
    for finding in findings:
        item = dict(finding)
        observation = _observation_from_finding(tool_name, item)
        if observation is not None:
            item["category"] = observation.category
            item["risk_score"] = str(observation.risk_score)
            item["normalized_path"] = observation.normalized_path
            item["source_tool"] = observation.source_tool
            if observation.status is not None:
                item["status_code"] = str(observation.status)
            if observation.length is not None:
                item["content_length"] = str(observation.length)
        enriched.append(item)
    return enriched


def correlate_sensitive_paths(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
        path = str(metadata.get("normalized_path", row.get("key", "")) or "")
        category = str(row.get("category", metadata.get("category", "")) or "")
        if not path or not category:
            continue
        host = _host_for_row(row, metadata)
        marker = (host, path)
        entry = grouped.setdefault(
            marker,
            {
                "host": host or "-",
                "path": path,
                "category": category,
                "status": metadata.get("status_code") or row.get("value") or "-",
                "length": _to_int(metadata.get("content_length")),
                "source_tools": set(),
                "risk_score": 0,
                "evidence": [],
            },
        )
        source_tool = str(metadata.get("source_tool", row.get("tool_name", "")) or row.get("tool_name", ""))
        if source_tool:
            entry["source_tools"].add(source_tool)
        score = _to_int(row.get("risk_score")) or _to_int(metadata.get("risk_score")) or 0
        if score > int(entry["risk_score"]):
            entry["risk_score"] = score
        if not entry.get("length") and _to_int(metadata.get("content_length")):
            entry["length"] = _to_int(metadata.get("content_length"))
        if metadata.get("status_code"):
            entry["status"] = metadata.get("status_code")
        entry["evidence"].append(
            {
                "source_tool": source_tool or "-",
                "finding_type": str(row.get("finding_type", "")),
                "key": str(row.get("key", "")),
                "value": str(row.get("value", "")),
                "metadata": metadata,
            }
        )

    correlated: list[dict[str, object]] = []
    for value in grouped.values():
        source_tools = sorted(str(item) for item in value["source_tools"])
        recomputed = SensitivePath.score(
            category=str(value["category"]),
            status=_to_int(value.get("status")),
            source_tool=source_tools[0] if source_tools else "katana",
            length=_to_int(value.get("length")),
            source_count=max(len(source_tools), 1),
        )
        value["risk_score"] = max(int(value["risk_score"]), recomputed)
        value["source_tools"] = source_tools
        correlated.append(value)
    correlated.sort(key=lambda item: (-int(item["risk_score"]), str(item["host"]), str(item["path"])))
    return correlated


def grouped_sensitive_paths(items: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in items:
        result[str(item.get("category", "Uncategorized"))].append(item)
    for category_items in result.values():
        category_items.sort(key=lambda entry: (-int(entry.get("risk_score", 0) or 0), str(entry.get("host", "")), str(entry.get("path", ""))))
    return dict(result)


def build_web_path_review_items(items: list[dict[str, object]]) -> list[dict[str, str]]:
    reviews: list[dict[str, str]] = []
    for item in items:
        source_tools = [str(tool) for tool in item.get("source_tools", [])]
        severity = _severity_from_risk(int(item.get("risk_score", 0) or 0))
        reviews.append(
            {
                "host": str(item.get("host", "-")),
                "source_tool": "angel-eyes",
                "finding_key": str(item.get("path", "-")),
                "title": f"{item.get('category', 'Sensitive Path')} review required at {item.get('path', '-')}",
                "severity": severity,
                "confidence": "high" if len(source_tools) > 1 else "medium",
                "recommendation": "Verify access control behavior, confirm exposure is intentional, and move sensitive artifacts outside the web root where possible.",
            }
        )
    return reviews


def _observation_from_finding(tool_name: str, finding: dict[str, str]) -> SensitivePath | None:
    if tool_name in {"gobuster", "ffuf"} and finding.get("type") == "web_path":
        return SensitivePath.from_observation(
            raw_path=finding.get("host", finding.get("key", "")),
            source_tool=tool_name,
            status=_to_int(finding.get("status_code")),
            length=_to_int(finding.get("content_length")),
        )
    if tool_name == "katana" and finding.get("type") == "web_path":
        raw = finding.get("host", finding.get("key", ""))
        parsed = urlparse(raw)
        return SensitivePath.from_observation(
            raw_path=parsed.path or raw,
            source_tool=tool_name,
            host=parsed.hostname or "",
            url=raw,
        )
    if tool_name == "httpx" and finding.get("type") == "http_service":
        raw = finding.get("host", "")
        parsed = urlparse(raw)
        return SensitivePath.from_observation(
            raw_path=parsed.path or "/",
            source_tool=tool_name,
            host=parsed.hostname or "",
            url=raw,
            status=_to_int(finding.get("status_code")),
            length=_to_int(finding.get("content_length")),
        )
    if tool_name == "nuclei" and finding.get("type") == "nuclei_finding":
        raw = finding.get("host", "")
        parsed = urlparse(raw)
        return SensitivePath.from_observation(
            raw_path=parsed.path or raw,
            source_tool=tool_name,
            host=parsed.hostname or "",
            url=raw,
            severity=finding.get("severity"),
        )
    return None


def _host_for_row(row: dict[str, object], metadata: dict[str, object]) -> str:
    host = str(metadata.get("host", "") or "")
    if host:
        return host
    key = str(row.get("key", "") or "")
    parsed = urlparse(key)
    if parsed.hostname:
        return parsed.hostname
    value = str(metadata.get("url", "") or "")
    parsed_value = urlparse(value)
    if parsed_value.hostname:
        return parsed_value.hostname
    return str(row.get("tool_name", "-"))


def _severity_from_risk(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def _to_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
