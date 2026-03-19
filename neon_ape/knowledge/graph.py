from __future__ import annotations

from collections import Counter
import sqlite3
from urllib.parse import urlparse

from neon_ape.db.repository import domain_overview


def lookup_prior_context(
    connection: sqlite3.Connection,
    target: str,
    *,
    limit: int = 5,
) -> dict[str, object]:
    pattern = _like_pattern(target)
    if not hasattr(connection, "execute"):
        return {"prior_scans": [], "prior_notes": []}
    try:
        scans = connection.execute(
            """
            SELECT tool_name, target, status, finished_at
            FROM scan_runs
            WHERE target LIKE ?
               OR raw_output_path LIKE ?
            ORDER BY finished_at DESC
            LIMIT ?
            """,
            (pattern, pattern, limit),
        ).fetchall()
    except sqlite3.Error:
        scans = []
    try:
        notes = connection.execute(
            """
            SELECT target, title, updated_at
            FROM notes
            WHERE COALESCE(target, '') LIKE ?
               OR title LIKE ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (pattern, pattern, limit),
        ).fetchall()
    except sqlite3.Error:
        notes = []
    return {
        "prior_scans": [dict(row) for row in scans],
        "prior_notes": [dict(row) for row in notes],
    }


def build_target_graph(
    connection: sqlite3.Connection,
    target: str,
    *,
    limit: int = 100,
) -> dict[str, object]:
    if hasattr(connection, "execute"):
        try:
            overview = domain_overview(connection, target, limit=limit)
        except sqlite3.Error:
            overview = _empty_overview()
    else:
        overview = _empty_overview()
    nodes: list[dict[str, str | int]] = [{"id": target, "kind": "target", "label": target}]
    edges: list[dict[str, str]] = []

    for item in overview["inventory"]:
        host = str(item.get("host") or "")
        if not host:
            continue
        service_label = _service_label(item)
        nodes.append({"id": f"host:{host}", "kind": "host", "label": host})
        edges.append({"source": target, "target": f"host:{host}", "relation": "contains"})
        if service_label:
            service_id = f"service:{host}:{item.get('port', '')}:{service_label}"
            nodes.append({"id": service_id, "kind": "service", "label": service_label})
            edges.append({"source": f"host:{host}", "target": service_id, "relation": "exposes"})

    for item in overview["angel_eyes"]["items"]:
        host = str(item.get("host") or target)
        path = str(item.get("path") or "")
        if not path:
            continue
        path_id = f"path:{host}:{path}"
        nodes.append({"id": path_id, "kind": "path", "label": path})
        edges.append({"source": f"host:{host}", "target": path_id, "relation": "exposes"})

    for item in overview["reviews"]:
        host = str(item.get("host") or target)
        title = str(item.get("title") or item.get("finding_key") or "review")
        review_id = f"review:{host}:{title}"
        nodes.append({"id": review_id, "kind": "review", "label": title})
        edges.append({"source": f"host:{host}", "target": review_id, "relation": "has_review"})

    deduped_nodes = _dedupe_nodes(nodes)
    related_targets = find_related_targets(connection, target, limit=3, current_overview=overview)
    return {
        "target": target,
        "nodes": deduped_nodes,
        "edges": _dedupe_edges(edges),
        "summary": {
            "hosts": sum(1 for item in deduped_nodes if item["kind"] == "host"),
            "services": sum(1 for item in deduped_nodes if item["kind"] == "service"),
            "paths": sum(1 for item in deduped_nodes if item["kind"] == "path"),
            "reviews": sum(1 for item in deduped_nodes if item["kind"] == "review"),
        },
        "related_targets": related_targets,
        "overview": overview,
    }


def _empty_overview() -> dict[str, object]:
    return {
        "inventory": [],
        "angel_eyes": {"items": [], "grouped": {}},
        "reviews": [],
    }


def find_related_targets(
    connection: sqlite3.Connection,
    target: str,
    *,
    limit: int = 3,
    current_overview: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    current = current_overview or domain_overview(connection, target, limit=50)
    current_signals = _signal_bundle(current)
    if not hasattr(connection, "execute"):
        return []
    try:
        rows = connection.execute(
            """
            SELECT DISTINCT target
            FROM scan_runs
            WHERE target IS NOT NULL
            ORDER BY finished_at DESC
            LIMIT 100
            """
        ).fetchall()
    except sqlite3.Error:
        return []
    scored: list[dict[str, object]] = []
    for row in rows:
        candidate = str(row["target"] or "").strip()
        if not candidate or candidate == target:
            continue
        candidate_overview = domain_overview(connection, candidate, limit=25)
        candidate_signals = _signal_bundle(candidate_overview)
        overlap = _signal_overlap(current_signals, candidate_signals)
        if overlap["score"] <= 0:
            continue
        scored.append(
            {
                "target": candidate,
                "score": overlap["score"],
                "shared_products": overlap["shared_products"],
                "shared_categories": overlap["shared_categories"],
                "shared_reviews": overlap["shared_reviews"],
            }
        )
    scored.sort(key=lambda item: int(item["score"]), reverse=True)
    return scored[:limit]


def _service_label(item: dict[str, object]) -> str:
    product = str(item.get("product") or "").strip()
    version = str(item.get("version") or "").strip()
    service_name = str(item.get("service_name") or "").strip()
    return " ".join(part for part in (product or service_name, version) if part).strip()


def _signal_bundle(overview: dict[str, object]) -> dict[str, set[str]]:
    inventory = overview.get("inventory", [])
    angel_items = overview.get("angel_eyes", {}).get("items", []) if isinstance(overview.get("angel_eyes"), dict) else []
    reviews = overview.get("reviews", [])
    products = {
        _service_label(item).lower()
        for item in inventory
        if isinstance(item, dict) and _service_label(item)
    }
    categories = {
        str(item.get("category") or "").lower()
        for item in angel_items
        if isinstance(item, dict) and item.get("category")
    }
    review_titles = {
        str(item.get("title") or "").lower()
        for item in reviews
        if isinstance(item, dict) and item.get("title")
    }
    return {
        "products": products,
        "categories": categories,
        "reviews": review_titles,
    }


def _signal_overlap(current: dict[str, set[str]], candidate: dict[str, set[str]]) -> dict[str, object]:
    shared_products = sorted(current["products"] & candidate["products"])
    shared_categories = sorted(current["categories"] & candidate["categories"])
    shared_reviews = sorted(current["reviews"] & candidate["reviews"])
    score = len(shared_products) * 3 + len(shared_categories) * 2 + len(shared_reviews)
    return {
        "score": score,
        "shared_products": ", ".join(shared_products[:3]) or "-",
        "shared_categories": ", ".join(shared_categories[:3]) or "-",
        "shared_reviews": ", ".join(shared_reviews[:2]) or "-",
    }


def _like_pattern(target: str) -> str:
    hostname = _normalized_hostname(target)
    return f"%{hostname}%"


def _normalized_hostname(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return (parsed.hostname or target).strip()


def _dedupe_nodes(nodes: list[dict[str, str | int]]) -> list[dict[str, str | int]]:
    deduped: list[dict[str, str | int]] = []
    seen: Counter[str] = Counter()
    for node in nodes:
        key = str(node["id"])
        if seen[key]:
            continue
        seen[key] += 1
        deduped.append(node)
    return deduped


def _dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, str]] = []
    for edge in edges:
        marker = (edge["source"], edge["target"], edge["relation"])
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(edge)
    return deduped
