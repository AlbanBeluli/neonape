from __future__ import annotations

import sqlite3

from neon_ape.knowledge.graph import build_target_graph, lookup_prior_context


def test_build_target_graph_summarizes_overview(monkeypatch) -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    monkeypatch.setattr(
        "neon_ape.knowledge.graph.domain_overview",
        lambda _connection, _target, limit=100: {
            "inventory": [
                {
                    "host": "app.example.com",
                    "port": "443",
                    "product": "nginx",
                    "version": "1.24.0",
                    "service_name": "http",
                }
            ],
            "angel_eyes": {
                "items": [
                    {
                        "host": "app.example.com",
                        "path": "/.env",
                        "category": "Secrets",
                        "risk_score": 95,
                    }
                ]
            },
            "reviews": [
                {
                    "host": "app.example.com",
                    "title": "Sensitive path exposed",
                }
            ],
        },
    )

    graph = build_target_graph(connection, "example.com")

    assert graph["summary"]["hosts"] == 1
    assert graph["summary"]["services"] == 1
    assert graph["summary"]["paths"] == 1
    assert graph["summary"]["reviews"] == 1


def test_lookup_prior_context_returns_matching_scans_and_notes() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE scan_runs (tool_name TEXT, target TEXT, status TEXT, finished_at TEXT, raw_output_path TEXT)"
    )
    connection.execute(
        "CREATE TABLE notes (target TEXT, title TEXT, updated_at TEXT)"
    )
    connection.execute(
        "INSERT INTO scan_runs VALUES ('httpx', 'example.com', 'success', '2026-03-19', '/tmp/example.com.json')"
    )
    connection.execute(
        "INSERT INTO notes VALUES ('example.com', 'Example note', '2026-03-19')"
    )

    context = lookup_prior_context(connection, "example.com")

    assert len(context["prior_scans"]) == 1
    assert len(context["prior_notes"]) == 1
