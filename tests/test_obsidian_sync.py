from pathlib import Path

from neon_ape.config import AppConfig
from neon_ape.obsidian_sync import (
    build_attack_canvas,
    build_target_index,
    parse_frontmatter,
    preview_scan_artifacts,
    render_findings_markdown,
    render_markdown_table,
    resolve_vault_path,
    sanitize_target_name,
)


def test_parse_frontmatter_extracts_yaml_and_body() -> None:
    markdown = (
        "---\n"
        'target: "example.com"\n'
        'scope: "in-scope"\n'
        'checklist: "pd_web_chain"\n'
        "---\n\n"
        "# Notes\n"
    )
    frontmatter, body = parse_frontmatter(markdown)
    assert frontmatter["target"] == "example.com"
    assert frontmatter["scope"] == "in-scope"
    assert frontmatter["checklist"] == "pd_web_chain"
    assert "# Notes" in body


def test_parse_frontmatter_requires_fences() -> None:
    try:
        parse_frontmatter("# Missing frontmatter")
    except ValueError as exc:
        assert "missing YAML frontmatter" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing frontmatter")


def test_render_markdown_table_adds_placeholder_row() -> None:
    table = render_markdown_table(["A", "B"], [])
    assert "| A | B |" in table
    assert "| - | - |" in table


def test_render_findings_markdown_includes_sections() -> None:
    overview = {
        "reviews": [{"title": "Exposed Login", "severity": "high", "source_tool": "nuclei", "host": "https://example.com/login"}],
        "inventory": [{"host": "example.com", "port": "443", "service_name": "https", "product": "nginx", "version": "1.25"}],
        "web_paths": {
            "katana": [{"host": "https://example.com/app.js", "value": "crawl"}],
            "gobuster": [{"host": "/admin", "value": "301"}],
        },
        "findings": [{"finding_type": "http_service", "key": "https://example.com", "value": "200"}],
    }
    markdown = render_findings_markdown("example.com", "in-scope", "pd_web_chain", overview)
    assert "# Findings for example.com" in markdown
    assert "## Review Matches" in markdown
    assert "## Web Paths" in markdown
    assert "/admin" in markdown
    assert "https://example.com/app.js" in markdown


def test_build_attack_canvas_creates_target_and_review_nodes() -> None:
    overview = {
        "reviews": [{"title": "Exposed Login", "severity": "high", "host": "https://example.com/login"}],
    }
    canvas = build_attack_canvas("example.com", overview)
    assert canvas["nodes"][0]["id"] == "target-root"
    assert any(node["id"] == "review-1" for node in canvas["nodes"])
    assert any(edge["toNode"] == "review-1" for edge in canvas["edges"])


def test_sanitize_target_name_removes_unsafe_characters() -> None:
    assert sanitize_target_name("example.com/path?x=1") == "example.com_path_x_1"


def test_build_target_index_preserves_frontmatter_keys() -> None:
    payload = build_target_index({"target": "example.com", "scope": "in-scope", "checklist": "pd_web_chain"}, "# Notes")
    assert 'target: example.com' in payload
    assert "# Notes" in payload


def test_preview_scan_artifacts_returns_unique_names() -> None:
    artifacts = preview_scan_artifacts(
        [
            {"raw_output_path": "~/.neon_ape/scans/httpx_example.jsonl"},
            {"raw_output_path": "~/.neon_ape/scans/httpx_example.jsonl"},
            {"raw_output_path": "~/.neon_ape/scans/nuclei_example.jsonl"},
        ]
    )
    assert artifacts == ["httpx_example.jsonl", "nuclei_example.jsonl"]


def test_resolve_vault_path_uses_config_value(tmp_path, monkeypatch) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    config = AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=vault,
    )

    assert resolve_vault_path(None, config) == vault.resolve()


def test_resolve_vault_path_discovers_current_vault(tmp_path, monkeypatch) -> None:
    vault = tmp_path / "vault"
    project = vault / "Pentests" / "example.com"
    (vault / ".obsidian").mkdir(parents=True)
    project.mkdir(parents=True)
    monkeypatch.chdir(project)
    config = AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=None,
    )

    assert resolve_vault_path(None, config) == vault.resolve()
