from pathlib import Path

from neon_ape.tools import passive_recon


def test_execute_passive_recon_whois_fallback_writes_scan(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        passive_recon,
        "run_whois_command",
        lambda domain: passive_recon.ToolResult(
            tool_name="passive_recon",
            target=domain,
            command=["whois", domain],
            stderr="Executable not found: whois",
            exit_code=127,
        ),
    )
    monkeypatch.setattr(
        passive_recon,
        "lookup_whois",
        lambda domain: {"domain_name": domain, "registrar": "Example Registrar"},
    )

    result, findings = passive_recon.execute_passive_recon("whois_lookup", "example.com", scan_dir=tmp_path)

    assert result.exit_code == 0
    assert result.raw_output_path
    assert Path(result.raw_output_path).exists()
    assert findings[0]["type"] == "whois"


def test_execute_passive_recon_dns_fallback_writes_scan(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        passive_recon,
        "run_dig_command",
        lambda hostname: passive_recon.ToolResult(
            tool_name="passive_recon",
            target=hostname,
            command=["dig", "+short", "A", hostname],
            stderr="Executable not found: dig",
            exit_code=127,
        ),
    )
    monkeypatch.setattr(passive_recon, "resolve_a_records", lambda hostname: ["93.184.216.34"])

    result, findings = passive_recon.execute_passive_recon("dns_a_records", "example.com", scan_dir=tmp_path)

    assert result.exit_code == 0
    assert Path(result.raw_output_path).exists()
    assert findings == [{"type": "dns_a", "host": "example.com", "key": "example.com", "value": "93.184.216.34"}]
