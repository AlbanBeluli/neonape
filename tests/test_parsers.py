from pathlib import Path

from neon_ape.tools.nmap import parse_nmap_xml, render_command_preview
from neon_ape.tools.projectdiscovery import (
    build_projectdiscovery_batch_command,
    execute_projectdiscovery,
    parse_projectdiscovery_output,
)
from neon_ape.tools.base import run_command
from neon_ape.tools.web_enum import build_gobuster_command, parse_gobuster_output


def test_parse_nmap_xml_extracts_host_and_port(tmp_path) -> None:
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.10.10" />
    <ports>
      <port portid="80" protocol="tcp">
        <state state="open" />
        <service name="http" product="Apache httpd" version="2.4.49" />
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    findings = parse_nmap_xml(xml_path)
    assert {"type": "host", "host": "10.10.10.10", "value": "10.10.10.10"} in findings
    assert any(item["type"] == "port" and item["key"] == "80" for item in findings)
    assert any(item.get("product") == "Apache httpd" and item.get("version") == "2.4.49" for item in findings)


def test_parse_httpx_jsonl_extracts_rich_fields(tmp_path) -> None:
    output = tmp_path / "httpx.jsonl"
    output.write_text(
        '{"url":"https://example.com","status_code":200,"title":"Example","tech":["nginx"],"webserver":"Apache/2.4.49","host":"93.184.216.34"}\n',
        encoding="utf-8",
    )
    findings = parse_projectdiscovery_output("httpx", output)
    assert findings[0]["type"] == "http_service"
    assert findings[0]["status_code"] == "200"
    assert findings[0]["webserver"] == "Apache/2.4.49"
    assert findings[0]["product"] == "Apache"
    assert findings[0]["version"] == "2.4.49"


def test_parse_dnsx_jsonl_extracts_records(tmp_path) -> None:
    output = tmp_path / "dnsx.jsonl"
    output.write_text(
        '{"host":"example.com","a":["93.184.216.34"],"ns":["ns1.example.com"]}\n',
        encoding="utf-8",
    )
    findings = parse_projectdiscovery_output("dnsx", output)
    assert any(item["record_type"] == "A" for item in findings)
    assert any(item["record_type"] == "NS" for item in findings)


def test_parse_nuclei_jsonl_extracts_match_metadata(tmp_path) -> None:
    output = tmp_path / "nuclei.jsonl"
    output.write_text(
        '{"template-id":"exposed-panel","info":{"name":"Exposed Panel","severity":"medium"},"matched-at":"https://example.com/login"}\n',
        encoding="utf-8",
    )
    findings = parse_projectdiscovery_output("nuclei", output)
    assert findings[0]["type"] == "nuclei_finding"
    assert findings[0]["template_id"] == "exposed-panel"
    assert findings[0]["severity"] == "medium"


def test_parse_assetfinder_output_extracts_subdomains(tmp_path) -> None:
    output = tmp_path / "assetfinder.txt"
    output.write_text("api.example.com\nwww.example.com\n", encoding="utf-8")
    findings = parse_projectdiscovery_output("assetfinder", output)
    assert findings[0]["type"] == "subdomain"
    assert findings[0]["host"] == "api.example.com"


def test_parse_amass_json_extracts_subdomains(tmp_path) -> None:
    output = tmp_path / "amass.jsonl"
    output.write_text('{"name":"api.example.com","addresses":[{"ip":"1.2.3.4"}]}\n', encoding="utf-8")
    findings = parse_projectdiscovery_output("amass", output)
    assert findings[0]["type"] == "subdomain"
    assert findings[0]["host"] == "api.example.com"
    assert findings[0]["value"] == "1.2.3.4"


def test_parse_amass_plain_output_extracts_subdomains(tmp_path) -> None:
    output = tmp_path / "amass.txt"
    output.write_text("api.example.com\nwww.example.com\n", encoding="utf-8")
    findings = parse_projectdiscovery_output("amass", output)
    assert findings[0]["type"] == "subdomain"
    assert findings[0]["host"] == "api.example.com"


def test_parse_katana_json_extracts_paths(tmp_path) -> None:
    output = tmp_path / "katana.jsonl"
    output.write_text('{"request":{"endpoint":"https://example.com/app.js"},"source":"crawl"}\n', encoding="utf-8")
    findings = parse_projectdiscovery_output("katana", output)
    assert findings[0]["type"] == "web_path"
    assert findings[0]["host"] == "https://example.com/app.js"


def test_build_httpx_batch_command_creates_input_file(tmp_path) -> None:
    output = tmp_path / "httpx.jsonl"
    targets, command, input_path = build_projectdiscovery_batch_command("httpx", ["app.example.com", "api.example.com"], output)
    assert targets == ["app.example.com", "api.example.com"]
    assert "-l" in command
    assert input_path.exists()
    assert input_path.read_text(encoding="utf-8") == "app.example.com\napi.example.com\n"


def test_build_katana_batch_command_creates_input_file(tmp_path) -> None:
    output = tmp_path / "katana.jsonl"
    targets, command, input_path = build_projectdiscovery_batch_command("katana", ["https://app.example.com"], output)
    assert targets == ["https://app.example.com"]
    assert "-list" in command
    assert input_path.exists()


def test_parse_gobuster_output_extracts_paths(tmp_path) -> None:
    output = tmp_path / "gobuster.txt"
    output.write_text("/admin           Status: 301\n/assets          Status: 200\n", encoding="utf-8")
    findings = parse_gobuster_output(output)
    assert findings[0]["type"] == "web_path"
    assert findings[0]["host"] == "/admin"
    assert findings[0]["value"] == "301"


def test_build_gobuster_command_adds_https_to_bare_domain(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("neon_ape.tools.web_enum._detect_wordlist", lambda: "/tmp/wordlist.txt")
    validated, command = build_gobuster_command("example.com", tmp_path / "gobuster.txt")
    assert validated == "https://example.com"
    assert "https://example.com" in command


def test_build_gobuster_command_adds_exclude_length(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("neon_ape.tools.web_enum._detect_wordlist", lambda: "/tmp/wordlist.txt")
    _, command = build_gobuster_command("example.com", tmp_path / "gobuster.txt", exclude_length="24824")
    assert "--exclude-length" in command
    assert "24824" in command


def test_render_command_preview_masks_home_paths(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/tmp/test-home")
    preview = render_command_preview(["httpx", "-o", "/tmp/test-home/.neon_ape/scans/httpx.jsonl"])
    assert "/tmp/test-home" not in preview
    assert "~/.neon_ape/scans/httpx.jsonl" in preview


def test_parse_projectdiscovery_output_deduplicates_exact_matches(tmp_path) -> None:
    output = tmp_path / "subfinder.jsonl"
    output.write_text(
        '{"host":"api.example.com"}\n{"host":"api.example.com"}\n',
        encoding="utf-8",
    )
    findings = parse_projectdiscovery_output("subfinder", output)
    assert len(findings) == 1


def test_run_command_handles_missing_executable() -> None:
    result = run_command("missing", "target", ["definitely-not-a-real-binary"])
    assert result.exit_code == 127
    assert "Executable not found" in result.stderr


def test_execute_projectdiscovery_cleans_dnsx_temp_input(tmp_path, monkeypatch) -> None:
    input_path = tmp_path / "dnsx_test.input.txt"
    input_path.write_text("example.com\n", encoding="utf-8")
    output_path = tmp_path / "dnsx_test.jsonl"

    def fake_run_command(*args, **kwargs):
        return type("Result", (), {"tool_name": "dnsx", "target": "example.com", "command": [], "stdout": "", "stderr": "", "exit_code": 0, "raw_output_path": str(output_path)})()

    monkeypatch.setattr("neon_ape.tools.projectdiscovery.run_command", fake_run_command)
    execute_projectdiscovery(["dnsx"], "dnsx", "example.com", output_path)
    assert not input_path.exists()
