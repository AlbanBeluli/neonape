from pathlib import Path

from neon_ape.tools.nmap import parse_nmap_xml
from neon_ape.tools.projectdiscovery import execute_projectdiscovery, parse_projectdiscovery_output
from neon_ape.tools.base import run_command


def test_parse_nmap_xml_extracts_host_and_port(tmp_path) -> None:
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.10.10" />
    <ports>
      <port portid="80">
        <state state="open" />
        <service name="http" />
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


def test_parse_httpx_jsonl_extracts_rich_fields(tmp_path) -> None:
    output = tmp_path / "httpx.jsonl"
    output.write_text(
        '{"url":"https://example.com","status_code":200,"title":"Example","tech":["nginx"],"webserver":"nginx","host":"93.184.216.34"}\n',
        encoding="utf-8",
    )
    findings = parse_projectdiscovery_output("httpx", output)
    assert findings[0]["type"] == "http_service"
    assert findings[0]["status_code"] == "200"
    assert findings[0]["webserver"] == "nginx"


def test_parse_dnsx_jsonl_extracts_records(tmp_path) -> None:
    output = tmp_path / "dnsx.jsonl"
    output.write_text(
        '{"host":"example.com","a":["93.184.216.34"],"ns":["ns1.example.com"]}\n',
        encoding="utf-8",
    )
    findings = parse_projectdiscovery_output("dnsx", output)
    assert any(item["record_type"] == "A" for item in findings)
    assert any(item["record_type"] == "NS" for item in findings)


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
