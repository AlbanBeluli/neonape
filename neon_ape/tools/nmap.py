from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from neon_ape.tools.base import ToolResult, run_command


SAFE_PROFILES = {
    "host_discovery": ["nmap", "-sn"],
    "service_scan": ["nmap", "-sV"],
    "aggressive": ["nmap", "-A", "-T4"],
}


def build_nmap_command(target: str, profile: str, output_xml: Path) -> list[str]:
    if profile not in SAFE_PROFILES:
        raise ValueError(f"Unsupported nmap profile: {profile}")
    return [*SAFE_PROFILES[profile], "-oX", str(output_xml), target]


def parse_nmap_xml(xml_path: Path) -> list[dict[str, str]]:
    if not xml_path.exists():
        return []
    root = ET.parse(xml_path).getroot()
    findings: list[dict[str, str]] = []
    for host in root.findall("host"):
        address = host.find("address")
        host_value = address.attrib.get("addr", "") if address is not None else ""
        if host_value:
            findings.append({"type": "host", "host": host_value, "value": host_value})
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            service = port.find("service")
            state = port.find("state")
            service_name = service.attrib.get("name", "") if service is not None else ""
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            extrainfo = service.attrib.get("extrainfo", "") if service is not None else ""
            port_id = port.attrib.get("portid", "")
            protocol = port.attrib.get("protocol", "")
            value_parts = [service_name or "unknown"]
            if product:
                value_parts.append(product)
            if version:
                value_parts.append(version)
            if extrainfo:
                value_parts.append(extrainfo)
            service_value = " ".join(part for part in value_parts if part).strip()
            findings.append(
                {
                    "type": "port",
                    "host": host_value,
                    "key": port_id,
                    "value": f"{service_value or 'unknown'} ({state.attrib.get('state', 'unknown') if state is not None else 'unknown'})",
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "protocol": protocol,
                }
            )
    return findings


def render_command_preview(command: list[str]) -> str:
    return " ".join(_sanitize_token(token) for token in command)


def empty_result(target: str, command: list[str]) -> ToolResult:
    return ToolResult(tool_name="nmap", target=target, command=command)


def execute_nmap(command: list[str], target: str) -> ToolResult:
    raw_output_path = ""
    if "-oX" in command:
        output_index = command.index("-oX") + 1
        if output_index < len(command):
            raw_output_path = command[output_index]
    return run_command("nmap", target, command, timeout=300, raw_output_path=raw_output_path)


def _sanitize_token(token: str) -> str:
    path = Path(token)
    if path.is_absolute():
        home = Path.home()
        try:
            return f"~/{path.relative_to(home)}"
        except ValueError:
            return path.name
    return token
