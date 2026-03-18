from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

import dns.resolver
import whois

from neon_ape.config import AppConfig
from neon_ape.tools.base import ToolResult


def sanitize_target_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned or "target"


def _pretty_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _scan_output_path(scan_dir: Path, profile: str, target: str) -> Path:
    return scan_dir / f"passive_recon_{profile}_{sanitize_target_name(target)}.txt"


def lookup_whois(domain: str) -> dict[str, str]:
    record = whois.whois(domain)
    return {
        "domain_name": str(record.domain_name),
        "registrar": str(record.registrar),
        "name_servers": str(record.name_servers),
        "emails": str(record.emails),
        "creation_date": str(record.creation_date),
        "expiration_date": str(record.expiration_date),
    }


def run_whois_command(domain: str) -> ToolResult:
    command = ["whois", domain]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
            shell=False,
        )
        return ToolResult(
            tool_name="passive_recon",
            target=domain,
            command=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
        )
    except FileNotFoundError:
        return ToolResult(
            tool_name="passive_recon",
            target=domain,
            command=command,
            stderr="Executable not found: whois",
            exit_code=127,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool_name="passive_recon",
            target=domain,
            command=command,
            stderr="WHOIS command timed out after 45 seconds",
            exit_code=124,
        )


def resolve_a_records(hostname: str) -> list[str]:
    answers = dns.resolver.resolve(hostname, "A")
    return [answer.to_text() for answer in answers]


def run_dig_command(hostname: str) -> ToolResult:
    command = ["dig", "+short", "A", hostname]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            shell=False,
        )
        return ToolResult(
            tool_name="passive_recon",
            target=hostname,
            command=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
        )
    except FileNotFoundError:
        return ToolResult(
            tool_name="passive_recon",
            target=hostname,
            command=command,
            stderr="Executable not found: dig",
            exit_code=127,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool_name="passive_recon",
            target=hostname,
            command=command,
            stderr="dig command timed out after 30 seconds",
            exit_code=124,
        )


def build_passive_recon_findings(profile: str, target: str) -> list[dict[str, str]]:
    result, findings = execute_passive_recon(profile, target)
    if result.exit_code != 0 and not findings:
        raise RuntimeError(result.stderr or f"Passive recon profile failed: {profile}")
    return findings


def execute_passive_recon(
    profile: str,
    target: str,
    *,
    scan_dir: Path | None = None,
) -> tuple[ToolResult, list[dict[str, str]]]:
    active_scan_dir = scan_dir or AppConfig.default().scan_dir
    active_scan_dir.mkdir(parents=True, exist_ok=True)
    output_path = _scan_output_path(active_scan_dir, profile, target)

    if profile == "whois_lookup":
        command_result = run_whois_command(target)
        raw_text = command_result.stdout.strip()
        findings: list[dict[str, str]] = []
        if command_result.exit_code == 0 and raw_text:
            for line in raw_text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if value.strip():
                    findings.append(
                        {
                            "type": "whois",
                            "host": target,
                            "key": key.strip().lower().replace(" ", "_"),
                            "value": value.strip(),
                        }
                    )
        else:
            fallback = lookup_whois(target)
            raw_text = _pretty_json(fallback)
            findings = [
                {"type": "whois", "host": target, "key": key, "value": value}
                for key, value in fallback.items()
                if value and value != "None"
            ]
            command_result = ToolResult(
                tool_name="passive_recon",
                target=target,
                command=["python", "-m", "neon_ape.tools.passive_recon", "whois", target],
                stdout=raw_text,
                stderr=command_result.stderr,
                exit_code=0 if findings else command_result.exit_code,
                raw_output_path=str(output_path),
            )
        output_path.write_text(raw_text + ("\n" if raw_text and not raw_text.endswith("\n") else ""), encoding="utf-8")
        return (
            ToolResult(
                tool_name="passive_recon",
                target=target,
                command=command_result.command or ["whois", target],
                stdout=command_result.stdout,
                stderr=command_result.stderr,
                exit_code=command_result.exit_code,
                raw_output_path=str(output_path),
            ),
            findings,
        )

    if profile == "dns_a_records":
        command_result = run_dig_command(target)
        raw_text = command_result.stdout.strip()
        addresses = [line.strip() for line in raw_text.splitlines() if line.strip()]
        if not addresses:
            addresses = resolve_a_records(target)
            raw_text = "\n".join(addresses)
            command_result = ToolResult(
                tool_name="passive_recon",
                target=target,
                command=["python", "-m", "neon_ape.tools.passive_recon", "dns-a", target],
                stdout=raw_text,
                stderr=command_result.stderr,
                exit_code=0 if addresses else command_result.exit_code,
                raw_output_path=str(output_path),
            )
        output_path.write_text(raw_text + ("\n" if raw_text and not raw_text.endswith("\n") else ""), encoding="utf-8")
        findings = [
            {"type": "dns_a", "host": target, "key": target, "value": address}
            for address in addresses
        ]
        return (
            ToolResult(
                tool_name="passive_recon",
                target=target,
                command=command_result.command or ["dig", "+short", "A", target],
                stdout=command_result.stdout,
                stderr=command_result.stderr,
                exit_code=command_result.exit_code if addresses or command_result.exit_code == 0 else command_result.exit_code,
                raw_output_path=str(output_path),
            ),
            findings,
        )

    raise ValueError(f"Unsupported passive recon profile: {profile}")


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m neon_ape.tools.passive_recon")
    parser.add_argument("profile", choices=("whois", "dns-a"))
    parser.add_argument("target")
    return parser


def main() -> int:
    args = _build_cli_parser().parse_args()
    profile = "whois_lookup" if args.profile == "whois" else "dns_a_records"
    result, _ = execute_passive_recon(profile, args.target)
    if result.raw_output_path:
        print(result.raw_output_path)
    if result.stderr:
        print(result.stderr)
    return 0 if result.exit_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
