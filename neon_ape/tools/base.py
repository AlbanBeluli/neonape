from __future__ import annotations

from dataclasses import dataclass, field
import subprocess


@dataclass(slots=True)
class ToolResult:
    tool_name: str
    target: str
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    raw_output_path: str = ""


def run_command(
    tool_name: str,
    target: str,
    command: list[str],
    *,
    timeout: int = 300,
    raw_output_path: str = "",
) -> ToolResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        return ToolResult(
            tool_name=tool_name,
            target=target,
            command=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            raw_output_path=raw_output_path,
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(
            tool_name=tool_name,
            target=target,
            command=command,
            stdout=exc.stdout or "",
            stderr=f"Command timed out after {timeout} seconds",
            exit_code=124,
            raw_output_path=raw_output_path,
        )
    except FileNotFoundError:
        return ToolResult(
            tool_name=tool_name,
            target=target,
            command=command,
            stdout="",
            stderr=f"Executable not found: {command[0]}",
            exit_code=127,
            raw_output_path=raw_output_path,
        )
