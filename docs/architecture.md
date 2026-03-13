# Neon Ape Architecture

## Overview

Neon Ape is a local-only terminal application with four main layers:

1. UI layer: Rich-based menus, panels, tables, progress bars, and ASCII art
2. Application layer: user flows, routing, checklist orchestration
3. Service layer: validation, crypto, storage, and logging
4. Integration layer: safe wrappers around local tools and parsers

## Data Flow

1. The user selects a workflow step from the terminal UI.
2. Inputs are validated and normalized before execution.
3. A tool wrapper builds a fixed argument list.
4. Command output is captured and parsed.
5. Structured results are stored in SQLite through repositories.
6. Sensitive note or secret fields are encrypted before persistence.
7. The UI reads structured data and renders Rich tables and status panels.

## Module Responsibilities

- `cli.py`: entrypoint and startup lifecycle
- `app.py`: main menu loop and section dispatch
- `config.py`: local settings and data path management
- `models.py`: dataclasses and enums shared across modules
- `ui/`: presentation logic only
- `tools/`: wrappers for external tools and Python-native recon helpers
- `services/`: reusable utilities with no UI concerns
- `db/`: schema bootstrap and repository methods

## Tool Integration Model

- `nmap` writes XML artifacts and parses host and port findings
- `subfinder`, `httpx`, `naabu`, and `dnsx` write JSONL artifacts
- All wrappers return a shared `ToolResult`
- Parsed output is normalized into the same `scan_runs`, `scan_findings`, and `tool_history` tables

## Safety Boundaries

- Tool wrappers must not accept raw shell strings.
- Each tool wrapper owns its own argument builder.
- Secrets are encrypted before database writes.
- User-facing exceptions are sanitized.
- No background listener or network service is started by the app.
