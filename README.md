# Neon Ape

Neon Ape is a local-only Python terminal dashboard for lab-safe penetration testing workflows. It uses a Neon Genesis Evangelion-inspired interface, guided checklists, encrypted local storage, and vetted wrappers for common reconnaissance and enumeration tools.

For a compact current-state reference, see [MEMORY.md](MEMORY.md).

## At a Glance

- Local-only terminal workflow for scoped recon and service review
- Interactive `neonape` shell plus direct CLI commands
- Built-in wrappers for `nmap`, `subfinder`, `dnsx`, `httpx`, `naabu`, and `nuclei`
- Chained recon flow: `subfinder -> httpx -> naabu`
- SQLite-backed checklist, scan history, findings, and notes storage

This project does not automate brute force, exploitation, credential attacks, or post-exploitation activity.

## Quick Start

Install from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/AlbanBeluli/neonape/main/install.sh | bash -s -- --repo https://github.com/AlbanBeluli/neonape.git
neonape
```

Useful first commands:

```bash
neonape
neonape --workflow pd_chain --target example.com
neonape --tool nuclei --target https://example.com
neonape db scans
```

## Scope

The current release is intentionally scoped toward:

- Passive reconnaissance
- Active scanning in authorized environments
- Findings tracking
- Notes and checklist management
- Safe local automation

## Goals

- Provide a terminal UI with an intentional NGE-inspired theme
- Guide users through a repeatable workflow with checklists
- Wrap common tools such as `nmap` with input validation and parsing
- Store local results securely using SQLite plus field-level encryption
- Keep the application local-only with no listening service

## MVP Scope

The first implementation milestone focuses on:

- Rich-based terminal shell
- Main menu and themed sections
- Checklist engine backed by SQLite
- Nmap integration with XML parsing
- Interactive terminal workflow with menu-driven actions
- ProjectDiscovery wrappers for `subfinder`, `httpx`, `naabu`, `dnsx`, and `nuclei`
- Chained recon workflow: `subfinder -> httpx -> naabu`
- Passive recon helpers for WHOIS and DNS
- Encrypted notes and API secrets
- Local audit logging

## Package Layout

```text
neon_ape/
  __init__.py
  __main__.py
  app.py
  cli.py
  config.py
  models.py
  ui/
    ascii.py
    layout.py
    theme.py
  tools/
    base.py
    custom_runner.py
    nmap.py
    passive_recon.py
    projectdiscovery.py
  services/
    crypto.py
    logging_utils.py
    storage.py
    validation.py
  db/
    __init__.py
    repository.py
    schema.sql
  checklists/
    oscp_black_book_mvp.json
docs/
  architecture.md
  schema.md
tests/
requirements.txt
pyproject.toml
```

## Local Sections

- `Eva Unit Scanner`: active scanning and scan history
- `Angel Enumeration`: passive recon and DNS/WHOIS collection
- `MAGI Checklist`: workflow tracking and step guidance
- `AT Field Protector`: encryption, storage, and local safety checks
- `Entry Plug Scripts`: vetted custom automation hooks

## Dependencies

See [requirements.txt](requirements.txt).

Core libraries:

- `rich` for terminal UI
- `cryptography` for key derivation and Fernet encryption
- `dnspython` for DNS resolution and passive data gathering
- `python-whois` for WHOIS lookups
- `pydantic` for config and model validation
- `lxml` for robust XML parsing

Optional external tools expected on the host:

- `nmap`
- `whois`
- `dig`
- `gobuster` or `dirb` for future user-approved expansions

Detected locally in this workspace environment:

- `nmap`
- `subfinder`
- `httpx`
- `naabu`
- `nuclei`
- `dnsx`
- `katana`
- `assetfinder`
- `amass`
- `whois`
- `dig`
- `gobuster`
- `msfconsole`

## Security Model

- Local-only execution, no HTTP service
- `subprocess.run(..., shell=False)` only
- Strict validation for targets, CIDRs, URLs, and script paths
- Parameterized SQLite queries only
- Encrypted secrets and notes with user-derived keys
- Restricted custom script runner with explicit allowlists
- Redacted logging and bounded error reporting

## Database Design

Schema details live in [docs/schema.md](docs/schema.md) and the initial SQL lives in [schema.sql](neon_ape/db/schema.sql).

Tables planned for the MVP:

- `checklists`
- `checklist_items`
- `scan_runs`
- `scan_findings`
- `notes`
- `tool_history`
- `secrets`

## Install

Local checkout:

```bash
./install.sh --source "$(pwd)"
neonape --init-only
```

GitHub install:

```bash
curl -fsSL https://raw.githubusercontent.com/AlbanBeluli/neonape/main/install.sh | bash -s -- --repo https://github.com/AlbanBeluli/neonape.git
neonape --init-only
```

What the installer does:

- creates a private virtual environment under `~/.local/share/neonape/venv`
- installs Neon Ape into that private environment
- links the global launcher to `~/.local/bin/neonape`
- keeps runtime data under `~/.neon_ape/`

## Manual Dev Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
.venv/bin/python -m pip install -e .
neonape --show-checklist --init-only
```

Runtime paths:

- Neon Ape now stores its local database, logs, and scan artifacts under `~/.neon_ape/`
- Optional config file: `~/.config/neonape/config.toml`
- Packaged assets such as the schema and checklist seed are resolved relative to the installed project, not your current working directory
- That means `neonape` can be run from any directory
- The installer keeps the app itself under `~/.local/share/neonape/`

Example config:

```toml
[neonape]
privacy_mode = true
data_dir = "~/.neon_ape"
install_root = "~/.local/share/neonape"
bin_dir = "~/.local/bin"
```

Maintenance:

```bash
neonape uninstall
neonape uninstall --purge-data --yes
~/.local/share/neonape/update.sh
~/.local/share/neonape/uninstall.sh
```

Initialize storage only:

```bash
neonape --init-only
```

Default startup:

- `neonape` now opens an interactive local shell with checklist progress, next steps, recent scans, and menu-driven actions
- it does not run any external tools until you choose an action

Run the safe `nmap` workflow:

```bash
neonape --target 192.168.1.10 --profile service_scan --run-nmap
```

Run a ProjectDiscovery wrapper:

```bash
neonape --tool subfinder --target example.com
neonape --tool httpx --target https://example.com
neonape --tool naabu --target 192.168.1.10
neonape --tool dnsx --target example.com
neonape --tool nuclei --target https://example.com
```

Run the chained recon workflow:

```bash
neonape --workflow pd_chain --target example.com
```

Inspect stored database information:

```bash
neonape db tables
neonape db checklist
neonape db scans
neonape db findings
neonape db cleanup-history
```

Export and import:

```bash
neonape export scans --output scans.json
neonape export findings --format csv --output findings.csv
neonape import scans --input scans.json
```

Output handling:

- Each run stores a row in `scan_runs`
- Parsed records are normalized into `scan_findings`
- Command history is stored in `tool_history`
- Raw XML or JSONL artifacts are kept under `.neon_ape/scans/`
- Runtime data is stored under `~/.neon_ape/`
- Checklist steps with attached actions are marked `complete` on success and `in_progress` on failure
- Landing mode masks recent targets by default; use `neonape --show-targets` to reveal them
- `neonape db cleanup-history` rewrites older chained `httpx` and `naabu` history rows to the newer stable workflow labels

## Implementation Roadmap

### Phase 1: Foundation

- Build package skeleton and config loading
- Create Rich theme, layout shell, and section routing
- Add encrypted SQLite bootstrap and migrations
- Add checklist seed loader

### Phase 2: Core Workflow

- Implement checklist browsing and completion tracking
- Add secure notes and local history
- Implement target validation and command builders

### Phase 3: Tool Integrations

- Add `nmap` runner with XML parsing
- Add passive recon helpers for DNS and WHOIS
- Add ProjectDiscovery wrapper support for `subfinder`, `httpx`, `naabu`, `dnsx`, `nuclei`, and `katana`
- Add import/export for local results

### Phase 4: Hardening

- Improve logging, redaction, and failure handling
- Add tests for validators, crypto, repositories, and parsers
- Add packaging and installation guidance

## Existing Files In This Repo

The following legacy scripts remain in place as standalone references and are not part of the Neon Ape package:

- [port_scanner.py](port_scanner.py)
- [packet_sniffer.py](packet_sniffer.py)
- [web_scraper.py](web_scraper.py)
- [exploit_development.py](exploit_development.py)
- [ssh_bruteforce.py](ssh_bruteforce.py)

They should not be treated as production-safe components for the dashboard.
