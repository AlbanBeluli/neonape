# Neon Ape

Neon Ape is a local-only Python terminal dashboard for lab-safe penetration testing workflows. It combines a Neon Genesis Evangelion-inspired terminal UI, guided checklist execution, encrypted local notes, and safe wrappers around common recon tooling.

## At a Glance

- Local-only workflow with no web server or exposed listener
- Interactive `neonape` shell plus direct CLI subcommands
- Safe wrappers for `nmap`, `subfinder`, `assetfinder`, `amass`, `dnsx`, `httpx`, `naabu`, `katana`, `gobuster`, and `nuclei`
- Chained recon flows for light recon, deep recon, web triage, and JS-heavy targets
- SQLite-backed checklist, scan history, findings, and encrypted notes
- Config-backed Obsidian sync with vault auto-discovery and dry-run previews

This project does not automate brute force, exploitation, credential attacks, or post-exploitation activity.

## Why NeonApe?

NeonApe is built for operators who want speed, local control, and a workflow that actually feels good to use. It stays local-only, ships with no telemetry, keeps data on your machine, and defaults to safer recon and review flows instead of reckless automation. The goal is simple: give you a sharp, memorable terminal dashboard with Evangelion energy, fast chained workflows, encrypted notes, and enough structure to move from recon to review without turning your shell into a mess.

## Quick Start

Install from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/AlbanBeluli/neonape/main/install.sh | bash -s -- --repo https://github.com/AlbanBeluli/neonape.git
neonape
```

If your shell has not picked up `~/.local/bin` yet, run:

```bash
~/.local/bin/neonape
~/.local/bin/neonape-obsidian -h
```

Useful first commands:

```bash
neonape
neonape --workflow pd_chain --target example.com
neonape --workflow pd_web_chain --target example.com
neonape --workflow light_recon --target example.com
neonape --workflow js_web_chain --target example.com
neonape --tool nuclei --target https://example.com
neonape db scans
neonape db inventory
neonape notes list
neonape obsidian --target-note Pentests/example.com/Target.md --dry-run
```

## What It Covers

- Passive reconnaissance
- Active scanning in authorized environments
- Findings tracking and local history
- Notes and checklist management
- Safe local automation

## Current Feature Set

- Rich-based terminal UI with an interactive startup shell
- Checklist engine backed by SQLite
- `nmap` integration with XML parsing
- ProjectDiscovery wrappers for `subfinder`, `assetfinder`, `amass`, `httpx`, `naabu`, `dnsx`, `katana`, and `nuclei`
- Safe web enumeration wrapper for `gobuster`
- Chained workflows: `pd_chain`, `pd_web_chain`, `light_recon`, `deep_recon`, and `js_web_chain`
- Welcome panel, missing-tool guidance, and severity-colored review tables
- Encrypted notes and local scan history
- Import/export, uninstall, and DB inspection commands
- Native `neonape obsidian`, `neonape config`, and `neonape update` maintenance flows

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
    neon_ape_checklist.json
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

Supported host tools:

- `nmap`
- `subfinder`
- `assetfinder`
- `amass`
- `httpx`
- `naabu`
- `nuclei`
- `dnsx`
- `katana`
- `gobuster`
- `whois`
- `dig`
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

Schema details live in [docs/schema.md](docs/schema.md) and the SQL lives in [schema.sql](neon_ape/db/schema.sql).

Current tables:

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
neonape
```

GitHub install:

```bash
curl -fsSL https://raw.githubusercontent.com/AlbanBeluli/neonape/main/install.sh | bash -s -- --repo https://github.com/AlbanBeluli/neonape.git
neonape
```

Tool bootstrap:

```bash
bash install_recon_tools.sh
```

The helper script detects `apt-get`, `pacman`, or `brew`, installs the common base packages it can manage directly, and then prints follow-up guidance for ProjectDiscovery tools.

What the installer does:

- creates a private virtual environment under `~/.local/share/neonape/venv`
- installs Neon Ape into that private environment
- links the global launcher to `~/.local/bin/neonape`
- links the Obsidian launcher to `~/.local/bin/neonape-obsidian`
- keeps runtime data under `~/.neon_ape/`

## Manual Dev Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
.venv/bin/python -m pip install -e .
neonape
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
theme_name = "eva"
data_dir = "~/.neon_ape"
install_root = "~/.local/share/neonape"
bin_dir = "~/.local/bin"
obsidian_vault_path = "~/Documents/Obsidian"
```

Built-in config commands:

```bash
neonape config show
neonape config init
neonape config set privacy_mode false
neonape config set theme_name seele
neonape config set obsidian_vault_path ~/Documents/Obsidian
```

Maintenance:

```bash
neonape update
neonape update --yes
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

## Main Commands

Run the safe `nmap` workflow:

```bash
neonape --target 192.168.1.10 --profile service_scan --run-nmap
```

Run a single wrapper:

```bash
neonape --tool subfinder --target example.com
neonape --tool assetfinder --target example.com
neonape --tool amass --target example.com
neonape --tool httpx --target https://example.com
neonape --tool naabu --target 192.168.1.10
neonape --tool dnsx --target example.com
neonape --tool katana --target https://example.com
neonape --tool gobuster --target https://example.com
neonape --tool nuclei --target https://example.com
```

Run a chained workflow:

```bash
neonape --workflow pd_chain --target example.com
neonape --workflow pd_web_chain --target example.com
neonape --workflow light_recon --target example.com
neonape --workflow deep_recon --target example.com
neonape --workflow js_web_chain --target example.com
```

## Example Walkthroughs

### Recon a bug-bounty target in 5 minutes

Use this for a fast first pass on an authorized public target:

```bash
neonape --workflow light_recon --target example.com
neonape --workflow pd_web_chain --target example.com
neonape review --target example.com
neonape db domain --target example.com
```

What this does:

- discovers subdomains with passive sources
- probes live HTTP targets
- runs nuclei against reachable web assets
- summarizes saved scans, findings, inventory, and review matches

If the target is JavaScript-heavy, switch the second command to:

```bash
neonape --workflow js_web_chain --target example.com
```

### Using encrypted notes during a red team engagement

Use notes to track observations locally without leaving plaintext findings around:

```bash
neonape notes add --title "External login panel" --body "Observed admin login at /portal with MFA prompt." --target app.example.com
neonape notes list
neonape notes view --id 1
neonape db domain --target app.example.com
```

A practical pattern:

- run recon or review commands first
- save operator notes with a short title and target label
- pull everything back together with `neonape db domain --target ...`
- keep notes encrypted at rest in the local SQLite store

Manage encrypted notes:

```bash
neonape notes list
neonape notes add --title "Admin portal" --body "Observed login at /admin" --target app.example.com
neonape notes view --id 1
```

Inspect local database information:

```bash
neonape db tables
neonape db checklist
neonape db scans
neonape db findings
neonape db inventory
neonape db reviews
neonape db notes
neonape db domain --target example.com
neonape db cleanup-history
```

Export and import:

```bash
neonape export scans --output scans.json
neonape export findings --format csv --output findings.csv
neonape import scans --input scans.json
```

## Obsidian Sync

Neon Ape also ships with an Obsidian bridge that can read a target note with YAML frontmatter, run a Neon Ape workflow, and write findings, notes, copied scan artifacts, and a basic Canvas file back into your vault.

Example source note frontmatter:

```yaml
---
target: "example.com"
scope: "in-scope subdomains only"
checklist: "pd_web_chain"
---
```

If you save your vault path in config, this is enough:

```bash
neonape obsidian \
  --target-note "Pentests/example.com/Target.md" \
  --notes-passphrase "your-passphrase"
```

You can still pass a vault path explicitly:

```bash
neonape obsidian \
  --vault-path "/path/to/ObsidianVault" \
  --target-note "Pentests/example.com/Target.md"
```

Preview without writing anything:

```bash
neonape obsidian \
  --target-note "Pentests/example.com/Target.md" \
  --dry-run
```

If you are already somewhere inside the vault, Neon Ape will also auto-discover the vault root by walking upward until it finds `.obsidian/`.

The standalone launcher still works too:

```bash
neonape-obsidian --target-note "Pentests/example.com/Target.md"
```

The sync creates or updates:

- `Pentests/<target>/Target.md`
- `Pentests/<target>/Findings.md`
- `Pentests/<target>/Notes.md`
- `Pentests/<target>/Scans/`
- `Pentests/<target>/Screenshots/`
- `Pentests/<target>/Attack-Chain.canvas`
- `Pentests/Templates/Pentest-Target.md`

Sample inputs live under:

- [Target.md](docs/obsidian/Target.md)
- [Attack-Chain.canvas](docs/obsidian/Attack-Chain.canvas)

## Storage Behavior

- Each run stores a row in `scan_runs`
- Parsed results are normalized into `scan_findings`
- Command execution history is stored in `tool_history`
- Raw XML and JSONL artifacts are stored under `~/.neon_ape/scans/`
- Checklist actions are marked `complete` on success and `in_progress` on failure
- Landing mode masks saved targets by default; use `neonape --show-targets` to reveal them
- `neonape db cleanup-history` rewrites older chained `httpx` and `naabu` history rows to the newer workflow labels
- Notes are encrypted before being stored in SQLite

## Security Notes

- Local-only execution by design
- `subprocess.run(..., shell=False)` only
- Input validation for targets, domains, URLs, and script paths
- Parameterized SQLite queries
- Application-layer encryption for notes and secrets
- No exploitation automation, brute force support, or post-exploitation workflow
