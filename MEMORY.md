# Neon Ape Memory

## Current Architecture

- `neon_ape/cli.py`: CLI entrypoint and argument parsing
- `neon_ape/app.py`: main application flow, dashboard rendering, tool dispatch, DB views
- `neon_ape/config.py`: runtime paths, packaged asset paths, tool detection
- `neon_ape/ui/`: Rich tables, theme, and ASCII banner
- `neon_ape/tools/nmap.py`: safe `nmap` command builder and XML parsing
- `neon_ape/tools/projectdiscovery.py`: wrappers for `subfinder`, `httpx`, `naabu`, and `dnsx`
- `neon_ape/services/`: validation, logging, storage, and crypto helpers
- `neon_ape/db/repository.py`: schema bootstrap, checklist seeding, scan persistence, DB inspection queries
- `neon_ape/checklists/oscp_black_book_mvp.json`: seeded checklist definition with attached tool actions

## Supported Commands

Main usage:

- `neonape`
- `neonape --init-only`
- `neonape --show-checklist --init-only`
- `neonape --checklist-step <step> --target <target>`

Tool execution:

- `neonape --target <target> --run-nmap --profile host_discovery`
- `neonape --target <target> --run-nmap --profile service_scan`
- `neonape --target <target> --run-nmap --profile aggressive`
- `neonape --tool subfinder --target <domain>`
- `neonape --tool dnsx --target <domain>`
- `neonape --tool httpx --target <url-or-host>`
- `neonape --tool naabu --target <host-or-ip>`

Database inspection:

- `neonape db tables`
- `neonape db checklist`
- `neonape db scans`
- `neonape db findings`

## Data Locations

- Runtime directory: `~/.neon_ape/`
- SQLite database: `~/.neon_ape/neon_ape.db`
- Log file: `~/.neon_ape/neon_ape.log`
- Scan artifacts: `~/.neon_ape/scans/`
- Launcher path: `~/.local/bin/neonape`

## Known Limitations

- The app is still command-driven, not a fully interactive terminal menu workflow
- `neonape` with no arguments shows the dashboard shell but does not enter an interactive prompt
- DB views render the full dashboard header first, not a minimal data-only output mode
- Checklist status is persisted after step execution, but the checklist table shown at startup may reflect pre-run state in the same invocation
- Full encrypted SQLite is not implemented; sensitive field encryption scaffolding exists, but DB-wide SQLCipher support is not wired in
- Custom script execution is only scaffolded and not yet a full user-facing feature
- No built-in export/import flow yet for findings or scan history

## Next Planned Features

- Add interactive menu navigation for checklist steps and DB views
- Add cleaner data-only output mode for `neonape db ...`
- Mark checklist progress live in the rendered table after step execution
- Add richer parsed views for more tool outputs
- Add wrappers for additional installed tools where appropriate
- Add notes management and encrypted secret storage flows
- Add tests for CLI, DB views, parsers, and checklist execution
