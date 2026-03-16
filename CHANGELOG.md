# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-03-16

### Added

- Full MAGI checklist expansion covering passive recon, host discovery, port scanning, service enumeration, nuclei review, and web path review
- Adam-driven MAGI checklist execution with live Rich progress and per-step run/skip/done prompts
- Passive recon checklist actions backed by WHOIS and DNS A-record collection with DB persistence
- Checklist state preservation across reseeds so Adam and the interactive shell keep prior completion history

### Changed

- Checklist status flow now uses `todo`, `in_progress`, and `done`
- Adam now seeds recon-complete checklist steps from its existing workflow evidence before entering the MAGI phase
- macOS Daniel notification now reflects MAGI completion wording

### Fixed

- Checklist rows are no longer reset to empty state every time the seed file is reloaded
- Landing and checklist views now treat legacy `complete/pending` rows as normalized `done/todo`

## [0.3.0] - 2026-03-14

### Added

- Config-backed Obsidian sync defaults, vault auto-discovery, and native `neonape obsidian`
- New DB views for `inventory`, `reviews`, and `notes`
- Interactive shell actions for config, update, and Obsidian sync
- Built-in `neonape update` flow for install-managed copies

### Changed

- Obsidian dry-run mode now stays fully read-only
- Quick-start and help output now surface Obsidian and DB review commands more clearly
- Gobuster wordlist discovery now uses generic home-relative paths instead of user-specific paths

### Fixed

- Removed remaining hardcoded local path leaks from the repo-facing application code

## [0.2.0] - 2026-03-13

### Added

- Interactive terminal startup with menu-driven actions
- Safe wrappers for `nmap`, `subfinder`, `dnsx`, `httpx`, `naabu`, and `nuclei`
- Chained workflows for `subfinder -> httpx -> naabu` and `subfinder -> httpx -> nuclei`
- Encrypted notes commands and interactive notes access
- Database history cleanup command for older chained workflow labels
- Release notes file for `v0.2.0`

### Changed

- Improved command previews to avoid leaking absolute local paths
- Added clearer batch history labels in scan history
- Improved startup UX and workflow summaries
- Added richer tool-specific output views, including `naabu` and `nuclei`

### Fixed

- Deduplicated exact duplicate ProjectDiscovery findings
- Corrected recent findings table rendering
- Improved chained workflow history readability
