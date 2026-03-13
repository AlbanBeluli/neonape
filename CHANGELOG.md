# Changelog

All notable changes to this project will be documented in this file.

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
