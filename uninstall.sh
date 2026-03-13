#!/usr/bin/env bash
set -euo pipefail

APP_NAME="neonape"
INSTALL_ROOT="${NEONAPE_INSTALL_ROOT:-${HOME}/.local/share/${APP_NAME}}"
BIN_DIR="${NEONAPE_BIN_DIR:-${HOME}/.local/bin}"

rm -f "${BIN_DIR}/neonape"
rm -rf "$INSTALL_ROOT"

echo "Neon Ape removed from ${BIN_DIR}/neonape and ${INSTALL_ROOT}"
