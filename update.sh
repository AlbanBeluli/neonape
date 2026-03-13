#!/usr/bin/env bash
set -euo pipefail

APP_NAME="neonape"
INSTALL_ROOT="${NEONAPE_INSTALL_ROOT:-${HOME}/.local/share/${APP_NAME}}"
METADATA_FILE="${INSTALL_ROOT}/install.env"

if [[ ! -f "$METADATA_FILE" ]]; then
  echo "No Neon Ape installation metadata found at $METADATA_FILE" >&2
  echo "Run ./install.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$METADATA_FILE"

if [[ -n "${REPO_URL:-}" ]]; then
  exec "$(cd "$(dirname "$0")" && pwd)/install.sh" --repo "$REPO_URL" --branch "${BRANCH:-main}" --install-root "$INSTALL_ROOT" --bin-dir "${BIN_DIR:-$HOME/.local/bin}"
fi

if [[ -n "${SRC_DIR:-}" && -d "${SRC_DIR:-}" ]]; then
  exec "$(cd "$(dirname "$0")" && pwd)/install.sh" --source "$SRC_DIR" --install-root "$INSTALL_ROOT" --bin-dir "${BIN_DIR:-$HOME/.local/bin}"
fi

echo "Installation metadata is incomplete. Re-run ./install.sh." >&2
exit 1
