#!/usr/bin/env bash
set -euo pipefail

APP_NAME="neonape"
DEFAULT_INSTALL_ROOT="${HOME}/.local/share/${APP_NAME}"
DEFAULT_BIN_DIR="${HOME}/.local/bin"
DEFAULT_BRANCH="main"
DEFAULT_CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/${APP_NAME}"
DEFAULT_CONFIG_PATH="${DEFAULT_CONFIG_DIR}/config.toml"

INSTALL_ROOT="${NEONAPE_INSTALL_ROOT:-$DEFAULT_INSTALL_ROOT}"
BIN_DIR="${NEONAPE_BIN_DIR:-$DEFAULT_BIN_DIR}"
BRANCH="${NEONAPE_BRANCH:-$DEFAULT_BRANCH}"
REPO_URL="${NEONAPE_REPO_URL:-}"
SOURCE_DIR=""
UPDATE_MODE="${NEONAPE_UPDATE_MODE:-0}"

usage() {
  cat <<'EOF'
Usage:
  ./install.sh
  ./install.sh --source /path/to/neonape
  ./install.sh --repo https://github.com/<user>/<repo>.git

Options:
  --source PATH        Install from a local checkout.
  --repo URL           Clone and install from a Git repository.
  --branch NAME        Git branch to clone or update. Default: main
  --install-root PATH  Install root. Default: ~/.local/share/neonape
  --bin-dir PATH       Directory for the global launcher. Default: ~/.local/bin
  -h, --help           Show this help message.

Environment overrides:
  NEONAPE_INSTALL_ROOT
  NEONAPE_BIN_DIR
  NEONAPE_BRANCH
  NEONAPE_REPO_URL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE_DIR="${2:?missing path for --source}"
      shift 2
      ;;
    --repo)
      REPO_URL="${2:?missing URL for --repo}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:?missing value for --branch}"
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT="${2:?missing path for --install-root}"
      shift 2
      ;;
    --bin-dir)
      BIN_DIR="${2:?missing path for --bin-dir}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd python3

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"

SRC_DIR="${INSTALL_ROOT}/src"
VENV_DIR="${INSTALL_ROOT}/venv"
METADATA_FILE="${INSTALL_ROOT}/install.env"
CONFIG_PATH="$DEFAULT_CONFIG_PATH"

detect_obsidian_vault() {
  if [[ -n "${NEONAPE_OBSIDIAN_VAULT:-}" && -d "${NEONAPE_OBSIDIAN_VAULT:-}" ]]; then
    printf '%s\n' "$NEONAPE_OBSIDIAN_VAULT"
    return 0
  fi

  local candidates=(
    "$HOME/Documents/Obsidian"
    "$HOME/Obsidian"
    "$HOME/Documents/Notes"
  )
  local candidate=""
  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate/.obsidian" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local search_root=""
  for search_root in "$HOME/Documents" "$HOME"; do
    if [[ -d "$search_root" ]]; then
      candidate="$(find "$search_root" -maxdepth 3 -type d -name .obsidian 2>/dev/null | head -n 1 || true)"
      if [[ -n "$candidate" ]]; then
        dirname "$candidate"
        return 0
      fi
    fi
  done

  return 1
}

seed_obsidian_config() {
  local vault_path="$1"
  if [[ -z "$vault_path" ]]; then
    return 0
  fi

  mkdir -p "$(dirname "$CONFIG_PATH")"

  if [[ -f "$CONFIG_PATH" ]] && grep -q '^[[:space:]]*obsidian_vault_path[[:space:]]*=' "$CONFIG_PATH"; then
    return 0
  fi

  "$VENV_DIR/bin/python" - <<'PY' "$CONFIG_PATH" "$vault_path"
from pathlib import Path
import sys

config_path = Path(sys.argv[1]).expanduser()
vault_path = sys.argv[2]
existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
lines = existing.splitlines()

if any(line.strip().startswith("obsidian_vault_path") for line in lines):
    raise SystemExit(0)

if not existing.strip():
    payload = f"[neonape]\nobsidian_vault_path = \"{vault_path}\"\n"
elif "[neonape]" in existing:
    updated = []
    inserted = False
    for line in lines:
        updated.append(line)
        if not inserted and line.strip() == "[neonape]":
            updated.append(f"obsidian_vault_path = \"{vault_path}\"")
            inserted = True
    payload = "\n".join(updated) + ("\n" if existing.endswith("\n") else "\n")
else:
    payload = existing.rstrip() + "\n\n[neonape]\n" + f"obsidian_vault_path = \"{vault_path}\"\n"

config_path.write_text(payload, encoding="utf-8")
PY
}

if [[ -z "$SOURCE_DIR" && -z "$REPO_URL" ]]; then
  if [[ -f "./pyproject.toml" && -d "./neon_ape" ]]; then
    SOURCE_DIR="$(pwd)"
  else
    echo "No source specified. Use --source <path> or --repo <git-url>." >&2
    exit 1
  fi
fi

if [[ -n "$SOURCE_DIR" ]]; then
  SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  cp -R "$SOURCE_DIR"/. "$SRC_DIR"/
  rm -rf "$SRC_DIR/.git" "$SRC_DIR/.venv" "$SRC_DIR/.neon_ape" "$SRC_DIR/neonape.egg-info"
  find "$SRC_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} +
else
  require_cmd git
  if [[ -d "$SRC_DIR/.git" ]]; then
    git -C "$SRC_DIR" fetch --quiet --depth 1 origin "$BRANCH"
    git -C "$SRC_DIR" checkout --quiet -B "$BRANCH" "origin/$BRANCH"
  else
    rm -rf "$SRC_DIR"
    git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
fi

python3 -m venv "$VENV_DIR"
INSTALL_LOG="$(mktemp)"
trap 'rm -f "$INSTALL_LOG"' EXIT
if ! "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-build-isolation --quiet "$SRC_DIR" >"$INSTALL_LOG" 2>&1; then
  echo "Initial install failed. Attempting setuptools/wheel bootstrap..." >&2
  "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --quiet setuptools wheel >>"$INSTALL_LOG" 2>&1
  if ! "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-build-isolation --quiet "$SRC_DIR" >>"$INSTALL_LOG" 2>&1; then
    cat "$INSTALL_LOG" >&2
    exit 1
  fi
fi
ln -sf "$VENV_DIR/bin/neonape" "$BIN_DIR/neonape"
ln -sf "$VENV_DIR/bin/neonape-obsidian" "$BIN_DIR/neonape-obsidian"
cp "$SRC_DIR/install.sh" "$SRC_DIR/update.sh" "$SRC_DIR/uninstall.sh" "$INSTALL_ROOT"/
chmod +x "$INSTALL_ROOT/install.sh" "$INSTALL_ROOT/update.sh" "$INSTALL_ROOT/uninstall.sh"

DETECTED_OBSIDIAN_VAULT="$(detect_obsidian_vault || true)"
if [[ -n "$DETECTED_OBSIDIAN_VAULT" ]]; then
  seed_obsidian_config "$DETECTED_OBSIDIAN_VAULT"
fi

cat > "$METADATA_FILE" <<EOF
INSTALL_ROOT=$INSTALL_ROOT
BIN_DIR=$BIN_DIR
BRANCH=$BRANCH
REPO_URL=$REPO_URL
SRC_DIR=$SRC_DIR
EOF

INSTALLED_VERSION="$("$VENV_DIR/bin/python" - <<'PY'
from importlib.metadata import version
print(version("neonape"))
PY
)"

cat <<EOF
Neon Ape $([[ "$UPDATE_MODE" == "1" ]] && echo "updated" || echo "installed").

Version:
  $INSTALLED_VERSION

Command:
  $BIN_DIR/neonape
  $BIN_DIR/neonape-obsidian

If $BIN_DIR is already on your PATH, just run:
  neonape --init-only
  neonape-obsidian -h

Maintenance:
  $INSTALL_ROOT/update.sh
  $INSTALL_ROOT/uninstall.sh
EOF

if [[ -n "$DETECTED_OBSIDIAN_VAULT" ]]; then
  cat <<EOF

Obsidian:
  Detected vault: $DETECTED_OBSIDIAN_VAULT
  Seeded obsidian_vault_path in:
    $CONFIG_PATH
EOF
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    cat <<EOF

PATH note:
  $BIN_DIR is not currently on your PATH.
  Add this to your shell config:
    export PATH="$BIN_DIR:\$PATH"
EOF
    ;;
esac
