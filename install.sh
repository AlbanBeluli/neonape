#!/usr/bin/env bash
set -euo pipefail

APP_NAME="neonape"
DEFAULT_INSTALL_ROOT="${HOME}/.local/share/${APP_NAME}"
DEFAULT_BIN_DIR="${HOME}/.local/bin"
DEFAULT_BRANCH="main"

INSTALL_ROOT="${NEONAPE_INSTALL_ROOT:-$DEFAULT_INSTALL_ROOT}"
BIN_DIR="${NEONAPE_BIN_DIR:-$DEFAULT_BIN_DIR}"
BRANCH="${NEONAPE_BRANCH:-$DEFAULT_BRANCH}"
REPO_URL="${NEONAPE_REPO_URL:-}"
SOURCE_DIR=""

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
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH"
    git -C "$SRC_DIR" checkout "$BRANCH"
    git -C "$SRC_DIR" pull --ff-only origin "$BRANCH"
  else
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
fi

python3 -m venv "$VENV_DIR"
if ! "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel; then
  echo "Continuing with the virtualenv's bundled packaging tools." >&2
fi
"$VENV_DIR/bin/python" -m pip install "$SRC_DIR"
ln -sf "$VENV_DIR/bin/neonape" "$BIN_DIR/neonape"
cp "$SELF_DIR/install.sh" "$SELF_DIR/update.sh" "$SELF_DIR/uninstall.sh" "$INSTALL_ROOT"/
chmod +x "$INSTALL_ROOT/install.sh" "$INSTALL_ROOT/update.sh" "$INSTALL_ROOT/uninstall.sh"

cat > "$METADATA_FILE" <<EOF
INSTALL_ROOT=$INSTALL_ROOT
BIN_DIR=$BIN_DIR
BRANCH=$BRANCH
REPO_URL=$REPO_URL
SRC_DIR=$SRC_DIR
EOF

cat <<EOF
Neon Ape installed.

Command:
  $BIN_DIR/neonape

If $BIN_DIR is already on your PATH, just run:
  neonape --init-only

Maintenance:
  $INSTALL_ROOT/update.sh
  $INSTALL_ROOT/uninstall.sh
EOF

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
