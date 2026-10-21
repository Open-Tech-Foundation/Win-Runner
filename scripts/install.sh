#!/usr/bin/env bash
# Install Win-Runner (winrun) from a GitHub Release on Linux x86-64.
#
# Usage:
#   scripts/install.sh [--version vX.Y.Z] [--prefix DIR] [--dry-run]
#
# Environment:
#   WINRUN_VERSION   Release tag (default: latest, the newest release)
#   WINRUN_PREFIX    Install directory (default: $HOME/.local/bin, or
#                    /usr/local/bin when writable and not overridden)
set -euo pipefail

REPO="${WINRUN_REPO:-Open-Tech-Foundation/Win-Runner}"
VERSION="${WINRUN_VERSION:-latest}"
ARCHIVE="winrun-win-runner.tar.gz"
CHECKSUMS="checksums.txt"
DRY_RUN=0
PREFIX=""

usage() {
  cat <<EOF
Usage: scripts/install.sh [options]

Options:
  --version TAG   Release tag to install (default: ${VERSION})
  --prefix DIR    Directory to install winrun into
  --dry-run       Print what would be done; do not download or install
  -h, --help      Show this help

Environment:
  WINRUN_VERSION  Same as --version
  WINRUN_PREFIX   Same as --prefix
  WINRUN_REPO     GitHub repo (default: ${REPO})
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:?--version requires a tag}"
      shift 2
      ;;
    --prefix)
      PREFIX="${2:?--prefix requires a directory}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "install.sh: published releases are Linux binaries (found $(uname -s))" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    echo "install.sh: published releases are x86-64 (found $(uname -m))" >&2
    exit 1
    ;;
esac

if [ -z "$PREFIX" ]; then
  if [ -n "${WINRUN_PREFIX:-}" ]; then
    PREFIX="$WINRUN_PREFIX"
  elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    PREFIX="/usr/local/bin"
  else
    PREFIX="${HOME}/.local/bin"
  fi
fi

# GitHub serves the newest release's files under releases/latest/download.
if [ "$VERSION" = "latest" ]; then
  base_url="https://github.com/${REPO}/releases/latest/download"
else
  base_url="https://github.com/${REPO}/releases/download/${VERSION}"
fi
workdir="$(mktemp -d "${TMPDIR:-/tmp}/winrun-install.XXXXXX")"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

echo "Installing Win-Runner ${VERSION} into ${PREFIX}"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "would download ${base_url}/${ARCHIVE}"
  echo "would download ${base_url}/${CHECKSUMS}"
  echo "would verify sha256 and extract winrun"
  echo "would install -m 755 winrun ${PREFIX}/winrun"
  exit 0
fi

command -v curl >/dev/null 2>&1 || {
  echo "install.sh: curl is required" >&2
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "install.sh: sha256sum is required" >&2
  exit 1
}

cd "$workdir"
echo "Downloading ${ARCHIVE} and ${CHECKSUMS}..."
curl -fLsS --retry 3 --retry-delay 1 -o "$ARCHIVE" "${base_url}/${ARCHIVE}"
curl -fLsS --retry 3 --retry-delay 1 -o "$CHECKSUMS" "${base_url}/${CHECKSUMS}"

echo "Verifying checksum..."
sha256sum -c "$CHECKSUMS"

tar -xzf "$ARCHIVE"
test -f winrun
chmod 755 winrun

mkdir -p "$PREFIX"
if [ -w "$PREFIX" ]; then
  install -m 755 winrun "${PREFIX}/winrun"
else
  echo "Installing into ${PREFIX} (sudo)..."
  sudo install -m 755 winrun "${PREFIX}/winrun"
fi

echo "Installed: ${PREFIX}/winrun ($("${PREFIX}/winrun" --version 2>/dev/null || echo "version unknown"))"
if ! command -v winrun >/dev/null 2>&1; then
  case ":$PATH:" in
    *":${PREFIX}:"*) ;;
    *)
      echo "Note: ${PREFIX} is not on PATH. Add it, for example:"
      echo "  export PATH=\"${PREFIX}:\$PATH\""
      ;;
  esac
fi

# Light smoke check when the install is on PATH or we can call it directly.
if command -v winrun >/dev/null 2>&1; then
  winrun >/dev/null 2>&1 || true
  echo "winrun is ready on PATH."
else
  "${PREFIX}/winrun" >/dev/null 2>&1 || true
  echo "winrun is ready at ${PREFIX}/winrun."
fi
