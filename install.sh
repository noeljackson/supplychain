#!/usr/bin/env bash
# Installer for the supplychain binary. Downloads the latest release matching
# this host's OS/arch and drops it in $BIN_DIR (default ~/.local/bin).
#
#   curl -fsSL https://raw.githubusercontent.com/noeljackson/supplychain/main/install.sh | bash
#
# Env overrides:
#   SUPPLYCHAIN_REPO   - source repo (default noeljackson/supplychain)
#   SUPPLYCHAIN_TAG    - pin to a release tag (default: latest)
#   SUPPLYCHAIN_BIN_DIR - install target (default ~/.local/bin)

set -euo pipefail

REPO="${SUPPLYCHAIN_REPO:-noeljackson/supplychain}"
TAG="${SUPPLYCHAIN_TAG:-latest}"
BIN_DIR="${SUPPLYCHAIN_BIN_DIR:-$HOME/.local/bin}"

info() { echo "==> $*"; }
die()  { echo "error: $*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required"

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported arch: $(uname -m)" ;;
esac

if [ "$TAG" = "latest" ]; then
  API_URL="https://api.github.com/repos/$REPO/releases/latest"
else
  API_URL="https://api.github.com/repos/$REPO/releases/tags/$TAG"
fi

info "looking up release: $API_URL"
META="$(curl -fsSL "$API_URL")"

# Find the matching asset.
ASSET_URL="$(printf '%s\n' "$META" \
  | grep -oE '"browser_download_url":[[:space:]]*"[^"]+"' \
  | sed -E 's/.*"(https[^"]+)".*/\1/' \
  | grep -i "$OS" | grep -i "$ARCH" \
  | grep -viE 'sbom|sig|sha256|attestation|\.json"?$|\.txt"?$' \
  | head -1)"

[ -n "$ASSET_URL" ] || die "no release asset for ${OS}/${ARCH} in $REPO@$TAG"

mkdir -p "$BIN_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "downloading $ASSET_URL"
curl -fsSL "$ASSET_URL" -o "$TMP/asset"

# Asset may be a raw binary or a tarball.
case "$ASSET_URL" in
  *.tar.gz|*.tgz)
    tar -xzf "$TMP/asset" -C "$TMP"
    BIN="$(find "$TMP" -type f -name 'supplychain*' | head -1)"
    ;;
  *.zip)
    ( cd "$TMP" && unzip -q asset )
    BIN="$(find "$TMP" -type f -name 'supplychain*' | grep -v '\.zip$' | head -1)"
    ;;
  *)
    BIN="$TMP/asset"
    ;;
esac
[ -n "${BIN:-}" ] || die "no supplychain binary in downloaded asset"

install -m 0755 "$BIN" "$BIN_DIR/supplychain"
info "installed $BIN_DIR/supplychain"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not in PATH. Add to your shell rc:"
     echo "      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo
echo "next: 'supplychain doctor' to verify; 'supplychain scan' in any project."
