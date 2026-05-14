#!/usr/bin/env bash
# Claude Code SessionStart hook.
# Runs a scan against $CLAUDE_PROJECT_DIR (or cwd) and emits a banner only
# if findings exist — silent otherwise. Never blocks session start.
set -euo pipefail

TARGET="${CLAUDE_PROJECT_DIR:-$PWD}"

command -v supplychain >/dev/null 2>&1 || exit 0

# Resolve a portable timeout command. GNU coreutils ships `timeout`; macOS
# does not by default (gtimeout via `brew install coreutils`). If neither is
# present we run without a wall-clock cap and rely on supplychain's own
# internal timeouts (registry: 8s, osv-scanner exec: 120s).
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT="timeout 20"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT="gtimeout 20"
else
  TIMEOUT=""
fi

OUT="$($TIMEOUT supplychain scan --quiet "$TARGET" 2>&1 || true)"
if [ -n "$OUT" ]; then
  echo "supply-chain scanner: findings in $TARGET"
  echo "$OUT"
fi
exit 0
