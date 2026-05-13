#!/usr/bin/env bash
# Claude Code SessionStart hook.
# Runs a scan against $CLAUDE_PROJECT_DIR (or cwd) and emits a banner only
# if findings exist — silent otherwise. Never blocks session start.
set -euo pipefail

TARGET="${CLAUDE_PROJECT_DIR:-$PWD}"

command -v supplychain >/dev/null 2>&1 || exit 0

OUT="$(timeout 20 supplychain scan --quiet "$TARGET" 2>&1 || true)"
if [ -n "$OUT" ]; then
  echo "supply-chain scanner: findings in $TARGET"
  echo "$OUT"
fi
exit 0
