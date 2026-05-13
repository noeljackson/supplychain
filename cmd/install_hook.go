package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func cmdInstallHook(g *Globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: supplychain install-hook <claude-sessionstart|pre-commit>")
		return 2
	}
	switch args[0] {
	case "claude-sessionstart":
		return installClaudeHook(g)
	case "pre-commit":
		return installPreCommitHook(g)
	default:
		fmt.Fprintln(os.Stderr, "unknown hook:", args[0])
		return 2
	}
}

func installClaudeHook(g *Globals) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	fmt.Printf(`To enable the Claude Code SessionStart scanner, add this to %s
(merge with existing keys — we don't auto-edit your settings):

  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "supplychain scan --quiet" }
        ]
      }
    ]
  }
`, settings)
	return 0
}

func installPreCommitHook(g *Globals) int {
	// Must be inside a git repo.
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not inside a git repo")
		return 1
	}
	repo := strings.TrimSpace(string(out))
	hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if st, err := os.Lstat(hook); err == nil && st.Mode()&os.ModeSymlink == 0 {
		fmt.Fprintln(os.Stderr, hook, "exists and is not a symlink — install manually")
		return 1
	}
	// Hook script is shipped in the repo we were installed from. With a
	// `go install`-only install we don't have that on disk, so embed the
	// script content inline here.
	const hookScript = `#!/usr/bin/env bash
# supplychain pre-commit: run scan when a lockfile is in the staged changes.
set -euo pipefail
CHANGED="$(git diff --cached --name-only --diff-filter=ACMR \
  | grep -E '(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock|package\.json)$' || true)"
[ -z "$CHANGED" ] && exit 0
command -v supplychain >/dev/null 2>&1 || { echo "supplychain missing; skipping" >&2; exit 0; }
REPO="$(git rev-parse --show-toplevel)"
if ! supplychain scan "$REPO"; then
  echo "commit blocked: supply-chain findings in changed manifest/lockfile(s)." >&2
  echo "bypass with: git commit --no-verify" >&2
  exit 1
fi
`
	_ = os.Remove(hook)
	if err := os.WriteFile(hook, []byte(hookScript), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "write hook:", err)
		return 1
	}
	fmt.Println("installed pre-commit hook in", repo)
	return 0
}
