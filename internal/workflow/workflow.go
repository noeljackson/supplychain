// Package workflow runs a pinned GitHub Actions security audit through zizmor.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Run audits workflow and action definitions beneath target. Network-backed
// rules are disabled so no GitHub token is exposed to the external analyzer.
func Run(target, binDir string) error {
	if target == "" {
		return errors.New("workflow: target is required")
	}
	definitions, err := definitionPaths(target)
	if err != nil {
		return fmt.Errorf("workflow: discover definitions: %w", err)
	}
	if len(definitions) == 0 {
		return nil
	}
	zizmor, err := locate(binDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{
		"--offline",
		"--strict-collection",
		"--persona=regular",
		"--min-severity=medium",
		"--min-confidence=medium",
		"--format=github",
	}
	args = append(args, definitions...)
	cmd := exec.CommandContext(ctx, zizmor, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("workflow: zizmor audit timed out")
		}
		return fmt.Errorf("workflow: zizmor policy failed: %w", err)
	}
	return nil
}

func definitionPaths(root string) ([]string, error) {
	var definitions []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "target":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		if name == "action.yml" || name == "action.yaml" {
			definitions = append(definitions, path)
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(strings.ToLower(rel))
		if (strings.HasPrefix(rel, ".github/workflows/") ||
			strings.HasPrefix(rel, ".gitea/workflows/") ||
			strings.HasPrefix(rel, ".gitea/scoped_workflows/") ||
			rel == ".github/dependabot.yml" || rel == ".github/dependabot.yaml") &&
			(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			definitions = append(definitions, path)
		}
		return nil
	})
	sort.Strings(definitions)
	return definitions, err
}

func locate(binDir string) (string, error) {
	if binDir != "" {
		candidate := filepath.Join(binDir, "zizmor")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	path, err := exec.LookPath("zizmor")
	if err != nil {
		return "", errors.New("workflow: zizmor is required but unavailable")
	}
	return path, nil
}
