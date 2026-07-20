// Package secrets runs redacted repository secret scanning through Gitleaks.
package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const scanTimeout = 10 * time.Minute

// Run scans target with Gitleaks. Findings are reported by Gitleaks and cause
// a non-zero exit. Repository configuration is ignored unless config is an
// explicit, tracked path inside target.
func Run(target, binDir, config string) error {
	if target == "" {
		return errors.New("secrets: target is required")
	}
	gitleaks, err := locate(binDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	configPath, configRel, err := resolveConfig(ctx, target, config)
	if err != nil {
		return err
	}
	scanRoot, cleanup, err := stageGitVisible(ctx, target, configRel)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{
		"dir",
		".",
		"--no-banner",
		"--no-color",
		"--redact",
		"--log-level", "warn",
		"--max-target-megabytes", "10",
		"--exit-code", "1",
	}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	cmd := exec.CommandContext(ctx, gitleaks, args...)
	cmd.Dir = scanRoot
	cmd.Env = append(withoutGitleaksConfig(os.Environ()), "GITLEAKS_ENABLE_ANALYTICS=false")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("secrets: gitleaks scan timed out")
		}
		return fmt.Errorf("secrets: gitleaks policy failed: %w", err)
	}
	return nil
}

// stageGitVisible builds a hard-linked view containing tracked files and
// untracked files that are not ignored by Git. Gitleaks' directory scanner
// does not honor .gitignore itself, so scanning target directly would inspect
// generated binaries and dependency caches. The staging tree lives under the
// repository's Git directory, has no copied secret material, and is removed
// after every scan.
func stageGitVisible(ctx context.Context, target, explicitConfigRel string) (string, func(), error) {
	target, err := filepath.Abs(target)
	if err != nil {
		return "", nil, fmt.Errorf("secrets: resolve target: %w", err)
	}
	if st, err := os.Stat(target); err != nil {
		return "", nil, fmt.Errorf("secrets: inspect target: %w", err)
	} else if !st.IsDir() {
		return "", nil, errors.New("secrets: target must be a directory")
	}

	rootOutput, err := exec.CommandContext(ctx, "git", "-C", target, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", nil, errors.New("secrets: target must be inside a Git worktree")
	}
	root := filepath.Clean(strings.TrimSpace(string(rootOutput)))
	targetRel, err := filepath.Rel(root, target)
	if err != nil || outside(targetRel) {
		return "", nil, errors.New("secrets: target is outside its Git worktree")
	}

	pathspec := "."
	if targetRel != "." {
		pathspec = filepath.ToSlash(targetRel)
	}
	listOutput, err := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "-z",
		"--cached", "--others", "--exclude-standard", "--", pathspec).Output()
	if err != nil {
		return "", nil, fmt.Errorf("secrets: list Git-visible files: %w", err)
	}

	gitDirOutput, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--absolute-git-dir").Output()
	if err != nil {
		return "", nil, fmt.Errorf("secrets: resolve Git directory: %w", err)
	}
	gitDir := filepath.Clean(strings.TrimSpace(string(gitDirOutput)))
	scanRoot, err := os.MkdirTemp(gitDir, "supplychain-gitleaks-")
	if err != nil {
		return "", nil, fmt.Errorf("secrets: create scan view: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(scanRoot) }

	seen := make(map[string]struct{})
	for _, raw := range bytes.Split(listOutput, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		repoRel := filepath.Clean(filepath.FromSlash(string(raw)))
		if filepath.IsAbs(repoRel) || outside(repoRel) {
			cleanup()
			return "", nil, fmt.Errorf("secrets: unsafe Git path %q", string(raw))
		}
		source := filepath.Join(root, repoRel)
		scanRel, err := filepath.Rel(target, source)
		if err != nil || outside(scanRel) {
			cleanup()
			return "", nil, fmt.Errorf("secrets: Git returned path outside target: %q", string(raw))
		}
		if _, ok := seen[scanRel]; ok {
			continue
		}
		seen[scanRel] = struct{}{}
		if scanRel == ".gitleaks.toml" || scanRel == ".gitleaksignore" || scanRel == explicitConfigRel {
			continue
		}
		info, err := os.Lstat(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			cleanup()
			return "", nil, fmt.Errorf("secrets: inspect %q: %w", repoRel, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		destination := filepath.Join(scanRoot, scanRel)
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("secrets: stage directory for %q: %w", repoRel, err)
		}
		if err := os.Link(source, destination); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("secrets: stage %q without copying: %w", repoRel, err)
		}
	}
	return scanRoot, cleanup, nil
}

// resolveConfig accepts only an explicitly selected, tracked, regular file
// inside target. The default remains immune to repository-owned Gitleaks
// configuration, and .gitleaksignore is never honored.
func resolveConfig(ctx context.Context, target, config string) (string, string, error) {
	if config == "" {
		return "", "", nil
	}
	target, err := filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("secrets: resolve target: %w", err)
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", "", fmt.Errorf("secrets: resolve target links: %w", err)
	}
	candidate := config
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(target, candidate)
	}
	candidate = filepath.Clean(candidate)
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", "", fmt.Errorf("secrets: inspect Gitleaks config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", errors.New("secrets: Gitleaks config must be a regular file, not a symlink")
	}
	realCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", "", fmt.Errorf("secrets: resolve Gitleaks config links: %w", err)
	}
	realRel, err := filepath.Rel(realTarget, realCandidate)
	if err != nil || outside(realRel) {
		return "", "", errors.New("secrets: Gitleaks config must be inside the scan target")
	}
	configRel, err := filepath.Rel(target, candidate)
	if err != nil || outside(configRel) {
		return "", "", errors.New("secrets: Gitleaks config must be inside the scan target")
	}

	rootOutput, err := exec.CommandContext(ctx, "git", "-C", target, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", "", errors.New("secrets: target must be inside a Git worktree")
	}
	root := filepath.Clean(strings.TrimSpace(string(rootOutput)))
	repoRel, err := filepath.Rel(root, candidate)
	if err != nil || outside(repoRel) {
		return "", "", errors.New("secrets: Gitleaks config must be inside the Git worktree")
	}
	tracked := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "--error-unmatch", "--", repoRel)
	tracked.Stdout = nil
	tracked.Stderr = nil
	if err := tracked.Run(); err != nil {
		return "", "", errors.New("secrets: Gitleaks config must be tracked by Git")
	}
	return realCandidate, filepath.Clean(configRel), nil
}

func outside(path string) bool {
	return path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func withoutGitleaksConfig(environment []string) []string {
	clean := make([]string, 0, len(environment))
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GITLEAKS_CONFIG=") || strings.HasPrefix(entry, "GITLEAKS_CONFIG_TOML=") {
			continue
		}
		clean = append(clean, entry)
	}
	return clean
}

func locate(binDir string) (string, error) {
	if binDir != "" {
		candidate := filepath.Join(binDir, "gitleaks")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	path, err := exec.LookPath("gitleaks")
	if err != nil {
		return "", errors.New("secrets: gitleaks is required but unavailable")
	}
	return path, nil
}
