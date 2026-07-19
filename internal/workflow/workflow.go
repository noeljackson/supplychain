// Package workflow runs a pinned GitHub Actions security audit through zizmor.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Run audits workflow and action definitions beneath target. Network-backed
// rules are disabled so no GitHub token is exposed to the external analyzer.
func Run(target, binDir string) error {
	if target == "" {
		return errors.New("workflow: target is required")
	}
	zizmor, err := locate(binDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, zizmor,
		"--offline",
		"--strict-collection",
		"--persona=regular",
		"--min-severity=medium",
		"--min-confidence=medium",
		"--format=github",
		target,
	)
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
