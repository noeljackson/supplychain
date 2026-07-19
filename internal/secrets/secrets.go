// Package secrets runs redacted repository secret scanning through Gitleaks.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const scanTimeout = 10 * time.Minute

// Run scans target with Gitleaks. Findings are reported by Gitleaks and cause
// a non-zero exit.
func Run(target, binDir string) error {
	if target == "" {
		return errors.New("secrets: target is required")
	}
	gitleaks, err := locate(binDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitleaks,
		"dir",
		target,
		"--no-banner",
		"--no-color",
		"--redact",
		"--log-level", "warn",
		"--max-target-megabytes", "10",
		"--exit-code", "1",
	)
	cmd.Env = append(os.Environ(), "GITLEAKS_ENABLE_ANALYTICS=false")
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
