// Package artifact generates an SBOM for an OCI image and scans that exact
// inventory for known vulnerabilities.
package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const scanTimeout = 15 * time.Minute

// Options controls an image scan.
type Options struct {
	Image      string
	SBOMPath   string
	FailOn     string
	OnlyFixed  bool
	VEXPath    string
	PolicyRoot string
	BinDir     string
}

// Run inventories Image with Syft, validates the resulting SPDX document,
// then asks Grype to scan that exact document.
func Run(opts Options) error {
	if strings.TrimSpace(opts.Image) == "" {
		return errors.New("artifact: image is required")
	}
	if strings.TrimSpace(opts.SBOMPath) == "" {
		return errors.New("artifact: SBOM path is required")
	}
	if !validSeverity(opts.FailOn) {
		return fmt.Errorf("artifact: invalid severity %q", opts.FailOn)
	}
	vexPath, err := resolveReviewedFile(opts.PolicyRoot, opts.VEXPath, "VEX")
	if err != nil {
		return err
	}

	syft, err := locate("syft", opts.BinDir)
	if err != nil {
		return err
	}
	grype, err := locate("grype", opts.BinDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opts.SBOMPath), 0o755); err != nil {
		return fmt.Errorf("artifact: create SBOM directory: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	syftCmd := exec.CommandContext(ctx, syft, opts.Image, "--output", "spdx-json="+opts.SBOMPath)
	syftCmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false")
	if out, err := syftCmd.CombinedOutput(); err != nil {
		return commandError("syft", err, out)
	}
	if err := validateSBOM(opts.SBOMPath); err != nil {
		return err
	}

	// Always select an isolated, empty config. Without an explicit config,
	// Grype discovers repository-owned .grype.yaml files, which could silently
	// weaken the caller's severity gate or add unreviewed ignore rules.
	grypeConfig, err := os.CreateTemp("", "supplychain-grype-*.yaml")
	if err != nil {
		return fmt.Errorf("artifact: create isolated Grype config: %w", err)
	}
	grypeConfigPath := grypeConfig.Name()
	defer os.Remove(grypeConfigPath)
	if _, err := grypeConfig.WriteString("ignore: []\n"); err != nil {
		_ = grypeConfig.Close()
		return fmt.Errorf("artifact: write isolated Grype config: %w", err)
	}
	if err := grypeConfig.Close(); err != nil {
		return fmt.Errorf("artifact: close isolated Grype config: %w", err)
	}

	args := []string{"--config", grypeConfigPath, "sbom:" + opts.SBOMPath, "--fail-on", opts.FailOn}
	if opts.OnlyFixed {
		args = append(args, "--only-fixed")
	}
	if vexPath != "" {
		args = append(args, "--vex", vexPath)
	}
	grypeCmd := exec.CommandContext(ctx, grype, args...)
	grypeCmd.Env = append(os.Environ(),
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_AUTO_UPDATE=true",
		"GRYPE_DB_VALIDATE_BY_HASH_ON_START=true",
		"GRYPE_DB_VALIDATE_AGE=true",
		"GRYPE_DB_MAX_ALLOWED_BUILT_AGE=120h",
		"GRYPE_DB_REQUIRE_UPDATE_CHECK=true",
	)
	grypeCmd.Stdout = os.Stdout
	grypeCmd.Stderr = os.Stderr
	if err := grypeCmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("artifact: image scan timed out")
		}
		return fmt.Errorf("artifact: grype policy failed: %w", err)
	}
	return nil
}

// resolveReviewedFile accepts only an explicitly selected, tracked, regular
// policy file inside policyRoot. This prevents unreviewed files, symlinks, and
// paths outside the checked-out repository from altering scan results.
func resolveReviewedFile(policyRoot, selected, kind string) (string, error) {
	if selected == "" {
		return "", nil
	}
	if policyRoot == "" {
		policyRoot = "."
	}
	root, err := filepath.Abs(policyRoot)
	if err != nil {
		return "", fmt.Errorf("artifact: resolve policy root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("artifact: resolve policy root links: %w", err)
	}
	candidate := selected
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", fmt.Errorf("artifact: inspect %s policy: %w", kind, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("artifact: %s policy must be a regular file, not a symlink", kind)
	}
	if info.Size() > 1024*1024 {
		return "", fmt.Errorf("artifact: %s policy exceeds 1 MiB", kind)
	}
	realCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("artifact: resolve %s policy links: %w", kind, err)
	}
	if rel, err := filepath.Rel(realRoot, realCandidate); err != nil || outside(rel) {
		return "", fmt.Errorf("artifact: %s policy must be inside the policy root", kind)
	}
	gitRootOutput, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", errors.New("artifact: policy root must be inside a Git worktree")
	}
	gitRoot := filepath.Clean(strings.TrimSpace(string(gitRootOutput)))
	repoRel, err := filepath.Rel(gitRoot, candidate)
	if err != nil || outside(repoRel) {
		return "", fmt.Errorf("artifact: %s policy must be inside the Git worktree", kind)
	}
	tracked := exec.Command("git", "-C", gitRoot, "ls-files", "--error-unmatch", "--", repoRel)
	tracked.Stdout = nil
	tracked.Stderr = nil
	if err := tracked.Run(); err != nil {
		return "", fmt.Errorf("artifact: %s policy must be tracked by Git", kind)
	}
	return realCandidate, nil
}

func outside(path string) bool {
	return path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func validSeverity(value string) bool {
	switch strings.ToLower(value) {
	case "negligible", "low", "medium", "high", "critical":
		return value == strings.ToLower(value)
	default:
		return false
	}
}

func locate(name, binDir string) (string, error) {
	if binDir != "" {
		candidate := filepath.Join(binDir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("artifact: %s is required but unavailable", name)
	}
	return path, nil
}

func validateSBOM(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("artifact: open generated SBOM: %w", err)
	}
	defer f.Close()
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		SPDXID      string `json:"SPDXID"`
	}
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return fmt.Errorf("artifact: invalid generated SBOM: %w", err)
	}
	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") || doc.SPDXID != "SPDXRef-DOCUMENT" {
		return errors.New("artifact: generated SBOM is not an SPDX document")
	}
	return nil
}

func commandError(name string, err error, output []byte) error {
	message := strings.TrimSpace(string(output))
	if len(message) > 2048 {
		message = message[:2048] + "..."
	}
	if message == "" {
		return fmt.Errorf("artifact: %s failed: %w", name, err)
	}
	return fmt.Errorf("artifact: %s failed: %w: %s", name, err, message)
}
