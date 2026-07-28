// Package trustedpolicy resolves policy files supplied by a trusted CI
// workflow rather than by the repository being scanned.
package trustedpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	SourcePolicyName = "source-policy.json"
	GitleaksName     = "gitleaks.toml"
	BunBaselineName  = "bun-baseline.json"
)

// Bundle contains the optional, fixed-name files in a trusted policy
// directory. Missing files are represented by empty paths.
type Bundle struct {
	SourcePolicy string
	Gitleaks     string
	BunBaseline  string
}

// Resolve accepts a real directory, not a symlink, and resolves only known
// direct-child policy files. Each present file must be regular and
// non-symlinked.
func Resolve(path string) (Bundle, error) {
	if path == "" {
		return Bundle{}, errors.New("trusted policy directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("trusted policy directory: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return Bundle{}, fmt.Errorf("trusted policy directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Bundle{}, errors.New("trusted policy directory must be a real directory, not a symlink")
	}

	sourcePolicy, err := resolveOptionalFile(absolute, SourcePolicyName)
	if err != nil {
		return Bundle{}, err
	}
	gitleaks, err := resolveOptionalFile(absolute, GitleaksName)
	if err != nil {
		return Bundle{}, err
	}
	bunBaseline, err := resolveOptionalFile(absolute, BunBaselineName)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		SourcePolicy: sourcePolicy,
		Gitleaks:     gitleaks,
		BunBaseline:  bunBaseline,
	}, nil
}

func resolveOptionalFile(directory, name string) (string, error) {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("trusted policy %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("trusted policy %s must be a regular, non-symlinked file", name)
	}
	return path, nil
}
