// Package npmsig wraps `npm audit signatures --json` to surface packages
// whose registry signatures fail verification (or are missing entirely).
// As of 2023+, npm publishes ECDSA signatures for tarballs; mismatches catch
// tampered or non-canonical artifacts that other layers (OSV, IOC lists) miss.
package npmsig

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

// Hit is one (name, version) whose registry signature failed verification or
// was absent.
type Hit struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Reason   string `json:"reason"`   // "invalid" | "missing"
	Resolved string `json:"resolved"` // tarball URL
}

var (
	ErrUnavailable   = errors.New("npm is unavailable")
	ErrNotApplicable = errors.New("package-lock.json not found")
	auditTimeout     = 120 * time.Second
)

// Run shells to `npm audit signatures --json` against target. ErrUnavailable
// and ErrNotApplicable let the orchestrator distinguish absent coverage from a
// completed clean check. On a successful run, exit codes 0 and 1 are both
// treated as success: npm uses 1 to indicate findings, not an operational error.
func Run(target string) ([]Hit, error) {
	if _, err := exec.LookPath("npm"); err != nil {
		return nil, ErrUnavailable
	}
	if _, err := os.Stat(filepath.Join(target, "package-lock.json")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotApplicable
		}
		return nil, fmt.Errorf("inspect package-lock.json: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npm", "audit", "signatures", "--json")
	cmd.Dir = target
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("npm audit signatures timed out")
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return nil, fmt.Errorf("npm audit signatures: %w", err)
		}
	}

	return parse(out)
}

// parse handles npm's audit signatures JSON. The shape varies slightly
// between npm versions; we tolerate both the v9+ shape (top-level
// invalid/missing arrays) and degenerate cases.
func parse(b []byte) ([]Hit, error) {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 {
		return nil, nil
	}

	var doc struct {
		Invalid []entry `json:"invalid"`
		Missing []entry `json:"missing"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse npm audit signatures JSON: %w", err)
	}
	var hits []Hit
	for _, e := range doc.Invalid {
		hits = append(hits, Hit{Name: e.Name, Version: e.Version, Reason: "invalid", Resolved: e.Resolved})
	}
	for _, e := range doc.Missing {
		hits = append(hits, Hit{Name: e.Name, Version: e.Version, Reason: "missing", Resolved: e.Resolved})
	}
	return hits, nil
}

type entry struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
}
