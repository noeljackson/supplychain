// Package bunverify validates every registry package pinned by a Bun lockfile.
// It never executes package code and fails closed when registry security
// metadata is absent or inconsistent.
package bunverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/noeljackson/supplychain/internal/registry"
)

const BaselineVersion = 1
const maxBaselineSize = 1024 * 1024

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

type BaselinePackage struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Integrity      string   `json:"integrity"`
	Published      string   `json:"published"`
	Maintainers    []string `json:"maintainers,omitempty"`
	SignatureKeyID string   `json:"signature_key_id"`
	Provenance     bool     `json:"provenance"`
	Attestations   string   `json:"attestations_url,omitempty"`
}

type Baseline struct {
	Version  int                        `json:"version"`
	Packages map[string]BaselinePackage `json:"packages"`
}

type Issue struct {
	Code    string `json:"code"`
	Package string `json:"package,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	Lockfile string                     `json:"lockfile"`
	Checked  int                        `json:"checked"`
	Issues   []Issue                    `json:"issues"`
	Baseline map[string]BaselinePackage `json:"baseline"`
}

type Options struct {
	Lockfile       string
	MinimumAgeDays int
	BaselinePath   string
	Registry       *registry.Client
	Now            time.Time
}

func Verify(opts Options) (Result, error) {
	result := Result{Lockfile: opts.Lockfile, Baseline: map[string]BaselinePackage{}}
	if opts.Registry == nil {
		return result, errors.New("bunverify: registry client is required")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	packages, parseIssues, err := ParseLockfile(opts.Lockfile)
	if err != nil {
		return result, err
	}
	result.Issues = append(result.Issues, parseIssues...)
	result.Checked = len(packages)

	keys, err := opts.Registry.SigningKeys()
	if err != nil {
		return result, fmt.Errorf("fetch npm signing keys: %w", err)
	}
	keyring := make(map[string]*ecdsa.PublicKey, len(keys))
	for _, key := range keys {
		pub, err := parseSigningKey(key.Key)
		if err == nil {
			keyring[key.KeyID] = pub
		}
	}

	var previous Baseline
	if opts.BaselinePath != "" {
		previous, err = ReadBaseline(opts.BaselinePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
	}

	cutoff := opts.Now.Add(-time.Duration(opts.MinimumAgeDays) * 24 * time.Hour)
	for _, locked := range packages {
		label := locked.Name + "@" + locked.Version
		packument, err := opts.Registry.Get(locked.Name)
		if err != nil {
			result.add("registry-error", label, err.Error())
			continue
		}
		meta, ok := packument.Versions[locked.Version]
		if !ok {
			result.add("version-missing", label, "version is not currently published by npm")
			continue
		}
		if locked.Integrity == "" || !strings.HasPrefix(locked.Integrity, "sha512-") {
			result.add("integrity-missing", label, "bun.lock must contain sha512 integrity")
		} else if meta.Dist.Integrity != locked.Integrity {
			result.add("integrity-mismatch", label, "bun.lock integrity differs from npm registry metadata")
		}

		published, hasTime := packument.Time[locked.Version]
		if !hasTime || published.IsZero() {
			result.add("publish-time-missing", label, "npm registry did not provide a publication timestamp")
		} else if opts.MinimumAgeDays > 0 && published.After(cutoff) {
			result.add("release-too-young", label, fmt.Sprintf("published %s; minimum age is %d days", published.UTC().Format(time.RFC3339), opts.MinimumAgeDays))
		}

		verifiedKey := ""
		for _, sig := range meta.Dist.Signatures {
			pub := keyring[sig.KeyID]
			if pub != nil && verifySignature(pub, sig.Sig, label+":"+meta.Dist.Integrity) {
				verifiedKey = sig.KeyID
				break
			}
		}
		if verifiedKey == "" {
			result.add("signature-invalid", label, "no valid npm registry signature")
		}

		maintainers := make([]string, 0, len(packument.Maintainers))
		for _, maintainer := range packument.Maintainers {
			maintainers = append(maintainers, strings.ToLower(maintainer.Name+" <"+maintainer.Email+">"))
		}
		sort.Strings(maintainers)
		provenance := meta.Dist.Attestations != nil && meta.Dist.Attestations.Provenance != nil
		attestationsURL := ""
		if meta.Dist.Attestations != nil {
			attestationsURL = meta.Dist.Attestations.URL
		}
		result.Baseline[label] = BaselinePackage{
			Name: locked.Name, Version: locked.Version, Integrity: locked.Integrity,
			Published: published.UTC().Format(time.RFC3339), Maintainers: maintainers,
			SignatureKeyID: verifiedKey, Provenance: provenance, Attestations: attestationsURL,
		}

		comparePrevious(&result, previous, result.Baseline[label])
	}
	sort.Slice(result.Issues, func(i, j int) bool {
		if result.Issues[i].Package == result.Issues[j].Package {
			return result.Issues[i].Code < result.Issues[j].Code
		}
		return result.Issues[i].Package < result.Issues[j].Package
	})
	return result, nil
}

func (r *Result) add(code, pkg, message string) {
	r.Issues = append(r.Issues, Issue{Code: code, Package: pkg, Message: message})
}

func comparePrevious(result *Result, previous Baseline, current BaselinePackage) {
	if len(previous.Packages) == 0 {
		return
	}
	key := current.Name + "@" + current.Version
	if old, ok := previous.Packages[key]; ok {
		if old.Integrity != current.Integrity {
			result.add("baseline-integrity-drift", key, "integrity changed for an already-baselined version")
		}
		if old.Provenance && !current.Provenance {
			result.add("provenance-downgrade", key, "reviewed version no longer advertises npm provenance")
		}
		if !sameStrings(old.Maintainers, current.Maintainers) {
			result.add("maintainer-drift", key, "npm maintainer set differs from the reviewed baseline")
		}
		return
	}
	for _, old := range previous.Packages {
		if old.Name != current.Name {
			continue
		}
		if old.Provenance && !current.Provenance {
			result.add("provenance-downgrade", key, "previous locked version advertised npm provenance but the replacement does not")
		}
		if !sameStrings(old.Maintainers, current.Maintainers) {
			result.add("maintainer-drift", key, "npm maintainer set differs from the reviewed baseline")
		}
		return
	}
	result.add("baseline-new-package", key, "package is not present in the reviewed baseline")
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseSigningKey(encoded string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("npm signing key is not ECDSA")
	}
	return pub, nil
}

func verifySignature(pub *ecdsa.PublicKey, encodedSig, message string) bool {
	sig, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(message))
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

func ParseLockfile(path string) ([]Package, []Issue, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return parseLockfile(raw, path)
}

func parseLockfile(raw []byte, path string) ([]Package, []Issue, error) {
	raw = stripTrailingCommas(raw)
	var doc struct {
		LockfileVersion int                        `json:"lockfileVersion"`
		Packages        map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.LockfileVersion != 1 {
		return nil, nil, fmt.Errorf(
			"parse %s: unsupported Bun lockfile version %d", path, doc.LockfileVersion,
		)
	}
	if doc.Packages == nil {
		return nil, nil, fmt.Errorf("parse %s: packages object is missing", path)
	}
	seen := map[string]struct{}{}
	var packages []Package
	var issues []Issue
	for key, encoded := range doc.Packages {
		var fields []json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			return nil, nil, fmt.Errorf("parse %s package %q: %w", path, key, err)
		}
		if len(fields) == 0 {
			return nil, nil, fmt.Errorf("parse %s package %q: entry is empty", path, key)
		}
		var descriptor string
		if err := json.Unmarshal(fields[0], &descriptor); err != nil {
			return nil, nil, fmt.Errorf("parse %s package %q descriptor: %w", path, key, err)
		}
		name, version, ok := splitDescriptor(descriptor)
		if !ok {
			return nil, nil, fmt.Errorf("parse %s package %q: invalid descriptor %q", path, key, descriptor)
		}
		if strings.HasPrefix(version, "workspace:") {
			continue
		}
		if len(fields) < 2 {
			return nil, nil, fmt.Errorf(
				"parse %s package %q: non-workspace entry has no source field",
				path, key,
			)
		}
		label := name + "@" + version
		var source string
		if len(fields) > 1 {
			if err := json.Unmarshal(fields[1], &source); err != nil {
				return nil, nil, fmt.Errorf("parse %s package %q source: %w", path, key, err)
			}
		}
		if source != "" {
			issues = append(issues, Issue{Code: "non-registry-source", Package: label, Message: "Bun lock entry resolves from " + source})
			continue
		}
		var integrity string
		if len(fields) > 3 {
			if err := json.Unmarshal(fields[3], &integrity); err != nil {
				return nil, nil, fmt.Errorf("parse %s package %q integrity: %w", path, key, err)
			}
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		packages = append(packages, Package{Name: name, Version: version, Integrity: integrity})
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Package == issues[j].Package {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Package < issues[j].Package
	})
	return packages, issues, nil
}

func splitDescriptor(value string) (string, string, bool) {
	index := strings.LastIndex(value, "@")
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func stripTrailingCommas(input []byte) []byte {
	output := make([]byte, 0, len(input))
	inString, escaped := false, false
	for index, char := range input {
		if inString {
			output = append(output, char)
			switch {
			case escaped:
				escaped = false
			case char == '\\':
				escaped = true
			case char == '"':
				inString = false
			}
			continue
		}
		if char == '"' {
			inString = true
			output = append(output, char)
			continue
		}
		if char == ',' {
			next := index + 1
			for next < len(input) && strings.ContainsRune(" \t\r\n", rune(input[next])) {
				next++
			}
			if next < len(input) && (input[next] == '}' || input[next] == ']') {
				continue
			}
		}
		output = append(output, char)
	}
	return output
}

func ReadBaseline(path string) (Baseline, error) {
	var baseline Baseline
	raw, err := os.ReadFile(path)
	if err != nil {
		return baseline, err
	}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return baseline, err
	}
	if baseline.Version != BaselineVersion {
		return baseline, fmt.Errorf("unsupported Bun baseline version %d", baseline.Version)
	}
	return baseline, nil
}

// ResolveReviewedBaseline accepts only a small, tracked, regular baseline
// contained by target. Missing paths are returned unchanged so
// --write-baseline can create a new review candidate.
func ResolveReviewedBaseline(target, path string) (string, error) {
	if path == "" {
		return "", nil
	}
	target, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(target, candidate)
	}
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(target, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("Bun baseline must be inside the verification target")
	}
	info, err := os.Lstat(candidate)
	if errors.Is(err, os.ErrNotExist) {
		return candidate, nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("Bun baseline must be a regular file, not a symlink")
	}
	if info.Size() > maxBaselineSize {
		return "", fmt.Errorf("Bun baseline exceeds %d bytes", maxBaselineSize)
	}
	rootOutput, err := exec.Command("git", "-C", target, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", errors.New("Bun baseline requires a Git worktree")
	}
	root := strings.TrimSpace(string(rootOutput))
	repoRelative, err := filepath.Rel(root, candidate)
	if err != nil || repoRelative == ".." ||
		strings.HasPrefix(repoRelative, ".."+string(os.PathSeparator)) {
		return "", errors.New("Bun baseline is outside the Git worktree")
	}
	if err := exec.Command(
		"git", "-C", root, "ls-files", "--error-unmatch", "--",
		filepath.ToSlash(repoRelative),
	).Run(); err != nil {
		return "", errors.New("Bun baseline must be tracked by Git")
	}
	return candidate, nil
}

func WriteBaseline(path string, packages map[string]BaselinePackage) error {
	baseline := Baseline{Version: BaselineVersion, Packages: packages}
	encoded, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644)
}
