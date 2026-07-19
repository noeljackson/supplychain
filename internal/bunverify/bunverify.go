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
	"sort"
	"strings"
	"time"

	"github.com/noeljackson/supplychain/internal/registry"
)

const BaselineVersion = 1

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
	raw = stripTrailingCommas(raw)
	var doc struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]struct{}{}
	var packages []Package
	var issues []Issue
	for _, encoded := range doc.Packages {
		var fields []json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) == 0 {
			continue
		}
		var descriptor string
		if json.Unmarshal(fields[0], &descriptor) != nil {
			continue
		}
		name, version, ok := splitDescriptor(descriptor)
		if !ok || strings.HasPrefix(version, "workspace:") {
			continue
		}
		label := name + "@" + version
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		var source string
		if len(fields) > 1 {
			_ = json.Unmarshal(fields[1], &source)
		}
		if source != "" {
			issues = append(issues, Issue{Code: "non-registry-source", Package: label, Message: "Bun lock entry resolves from " + source})
			continue
		}
		var integrity string
		if len(fields) > 3 {
			_ = json.Unmarshal(fields[3], &integrity)
		}
		packages = append(packages, Package{Name: name, Version: version, Integrity: integrity})
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
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

func WriteBaseline(path string, packages map[string]BaselinePackage) error {
	baseline := Baseline{Version: BaselineVersion, Packages: packages}
	encoded, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644)
}
