// Package policy loads and applies a repository-tracked source advisory policy.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/osv"
)

const (
	DefaultPath = ".supplychain/source-policy.json"
	maxSize     = 64 * 1024
)

type Identity struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256"`
}

type AdvisoryPolicy struct {
	MinimumSeverity string `json:"minimum_severity"`
	OnlyFixed       bool   `json:"only_fixed"`
}

type Exception struct {
	Kind        string `json:"kind"`
	AdvisoryID  string `json:"advisory_id,omitempty"`
	Package     string `json:"package"`
	DriftReason string `json:"drift_reason,omitempty"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	Expires     string `json:"expires"`
}

type Document struct {
	SchemaVersion int            `json:"schema_version"`
	Advisories    AdvisoryPolicy `json:"advisories"`
	Exceptions    []Exception    `json:"exceptions"`
	// Lockfiles names lockfiles the OSV advisory check must read although
	// their names are not the standard ones, e.g. image lockfiles such as
	// "deployments/docker/*.Cargo.lock". Each entry is a target-relative
	// pattern (path.Match syntax per segment) whose file name ends in
	// ".<format>" or is "<format>", for a format in LockfileFormats.
	Lockfiles []string `json:"lockfiles,omitempty"`
}

// LockfileFormats are the lockfile formats a policy may name, by the file name
// osv-scanner parses them as.
var LockfileFormats = []string{
	"Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
	"go.mod", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
	"Gemfile.lock", "composer.lock", "pom.xml", "gradle.lockfile",
}

// lockfileFormat returns the format a lockfile name declares, or "".
func lockfileFormat(name string) string {
	for _, format := range LockfileFormats {
		if name == format || strings.HasSuffix(name, "."+format) {
			return format
		}
	}
	return ""
}

type Loaded struct {
	Document Document
	Identity Identity
}

type Suppressed struct {
	Kind        string `json:"kind"`
	Package     string `json:"package"`
	Version     string `json:"version,omitempty"`
	AdvisoryID  string `json:"advisory_id,omitempty"`
	DriftReason string `json:"drift_reason,omitempty"`
	SourcePath  string `json:"source_path,omitempty"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner,omitempty"`
	Expires     string `json:"expires,omitempty"`
}

func Builtin() Loaded {
	body := []byte(`{"schema_version":1,"advisories":{"minimum_severity":"any","only_fixed":false},"exceptions":[]}`)
	sum := sha256.Sum256(body)
	return Loaded{
		Document: Document{
			SchemaVersion: 1,
			Advisories: AdvisoryPolicy{
				MinimumSeverity: "any",
			},
		},
		Identity: Identity{
			Name:   "builtin-all-advisories",
			SHA256: hex.EncodeToString(sum[:]),
		},
	}
}

// Load returns the built-in policy when no policy file exists. A present policy
// must be a small, regular, non-symlinked Git-tracked file contained by target.
func Load(target, requested string, now time.Time) (Loaded, error) {
	if requested == "" {
		requested = DefaultPath
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return Loaded{}, err
	}
	policyPath := requested
	if !filepath.IsAbs(policyPath) {
		policyPath = filepath.Join(targetAbs, policyPath)
	}
	policyPath = filepath.Clean(policyPath)
	relTarget, err := filepath.Rel(targetAbs, policyPath)
	if err != nil || relTarget == ".." || strings.HasPrefix(relTarget, ".."+string(os.PathSeparator)) {
		return Loaded{}, errors.New("source policy must be contained by the scan target")
	}
	info, err := os.Lstat(policyPath)
	if errors.Is(err, os.ErrNotExist) && requested == DefaultPath {
		return Builtin(), nil
	}
	if err != nil {
		return Loaded{}, fmt.Errorf("source policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Loaded{}, errors.New("source policy must be a regular, non-symlinked file")
	}
	if info.Size() > maxSize {
		return Loaded{}, fmt.Errorf("source policy exceeds %d bytes", maxSize)
	}
	if err := requireTracked(targetAbs, policyPath, "source policy"); err != nil {
		return Loaded{}, err
	}
	body, err := os.ReadFile(policyPath)
	if err != nil {
		return Loaded{}, err
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Loaded{}, fmt.Errorf("source policy is malformed: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Loaded{}, err
	}
	if err := validate(document, now); err != nil {
		return Loaded{}, err
	}
	sum := sha256.Sum256(body)
	return Loaded{
		Document: document,
		Identity: Identity{
			Name:   "repository-source-policy",
			Path:   filepath.ToSlash(relTarget),
			SHA256: hex.EncodeToString(sum[:]),
		},
	}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("source policy contains multiple JSON values")
		}
		return fmt.Errorf("source policy has trailing data: %w", err)
	}
	return nil
}

func requireTracked(target, file, noun string) error {
	rootOutput, err := exec.Command("git", "-C", target, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return fmt.Errorf("%s requires a Git worktree", noun)
	}
	root := strings.TrimSpace(string(rootOutput))
	rel, err := filepath.Rel(root, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%s is outside the Git worktree", noun)
	}
	if err := exec.Command(
		"git", "-C", root, "ls-files", "--error-unmatch", "--", filepath.ToSlash(rel),
	).Run(); err != nil {
		return fmt.Errorf("%s must be tracked by Git", noun)
	}
	return nil
}

func validate(document Document, now time.Time) error {
	if document.SchemaVersion != 1 {
		return fmt.Errorf("source policy: unsupported schema_version %d", document.SchemaVersion)
	}
	if _, ok := severityRank(document.Advisories.MinimumSeverity); !ok {
		return fmt.Errorf(
			"source policy: invalid minimum_severity %q",
			document.Advisories.MinimumSeverity,
		)
	}
	if err := validateLockfiles(document.Lockfiles); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	today := dateOnly(now)
	for i, exception := range document.Exceptions {
		prefix := fmt.Sprintf("source policy exception %d", i)
		if exception.Kind != "osv" && exception.Kind != "drift" {
			return fmt.Errorf("%s: kind must be osv or drift", prefix)
		}
		if exception.Package == "" || exception.Reason == "" ||
			exception.Owner == "" || exception.Expires == "" {
			return fmt.Errorf("%s: package, reason, owner, and expires are required", prefix)
		}
		expiry, err := time.Parse("2006-01-02", exception.Expires)
		if err != nil {
			return fmt.Errorf("%s: expires must be YYYY-MM-DD", prefix)
		}
		if expiry.Before(today) {
			return fmt.Errorf("%s: expired on %s", prefix, exception.Expires)
		}
		switch exception.Kind {
		case "osv":
			if exception.AdvisoryID == "" || exception.DriftReason != "" {
				return fmt.Errorf("%s: advisory_id is required only for osv", prefix)
			}
		case "drift":
			if exception.DriftReason == "" || exception.AdvisoryID != "" {
				return fmt.Errorf("%s: drift_reason is required only for drift", prefix)
			}
		}
		key := strings.Join([]string{
			exception.Kind,
			strings.ToLower(exception.Package),
			strings.ToUpper(exception.AdvisoryID),
			exception.DriftReason,
		}, "\x00")
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%s: duplicate selector", prefix)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateLockfiles(patterns []string) error {
	seen := make(map[string]struct{}, len(patterns))
	for i, pattern := range patterns {
		prefix := fmt.Sprintf("source policy lockfile %d", i)
		clean := path.Clean(pattern)
		switch {
		case pattern == "" || strings.ContainsRune(pattern, '\\'):
			return fmt.Errorf("%s: must be a non-empty forward-slash path", prefix)
		case path.IsAbs(pattern) || clean != pattern || clean == ".." || strings.HasPrefix(clean, "../"):
			return fmt.Errorf("%s: must be a clean path inside the target", prefix)
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("%s: invalid pattern: %w", prefix, err)
		}
		if lockfileFormat(path.Base(pattern)) == "" {
			return fmt.Errorf("%s: file name must end in .<format> for one of %s",
				prefix, strings.Join(LockfileFormats, ", "))
		}
		if _, duplicate := seen[pattern]; duplicate {
			return fmt.Errorf("%s: duplicate pattern", prefix)
		}
		seen[pattern] = struct{}{}
	}
	return nil
}

// ResolveLockfiles expands the policy's lockfile patterns inside target. Every
// pattern must match at least one regular, non-symlinked file that Git tracks;
// otherwise the named coverage would silently shrink, so it is an error.
func (loaded Loaded) ResolveLockfiles(target string) ([]osv.Lockfile, error) {
	if len(loaded.Document.Lockfiles) == 0 {
		return nil, nil
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	var lockfiles []osv.Lockfile
	for _, pattern := range loaded.Document.Lockfiles {
		matches, err := filepath.Glob(filepath.Join(targetAbs, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, fmt.Errorf("source policy lockfile %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("source policy lockfile %q matches no file", pattern)
		}
		sort.Strings(matches)
		for _, match := range matches {
			rel, err := filepath.Rel(targetAbs, match)
			if err != nil {
				return nil, err
			}
			noun := "source policy lockfile " + filepath.ToSlash(rel)
			info, err := os.Lstat(match)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", noun, err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s must be a regular, non-symlinked file", noun)
			}
			if err := requireTracked(targetAbs, match, noun); err != nil {
				return nil, err
			}
			lockfiles = append(lockfiles, osv.Lockfile{
				Format: lockfileFormat(filepath.Base(match)),
				Path:   match,
			})
		}
	}
	return lockfiles, nil
}

func dateOnly(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// Apply filters advisory/drift failures and returns every suppressed finding.
// IOC and malware findings are intentionally not accepted by this API.
func (loaded Loaded) Apply(
	osvHits []osv.PackageVuln,
	driftHits []drift.Hit,
) ([]osv.PackageVuln, []drift.Hit, []Suppressed) {
	filteredOSV, suppressed := loaded.applyOSV(osvHits)
	filteredDrift, driftSuppressed := loaded.applyDrift(driftHits)
	suppressed = append(suppressed, driftSuppressed...)
	sort.Slice(suppressed, func(i, j int) bool {
		if suppressed[i].Kind != suppressed[j].Kind {
			return suppressed[i].Kind < suppressed[j].Kind
		}
		if suppressed[i].Package != suppressed[j].Package {
			return suppressed[i].Package < suppressed[j].Package
		}
		if suppressed[i].AdvisoryID != suppressed[j].AdvisoryID {
			return suppressed[i].AdvisoryID < suppressed[j].AdvisoryID
		}
		return suppressed[i].DriftReason < suppressed[j].DriftReason
	})
	return filteredOSV, filteredDrift, suppressed
}

func (loaded Loaded) applyOSV(hits []osv.PackageVuln) ([]osv.PackageVuln, []Suppressed) {
	var filtered []osv.PackageVuln
	var suppressed []Suppressed
	minimum, _ := severityRank(loaded.Document.Advisories.MinimumSeverity)
	for _, hit := range hits {
		advisories := hit.Advisories
		if len(advisories) == 0 {
			for _, id := range hit.IDs {
				advisories = append(advisories, osv.Advisory{ID: id, Severity: "unknown"})
			}
		}
		kept := make([]osv.Advisory, 0, len(advisories))
		for _, advisory := range advisories {
			if exception, ok := loaded.osvException(hit.Name, advisory.ID); ok {
				suppressed = append(suppressed, suppressionForOSV(
					hit, advisory, exception.Reason, exception.Owner, exception.Expires,
				))
				continue
			}
			rank, known := severityRank(advisory.Severity)
			if minimum > 0 && known && rank < minimum {
				suppressed = append(suppressed, suppressionForOSV(
					hit, advisory,
					fmt.Sprintf("below minimum severity %s", loaded.Document.Advisories.MinimumSeverity),
					"", "",
				))
				continue
			}
			if loaded.Document.Advisories.OnlyFixed && len(advisory.FixedVersions) == 0 {
				suppressed = append(suppressed, suppressionForOSV(
					hit, advisory, "no known fixed version", "", "",
				))
				continue
			}
			kept = append(kept, advisory)
		}
		if len(kept) == 0 {
			continue
		}
		hit.Advisories = kept
		hit.IDs = make([]string, 0, len(kept))
		for _, advisory := range kept {
			hit.IDs = append(hit.IDs, advisory.ID)
		}
		filtered = append(filtered, hit)
	}
	return filtered, suppressed
}

func suppressionForOSV(
	hit osv.PackageVuln,
	advisory osv.Advisory,
	reason, owner, expires string,
) Suppressed {
	return Suppressed{
		Kind:       "osv",
		Package:    hit.Name,
		Version:    hit.Version,
		AdvisoryID: advisory.ID,
		SourcePath: hit.SourcePath,
		Reason:     reason,
		Owner:      owner,
		Expires:    expires,
	}
}

func (loaded Loaded) applyDrift(hits []drift.Hit) ([]drift.Hit, []Suppressed) {
	var filtered []drift.Hit
	var suppressed []Suppressed
	for _, hit := range hits {
		exception, ok := loaded.driftException(hit.Name, hit.Reason)
		if !ok {
			filtered = append(filtered, hit)
			continue
		}
		suppressed = append(suppressed, Suppressed{
			Kind:        "drift",
			Package:     hit.Name,
			DriftReason: hit.Reason,
			SourcePath:  hit.ManifestFile,
			Reason:      exception.Reason,
			Owner:       exception.Owner,
			Expires:     exception.Expires,
		})
	}
	return filtered, suppressed
}

func (loaded Loaded) osvException(packageName, advisoryID string) (Exception, bool) {
	for _, exception := range loaded.Document.Exceptions {
		if exception.Kind == "osv" &&
			strings.EqualFold(exception.Package, packageName) &&
			strings.EqualFold(exception.AdvisoryID, advisoryID) {
			return exception, true
		}
	}
	return Exception{}, false
}

func (loaded Loaded) driftException(packageName, reason string) (Exception, bool) {
	for _, exception := range loaded.Document.Exceptions {
		if exception.Kind == "drift" &&
			strings.EqualFold(exception.Package, packageName) &&
			exception.DriftReason == reason {
			return exception, true
		}
	}
	return Exception{}, false
}

func severityRank(value string) (int, bool) {
	switch strings.ToLower(value) {
	case "any", "":
		return 0, true
	case "low":
		return 1, true
	case "moderate", "medium":
		return 2, true
	case "high":
		return 3, true
	case "critical":
		return 4, true
	case "unknown":
		return 0, false
	default:
		return 0, false
	}
}
