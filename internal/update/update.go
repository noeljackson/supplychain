// Package update pulls fresh IOC data from the upstream repo. The binary
// itself is NOT auto-updated here — that's intentional. Compiled binaries
// should move slowly and explicitly; data files move fast.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var IOCFiles = []string{
	"persistence-paths.txt",
	"payload-filenames.txt",
	"packages.txt",
	"c2-domains.txt",
	"dead-drop-signatures.txt",
	"blocked-package-names.txt",
}

const (
	envURL        = "SUPPLYCHAIN_IOC_URL"
	envPin        = "SUPPLYCHAIN_PIN"
	defaultURL    = "https://raw.githubusercontent.com/noeljackson/supplychain"
	defaultBranch = "main"
	throttleSecs  = 60
	httpTimeout   = 5 * time.Second
	manifestName  = "manifest.json"
	manifestV1    = 1
	maxIOCSize    = 8 * 1024 * 1024
)

type snapshotManifest struct {
	SchemaVersion  int                     `json:"schema_version"`
	GeneratedAt    string                  `json:"generated_at"`
	SourceRevision string                  `json:"source_revision"`
	Files          map[string]snapshotFile `json:"files"`
}

type snapshotFile struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SnapshotIdentity is the stable machine-report identity of the active IOC set.
type SnapshotIdentity struct {
	Source         string `json:"source"`
	SchemaVersion  int    `json:"schema_version"`
	GeneratedAt    string `json:"generated_at"`
	SourceRevision string `json:"source_revision"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// ReadSnapshotIdentity validates and identifies the active or embedded manifest.
func ReadSnapshotIdentity(dataDir string, defaults fs.FS) (SnapshotIdentity, error) {
	source := "embedded"
	var body []byte
	activeDir := filepath.Join(dataDir, "iocs")
	if info, err := os.Stat(activeDir); err == nil && info.IsDir() {
		source = "updated"
		body, err = os.ReadFile(filepath.Join(activeDir, manifestName))
		if err != nil {
			return SnapshotIdentity{}, fmt.Errorf("read active IOC manifest: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return SnapshotIdentity{}, fmt.Errorf("inspect active IOC snapshot: %w", err)
	} else {
		source = "embedded"
		body, err = fs.ReadFile(defaults, "iocs/"+manifestName)
		if err != nil {
			return SnapshotIdentity{}, fmt.Errorf("read embedded IOC manifest: %w", err)
		}
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return SnapshotIdentity{}, fmt.Errorf("parse IOC manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return SnapshotIdentity{}, err
	}
	sum := sha256.Sum256(body)
	return SnapshotIdentity{
		Source:         source,
		SchemaVersion:  manifest.SchemaVersion,
		GeneratedAt:    manifest.GeneratedAt,
		SourceRevision: manifest.SourceRevision,
		ManifestSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func baseURL() string {
	if v := os.Getenv(envURL); v != "" {
		return v
	}
	pin := os.Getenv(envPin)
	if pin == "" {
		pin = defaultBranch
	}
	return defaultURL + "/" + pin + "/iocs"
}

func throttleFile(dataDir string) string { return filepath.Join(dataDir, ".ioc_last_update") }

// IOCsThrottled refreshes the IOC files unless we did so in the last minute.
func IOCsThrottled(dataDir string) error {
	if last, ok := readUnix(throttleFile(dataDir)); ok {
		if time.Since(time.Unix(last, 0)) < throttleSecs*time.Second {
			return nil
		}
	}
	return IOCsForce(dataDir)
}

// IOCsForce fetches all IOC files unconditionally.
func IOCsForce(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dataDir, ".iocs-stage-")
	if err != nil {
		return fmt.Errorf("create IOC staging directory: %w", err)
	}
	defer os.RemoveAll(stage)

	base := strings.TrimSuffix(baseURL(), "/")
	manifestBytes, err := fetchBytes(base + "/" + manifestName)
	if err != nil {
		return fmt.Errorf("%s: %w", manifestName, err)
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("%s: invalid JSON: %w", manifestName, err)
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	for _, name := range IOCFiles {
		body, err := fetchBytes(base + "/" + name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := validateSnapshotFile(name, body, manifest.Files[name]); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stage, name), body, 0o644); err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, manifestName), manifestBytes, 0o644); err != nil {
		return fmt.Errorf("stage %s: %w", manifestName, err)
	}
	if err := activateSnapshot(dataDir, stage); err != nil {
		return err
	}
	return writeUnix(throttleFile(dataDir), time.Now().Unix())
}

// IOCAgeHuman returns a short human-readable string for the last successful update.
func IOCAgeHuman(dataDir string) string {
	last, ok := readUnix(throttleFile(dataDir))
	if !ok {
		return "never"
	}
	diff := time.Since(time.Unix(last, 0))
	switch {
	case diff < time.Minute:
		return fmt.Sprintf("%ds", int(diff.Seconds()))
	case diff < time.Hour:
		return fmt.Sprintf("%dm", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%dh", int(diff.Hours()))
	default:
		return fmt.Sprintf("%dd", int(diff.Hours()/24))
	}
}

func fetchBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIOCSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxIOCSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", url, maxIOCSize)
	}
	return body, nil
}

func validateManifest(manifest snapshotManifest) error {
	if manifest.SchemaVersion != manifestV1 {
		return fmt.Errorf("IOC manifest: unsupported schema version %d", manifest.SchemaVersion)
	}
	if manifest.GeneratedAt == "" || manifest.SourceRevision == "" {
		return errors.New("IOC manifest: generated_at and source_revision are required")
	}
	for _, name := range IOCFiles {
		entry, ok := manifest.Files[name]
		if !ok {
			return fmt.Errorf("IOC manifest: missing %s", name)
		}
		if len(entry.SHA256) != sha256.Size*2 {
			return fmt.Errorf("IOC manifest: invalid SHA-256 for %s", name)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return fmt.Errorf("IOC manifest: invalid SHA-256 for %s: %w", name, err)
		}
		if entry.Size <= 0 || entry.Size > maxIOCSize {
			return fmt.Errorf("IOC manifest: invalid size for %s", name)
		}
	}
	return nil
}

func validateSnapshotFile(name string, body []byte, expected snapshotFile) error {
	if int64(len(body)) != expected.Size {
		return fmt.Errorf(
			"IOC snapshot %s: size mismatch: got %d, want %d",
			name, len(body), expected.Size,
		)
	}
	actual := sha256.Sum256(body)
	if hex.EncodeToString(actual[:]) != strings.ToLower(expected.SHA256) {
		return fmt.Errorf("IOC snapshot %s: SHA-256 mismatch", name)
	}
	hasEntry := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			hasEntry = true
			break
		}
	}
	if !hasEntry {
		return fmt.Errorf("IOC snapshot %s: contains no entries", name)
	}
	return nil
}

func activateSnapshot(dataDir, stage string) error {
	active := filepath.Join(dataDir, "iocs")
	previous := filepath.Join(dataDir, "iocs.previous")
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("remove stale IOC backup: %w", err)
	}
	hadActive := false
	if _, err := os.Stat(active); err == nil {
		if err := os.Rename(active, previous); err != nil {
			return fmt.Errorf("preserve current IOC snapshot: %w", err)
		}
		hadActive = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current IOC snapshot: %w", err)
	}
	if err := os.Rename(stage, active); err != nil {
		if hadActive {
			_ = os.Rename(previous, active)
		}
		return fmt.Errorf("activate IOC snapshot: %w", err)
	}
	return nil
}

func readUnix(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(string(trim(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func writeUnix(path string, t int64) error {
	return os.WriteFile(path, []byte(strconv.FormatInt(t, 10)), 0o644)
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}
