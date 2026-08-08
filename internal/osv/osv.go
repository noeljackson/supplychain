// Package osv shells out to the osv-scanner CLI when present. The plan is to
// migrate to a direct osv-scalibr library import later; the surface here is
// designed to be swap-friendly.
package osv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Locate returns (path, version, nil) if osv-scanner is on PATH or under binDir.
func Locate(binDir string) (string, string, error) {
	candidates := make([]string, 0, 2)
	if binDir != "" {
		candidates = append(candidates, filepath.Join(binDir, "osv-scanner"))
	}
	if p, err := exec.LookPath("osv-scanner"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			out, _ := exec.Command(c, "--version").CombinedOutput()
			ver := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			if ver == "" {
				ver = "unknown"
			}
			return c, ver, nil
		}
	}
	return "", "", errors.New("not found")
}

// Ensure installs osv-scanner into binDir if it's not already present.
func Ensure(binDir string) error {
	expected, ok := pinnedChecksums[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return fmt.Errorf("no pinned osv-scanner asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	candidate := filepath.Join(binDir, "osv-scanner")
	if actual, err := fileSHA256(candidate); err == nil && actual == expected {
		return nil
	}
	return install(binDir)
}

// Advisory preserves policy-relevant metadata emitted by osv-scanner.
type Advisory struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	FixedVersions []string `json:"fixed_versions"`
}

// PackageVuln is a single (package, version, advisories, source path) finding.
type PackageVuln struct {
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Ecosystem  string     `json:"ecosystem"`
	IDs        []string   `json:"ids"`
	Advisories []Advisory `json:"advisories"`
	SourcePath string     `json:"source_path"`
}

// ErrNoPackageSources means the scanner ran successfully enough to determine
// that the target contains no supported dependency manifests or lockfiles.
// This is not a coverage failure for a docs-only repository.
var ErrNoPackageSources = errors.New("no package sources found")

var scanTimeout = 120 * time.Second

// Scan runs osv-scanner against target and returns parsed findings.
// Returns (nil, nil) if osv-scanner is unavailable — that's an expected
// state, not an error.
func Scan(binDir, target string, offline bool) ([]PackageVuln, error) {
	path, _, err := Locate(binDir)
	if err != nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// osv-scanner v2 changed the CLI to `osv-scanner scan source`; older
	// versions accepted a bare path. Try the new form first, fall back.
	args := scanArgs(target, offline)
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("osv-scanner timed out")
		}
		if isNoPackageSources(err) {
			return nil, ErrNoPackageSources
		}
		// Exit code 1 means findings — that's expected; only re-run on usage error.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			// The legacy syntax has no reviewed equivalent for the v2 offline
			// controls. Failing closed prevents an option error from silently
			// turning a hermetic scan into an online one.
			if offline {
				return nil, fmt.Errorf("osv-scanner offline scan failed: %w", err)
			}
			cmd = exec.CommandContext(ctx, path, "--recursive", "--format", "json", target)
			out, err = cmd.Output()
			if err != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, errors.New("osv-scanner timed out")
				}
				if isNoPackageSources(err) {
					return nil, ErrNoPackageSources
				}
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					return nil, fmt.Errorf("osv-scanner failed: %w", err)
				}
			}
		}
	}
	return parse(out)
}

func scanArgs(target string, offline bool) []string {
	args := []string{"scan", "source", "--recursive", "--format", "json"}
	if offline {
		args = append(args, "--offline", "--offline-vulnerabilities", "--no-resolve")
	}
	return append(args, target)
}

func isNoPackageSources(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && strings.Contains(
		strings.ToLower(string(exitErr.Stderr)), "no package sources found",
	)
}

// parse extracts a flat list of (name, version, ids, src) from osv-scanner's
// JSON output. We deliberately keep this lossy — we just need a glanceable
// summary.
func parse(b []byte) ([]PackageVuln, error) {
	var doc struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID               string `json:"id"`
					DatabaseSpecific struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
					Affected []struct {
						Ranges []struct {
							Events []struct {
								Fixed string `json:"fixed"`
							} `json:"events"`
						} `json:"ranges"`
					} `json:"affected"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if len(b) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []PackageVuln
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			if len(p.Vulnerabilities) == 0 {
				continue
			}
			ids := make([]string, 0, len(p.Vulnerabilities))
			advisories := make([]Advisory, 0, len(p.Vulnerabilities))
			for _, v := range p.Vulnerabilities {
				ids = append(ids, v.ID)
				fixedSet := make(map[string]struct{})
				for _, affected := range v.Affected {
					for _, affectedRange := range affected.Ranges {
						for _, event := range affectedRange.Events {
							if event.Fixed != "" {
								fixedSet[event.Fixed] = struct{}{}
							}
						}
					}
				}
				fixed := make([]string, 0, len(fixedSet))
				for version := range fixedSet {
					fixed = append(fixed, version)
				}
				sort.Strings(fixed)
				severity := strings.ToLower(v.DatabaseSpecific.Severity)
				if severity == "" {
					severity = "unknown"
				}
				advisories = append(advisories, Advisory{
					ID:            v.ID,
					Severity:      severity,
					FixedVersions: fixed,
				})
			}
			sort.Strings(ids)
			sort.Slice(advisories, func(i, j int) bool {
				return advisories[i].ID < advisories[j].ID
			})
			out = append(out, PackageVuln{
				Name:       p.Package.Name,
				Version:    p.Package.Version,
				Ecosystem:  p.Package.Ecosystem,
				IDs:        ids,
				Advisories: advisories,
				SourcePath: r.Source.Path,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourcePath != out[j].SourcePath {
			return out[i].SourcePath < out[j].SourcePath
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

const pinnedVersion = "2.4.0"

var pinnedChecksums = map[string]string{
	"darwin/amd64": "088119325156321c34c456ac3703d6013538fd71cbac82b891ab34db491e4d66",
	"darwin/arm64": "9ca3185ad63e9ab54f7cb90f46a7362be02d80e37f0123d095a54355ea202f5d",
	"linux/amd64":  "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
	"linux/arm64":  "44e580752910f0ff36ec99aff59af20f65df1e859aa31e5605a8f0d055b496e9",
}

// install downloads a reviewed osv-scanner release and verifies its committed
// digest before making it executable.
func install(binDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	expected, ok := pinnedChecksums[platform]
	if !ok {
		return fmt.Errorf("no pinned osv-scanner asset for %s", platform)
	}
	asset := fmt.Sprintf("osv-scanner_%s_%s", runtime.GOOS, runtime.GOARCH)
	url := fmt.Sprintf("https://github.com/google/osv-scanner/releases/download/v%s/%s", pinnedVersion, asset)

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(binDir, "osv-scanner.tmp")
	if err := download(ctx, url, tmp, expected); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(binDir, "osv-scanner"))
}

func download(ctx context.Context, url, dest, expected string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hash), resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dest)
		return err
	}
	actual := fmt.Sprintf("%x", hash.Sum(nil))
	if actual != expected {
		_ = os.Remove(dest)
		return fmt.Errorf("osv-scanner checksum mismatch: got %s", actual)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
