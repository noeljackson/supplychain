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

// PackageVuln is a single (package, version, vuln IDs, source path) finding.
type PackageVuln struct {
	Name       string
	Version    string
	Ecosystem  string
	IDs        []string
	SourcePath string
}

// Scan runs osv-scanner against target and returns parsed findings.
// Returns (nil, nil) if osv-scanner is unavailable — that's an expected
// state, not an error.
func Scan(binDir, target string) ([]PackageVuln, error) {
	path, _, err := Locate(binDir)
	if err != nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// osv-scanner v2 changed the CLI to `osv-scanner scan source`; older
	// versions accepted a bare path. Try the new form first, fall back.
	args := []string{"scan", "source", "--recursive", "--format", "json", target}
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.Output()
	if err != nil {
		// Exit code 1 means findings — that's expected; only re-run on usage error.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() > 1 {
			cmd = exec.CommandContext(ctx, path, "--recursive", "--format", "json", target)
			out, err = cmd.Output()
			if err != nil {
				if !errors.As(err, &exitErr) || exitErr.ExitCode() > 1 {
					return nil, fmt.Errorf("osv-scanner failed: %w", err)
				}
			}
		}
	}
	return parse(out)
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
					ID string `json:"id"`
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
			for _, v := range p.Vulnerabilities {
				ids = append(ids, v.ID)
			}
			out = append(out, PackageVuln{
				Name:       p.Package.Name,
				Version:    p.Package.Version,
				Ecosystem:  p.Package.Ecosystem,
				IDs:        ids,
				SourcePath: r.Source.Path,
			})
		}
	}
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
