// Package osv shells out to the osv-scanner CLI when present. The plan is to
// migrate to a direct osv-scalibr library import later; the surface here is
// designed to be swap-friendly.
package osv

import (
	"context"
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
	candidates := []string{
		filepath.Join(binDir, "osv-scanner"),
	}
	if p, err := exec.LookPath("osv-scanner"); err == nil {
		candidates = append([]string{p}, candidates...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
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
	if _, _, err := Locate(binDir); err == nil {
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

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// install downloads the latest osv-scanner release from GitHub and writes it
// to binDir/osv-scanner.
func install(binDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://api.github.com/repos/google/osv-scanner/releases/latest", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("decode release: %w", err)
	}

	osStr := runtime.GOOS
	archStr := runtime.GOARCH
	url := pickAsset(rel.Assets, osStr, archStr)
	if url == "" {
		return fmt.Errorf("no osv-scanner asset for %s/%s in release %s", osStr, archStr, rel.TagName)
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(binDir, "osv-scanner.tmp")
	if err := download(ctx, url, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(binDir, "osv-scanner"))
}

func pickAsset(assets []ghAsset, osStr, archStr string) string {
	wantOS := osStr
	wantArch := archStr
	var fallback string
	for _, a := range assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, ".sbom") || strings.Contains(n, ".sig") ||
			strings.Contains(n, ".sha") || strings.Contains(n, "checksum") ||
			strings.Contains(n, "attestation") {
			continue
		}
		if !strings.Contains(n, wantOS) {
			continue
		}
		if strings.Contains(n, wantArch) ||
			(wantArch == "amd64" && strings.Contains(n, "x86_64")) ||
			(wantArch == "arm64" && strings.Contains(n, "aarch64")) {
			return a.URL
		}
		fallback = a.URL
	}
	return fallback
}

func download(ctx context.Context, url, dest string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
