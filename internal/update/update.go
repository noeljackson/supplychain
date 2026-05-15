// Package update pulls fresh IOC data from the upstream repo. The binary
// itself is NOT auto-updated here — that's intentional. Compiled binaries
// should move slowly and explicitly; data files move fast.
package update

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var IOCFiles = []string{
	"persistence-paths.txt",
	"payload-filenames.txt",
	"packages.txt",
	"c2-domains.txt",
	"dead-drop-signatures.txt",
}

const (
	envURL        = "SUPPLYCHAIN_IOC_URL"
	envPin        = "SUPPLYCHAIN_PIN"
	defaultURL    = "https://raw.githubusercontent.com/noeljackson/supplychain"
	defaultBranch = "main"
	throttleSecs  = 60
	httpTimeout   = 5 * time.Second
)

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
	dir := filepath.Join(dataDir, "iocs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	base := baseURL()
	for _, name := range IOCFiles {
		if err := fetch(base+"/"+name, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
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

func fetch(url, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, dest)
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
