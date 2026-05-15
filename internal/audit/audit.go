// Package audit implements system-wide forensic checks: shell-history grep
// for known C2 domains, recursive payload-filename search outside any one
// project's scan target, and git-log sweep across all repos for known
// worm-propagation dead-drop commit signatures.
package audit

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/noeljackson/supplychain/internal/ioc"
)

// Findings is the aggregated result of an audit-system run.
type Findings struct {
	C2Hits       []C2Hit          `json:"c2_hits"`
	CommitHits   []CommitHit      `json:"commit_hits"`
	Payloads     []ioc.PayloadHit `json:"payload_hits"`
	Persistence  []string         `json:"persistence_hits"`
	HistoryFiles []string         `json:"history_files_scanned"`
	ReposScanned int              `json:"repos_scanned"`
}

func (f Findings) HasHits() bool {
	return len(f.C2Hits) > 0 ||
		len(f.CommitHits) > 0 ||
		len(f.Payloads) > 0 ||
		len(f.Persistence) > 0
}

// C2Hit is a single shell-history line that mentions a known C2 domain.
type C2Hit struct {
	File   string `json:"file"`
	Domain string `json:"domain"`
	Line   string `json:"line"`
}

// CommitHit is a single git commit whose author + subject matches a known
// dead-drop signature.
type CommitHit struct {
	Repo    string `json:"repo"`
	Commit  string `json:"commit"`
	Author  string `json:"author"`
	Subject string `json:"subject"`
}

// DeadDropSig is one entry from iocs/dead-drop-signatures.txt. Both fields
// must be present in the commit's metadata for it to be flagged.
type DeadDropSig struct {
	AuthorPattern  string // substring match
	MessagePattern string // substring match
}

// Options configures an audit run.
type Options struct {
	OpenIOC func(name string) (fs.File, error)

	// HomeDir is searched (skipping cache-heavy dirs) for the dropped-payload
	// filenames in iocs/payload-filenames.txt.
	HomeDir string

	// HistoryFiles is the list of shell-history paths to grep.
	HistoryFiles []string

	// GitRoot is walked recursively for .git directories.
	GitRoot string
}

// Run executes the audit.
func Run(opts Options) (Findings, error) {
	if opts.OpenIOC == nil {
		return Findings{}, fmt.Errorf("audit: OpenIOC is required")
	}
	var f Findings

	// 1. Persistence — reuse the existing IOC list.
	persistList, err := ioc.LoadList(opts.OpenIOC, "persistence-paths.txt")
	if err != nil {
		return f, err
	}
	f.Persistence = ioc.CheckPersistence(persistList)

	// 2. Payload filenames — walk HomeDir skipping cache-heavy dirs.
	payloadNames, err := ioc.LoadList(opts.OpenIOC, "payload-filenames.txt")
	if err != nil {
		return f, err
	}
	f.Payloads, err = findPayloadsSystemWide(opts.HomeDir, payloadNames)
	if err != nil {
		return f, err
	}

	// 3. C2 domains in shell history.
	domains, err := ioc.LoadList(opts.OpenIOC, "c2-domains.txt")
	if err != nil {
		return f, err
	}
	f.HistoryFiles, f.C2Hits = scanHistory(opts.HistoryFiles, domains)

	// 4. Dead-drop commits across git repos.
	sigs, err := loadDeadDropSignatures(opts.OpenIOC)
	if err != nil {
		return f, err
	}
	f.ReposScanned, f.CommitHits, err = scanGitRepos(opts.GitRoot, sigs)
	if err != nil {
		return f, err
	}

	return f, nil
}

// DefaultHistoryFiles returns the standard shell-history paths a user is
// likely to have written. Non-existent entries are tolerated by the caller.
func DefaultHistoryFiles(home string) []string {
	files := []string{
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".python_history"),
		filepath.Join(home, ".node_repl_history"),
		filepath.Join(home, ".local/share/fish/fish_history"),
	}
	// Add ~/.npm/_logs/*.log lazily — those are debug logs that record exact
	// URLs npm fetched, so they pick up exfil attempts via npm.
	logs, _ := filepath.Glob(filepath.Join(home, ".npm/_logs/*.log"))
	files = append(files, logs...)
	return files
}

// findPayloadsSystemWide walks home looking for any file with a basename in
// names. Skips known-noisy dirs that won't host malware (or will host so much
// other crap the walk is unusable).
func findPayloadsSystemWide(home string, names []string) ([]ioc.PayloadHit, error) {
	if len(names) == 0 || home == "" {
		return nil, nil
	}
	wanted := make(map[string]struct{}, len(names))
	for _, n := range names {
		wanted[n] = struct{}{}
	}
	skipDirs := map[string]struct{}{
		".cache":           {},
		"Cache":            {},
		"Caches":           {},
		"CacheStorage":     {},
		"GPUCache":         {},
		"ShaderCache":      {},
		"Code Cache":       {},
		".git":             {},
		"node_modules":     {}, // payloads inside node_modules ARE caught by per-target scan; system-wide we want fs-level drops
		".local":           {}, // walk explicit subset below
		".npm":             {}, // ditto
		"snap":             {},
		"steam":            {},
		".steam":           {},
		".mozilla":         {},
		".cargo":           {},
		".rustup":          {},
		"BraveSoftware":    {},
		"google-chrome":    {},
		"chromium":         {},
	}

	var hits []ioc.PayloadHit
	walk := func(root string) {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if _, skip := skipDirs[d.Name()]; skip {
					return fs.SkipDir
				}
				return nil
			}
			if _, ok := wanted[d.Name()]; ok {
				hits = append(hits, ioc.PayloadHit{Path: path, Filename: d.Name()})
			}
			return nil
		})
	}
	walk(home)
	walk(filepath.Join(home, ".local", "bin"))
	walk(filepath.Join(home, ".local", "share", "applications"))
	walk("/tmp")
	return hits, nil
}

// scanHistory greps each history file for any of the domains. Reads line by
// line and reports first-match-per-line. Missing history files are skipped
// silently. Returns the list of files actually opened plus all hits.
func scanHistory(historyFiles []string, domains []string) ([]string, []C2Hit) {
	var scanned []string
	var hits []C2Hit
	if len(domains) == 0 {
		return scanned, hits
	}
	for _, p := range historyFiles {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanned = append(scanned, p)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			for _, d := range domains {
				if strings.Contains(line, d) {
					hits = append(hits, C2Hit{File: p, Domain: d, Line: line})
					break // one hit per line is enough; don't multi-flag for overlapping domains
				}
			}
		}
		f.Close()
	}
	return scanned, hits
}

// loadDeadDropSignatures parses iocs/dead-drop-signatures.txt. Each non-blank
// non-comment line is "<author>\t<message-substring>".
func loadDeadDropSignatures(open func(string) (fs.File, error)) ([]DeadDropSig, error) {
	f, err := open("dead-drop-signatures.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []DeadDropSig
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		a := strings.TrimSpace(parts[0])
		m := strings.TrimSpace(parts[1])
		if a == "" || m == "" {
			continue
		}
		out = append(out, DeadDropSig{AuthorPattern: a, MessagePattern: m})
	}
	return out, sc.Err()
}

// scanGitRepos walks root looking for .git directories, then for each
// resolved repo runs `git log --all --pretty=format:%H|%ae|%s` and matches
// each commit against the signatures. Returns the number of repos scanned.
func scanGitRepos(root string, sigs []DeadDropSig) (int, []CommitHit, error) {
	if root == "" || len(sigs) == 0 {
		return 0, nil, nil
	}
	var repos []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == "node_modules" || base == ".cache" || base == ".tmp" {
			return fs.SkipDir
		}
		if base == ".git" {
			repos = append(repos, filepath.Dir(path))
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}

	var hits []CommitHit
	for _, repo := range repos {
		cmd := exec.Command("git", "-C", repo, "log", "--all", "--pretty=format:%H|%ae|%s")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(out)))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			parts := strings.SplitN(line, "|", 3)
			if len(parts) != 3 {
				continue
			}
			sha, author, subject := parts[0], parts[1], parts[2]
			for _, sig := range sigs {
				if strings.Contains(author, sig.AuthorPattern) &&
					strings.Contains(subject, sig.MessagePattern) {
					hits = append(hits, CommitHit{
						Repo:    repo,
						Commit:  sha,
						Author:  author,
						Subject: subject,
					})
					break
				}
			}
		}
	}
	return len(repos), hits, nil
}
