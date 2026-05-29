package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/noeljackson/supplychain/internal/registry"
	"github.com/noeljackson/supplychain/internal/report"
	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/update"
)

func cmdScanAll(g *Globals, args []string) int {
	root := ""
	if len(args) > 0 {
		root = args[0]
	}
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		root = filepath.Join(home, "src")
	}

	if !g.NoUpdate {
		if err := update.IOCsThrottled(g.DataDir); err != nil && !g.Quiet {
			fmt.Fprintln(os.Stderr, "warn: IOC auto-update failed:", err)
		}
	}

	repos, err := findGitRepos(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error walking", root+":", err)
		return 1
	}

	var summary scanAllSummary
	anyFailures := false
	for _, repo := range repos {
		if !g.Quiet && !g.JSON {
			fmt.Println("==>", repo)
		}
		summary.Scanned++
		findings, err := scan.Run(scan.Options{
			Target:            repo,
			OpenIOC:           g.OpenIOC,
			BinDir:            g.BinDir,
			FreshnessDays:     g.FreshnessDays,
			Registry:          registry.NewClient(filepath.Join(g.DataDir, "registry-cache")),
			Signatures:        g.Signatures,
			Maintainers:       g.Maintainers,
			MaintainerBaseDir: filepath.Join(g.DataDir, "maintainers"),
			TyposquatDistance: g.TyposquatDistance,
			OSMCachePath:      filepath.Join(g.DataDir, "osm-cache.json"),
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn:", repo+":", err)
			summary.Errors++
			continue
		}
		hasSupplyChain := findings.HasSupplyChainHits()
		hasAdvisory := findings.HasAdvisoryHits()
		switch {
		case hasSupplyChain:
			summary.SupplyChainRepos = append(summary.SupplyChainRepos, repo)
		case hasAdvisory:
			summary.AdvisoryOnlyRepos = append(summary.AdvisoryOnlyRepos, repo)
		default:
			summary.Clean++
		}
		if g.JSON {
			_ = report.JSON(os.Stdout, findings, report.Options{FailOnAdvisory: g.FailOnAdvisory})
		} else {
			_ = report.Human(os.Stdout, findings, report.Options{
				Quiet:          g.Quiet,
				ShowScripts:    g.Scripts,
				ScriptsOnly:    g.ScriptsOnly,
				FailOnAdvisory: g.FailOnAdvisory,
			})
		}
		if hasSupplyChain || (g.FailOnAdvisory && hasAdvisory) {
			anyFailures = true
		}
	}
	if !g.JSON && !g.Quiet {
		renderScanAllSummary(os.Stdout, summary)
	}
	if anyFailures {
		return 1
	}
	return 0
}

type scanAllSummary struct {
	Scanned           int
	Clean             int
	Errors            int
	SupplyChainRepos  []string
	AdvisoryOnlyRepos []string
}

func renderScanAllSummary(w *os.File, s scanAllSummary) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Summary:")
	fmt.Fprintf(w, "  repos scanned:              %d\n", s.Scanned)
	fmt.Fprintf(w, "  supply-chain indicators:    %d\n", len(s.SupplyChainRepos))
	fmt.Fprintf(w, "  advisory/audit only:        %d\n", len(s.AdvisoryOnlyRepos))
	fmt.Fprintf(w, "  clean:                      %d\n", s.Clean)
	if s.Errors > 0 {
		fmt.Fprintf(w, "  scan errors:                 %d\n", s.Errors)
	}
	if len(s.SupplyChainRepos) > 0 {
		fmt.Fprintln(w, "  supply-chain repos:")
		for _, repo := range s.SupplyChainRepos {
			fmt.Fprintf(w, "    %s\n", repo)
		}
	}
}

func findGitRepos(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !d.IsDir() {
			return nil
		}
		// Skip noisy + irrelevant dirs to keep walking fast.
		base := d.Name()
		if base == "node_modules" || base == ".cache" || base == ".tmp" {
			return fs.SkipDir
		}
		if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
			out = append(out, path)
			return fs.SkipDir // don't recurse into repo subdirs
		}
		return nil
	})
	return out, err
}
