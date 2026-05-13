package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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

	anyHits := false
	for _, repo := range repos {
		if !g.Quiet {
			fmt.Println("==>", repo)
		}
		findings, err := scan.Run(scan.Options{
			Target:  repo,
			OpenIOC: g.OpenIOC,
			BinDir:  g.BinDir,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn:", repo+":", err)
			continue
		}
		if g.JSON {
			_ = report.JSON(os.Stdout, findings)
		} else {
			_ = report.Human(os.Stdout, findings, report.Options{
				Quiet:       g.Quiet,
				ShowScripts: g.Scripts,
				ScriptsOnly: g.ScriptsOnly,
			})
		}
		if findings.HasHits() {
			anyHits = true
		}
	}
	if anyHits {
		return 1
	}
	return 0
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
