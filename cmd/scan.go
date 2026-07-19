package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/noeljackson/supplychain/internal/registry"
	"github.com/noeljackson/supplychain/internal/report"
	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/update"
)

func cmdScan(g *Globals, args []string) int {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		fmt.Fprintln(os.Stderr, "not a directory:", abs)
		return 1
	}

	if !g.NoUpdate {
		if err := update.IOCsThrottled(g.DataDir); err != nil && !g.Quiet {
			fmt.Fprintln(os.Stderr, "warn: IOC auto-update failed:", err)
		}
	}

	findings, err := scan.Run(scan.Options{
		Target:            abs,
		OpenIOC:           g.OpenIOC,
		BinDir:            g.BinDir,
		FreshnessDays:     g.FreshnessDays,
		Registry:          registry.NewClient(filepath.Join(g.DataDir, "registry-cache")),
		Signatures:        g.Signatures,
		Maintainers:       g.Maintainers,
		MaintainerBaseDir: filepath.Join(g.DataDir, "maintainers"),
		TyposquatDistance: g.TyposquatDistance,
		OSMCachePath:      filepath.Join(g.DataDir, "osm-cache.json"),
		RequireOSV:        g.FailOnAdvisory,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		return 1
	}

	if g.JSON {
		return report.JSON(os.Stdout, findings, report.Options{FailOnAdvisory: g.FailOnAdvisory})
	}
	return report.Human(os.Stdout, findings, report.Options{
		Quiet:          g.Quiet,
		ShowScripts:    g.Scripts,
		ScriptsOnly:    g.ScriptsOnly,
		FailOnAdvisory: g.FailOnAdvisory,
	})
}
