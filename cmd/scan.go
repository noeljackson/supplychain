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
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: supplychain scan [path]")
		return report.ExitUsage
	}
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return report.ExitOperational
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		fmt.Fprintln(os.Stderr, "not a directory:", abs)
		return report.ExitOperational
	}

	if !g.NoUpdate {
		if err := update.IOCsThrottled(g.DataDir); err != nil && !g.Quiet {
			fmt.Fprintln(os.Stderr, "warn: IOC auto-update failed:", err)
		}
	}

	findings, err := scan.Run(scan.Options{
		Target:              abs,
		OpenIOC:             g.OpenIOC,
		BinDir:              g.BinDir,
		FreshnessDays:       g.FreshnessDays,
		Registry:            registry.NewClient(filepath.Join(g.DataDir, "registry-cache")),
		Signatures:          g.Signatures,
		Maintainers:         g.Maintainers,
		AcceptMaintainers:   g.AcceptMaintainers,
		MaintainerBaseDir:   filepath.Join(g.DataDir, "maintainers"),
		MaintainerBaseline:  g.MaintainerBaseline,
		TyposquatDistance:   g.TyposquatDistance,
		OSMCachePath:        filepath.Join(g.DataDir, "osm-cache.json"),
		RequireOSV:          g.FailOnAdvisory,
		RequireComplete:     g.FailOnAdvisory,
		SourcePolicy:        g.SourcePolicy,
		TrustedSourcePolicy: g.TrustedPolicyDir != "" && g.SourcePolicy != "",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		return report.ExitOperational
	}
	iocIdentity, identityErr := update.ReadSnapshotIdentity(g.DataDir, g.DefaultIOCs)
	if identityErr != nil {
		findings.Coverage.Set(
			"ioc_snapshot_identity",
			"failed",
			true,
			identityErr.Error(),
		)
	}
	reportOptions := report.Options{
		Quiet:          g.Quiet,
		ShowScripts:    g.Scripts,
		ScriptsOnly:    g.ScriptsOnly,
		FailOnAdvisory: g.FailOnAdvisory,
		ScannerVersion: Version,
		IOCSnapshot:    iocIdentity,
	}

	if g.JSON {
		return report.JSON(os.Stdout, findings, reportOptions)
	}
	return report.Human(os.Stdout, findings, reportOptions)
}
