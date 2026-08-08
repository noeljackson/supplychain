package cmd

import (
	"encoding/json"
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
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: supplychain scan-all [root]")
		return 2
	}
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
	absRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error resolving", root+":", err)
		return report.ExitOperational
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error inspecting", absRoot+":", err)
		return report.ExitOperational
	}
	if !info.IsDir() {
		fmt.Fprintln(os.Stderr, "not a directory:", absRoot)
		return report.ExitOperational
	}
	root = absRoot

	if !g.NoUpdate {
		if err := update.IOCsThrottled(g.DataDir); err != nil && !g.Quiet {
			fmt.Fprintln(os.Stderr, "warn: IOC auto-update failed:", err)
		}
	}

	repos, err := findGitRepos(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error walking", root+":", err)
		return report.ExitOperational
	}

	var summary scanAllSummary
	var envelopes []report.Envelope
	var scanErrors []scanAllError
	anyFindings := false
	anyOperational := false
	iocIdentity, identityErr := update.ReadSnapshotIdentity(g.DataDir, g.DefaultIOCs)
	if identityErr != nil {
		anyOperational = true
		summary.Errors++
		scanErrors = append(scanErrors, scanAllError{
			Target:  root,
			Message: "IOC snapshot identity: " + identityErr.Error(),
		})
	}
	for _, repo := range repos {
		if !g.Quiet && !g.JSON {
			fmt.Println("==>", repo)
		}
		summary.Scanned++
		findings, err := scan.Run(scan.Options{
			Target:             repo,
			OpenIOC:            g.OpenIOC,
			BinDir:             g.BinDir,
			FreshnessDays:      g.FreshnessDays,
			Registry:           registry.NewClient(filepath.Join(g.DataDir, "registry-cache")),
			Signatures:         g.Signatures,
			Maintainers:        g.Maintainers,
			AcceptMaintainers:  g.AcceptMaintainers,
			MaintainerBaseDir:  filepath.Join(g.DataDir, "maintainers"),
			MaintainerBaseline: g.MaintainerBaseline,
			TyposquatDistance:  g.TyposquatDistance,
			OSMCachePath:       filepath.Join(g.DataDir, "osm-cache.json"),
			RequireOSV:         g.FailOnAdvisory,
			OSVOffline:         g.OSVOffline,
			RequireComplete:    g.FailOnAdvisory,
			SourcePolicy:       g.SourcePolicy,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn:", repo+":", err)
			summary.Errors++
			anyOperational = true
			scanErrors = append(scanErrors, scanAllError{Target: repo, Message: err.Error()})
			continue
		}
		if identityErr != nil {
			findings.Coverage.Set(
				"ioc_snapshot_identity",
				"failed",
				true,
				identityErr.Error(),
			)
		}
		hasSupplyChain := findings.HasSupplyChainHits()
		hasAdvisory := findings.HasAdvisoryHits()
		switch {
		case findings.HasRequiredCoverageGaps():
			summary.IncompleteRepos = append(summary.IncompleteRepos, repo)
		case hasSupplyChain:
			summary.SupplyChainRepos = append(summary.SupplyChainRepos, repo)
		case hasAdvisory:
			summary.AdvisoryOnlyRepos = append(summary.AdvisoryOnlyRepos, repo)
		default:
			summary.Clean++
		}
		reportOptions := report.Options{
			Quiet:          g.Quiet,
			ShowScripts:    g.Scripts,
			ScriptsOnly:    g.ScriptsOnly,
			FailOnAdvisory: g.FailOnAdvisory,
			ScannerVersion: Version,
			IOCSnapshot:    iocIdentity,
		}
		envelope := report.NewEnvelope(findings, reportOptions)
		if g.JSON {
			envelopes = append(envelopes, envelope)
		} else {
			_ = report.Human(os.Stdout, findings, report.Options{
				Quiet:          g.Quiet,
				ShowScripts:    g.Scripts,
				ScriptsOnly:    g.ScriptsOnly,
				FailOnAdvisory: g.FailOnAdvisory,
			})
		}
		switch envelope.Outcome.ExitCode {
		case report.ExitOperational:
			anyOperational = true
		case report.ExitFindings:
			anyFindings = true
		}
	}
	if g.JSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(scanAllEnvelope{
			SchemaVersion: report.SchemaVersion,
			Command:       "scan-all",
			Scanner:       report.ScannerIdentity{Name: "supplychain", Version: Version},
			IOCSnapshot:   iocIdentity,
			Reports:       nonNilReports(envelopes),
			Errors:        nonNilScanAllErrors(scanErrors),
			Summary:       summary,
		})
	} else if !g.Quiet {
		renderScanAllSummary(os.Stdout, summary)
	}
	if anyOperational {
		return report.ExitOperational
	}
	if anyFindings {
		return report.ExitFindings
	}
	return report.ExitClean
}

type scanAllSummary struct {
	Scanned           int      `json:"scanned"`
	Clean             int      `json:"clean"`
	Errors            int      `json:"errors"`
	SupplyChainRepos  []string `json:"supply_chain_repositories"`
	AdvisoryOnlyRepos []string `json:"advisory_only_repositories"`
	IncompleteRepos   []string `json:"incomplete_repositories"`
}

type scanAllError struct {
	Target  string `json:"target"`
	Message string `json:"message"`
}

type scanAllEnvelope struct {
	SchemaVersion int                     `json:"schema_version"`
	Command       string                  `json:"command"`
	Scanner       report.ScannerIdentity  `json:"scanner"`
	IOCSnapshot   update.SnapshotIdentity `json:"ioc_snapshot"`
	Reports       []report.Envelope       `json:"reports"`
	Errors        []scanAllError          `json:"errors"`
	Summary       scanAllSummary          `json:"summary"`
}

func nonNilReports(values []report.Envelope) []report.Envelope {
	if values == nil {
		return []report.Envelope{}
	}
	return values
}

func nonNilScanAllErrors(values []scanAllError) []scanAllError {
	if values == nil {
		return []scanAllError{}
	}
	return values
}

func renderScanAllSummary(w *os.File, s scanAllSummary) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Summary:")
	fmt.Fprintf(w, "  repos scanned:              %d\n", s.Scanned)
	fmt.Fprintf(w, "  supply-chain indicators:    %d\n", len(s.SupplyChainRepos))
	fmt.Fprintf(w, "  advisory/audit only:        %d\n", len(s.AdvisoryOnlyRepos))
	fmt.Fprintf(w, "  clean:                      %d\n", s.Clean)
	fmt.Fprintf(w, "  operationally incomplete:  %d\n", len(s.IncompleteRepos))
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

var walkGitDirectories = filepath.WalkDir

func findGitRepos(root string) ([]string, error) {
	var out []string
	err := walkGitDirectories(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
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
