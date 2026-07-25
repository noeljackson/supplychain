package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/noeljackson/supplychain/internal/audit"
	"github.com/noeljackson/supplychain/internal/report"
)

func cmdAuditSystem(g *Globals, args []string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	gitRoot := filepath.Join(home, "src")
	unsafeHistory := false
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--git-root="):
			gitRoot = strings.TrimPrefix(a, "--git-root=")
		case a == "--unsafe-history-context":
			unsafeHistory = true
		default:
			fmt.Fprintln(os.Stderr, "usage: supplychain audit-system [--git-root=PATH]")
			return report.ExitUsage
		}
	}

	findings, err := audit.Run(audit.Options{
		OpenIOC:              g.OpenIOC,
		HomeDir:              home,
		HistoryFiles:         audit.DefaultHistoryFiles(home),
		GitRoot:              gitRoot,
		UnsafeHistoryContext: unsafeHistory,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit error:", err)
		return report.ExitOperational
	}

	if g.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			SchemaVersion int                    `json:"schema_version"`
			Command       string                 `json:"command"`
			Scanner       report.ScannerIdentity `json:"scanner"`
			Outcome       struct {
				Status     string `json:"status"`
				ExitCode   int    `json:"exit_code"`
				HasHits    bool   `json:"has_findings"`
				Incomplete bool   `json:"incomplete"`
			} `json:"outcome"`
			Findings audit.Findings `json:"findings"`
		}{
			SchemaVersion: report.SchemaVersion,
			Command:       "audit-system",
			Scanner:       report.ScannerIdentity{Name: "supplychain", Version: Version},
			Outcome: struct {
				Status     string `json:"status"`
				ExitCode   int    `json:"exit_code"`
				HasHits    bool   `json:"has_findings"`
				Incomplete bool   `json:"incomplete"`
			}{
				Status:     auditOutcome(findings),
				ExitCode:   auditExitCode(findings),
				HasHits:    findings.HasHits(),
				Incomplete: findings.HasCoverageGaps(),
			},
			Findings: findings,
		})
		if findings.HasCoverageGaps() {
			return report.ExitOperational
		}
		if findings.HasHits() {
			return report.ExitFindings
		}
		return report.ExitClean
	}

	if !findings.HasHits() && !findings.HasCoverageGaps() {
		if !g.Quiet {
			fmt.Printf("ok  system audit clean — scanned %d history files, %d git repos under %s\n",
				findings.CompletedHistories(), findings.CompletedRepositories(), gitRoot)
		}
		return 0
	}

	if findings.HasHits() {
		fmt.Printf("err system audit found %d category hits\n",
			boolToInt(len(findings.C2Hits) > 0)+boolToInt(len(findings.CommitHits) > 0)+
				boolToInt(len(findings.Payloads) > 0)+boolToInt(len(findings.Persistence) > 0))
	}

	if len(findings.Persistence) > 0 {
		fmt.Println()
		fmt.Println("OS-level persistence artifacts:")
		for _, p := range findings.Persistence {
			fmt.Printf("  %s\n", p)
		}
	}
	if len(findings.Payloads) > 0 {
		fmt.Println()
		fmt.Println("Dropped payload filenames on disk:")
		for _, p := range findings.Payloads {
			fmt.Printf("  %s  (matches IOC %s)\n", p.Path, p.Filename)
		}
	}
	if len(findings.C2Hits) > 0 {
		fmt.Println()
		fmt.Println("C2 domains in shell history:")
		for _, h := range findings.C2Hits {
			fmt.Printf("  %s — %s:%d\n    %s\n", h.Domain, h.File, h.LineNumber, h.Context)
			if unsafeHistory && h.FullLine != "" {
				fmt.Printf("    unsafe full line: %s\n", truncate(h.FullLine, 140))
			}
		}
	}
	if len(findings.CommitHits) > 0 {
		fmt.Println()
		fmt.Println("Dead-drop commit signatures across git repos:")
		for _, c := range findings.CommitHits {
			fmt.Printf("  %s @ %s\n    %s — %s\n",
				c.Repo, c.Commit[:min(12, len(c.Commit))], c.Author, c.Subject)
		}
	}
	renderAuditCoverage(findings)
	if findings.HasCoverageGaps() {
		return report.ExitOperational
	}
	return report.ExitFindings
}

func auditExitCode(findings audit.Findings) int {
	if findings.HasCoverageGaps() {
		return report.ExitOperational
	}
	if findings.HasHits() {
		return report.ExitFindings
	}
	return report.ExitClean
}

func auditOutcome(findings audit.Findings) string {
	switch auditExitCode(findings) {
	case report.ExitOperational:
		return "incomplete"
	case report.ExitFindings:
		return "findings"
	default:
		return "clean"
	}
}

func renderAuditCoverage(findings audit.Findings) {
	if !findings.HasCoverageGaps() {
		return
	}
	fmt.Println()
	fmt.Println("Forensic coverage incomplete:")
	statuses := append(append([]audit.TargetStatus{}, findings.Histories...), findings.Repositories...)
	statuses = append(statuses, findings.PayloadRoots...)
	for _, status := range statuses {
		if status.Status == "failed" {
			fmt.Printf("  %s — %s\n", status.Path, status.Diagnostic)
		}
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
