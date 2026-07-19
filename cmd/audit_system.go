package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/noeljackson/supplychain/internal/audit"
)

func cmdAuditSystem(g *Globals, args []string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	gitRoot := filepath.Join(home, "src")
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--git-root="):
			gitRoot = strings.TrimPrefix(a, "--git-root=")
		}
	}

	findings, err := audit.Run(audit.Options{
		OpenIOC:      g.OpenIOC,
		HomeDir:      home,
		HistoryFiles: audit.DefaultHistoryFiles(home),
		GitRoot:      gitRoot,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit error:", err)
		return 1
	}

	if g.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			HasHits  bool           `json:"has_hits"`
			Findings audit.Findings `json:"findings"`
		}{findings.HasHits(), findings})
		if findings.HasHits() {
			return 1
		}
		return 0
	}

	if !findings.HasHits() {
		if !g.Quiet {
			fmt.Printf("ok  system audit clean — scanned %d history files, %d git repos under %s\n",
				len(findings.HistoryFiles), findings.ReposScanned, gitRoot)
		}
		return 0
	}

	fmt.Printf("err system audit found %d category hits\n",
		boolToInt(len(findings.C2Hits) > 0)+boolToInt(len(findings.CommitHits) > 0)+
			boolToInt(len(findings.Payloads) > 0)+boolToInt(len(findings.Persistence) > 0))

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
			fmt.Printf("  %s — %s\n    %s: %s\n", h.Domain, h.File, h.Domain, truncate(h.Line, 140))
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
	return 1
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
