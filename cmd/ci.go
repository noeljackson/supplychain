package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/noeljackson/supplychain/internal/bunverify"
	"github.com/noeljackson/supplychain/internal/osm"
	"github.com/noeljackson/supplychain/internal/report"
)

func cmdCI(g *Globals, args []string) int {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policy := fs.String("policy", "strict", "CI policy: auto or strict")
	minimumAge := fs.Int("minimum-age-days", 7, "minimum age for Bun packages")
	baseline := fs.String("baseline", ".supplychain/bun-baseline.json", "Bun baseline path")
	gitleaksConfig := fs.String("gitleaks-config", "", "explicit reviewed Gitleaks config inside the target")
	refreshOSM := fs.Bool(
		"refresh-osm", false,
		"refresh the OSM malware cache before scanning",
	)
	osmTokenFile := fs.String(
		"osm-token-file", "",
		"read the OSM bearer token from an owner-only regular file",
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policy != "auto" && *policy != "strict" {
		fmt.Fprintln(os.Stderr, "ci: policy must be auto or strict")
		return 2
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ci:", err)
		return report.ExitOperational
	}

	if *osmTokenFile != "" && !*refreshOSM {
		fmt.Fprintln(os.Stderr, "ci: --osm-token-file requires --refresh-osm")
		return report.ExitUsage
	}

	if *refreshOSM {
		token := osm.Token()
		if *osmTokenFile != "" {
			token, err = osm.TokenFromFile(*osmTokenFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ci: read OSM token file:", err)
				return report.ExitOperational
			}
		}
		if token == "" {
			fmt.Fprintln(
				os.Stderr,
				"ci: --refresh-osm requires --osm-token-file or SUPPLYCHAIN_OSM_TOKEN",
			)
			return report.ExitOperational
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		skipped, _, _, refreshErr := osm.RefreshWithToken(ctx, g.DataDir, []string{"npm"}, token)
		cancel()
		if refreshErr != nil {
			fmt.Fprintln(os.Stderr, "ci: refresh OSM:", refreshErr)
			return report.ExitOperational
		}
		if skipped {
			fmt.Fprintln(os.Stderr, "ci: OSM refresh unexpectedly skipped")
			return report.ExitOperational
		}
	}

	g.NoUpdate = true
	g.FailOnAdvisory = *policy == "strict"
	scanExit := cmdScan(g, []string{target})
	workflowsExit := 0
	secretsExit := 0
	if *policy == "strict" {
		workflowsExit = cmdWorkflows(g, []string{target})
		secretsArgs := []string{target}
		if *gitleaksConfig != "" {
			secretsArgs = []string{"--gitleaks-config=" + *gitleaksConfig, target}
		}
		secretsExit = cmdSecrets(g, secretsArgs)
	}

	if _, err := os.Stat(filepath.Join(abs, "bun.lock")); err != nil {
		return combinedExit(scanExit, workflowsExit, secretsExit)
	}
	verifyArgs := []string{fmt.Sprintf("--minimum-age-days=%d", *minimumAge)}
	baselinePath, baselineErr := bunverify.ResolveReviewedBaseline(abs, *baseline)
	if baselineErr != nil {
		fmt.Fprintln(os.Stderr, "ci:", baselineErr)
		return report.ExitOperational
	}
	if _, err := os.Stat(baselinePath); err == nil {
		verifyArgs = append(verifyArgs, "--baseline="+baselinePath)
	}
	verifyArgs = append(verifyArgs, abs)
	verifyExit := cmdVerifyBun(g, verifyArgs)
	return combinedExit(scanExit, workflowsExit, secretsExit, verifyExit)
}

func combinedExit(codes ...int) int {
	result := report.ExitClean
	for _, code := range codes {
		if code == report.ExitOperational {
			return report.ExitOperational
		}
		if code == report.ExitUsage {
			result = report.ExitUsage
		} else if code == report.ExitFindings && result == report.ExitClean {
			result = report.ExitFindings
		}
	}
	return result
}
