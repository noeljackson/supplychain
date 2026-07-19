package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func cmdCI(g *Globals, args []string) int {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policy := fs.String("policy", "strict", "CI policy: auto or strict")
	minimumAge := fs.Int("minimum-age-days", 7, "minimum age for Bun packages")
	baseline := fs.String("baseline", ".supplychain/bun-baseline.json", "Bun baseline path")
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
	g.NoUpdate = true
	g.FailOnAdvisory = *policy == "strict"
	scanExit := cmdScan(g, []string{target})
	workflowsExit := 0
	secretsExit := 0
	if *policy == "strict" {
		workflowsExit = cmdWorkflows(g, []string{target})
		secretsExit = cmdSecrets(g, []string{target})
	}

	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ci:", err)
		return 1
	}
	if _, err := os.Stat(filepath.Join(abs, "bun.lock")); err != nil {
		if scanExit != 0 || workflowsExit != 0 || secretsExit != 0 {
			return 1
		}
		return 0
	}
	verifyArgs := []string{fmt.Sprintf("--minimum-age-days=%d", *minimumAge)}
	baselinePath := filepath.Join(abs, *baseline)
	if _, err := os.Stat(baselinePath); err == nil {
		verifyArgs = append(verifyArgs, "--baseline="+baselinePath)
	}
	verifyArgs = append(verifyArgs, abs)
	verifyExit := cmdVerifyBun(g, verifyArgs)
	if scanExit != 0 || workflowsExit != 0 || secretsExit != 0 || verifyExit != 0 {
		return 1
	}
	return 0
}
