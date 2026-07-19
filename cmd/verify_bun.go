package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/noeljackson/supplychain/internal/bunverify"
	"github.com/noeljackson/supplychain/internal/registry"
)

func cmdVerifyBun(g *Globals, args []string) int {
	fs := flag.NewFlagSet("verify-bun", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	minimumAge := fs.Int("minimum-age-days", 7, "minimum npm package publication age")
	baseline := fs.String("baseline", "", "reviewed Bun dependency baseline")
	writeBaseline := fs.Bool("write-baseline", false, "write a new baseline after all registry checks pass")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-bun:", err)
		return 1
	}
	lockfile := abs
	if info, statErr := os.Stat(abs); statErr == nil && info.IsDir() {
		lockfile = filepath.Join(abs, "bun.lock")
	}
	baselinePath := *baseline
	if baselinePath != "" && !filepath.IsAbs(baselinePath) {
		baselinePath = filepath.Join(filepath.Dir(lockfile), baselinePath)
	}
	result, err := bunverify.Verify(bunverify.Options{
		Lockfile: lockfile, MinimumAgeDays: *minimumAge, BaselinePath: baselinePath,
		Registry: registry.NewClient(filepath.Join(g.DataDir, "registry-cache")),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-bun:", err)
		return 1
	}
	if g.JSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result)
	} else if len(result.Issues) == 0 {
		fmt.Printf("ok  verified %d Bun registry packages in %s\n", result.Checked, lockfile)
	} else {
		fmt.Fprintf(os.Stderr, "err Bun verification failed for %s\n", lockfile)
		for _, issue := range result.Issues {
			fmt.Fprintf(os.Stderr, "  %s  %s: %s\n", issue.Package, issue.Code, issue.Message)
		}
	}
	if len(result.Issues) > 0 {
		return 1
	}
	if *writeBaseline {
		if baselinePath == "" {
			baselinePath = filepath.Join(filepath.Dir(lockfile), ".supplychain", "bun-baseline.json")
		}
		if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "verify-bun:", err)
			return 1
		}
		if err := bunverify.WriteBaseline(baselinePath, result.Baseline); err != nil {
			fmt.Fprintln(os.Stderr, "verify-bun:", err)
			return 1
		}
		if !g.Quiet {
			fmt.Println("wrote reviewed baseline metadata ->", baselinePath)
		}
	}
	return 0
}
