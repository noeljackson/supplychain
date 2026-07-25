package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/noeljackson/supplychain/internal/artifact"
	"github.com/noeljackson/supplychain/internal/report"
)

func cmdImage(g *Globals, args []string) int {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sbom := fs.String("sbom", "supplychain.spdx.json", "SPDX JSON output path")
	failOn := fs.String("fail-on", "high", "minimum failing severity")
	onlyFixed := fs.Bool("only-fixed", false, "only fail vulnerabilities with a fix")
	vex := fs.String("vex", "", "explicit reviewed OpenVEX document inside the current Git worktree")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: supplychain image [--sbom=PATH] [--fail-on=high] [--only-fixed] [--vex=PATH] IMAGE")
		return 2
	}
	switch *failOn {
	case "negligible", "low", "medium", "high", "critical":
	default:
		fmt.Fprintln(os.Stderr, "image: --fail-on must be negligible, low, medium, high, or critical")
		return report.ExitUsage
	}
	if err := artifact.Run(artifact.Options{
		Image:      fs.Arg(0),
		SBOMPath:   *sbom,
		FailOn:     *failOn,
		OnlyFixed:  *onlyFixed,
		VEXPath:    *vex,
		PolicyRoot: ".",
		BinDir:     g.BinDir,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, artifact.ErrFindings) {
			return report.ExitFindings
		}
		return report.ExitOperational
	}
	fmt.Println("SBOM:", *sbom)
	return report.ExitClean
}
