package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/noeljackson/supplychain/internal/artifact"
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
		return 1
	}
	fmt.Println("SBOM:", *sbom)
	return 0
}
