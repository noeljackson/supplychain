package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/noeljackson/supplychain/internal/secrets"
)

func cmdSecrets(g *Globals, args []string) int {
	fs := flag.NewFlagSet("secrets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	config := fs.String("gitleaks-config", "", "explicit reviewed Gitleaks config inside the target")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: supplychain secrets [--gitleaks-config=PATH] [path]")
		return 2
	}
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets:", err)
		return 1
	}
	if err := secrets.Run(abs, g.BinDir, *config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
