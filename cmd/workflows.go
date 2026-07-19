package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/noeljackson/supplychain/internal/workflow"
)

func cmdWorkflows(g *Globals, args []string) int {
	target := "."
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: supplychain workflows [path]")
		return 2
	}
	if len(args) == 1 {
		target = args[0]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "workflows:", err)
		return 1
	}
	if err := workflow.Run(abs, g.BinDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
