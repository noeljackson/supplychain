package cmd

import (
	"fmt"
	"os"

	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/update"
)

func cmdUpdate(g *Globals, _ []string) int {
	fmt.Println("==> refreshing IOC data")
	if err := update.IOCsForce(g.DataDir); err != nil {
		fmt.Fprintln(os.Stderr, "IOC update failed:", err)
		return 1
	}
	fmt.Println("==> checking osv-scanner")
	if err := osv.Ensure(g.BinDir); err != nil {
		fmt.Fprintln(os.Stderr, "osv-scanner install failed:", err)
		// Non-fatal: scans still run, OSV section will be skipped.
	}
	fmt.Println("ok")
	return 0
}
