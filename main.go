// Package main is the supplychain CLI entry point.
package main

import (
	"embed"
	"os"

	"github.com/noeljackson/supplychain/cmd"
)

// Default IOC data is embedded so a fresh install works offline. Auto-update
// writes newer copies to $XDG_DATA_HOME/supplychain/iocs/, which take priority.
//
//go:embed iocs/persistence-paths.txt iocs/payload-filenames.txt iocs/packages.txt iocs/c2-domains.txt iocs/dead-drop-signatures.txt iocs/blocked-package-names.txt
var defaultIOCs embed.FS

func main() {
	os.Exit(cmd.Run(defaultIOCs))
}
