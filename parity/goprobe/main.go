// Command goprobe dumps internal scanner state in stable, line-oriented form so
// the Rust port can be diffed against this implementation.
//
// It exists only for the duration of the port and is removed with the rest of
// the Go tree once every check reaches parity. Each probe is a subcommand; the
// matching Rust command is declared alongside it in parity.toml.
package main

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/noeljackson/supplychain/internal/ioc"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: goprobe <probe>")
		os.Exit(2)
	}
	var err error
	switch probe := os.Args[1]; probe {
	case "ioc":
		err = probeIOC()
	case "semver-constraints":
		err = probeConstraints()
	default:
		fmt.Fprintf(os.Stderr, "goprobe: unknown probe %q\n", probe)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "goprobe: %v\n", err)
		os.Exit(1)
	}
}

// probeIOC dumps every parsed indicator, including whether each malicious
// version parsed as semver, since that governs range matching.
func probeIOC() error {
	open := func(name string) (fs.File, error) { return os.DirFS("iocs").Open(name) }
	packages, err := ioc.LoadPackages(open)
	if err != nil {
		return err
	}
	for _, p := range packages {
		parsed := "-"
		if p.Parsed != nil {
			parsed = p.Parsed.String()
		}
		fmt.Printf("PKG\t%s\t%s\t%s\n", p.Name, p.Version, parsed)
	}
	for _, name := range []string{
		"blocked-package-names.txt",
		"c2-domains.txt",
		"persistence-paths.txt",
		"dead-drop-signatures.txt",
		"payload-filenames.txt",
	} {
		list, err := ioc.LoadList(open, name)
		if err != nil {
			return err
		}
		for _, value := range list {
			fmt.Printf("LIST\t%s\t%s\n", name, value)
		}
	}
	return nil
}
