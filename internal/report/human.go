// Package report formats scan findings.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/noeljackson/supplychain/internal/scan"
)

// Human writes a human-readable report. Returns 1 if there are hits, 0 if clean.
func Human(w io.Writer, f scan.Findings, quiet bool) int {
	if !f.HasHits() {
		if !quiet {
			fmt.Fprintf(w, "ok  clean: %s\n", f.Target)
			if !f.OSVAvailable {
				fmt.Fprintln(w, "    note: osv-scanner not installed — OSV advisory check skipped. Run 'supplychain update' to install.")
			}
		}
		return 0
	}

	fmt.Fprintf(w, "err supply-chain findings in %s\n", f.Target)

	if len(f.OSV) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "OSV advisories:")
		for _, v := range f.OSV {
			fmt.Fprintf(w, "  %s@%s  %s  (%s)\n", v.Name, v.Version,
				strings.Join(v.IDs, ", "), v.SourcePath)
		}
	}
	if len(f.Manifest) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "IOC matches in package.json manifests:")
		for _, h := range f.Manifest {
			fmt.Fprintf(w, "  %s@%s declared as %q (%s) in %s — %s\n",
				h.Name, h.BadVersion, h.Range, h.Reason, h.Section, h.File)
		}
	}
	if len(f.Lockfile) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "IOC matches in lockfiles:")
		for _, h := range f.Lockfile {
			fmt.Fprintf(w, "  %s@%s in %s\n", h.Name, h.Version, h.File)
		}
	}
	if len(f.Payloads) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Dropped payload filenames found on disk:")
		for _, p := range f.Payloads {
			fmt.Fprintf(w, "  %s  (matches IOC %s)\n", p.Path, p.Filename)
		}
	}
	if len(f.Persistence) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "OS-level persistence artifacts found:")
		for _, p := range f.Persistence {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}
	return 1
}
