// Package report formats scan findings.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/noeljackson/supplychain/internal/scan"
)

// Options controls human-output rendering.
type Options struct {
	Quiet       bool
	ShowScripts bool // include the install-script section
	ScriptsOnly bool // suppress everything except the install-script section
}

// Human writes a human-readable report. Returns 1 if there are hits, 0 if clean.
// "Hits" excludes install-script findings (informational only).
func Human(w io.Writer, f scan.Findings, opts Options) int {
	if opts.ScriptsOnly {
		renderScripts(w, f, true)
		return 0
	}

	if !f.HasHits() {
		if !opts.Quiet {
			fmt.Fprintf(w, "ok  clean: %s\n", f.Target)
			if !f.OSVAvailable {
				fmt.Fprintln(w, "    note: osv-scanner not installed — OSV advisory check skipped. Run 'supplychain update' to install.")
			}
			renderFreshness(w, f)
			if len(f.Scripts) > 0 {
				if opts.ShowScripts {
					renderScripts(w, f, false)
				} else {
					fmt.Fprintf(w, "    note: %d installed deps declare install/postinstall scripts. Run with --scripts to list, --scripts-only to audit them in isolation.\n", len(f.Scripts))
				}
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
	renderFreshness(w, f)
	if opts.ShowScripts && len(f.Scripts) > 0 {
		renderScripts(w, f, false)
	} else if len(f.Scripts) > 0 {
		fmt.Fprintf(w, "\nnote: %d installed deps declare install/postinstall scripts. Run with --scripts to list.\n", len(f.Scripts))
	}
	return 1
}

func renderFreshness(w io.Writer, f scan.Findings) {
	if len(f.Freshness) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Recently-published deps (informational, %d):\n", len(f.Freshness))
	for _, h := range f.Freshness {
		fmt.Fprintf(w, "  %s@%s  published %s ago (%s)\n",
			h.Name, h.Version, h.AgeHuman, h.Published.Format("2006-01-02"))
	}
}

func renderScripts(w io.Writer, f scan.Findings, headerless bool) {
	if !headerless {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Install-script declarations (%d deps, informational):\n", len(f.Scripts))
	for _, h := range f.Scripts {
		for hook, body := range h.Hooks {
			one := strings.ReplaceAll(body, "\n", " ⏎ ")
			if len(one) > 160 {
				one = one[:157] + "..."
			}
			fmt.Fprintf(w, "  %s@%s  %s: %s\n", h.Name, h.Version, hook, one)
		}
	}
}
