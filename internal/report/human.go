// Package report formats scan findings.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/update"
)

// Options controls human-output rendering.
type Options struct {
	Quiet          bool
	ShowScripts    bool // include the install-script section
	ScriptsOnly    bool // suppress everything except the install-script section
	FailOnAdvisory bool // treat OSV/drift advisory findings as exit-code failures
	ScannerVersion string
	IOCSnapshot    update.SnapshotIdentity
}

// Human writes a human-readable report. Returns 1 if there are hits, 0 if clean.
// "Hits" excludes install-script findings (informational only).
func Human(w io.Writer, f scan.Findings, opts Options) int {
	if opts.ScriptsOnly {
		renderScripts(w, f, true)
		return 0
	}

	hasSupplyChain := f.HasSupplyChainHits()
	hasAdvisory := f.HasAdvisoryHits()
	hasCoverageGaps := f.HasCoverageGaps()
	hasRequiredCoverageGaps := f.HasRequiredCoverageGaps()
	if !hasSupplyChain && !hasAdvisory && !hasCoverageGaps {
		if !opts.Quiet {
			fmt.Fprintf(w, "ok  clean: %s\n", f.Target)
			if f.OSVStatus == scan.OSVNotApplicable {
				fmt.Fprintln(w, "    note: OSV dependency scan not applicable — no supported package sources found.")
			} else if !f.OSVAvailable {
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

	switch {
	case hasSupplyChain:
		fmt.Fprintf(w, "err supply-chain indicators in %s\n", f.Target)
	case hasAdvisory:
		fmt.Fprintf(w, "warn dependency advisory/audit findings in %s\n", f.Target)
	case hasRequiredCoverageGaps:
		fmt.Fprintf(w, "err required scan coverage incomplete in %s\n", f.Target)
	default:
		fmt.Fprintf(w, "warn optional scan coverage incomplete in %s\n", f.Target)
	}

	if len(f.Manifest) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "IOC matches in package.json manifests:")
		for _, h := range f.Manifest {
			fmt.Fprintf(w, "  %s@%s declared as %q (%s) in %s — %s\n",
				h.Name, h.BadVersion, h.Range, h.Reason, h.Section, h.File)
			if h.Resolved != "" {
				if h.ResolvedBad {
					fmt.Fprintf(w, "    will install %s on next `npm install` — RESOLVES TO A MALICIOUS VERSION\n", h.Resolved)
				} else {
					fmt.Fprintf(w, "    will install %s on next `npm install` (currently a non-flagged version)\n", h.Resolved)
				}
			}
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
	if len(f.Typosquat) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Possible typosquats (similar to popular package names):")
		for _, h := range f.Typosquat {
			fmt.Fprintf(w, "  %s (declared in %s)  — %d edit(s) from %q\n",
				h.Name, h.Section, h.Distance, h.Confused)
		}
	}
	if len(f.Signatures) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "npm audit signatures — tampered or unsigned packages:")
		for _, h := range f.Signatures {
			fmt.Fprintf(w, "  %s@%s  %s  (%s)\n", h.Name, h.Version, h.Reason, h.Resolved)
		}
	}
	if len(f.Vendored) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Vendored npm artifacts that failed registry verification:")
		for _, hit := range f.Vendored {
			location := hit.Path
			if location == "" {
				location = "registry metadata"
			}
			fmt.Fprintf(w, "  %s  %s  %s (%s)\n", hit.Package, hit.Code, hit.Message, location)
		}
	}
	if len(f.Maintainers) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Maintainer-set changes since last scan:")
		for _, h := range f.Maintainers {
			fmt.Fprintf(w, "  %s (%s)\n", h.Name, h.Reason)
			if len(h.Added) > 0 {
				fmt.Fprintf(w, "    +added:   %s\n", strings.Join(h.Added, ", "))
			}
			if len(h.Removed) > 0 {
				fmt.Fprintf(w, "    -removed: %s\n", strings.Join(h.Removed, ", "))
			}
			fmt.Fprintf(w, "    current:  %s\n", strings.Join(h.Current, ", "))
		}
	}
	if len(f.OSV) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Dependency vulnerability advisories (OSV; non-IOC):")
		for _, v := range f.OSV {
			fmt.Fprintf(w, "  %s@%s  %s  (%s)\n", v.Name, v.Version,
				strings.Join(v.IDs, ", "), v.SourcePath)
		}
	}
	if len(f.Drift) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Manifest/lockfile drift (audit warning):")
		for _, h := range f.Drift {
			switch h.Reason {
			case "missing-from-lockfile":
				fmt.Fprintf(w, "  %s declared in %s but absent from lockfile — stale lockfile (range %q, lockfile %s)\n",
					h.Name, h.Section, h.Range, h.LockFile)
			case "lockfile-out-of-range":
				fmt.Fprintf(w, "  %s manifest=%q lockfile=%s — lockfile pin doesn't satisfy manifest range (in %s)\n",
					h.Name, h.Range, h.LockVersion, h.Section)
			default:
				fmt.Fprintf(w, "  %s — %s\n", h.Name, h.Reason)
			}
		}
	}
	if len(f.Suppressed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Suppressed advisory/audit findings (policy-visible):")
		for _, item := range f.Suppressed {
			selector := item.AdvisoryID
			if selector == "" {
				selector = item.DriftReason
			}
			fmt.Fprintf(w, "  %s %s %s — %s", item.Kind, item.Package, selector, item.Reason)
			if item.Owner != "" {
				fmt.Fprintf(w, " (owner %s, expires %s)", item.Owner, item.Expires)
			}
			fmt.Fprintln(w)
		}
	}
	renderFreshness(w, f)
	if opts.ShowScripts && len(f.Scripts) > 0 {
		renderScripts(w, f, false)
	} else if len(f.Scripts) > 0 {
		fmt.Fprintf(w, "\nnote: %d installed deps declare install/postinstall scripts. Run with --scripts to list.\n", len(f.Scripts))
	}
	renderCoverageGaps(w, f)
	if hasRequiredCoverageGaps {
		return ExitOperational
	}
	if hasSupplyChain || (opts.FailOnAdvisory && hasAdvisory) {
		return ExitFindings
	}
	return ExitClean
}

func renderCoverageGaps(w io.Writer, f scan.Findings) {
	if !f.HasCoverageGaps() {
		return
	}
	names := make([]string, 0, len(f.Coverage))
	for name, result := range f.Coverage {
		if result.Status == "incomplete" || result.Status == "failed" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scan coverage gaps:")
	for _, name := range names {
		result := f.Coverage[name]
		requirement := "optional"
		if result.Required {
			requirement = "required"
		}
		fmt.Fprintf(w, "  %s  %s, %s", name, result.Status, requirement)
		if result.Diagnostic != "" {
			fmt.Fprintf(w, ": %s", result.Diagnostic)
		}
		fmt.Fprintln(w)
	}
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
