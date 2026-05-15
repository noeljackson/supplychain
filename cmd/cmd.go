// Package cmd dispatches subcommands for the supplychain CLI.
package cmd

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// Version is resolved (in priority order) from:
//  1. -ldflags "-X github.com/noeljackson/supplychain/cmd.Version=..." at build
//  2. runtime/debug.ReadBuildInfo() for `go install`-style builds
//  3. the "dev" fallback for plain `go build` in a checkout
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		Version = v
	}
}

// Globals holds the parsed global flags + dependencies passed down to commands.
type Globals struct {
	JSON        bool
	Quiet       bool
	NoUpdate    bool
	Scripts     bool // --scripts: include install-script section in human output
	ScriptsOnly bool // --scripts-only: ONLY show install-script section

	// FreshnessDays > 0 enables the freshness check with that window. Set via
	// --freshness (=7) or --freshness-days=N.
	FreshnessDays int

	// Signatures enables `npm audit signatures` for projects with a
	// package-lock.json. Set via --signatures.
	Signatures bool

	// Maintainers enables the maintainer-change check. Set via --maintainers.
	// First run establishes a baseline silently.
	Maintainers bool

	// TyposquatDistance overrides the default Levenshtein threshold (1).
	// Distance 2 catches double-typos but pulls in false positives like
	// vercel/parcel, jose/joi. Set via --typosquat-distance=N.
	TyposquatDistance int

	// DefaultIOCs is the embedded IOC data bundled into the binary.
	// User-writable overrides live under DataDir/iocs/.
	DefaultIOCs embed.FS

	// DataDir is where mutable state lives (auto-updated IOC files, bootstrapped
	// helper binaries, throttle timestamps). Default: $XDG_DATA_HOME/supplychain.
	DataDir string

	// BinDir is where supplychain installs supporting binaries (e.g. osv-scanner).
	BinDir string
}

// Run dispatches the CLI. Returns an exit code.
func Run(defaultIOCs embed.FS) int {
	g := &Globals{DefaultIOCs: defaultIOCs}

	// Strip global flags from the full argv first, then take the first
	// remaining token as the subcommand.
	remaining := parseGlobalFlags(g, os.Args[1:])
	if len(remaining) == 0 {
		usage()
		return 2
	}
	cmd := remaining[0]
	args := remaining[1:]

	if err := initPaths(g); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	switch cmd {
	case "scan":
		return cmdScan(g, args)
	case "scan-all":
		return cmdScanAll(g, args)
	case "update":
		return cmdUpdate(g, args)
	case "doctor":
		return cmdDoctor(g, args)
	case "install-hook":
		return cmdInstallHook(g, args)
	case "audit-system":
		return cmdAuditSystem(g, args)
	case "version", "--version", "-v":
		fmt.Println("supplychain", Version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage()
		return 2
	}
}

func parseGlobalFlags(g *Globals, args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch {
		case a == "--json":
			g.JSON = true
		case a == "--quiet" || a == "-q":
			g.Quiet = true
		case a == "--no-update":
			g.NoUpdate = true
		case a == "--scripts":
			g.Scripts = true
		case a == "--scripts-only":
			g.ScriptsOnly = true
			g.Scripts = true
		case a == "--freshness":
			g.FreshnessDays = 7
		case strings.HasPrefix(a, "--freshness-days="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--freshness-days=")); err == nil && n > 0 {
				g.FreshnessDays = n
			}
		case a == "--signatures":
			g.Signatures = true
		case a == "--maintainers":
			g.Maintainers = true
		case strings.HasPrefix(a, "--typosquat-distance="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--typosquat-distance=")); err == nil && n > 0 {
				g.TyposquatDistance = n
			}
		default:
			out = append(out, a)
		}
	}
	return out
}

func initPaths(g *Globals) error {
	if g.DataDir == "" {
		switch {
		case os.Getenv("SUPPLYCHAIN_DATA_DIR") != "":
			g.DataDir = os.Getenv("SUPPLYCHAIN_DATA_DIR")
		case os.Getenv("XDG_DATA_HOME") != "":
			g.DataDir = filepath.Join(os.Getenv("XDG_DATA_HOME"), "supplychain")
		default:
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			g.DataDir = filepath.Join(home, ".local", "share", "supplychain")
		}
	}
	if g.BinDir == "" {
		if v := os.Getenv("SUPPLYCHAIN_BIN_DIR"); v != "" {
			g.BinDir = v
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			g.BinDir = filepath.Join(home, ".local", "bin")
		}
	}
	return os.MkdirAll(g.DataDir, 0o755)
}

func usage() {
	fmt.Fprint(os.Stderr, `supplychain — supply-chain scanner

usage: supplychain <command> [args] [flags]

commands:
  scan [path]           scan a path (default: cwd) for known-bad deps + IOCs
  scan-all [root]       scan every git repo under root (default: ~/src)
  audit-system [flags]  forensic sweep: persistence files, dropped payloads
                        anywhere under $HOME, C2 domains in shell history,
                        dead-drop commit signatures across all git repos.
                        Flags: --git-root=PATH (default ~/src)
  update                refresh IOC data and osv-scanner
  install-hook <kind>   install integration hook: claude-sessionstart | pre-commit
  doctor                check install health
  version               print version
  help                  show this

flags (may appear anywhere):
  --json                machine-readable output
  --quiet, -q           silent if clean (useful in hooks)
  --no-update           skip auto-update for this run
  --scripts             include install/preinstall/postinstall script section
  --scripts-only        show only the install-script section (for audits)
  --freshness           flag installed deps published in the last 7 days
                        (queries npm registry; results cached 24h per package)
  --freshness-days=N    custom freshness window (implies --freshness)
  --signatures          run 'npm audit signatures' for projects with
                        a package-lock.json (requires npm on PATH)
  --maintainers         track maintainer-set changes per package. First run
                        establishes a baseline silently; subsequent runs
                        flag deltas (queries npm registry; baseline persists
                        under DataDir/maintainers/)
  --typosquat-distance=N  override the typosquat edit-distance threshold
                          (default 1 — unambiguous single-typo squats only)

environment:
  SUPPLYCHAIN_DATA_DIR  where mutable state lives (default: $XDG_DATA_HOME/supplychain,
                        else ~/.local/share/supplychain)
  SUPPLYCHAIN_BIN_DIR   where bootstrapped binaries (osv-scanner) install
                        (default: ~/.local/bin)
  SUPPLYCHAIN_IOC_URL   base URL for IOC data updates
                        (default: https://raw.githubusercontent.com/noeljackson/supplychain/main/iocs)
  SUPPLYCHAIN_PIN       git ref / tag to pin IOC data to (default: main)
  SUPPLYCHAIN_OSM_TOKEN OpenSourceMalware.com bearer token (free tier ok).
                        When set, 'supplychain update' fetches /query-latest
                        and merges npm IOCs into the matcher set. Absent →
                        OSM integration is a no-op. Free-tier TOS: non-
                        commercial use only.
`)
}

// UserIOCsDir returns the writable IOC override directory.
func (g *Globals) UserIOCsDir() string {
	return filepath.Join(g.DataDir, "iocs")
}

// OpenIOC opens an IOC file: prefers $DataDir/iocs/<name>, falls back to embedded.
func (g *Globals) OpenIOC(name string) (fs.File, error) {
	p := filepath.Join(g.UserIOCsDir(), name)
	if f, err := os.Open(p); err == nil {
		return f, nil
	}
	return g.DefaultIOCs.Open("iocs/" + name)
}
