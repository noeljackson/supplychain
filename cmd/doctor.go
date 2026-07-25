package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/report"
	"github.com/noeljackson/supplychain/internal/update"
)

type doctorCheck struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Required   bool   `json:"required"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

type doctorReport struct {
	SchemaVersion int                     `json:"schema_version"`
	Command       string                  `json:"command"`
	Scanner       report.ScannerIdentity  `json:"scanner"`
	Profile       string                  `json:"profile"`
	Healthy       bool                    `json:"healthy"`
	IOCSnapshot   update.SnapshotIdentity `json:"ioc_snapshot"`
	Checks        []doctorCheck           `json:"checks"`
}

func cmdDoctor(g *Globals, args []string) int {
	profile := "source"
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--profile="):
			profile = strings.TrimPrefix(arg, "--profile=")
		default:
			fmt.Fprintln(os.Stderr, "usage: supplychain doctor [--profile=source|strict|image|workflows|secrets]")
			return report.ExitUsage
		}
	}
	required, ok := doctorRequirements(profile)
	if !ok {
		fmt.Fprintln(os.Stderr, "doctor: unknown profile:", profile)
		return report.ExitUsage
	}
	checks := make([]doctorCheck, 0, len(required)+3)
	iocIdentity, iocErr := update.ReadSnapshotIdentity(g.DataDir, g.DefaultIOCs)
	iocCheck := doctorCheck{Name: "ioc_snapshot", Required: true, Status: "ok"}
	if iocErr != nil {
		iocCheck.Status = "unhealthy"
		iocCheck.Diagnostic = iocErr.Error()
	}
	checks = append(checks, iocCheck)

	helpers := map[string]bool{"osv-scanner": false}
	for name, isRequired := range required {
		helpers[name] = isRequired
	}
	for name, isRequired := range helpers {
		checks = append(checks, locateDoctorHelper(name, g.BinDir, isRequired))
	}
	if onPath(g.BinDir) {
		checks = append(checks, doctorCheck{Name: "managed_bin_on_path", Status: "ok"})
	} else {
		checks = append(checks, doctorCheck{
			Name:       "managed_bin_on_path",
			Status:     "warning",
			Diagnostic: g.BinDir + " is not in PATH",
		})
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	healthy := doctorHealthy(checks)
	document := doctorReport{
		SchemaVersion: report.SchemaVersion,
		Command:       "doctor",
		Scanner:       report.ScannerIdentity{Name: "supplychain", Version: Version},
		Profile:       profile,
		Healthy:       healthy,
		IOCSnapshot:   iocIdentity,
		Checks:        checks,
	}
	if g.JSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(document)
	} else {
		fmt.Printf("supplychain %s — doctor profile %s\n", Version, profile)
		for _, item := range checks {
			requirement := "optional"
			if item.Required {
				requirement = "required"
			}
			fmt.Printf("%-20s %-10s %s", item.Name+":", item.Status, requirement)
			if item.Version != "" {
				fmt.Printf(" (%s)", item.Version)
			}
			if item.Diagnostic != "" {
				fmt.Printf(" — %s", item.Diagnostic)
			}
			fmt.Println()
		}
	}
	if !healthy {
		return report.ExitOperational
	}
	return report.ExitClean
}

func doctorRequirements(profile string) (map[string]bool, bool) {
	switch profile {
	case "source":
		return map[string]bool{}, true
	case "strict":
		return map[string]bool{
			"osv-scanner": true,
			"gitleaks":    true,
			"zizmor":      true,
		}, true
	case "image":
		return map[string]bool{"syft": true, "grype": true}, true
	case "workflows":
		return map[string]bool{"zizmor": true}, true
	case "secrets":
		return map[string]bool{"gitleaks": true}, true
	default:
		return nil, false
	}
}

func locateDoctorHelper(name, binDir string, required bool) doctorCheck {
	item := doctorCheck{Name: name, Required: required, Status: "ok"}
	var path, version string
	var err error
	if name == "osv-scanner" {
		path, version, err = osv.Locate(binDir)
	} else {
		managed := filepath.Join(binDir, name)
		if info, statErr := os.Stat(managed); statErr == nil &&
			!info.IsDir() && info.Mode()&0o111 != 0 {
			path = managed
		} else {
			path, err = exec.LookPath(name)
		}
		if err == nil {
			output, versionErr := exec.Command(path, "--version").CombinedOutput()
			if versionErr == nil {
				version = strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
			}
		}
	}
	if err != nil {
		item.Status = "missing"
		if required {
			item.Diagnostic = "required by selected profile"
		} else {
			item.Diagnostic = "optional capability unavailable"
		}
		return item
	}
	item.Path = path
	item.Version = version
	return item
}

func doctorHealthy(checks []doctorCheck) bool {
	for _, item := range checks {
		if item.Required && item.Status != "ok" {
			return false
		}
	}
	return true
}

func onPath(dir string) bool {
	for _, path := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if path == dir {
			return true
		}
	}
	return false
}
