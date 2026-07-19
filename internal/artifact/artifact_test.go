package artifact

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func init() {
	if os.Getenv("GO_WANT_ARTIFACT_HELPER") != "1" {
		return
	}
	switch filepath.Base(os.Args[0]) {
	case "syft":
		if len(os.Args) < 4 || !strings.HasPrefix(os.Args[3], "spdx-json=") {
			os.Exit(9)
		}
		body := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`
		if os.Getenv("TEST_BAD_SBOM") == "1" {
			body = `{"not":"spdx"}`
		}
		if err := os.WriteFile(strings.TrimPrefix(os.Args[3], "spdx-json="), []byte(body), 0o600); err != nil {
			os.Exit(10)
		}
	case "grype":
		if os.Getenv("GRYPE_DB_REQUIRE_UPDATE_CHECK") != "true" ||
			os.Getenv("GRYPE_DB_VALIDATE_BY_HASH_ON_START") != "true" {
			os.Exit(11)
		}
		if err := os.WriteFile(os.Getenv("TEST_GRYPE_LOG"), []byte(strings.Join(os.Args[1:], " ")), 0o600); err != nil {
			os.Exit(12)
		}
		if code, _ := strconv.Atoi(os.Getenv("TEST_GRYPE_EXIT")); code != 0 {
			os.Exit(code)
		}
	default:
		os.Exit(13)
	}
	os.Exit(0)
}

func TestRunGeneratesAndScansExactSBOM(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "grype.log")
	linkHelpers(t, bin)
	t.Setenv("GO_WANT_ARTIFACT_HELPER", "1")
	t.Setenv("TEST_GRYPE_LOG", logPath)
	sbom := filepath.Join(t.TempDir(), "result.spdx.json")
	if err := Run(Options{Image: "example:test", SBOMPath: sbom, FailOn: "high", BinDir: bin}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "sbom:"+sbom+" --fail-on high") {
		t.Fatalf("grype did not scan exact SBOM: %s", got)
	}
}

func TestRunRejectsMalformedSBOM(t *testing.T) {
	bin := t.TempDir()
	linkHelpers(t, bin)
	t.Setenv("GO_WANT_ARTIFACT_HELPER", "1")
	t.Setenv("TEST_BAD_SBOM", "1")
	err := Run(Options{Image: "example:test", SBOMPath: filepath.Join(t.TempDir(), "bad.json"), FailOn: "high", BinDir: bin})
	if err == nil || !strings.Contains(err.Error(), "not an SPDX document") {
		t.Fatalf("expected malformed SBOM failure, got %v", err)
	}
}

func TestRunPropagatesGrypePolicyFailure(t *testing.T) {
	bin := t.TempDir()
	linkHelpers(t, bin)
	t.Setenv("GO_WANT_ARTIFACT_HELPER", "1")
	t.Setenv("TEST_GRYPE_LOG", filepath.Join(t.TempDir(), "grype.log"))
	t.Setenv("TEST_GRYPE_EXIT", "7")
	err := Run(Options{Image: "example:test", SBOMPath: filepath.Join(t.TempDir(), "result.json"), FailOn: "high", BinDir: bin})
	if err == nil || !strings.Contains(err.Error(), "grype policy failed") {
		t.Fatalf("expected Grype policy failure, got %v", err)
	}
}

func TestRunRejectsInvalidSeverity(t *testing.T) {
	err := Run(Options{Image: "example:test", SBOMPath: "out.json", FailOn: "urgent"})
	if err == nil || !strings.Contains(err.Error(), "invalid severity") {
		t.Fatalf("expected severity failure, got %v", err)
	}
}

func linkHelpers(t *testing.T, dir string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syft", "grype"} {
		if err := os.Symlink(executable, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}
