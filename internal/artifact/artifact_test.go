package artifact

import (
	"os"
	"os/exec"
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
		log := strings.Join(os.Args[1:], " ")
		for i, arg := range os.Args[1:] {
			if arg != "--config" || i+2 >= len(os.Args) {
				continue
			}
			contents, err := os.ReadFile(os.Args[i+2])
			if err != nil {
				os.Exit(14)
			}
			log += "\nconfig:" + string(contents)
		}
		if err := os.WriteFile(os.Getenv("TEST_GRYPE_LOG"), []byte(log), 0o600); err != nil {
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
	if !strings.Contains(string(got), "--config ") || !strings.Contains(string(got), "config:ignore: []") {
		t.Fatalf("grype did not use isolated config: %s", got)
	}
}

func TestRunUsesExplicitTrackedVEX(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "grype.log")
	linkHelpers(t, bin)
	t.Setenv("GO_WANT_ARTIFACT_HELPER", "1")
	t.Setenv("TEST_GRYPE_LOG", logPath)
	root := initArtifactGitTarget(t)
	vexPath := filepath.Join(root, "security", "scanner.openvex.json")
	writeArtifactTestFile(t, vexPath, `{"@context":"https://openvex.dev/ns/v0.2.0"}`)
	gitAddArtifact(t, root, "security/scanner.openvex.json")

	err := Run(Options{
		Image:      "example:test",
		SBOMPath:   filepath.Join(t.TempDir(), "result.spdx.json"),
		FailOn:     "high",
		OnlyFixed:  true,
		VEXPath:    "security/scanner.openvex.json",
		PolicyRoot: root,
		BinDir:     bin,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--only-fixed", "--vex " + vexPath} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("grype log missing %q: %s", want, got)
		}
	}
}

func TestRunRejectsUntrackedVEX(t *testing.T) {
	root := initArtifactGitTarget(t)
	writeArtifactTestFile(t, filepath.Join(root, "scanner.openvex.json"), `{}`)
	err := Run(Options{
		Image:      "example:test",
		SBOMPath:   "out.json",
		FailOn:     "high",
		VEXPath:    "scanner.openvex.json",
		PolicyRoot: root,
	})
	if err == nil || !strings.Contains(err.Error(), "must be tracked") {
		t.Fatalf("expected untracked VEX failure, got %v", err)
	}
}

func TestRunRejectsSymlinkedVEX(t *testing.T) {
	root := initArtifactGitTarget(t)
	writeArtifactTestFile(t, filepath.Join(root, "real.openvex.json"), `{}`)
	if err := os.Symlink("real.openvex.json", filepath.Join(root, "scanner.openvex.json")); err != nil {
		t.Fatal(err)
	}
	gitAddArtifact(t, root, "real.openvex.json", "scanner.openvex.json")
	err := Run(Options{
		Image:      "example:test",
		SBOMPath:   "out.json",
		FailOn:     "high",
		VEXPath:    "scanner.openvex.json",
		PolicyRoot: root,
	})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected symlinked VEX failure, got %v", err)
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

func initArtifactGitTarget(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	writeArtifactTestFile(t, filepath.Join(target, "tracked.txt"), "tracked\n")
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "tracked.txt"}} {
		cmd := exec.Command("git", append([]string{"-C", target}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	return target
}

func gitAddArtifact(t *testing.T, target string, paths ...string) {
	t.Helper()
	args := append([]string{"-C", target, "add", "--"}, paths...)
	if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		t.Fatalf("git add %v: %v: %s", paths, err, output)
	}
}

func writeArtifactTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
