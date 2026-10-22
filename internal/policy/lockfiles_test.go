package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/osv"
)

func lockfilePolicy(patterns string) string {
	return `{"schema_version": 1, "advisories": {"minimum_severity": "any", "only_fixed": false},
	  "exceptions": [], "lockfiles": [` + patterns + `]}`
}

func writeTracked(t *testing.T, repo, rel, body string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "-C", repo, "add", rel).Run(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsInvalidLockfilePatterns(t *testing.T) {
	for pattern, want := range map[string]string{
		`""`:                             "non-empty",
		`"/etc/Cargo.lock"`:              "clean path inside the target",
		`"../other/Cargo.lock"`:          "clean path inside the target",
		`"a/../Cargo.lock"`:              "clean path inside the target",
		`"deployments\\\\x.Cargo.lock"`:  "forward-slash",
		`"deployments/[.Cargo.lock"`:     "invalid pattern",
		`"deployments/x.lock"`:           "must end in .<format>",
		`"x.Cargo.lock", "x.Cargo.lock"`: "duplicate pattern",
	} {
		t.Run(pattern, func(t *testing.T) {
			repo := initPolicyRepo(t)
			writePolicy(t, repo, lockfilePolicy(pattern))
			_, err := Load(repo, "", policyNow)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Load() error = %v, want %q", err, want)
			}
		})
	}
}

func TestResolveLockfilesExpandsPatternsToTrackedFiles(t *testing.T) {
	repo := initPolicyRepo(t)
	writePolicy(t, repo, lockfilePolicy(`"deployments/docker/*.Cargo.lock", "images/web.package-lock.json"`))
	writeTracked(t, repo, "deployments/docker/derp.Cargo.lock", "version = 3\n")
	writeTracked(t, repo, "deployments/docker/mesh.Cargo.lock", "version = 3\n")
	writeTracked(t, repo, "images/web.package-lock.json", "{}\n")
	loaded, err := Load(repo, "", policyNow)
	if err != nil {
		t.Fatal(err)
	}
	lockfiles, err := loaded.ResolveLockfiles(repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []osv.Lockfile{
		{Format: "Cargo.lock", Path: filepath.Join(repo, "deployments/docker/derp.Cargo.lock")},
		{Format: "Cargo.lock", Path: filepath.Join(repo, "deployments/docker/mesh.Cargo.lock")},
		{Format: "package-lock.json", Path: filepath.Join(repo, "images/web.package-lock.json")},
	}
	if len(lockfiles) != len(want) {
		t.Fatalf("ResolveLockfiles() = %+v, want %+v", lockfiles, want)
	}
	for i := range want {
		if lockfiles[i] != want[i] {
			t.Fatalf("ResolveLockfiles()[%d] = %+v, want %+v", i, lockfiles[i], want[i])
		}
	}
}

func TestResolveLockfilesFailsClosed(t *testing.T) {
	tests := map[string]struct {
		setup func(t *testing.T, repo string)
		want  string
	}{
		"no match": {
			setup: func(*testing.T, string) {},
			want:  "matches no file",
		},
		"untracked": {
			setup: func(t *testing.T, repo string) {
				path := filepath.Join(repo, "deployments/docker/derp.Cargo.lock")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("version = 3\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "must be tracked by Git",
		},
		"symlink": {
			setup: func(t *testing.T, repo string) {
				writeTracked(t, repo, "real.Cargo.lock", "version = 3\n")
				dir := filepath.Join(repo, "deployments/docker")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(repo, "real.Cargo.lock"), filepath.Join(dir, "derp.Cargo.lock")); err != nil {
					t.Fatal(err)
				}
			},
			want: "regular, non-symlinked file",
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			repo := initPolicyRepo(t)
			writePolicy(t, repo, lockfilePolicy(`"deployments/docker/*.Cargo.lock"`))
			testCase.setup(t, repo)
			loaded, err := Load(repo, "", policyNow)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loaded.ResolveLockfiles(repo); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("ResolveLockfiles() error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestBuiltinPolicyNamesNoLockfiles(t *testing.T) {
	lockfiles, err := Builtin().ResolveLockfiles(t.TempDir())
	if err != nil || lockfiles != nil {
		t.Fatalf("ResolveLockfiles() = %+v, %v; want none", lockfiles, err)
	}
}
