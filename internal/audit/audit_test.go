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
	scanned, hits := scanHistory([]string{hpath}, []string{"masscan.cloud", "getsession.org"})
	if len(scanned) != 1 {
		t.Fatalf("scanned=%d, want 1", len(scanned))
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
	scanned, hits := scanHistory([]string{"/no/such/file"}, []string{"any.example"})
	if len(scanned) != 0 || len(hits) != 0 {
		t.Errorf("expected empty results for missing file, got scanned=%v hits=%v", scanned, hits)
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
