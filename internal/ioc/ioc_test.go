package ioc

import (
	"strings"
	"testing"
)

func TestParsePackages_ScopedAndUnscoped(t *testing.T) {
	in := `# comment
lodash@4.17.21

@scope/name@1.2.3
@tanstack/router-utils@1.161.11    # trailing comment

malformed-line
@badscope@1.0.0
weird@
@something@`
	got, err := parsePackages(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, version string }{
		{"lodash", "4.17.21"},
		{"@scope/name", "1.2.3"},
		{"@tanstack/router-utils", "1.161.11"},
		{"@badscope", "1.0.0"}, // legal as far as we're concerned — the @ at index 0 is just a scope-like prefix
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d (got %+v)", len(got), len(want), got)
	}
	for i, g := range got {
		if g.Name != want[i].name || g.Version != want[i].version {
			t.Errorf("[%d] got %s@%s, want %s@%s", i, g.Name, g.Version, want[i].name, want[i].version)
		}
	}
}

func TestParseList_StripsCommentsAndBlanks(t *testing.T) {
	in := `# header
foo
  bar
# inline section
baz # trailing
`
	got := parseList(strings.NewReader(in))
	want := []string{"foo", "bar", "baz"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("[%d] got %q, want %q", i, g, want[i])
		}
	}
}

func TestExpandPath(t *testing.T) {
	home := "/home/user"
	cases := []struct {
		in, want string
	}{
		{"~/foo", "/home/user/foo"},
		{"~", "/home/user"},
		{"$HOME/bar", "/home/user/bar"},
		{"/absolute/path", "/absolute/path"},
	}
	for _, c := range cases {
		if got := expand(c.in, home); got != c.want {
			t.Errorf("expand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
