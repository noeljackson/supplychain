package maintainer

import (
	"reflect"
	"testing"

	"github.com/noeljackson/supplychain/internal/registry"
)

func TestDiffSets(t *testing.T) {
	cases := []struct {
		name        string
		prev, curr  []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "no change",
			prev:        []string{"a", "b"},
			curr:        []string{"a", "b"},
			wantAdded:   nil,
			wantRemoved: nil,
		},
		{
			name:        "added one",
			prev:        []string{"a"},
			curr:        []string{"a", "b"},
			wantAdded:   []string{"b"},
			wantRemoved: nil,
		},
		{
			name:        "removed one",
			prev:        []string{"a", "b"},
			curr:        []string{"a"},
			wantAdded:   nil,
			wantRemoved: []string{"b"},
		},
		{
			name:        "swap one",
			prev:        []string{"alice", "bob"},
			curr:        []string{"alice", "attacker"},
			wantAdded:   []string{"attacker"},
			wantRemoved: []string{"bob"},
		},
		{
			name:        "first time (prev empty)",
			prev:        nil,
			curr:        []string{"alice"},
			wantAdded:   []string{"alice"},
			wantRemoved: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, r := diffSets(c.prev, c.curr)
			if !reflect.DeepEqual(a, c.wantAdded) {
				t.Errorf("added: got %v, want %v", a, c.wantAdded)
			}
			if !reflect.DeepEqual(r, c.wantRemoved) {
				t.Errorf("removed: got %v, want %v", r, c.wantRemoved)
			}
		})
	}
}

func TestMaintainersToStrings_DedupSorts(t *testing.T) {
	in := []registry.Maintainer{
		{Name: "bob"},
		{Name: "alice"},
		{Name: "bob"}, // dup
		{Email: "carol@example.com"},
		{}, // empty, skipped
	}
	got := maintainersToStrings(in)
	want := []string{"alice", "bob", "carol@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
