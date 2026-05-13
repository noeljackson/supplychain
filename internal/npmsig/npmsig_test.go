package npmsig

import "testing"

func TestParse_Empty(t *testing.T) {
	hits, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hits != nil {
		t.Errorf("expected nil, got %v", hits)
	}
}

func TestParse_NothingWrong(t *testing.T) {
	in := []byte(`{"invalid":[],"missing":[]}`)
	hits, err := parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("expected no hits, got %v", hits)
	}
}

func TestParse_InvalidAndMissing(t *testing.T) {
	in := []byte(`{
	  "invalid": [
	    {"name":"evil-pkg","version":"1.0.0","resolved":"https://r.example/evil-pkg-1.0.0.tgz"}
	  ],
	  "missing": [
	    {"name":"another","version":"2.0.0","resolved":"https://r.example/another-2.0.0.tgz"}
	  ]
	}`)
	hits, err := parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("len(hits)=%d, want 2: %+v", len(hits), hits)
	}
	want := map[string]string{"evil-pkg": "invalid", "another": "missing"}
	for _, h := range hits {
		if want[h.Name] != h.Reason {
			t.Errorf("%s: reason=%q, want %q", h.Name, h.Reason, want[h.Name])
		}
	}
}

func TestParse_GracefulOnNonJSON(t *testing.T) {
	// Some npm versions print a text summary even with --json. We tolerate that.
	hits, err := parse([]byte("some text not actually json"))
	if err != nil {
		t.Errorf("non-JSON should not error, got %v", err)
	}
	if hits != nil {
		t.Errorf("expected nil hits on non-JSON, got %v", hits)
	}
}
