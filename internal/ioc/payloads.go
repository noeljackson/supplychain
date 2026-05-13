package ioc

import (
	"io/fs"
	"path/filepath"
)

// PayloadHit is a single file on disk whose basename matches a known
// malicious payload filename.
type PayloadHit struct {
	Path     string
	Filename string
}

// FindPayloads walks target and returns files whose basename is in `names`.
// Skipped: the .git directory inside target. We DO walk node_modules — that's
// the most common place the malware writes itself.
func FindPayloads(target string, names []string) ([]PayloadHit, error) {
	if len(names) == 0 {
		return nil, nil
	}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}

	var hits []PayloadHit
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if _, ok := set[d.Name()]; ok {
			hits = append(hits, PayloadHit{Path: path, Filename: d.Name()})
		}
		return nil
	})
	return hits, err
}
