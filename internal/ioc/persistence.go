package ioc

import (
	"os"
	"path/filepath"
	"strings"
)

// CheckPersistence returns the subset of paths from the IOC list that actually
// exist on disk. ~ and $HOME are expanded.
func CheckPersistence(paths []string) []string {
	home, _ := os.UserHomeDir()
	var hits []string
	for _, p := range paths {
		expanded := expand(p, home)
		if expanded == "" {
			continue
		}
		if _, err := os.Lstat(expanded); err == nil {
			hits = append(hits, expanded)
		}
	}
	return hits
}

func expand(p, home string) string {
	if home == "" {
		return p
	}
	p = strings.ReplaceAll(p, "$HOME", home)
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(home, p[2:])
	} else if p == "~" {
		p = home
	}
	return p
}
