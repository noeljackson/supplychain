package eol

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The judgement is deliberately small and fixed:
//
//   - A release cycle past its end of life for longer than EOLGrace is a
//     finding. Strict policy fails on it unless a dated, reviewed exception
//     covers the product and cycle.
//   - Within EOLGrace after its end of life, within EOLSoon before it, after
//     its active support ended, or when an exact pin trails its cycle's newest
//     release by more than LatestSettle, the pin is a warning.
//   - A dated apt snapshot older than SnapshotMaxAge is a warning.
//
// EOLGrace leaves room to adopt a successor that is itself still inside a
// minimum-release-age window: Rust and Go end a cycle the day the next one
// ships.
const (
	EOLGrace       = 30 * 24 * time.Hour
	EOLSoon        = 90 * 24 * time.Hour
	LatestSettle   = 7 * 24 * time.Hour
	SnapshotMaxAge = 90 * 24 * time.Hour
)

// Reasons a Hit reports.
const (
	ReasonEndOfLife      = "end-of-life"
	ReasonEndOfLifeGrace = "end-of-life-grace"
	ReasonEndOfLifeSoon  = "end-of-life-soon"
	ReasonSupportEnded   = "active-support-ended"
	ReasonBehindLatest   = "behind-latest"
	ReasonSnapshotOld    = "snapshot-old"
)

// Hit is one judged pin.
type Hit struct {
	Product string `json:"product"`
	Cycle   string `json:"cycle,omitempty"`
	Version string `json:"version"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Source  string `json:"source"`
	Reason  string `json:"reason"`
	EOL     string `json:"eol,omitempty"`
	Latest  string `json:"latest,omitempty"`
	Detail  string `json:"detail"`
}

// Needed lists the products whose data the pins require.
func Needed(pins []Pin) []string {
	seen := map[string]bool{}
	var out []string
	for _, pin := range pins {
		for _, product := range pin.Products {
			if !seen[product] {
				seen[product] = true
				out = append(out, product)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Evaluate judges every pin against catalog at now and returns the blocking
// end-of-life findings and the warnings. A pin whose product has no data, or
// whose version names no known release cycle, is not judged.
func Evaluate(pins []Pin, catalog Catalog, now time.Time) (findings, warnings []Hit) {
	today := dateOnly(now)
	for _, pin := range pins {
		if !pin.Snapshot.IsZero() {
			if age := today.Sub(dateOnly(pin.Snapshot)); age > SnapshotMaxAge {
				warnings = append(warnings, Hit{
					Product: "apt-snapshot", Version: pin.Version, Path: pin.Path, Line: pin.Line,
					Source: pin.Source, Reason: ReasonSnapshotOld,
					Detail: fmt.Sprintf("apt snapshot of %s is %d days old; packages fixed since then are absent",
						pin.Snapshot.Format(time.DateOnly), int(age.Hours()/24)),
				})
			}
			continue
		}
		product, release, ok := resolve(pin, catalog)
		if !ok {
			continue
		}
		hit := Hit{
			Product: product, Cycle: release.Name, Version: pin.Version, Path: pin.Path,
			Line: pin.Line, Source: pin.Source,
		}
		if release.EOLFrom != nil {
			hit.EOL = *release.EOLFrom
		}
		if release.Latest != nil {
			hit.Latest = release.Latest.Name
		}
		eolDate, hasDate := parseDate(release.EOLFrom)
		ended := (hasDate && !today.Before(eolDate)) || (!hasDate && release.IsEOL)
		switch {
		case ended && (!hasDate || today.Sub(eolDate) >= EOLGrace):
			hit.Reason = ReasonEndOfLife
			hit.Detail = fmt.Sprintf("%s %s reached end of life", product, release.Name)
			if hasDate {
				hit.Detail += " on " + hit.EOL
			}
			findings = append(findings, hit)
			continue
		case ended:
			warnings = append(warnings, with(hit, ReasonEndOfLifeGrace, fmt.Sprintf(
				"%s %s reached end of life on %s; strict scans fail from %s",
				product, release.Name, hit.EOL, eolDate.Add(EOLGrace).Format(time.DateOnly))))
			continue
		case hasDate && eolDate.Sub(today) <= EOLSoon:
			warnings = append(warnings, with(hit, ReasonEndOfLifeSoon, fmt.Sprintf(
				"%s %s reaches end of life on %s", product, release.Name, hit.EOL)))
		}
		if pin.Floor {
			continue
		}
		if eoas, ok := parseDate(release.EOASFrom); ok && !today.Before(eoas) {
			warnings = append(warnings, with(hit, ReasonSupportEnded, fmt.Sprintf(
				"%s %s left active support on %s", product, release.Name, eoas.Format(time.DateOnly))))
		}
		if trails(pin.Version, release, today) {
			detail := fmt.Sprintf("%s %s trails %s, the newest %s %s release",
				product, pin.Version, release.Latest.Name, product, release.Name)
			if release.Latest.Date != nil {
				detail += " (" + *release.Latest.Date + ")"
			}
			warnings = append(warnings, with(hit, ReasonBehindLatest, detail))
		}
	}
	return findings, warnings
}

func with(hit Hit, reason, detail string) Hit {
	hit.Reason, hit.Detail = reason, detail
	return hit
}

func resolve(pin Pin, catalog Catalog) (string, Release, bool) {
	for _, product := range pin.Products {
		data, ok := catalog[product]
		if !ok {
			continue
		}
		if release, ok := match(data, pin.Version); ok {
			return product, release, true
		}
	}
	return "", Release{}, false
}

// match finds the release cycle a requested version selects: the cycle whose
// name equals the version or is its longest dotted prefix ("1.22" for
// "1.22.3", "1" for Bun "1.3.9"), or, for a word, the cycle whose codename
// starts with it ("bookworm", "noble", "iron").
func match(product Product, requested string) (Release, bool) {
	version := numericPrefix(requested)
	if version == "" {
		word := strings.ToLower(requested)
		for _, release := range product.Releases {
			if release.Codename == nil {
				continue
			}
			first, _, _ := strings.Cut(strings.ToLower(*release.Codename), " ")
			if first == word {
				return release, true
			}
		}
		return Release{}, false
	}
	best, found := Release{}, false
	for _, release := range product.Releases {
		if version != release.Name && !strings.HasPrefix(version, release.Name+".") {
			continue
		}
		if !found || len(release.Name) > len(best.Name) {
			best, found = release, true
		}
	}
	return best, found
}

// numericPrefix keeps the leading dotted number: "v1.22rc1" -> "1.22".
func numericPrefix(value string) string {
	value = strings.TrimPrefix(value, "v")
	end := 0
	for end < len(value) && (value[end] == '.' || (value[end] >= '0' && value[end] <= '9')) {
		end++
	}
	return strings.Trim(value[:end], ".")
}

// trails reports an exact pin, more precise than its cycle, older than the
// cycle's newest release. A pin exactly one patch behind a newest release
// younger than LatestSettle does not trail yet: that release is still inside
// the minimum-release-age window.
func trails(requested string, release Release, today time.Time) bool {
	if release.Latest == nil || release.Latest.Name == "" {
		return false
	}
	version := numericPrefix(requested)
	if strings.Count(version, ".") <= strings.Count(release.Name, ".") {
		return false
	}
	if compare(version, numericPrefix(release.Latest.Name)) >= 0 {
		return false
	}
	latest := numericPrefix(release.Latest.Name)
	if published, ok := parseDate(release.Latest.Date); ok && today.Sub(published) < LatestSettle &&
		onePatchBehind(version, latest) {
		return false
	}
	return true
}

func onePatchBehind(version, latest string) bool {
	cut := strings.LastIndex(version, ".")
	if cut < 0 || cut != strings.LastIndex(latest, ".") || version[:cut] != latest[:cut] {
		return false
	}
	patch, err1 := strconv.Atoi(version[cut+1:])
	newest, err2 := strconv.Atoi(latest[cut+1:])
	return err1 == nil && err2 == nil && newest-patch == 1
}

func compare(left, right string) int {
	a, b := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < len(a) || index < len(b); index++ {
		var x, y int
		if index < len(a) {
			x, _ = strconv.Atoi(a[index])
		}
		if index < len(b) {
			y, _ = strconv.Atoi(b[index])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseDate(value *string) (time.Time, bool) {
	if value == nil {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.DateOnly, *value)
	return parsed, err == nil
}

func dateOnly(value time.Time) time.Time {
	year, month, day := value.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// Sort orders hits by path, line, product and reason.
func Sort(hits []Hit) {
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		if hits[i].Line != hits[j].Line {
			return hits[i].Line < hits[j].Line
		}
		if hits[i].Product != hits[j].Product {
			return hits[i].Product < hits[j].Product
		}
		return hits[i].Reason < hits[j].Reason
	})
}

// Report is the outcome of Run.
type Report struct {
	Pins     int
	Findings []Hit
	Warnings []Hit
	// Missing names the products some pin needs whose data is absent.
	Missing []string
}

// Run discovers the pins under target and judges them against the data in
// dataDir at now.
func Run(target, dataDir string, now time.Time) (Report, error) {
	pins, err := Discover(target)
	if err != nil {
		return Report{}, err
	}
	report := Report{Pins: len(pins)}
	catalog, missing, err := Load(dataDir, Needed(pins))
	if err != nil {
		return report, err
	}
	report.Missing = missing
	report.Findings, report.Warnings = Evaluate(pins, catalog, now)
	Sort(report.Findings)
	Sort(report.Warnings)
	return report, nil
}
