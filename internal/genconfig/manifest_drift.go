package genconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Drift reporting, the manifest's third consumer (#278 finding c).
//
// Before the manifest, drift was invisible: 24 entries behind on Claude and 42
// on OpenCode, discoverable only by regenerating and diffing by hand. With a
// record of what guardrail wrote, the three interesting conditions can be
// named, and each one means something different to an operator.

type DriftReport struct {
	// Missing were recorded as guardrail's but are no longer in the file:
	// the floor drifted, or something rewrote the settings.
	Missing []string
	// Stale are guardrail-shaped entries present in the file that the record
	// does not claim -- output from an older release that no longer
	// regenerates, which nothing would ever clean up.
	Stale []string
	// Edited are recorded entries whose value the operator has since changed.
	// Reported, never corrected: the value is theirs now.
	Edited []string
	// NoManifest means nothing is known, which is not the same as clean.
	NoManifest bool
}

func (d DriftReport) Clean() bool {
	return !d.NoManifest && len(d.Missing) == 0 && len(d.Stale) == 0 && len(d.Edited) == 0
}

// DriftFor compares a plane's settings file against the manifest and against
// what this binary would generate now.
func DriftFor(plane, path string) (DriftReport, error) {
	report := DriftReport{}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return report, nil
	}
	if err != nil {
		return report, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil || doc == nil {
		return report, fmt.Errorf("%s is not a JSON object", path)
	}

	manifest, _ := LoadManifest(plane)
	if manifest == nil || !sameTarget(manifest.Target, path) {
		report.NoManifest = true
		return report, nil
	}

	claimed := make(map[string]bool, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		claimed[entryIdentity(entry)] = true
		name := joinPath(entry.Path)
		if entry.Key != "" {
			name += "." + entry.Key
		}
		switch current, present := currentValue(doc, entry); {
		case !present:
			report.Missing = append(report.Missing, name)
		case jsonKey(current) != jsonKey(entry.Value):
			report.Edited = append(report.Edited, name)
		}
	}

	// Anything this binary would generate that is present in the file but not
	// claimed by the record is output from a release whose manifest predates
	// it -- or predates manifests entirely.
	if fragment, ok := fallbackFragment(plane); ok {
		for _, entry := range ownershipEntries(map[string]any{}, fragment, nil) {
			if claimed[entryIdentity(entry)] {
				continue
			}
			if current, present := currentValue(doc, entry); present && jsonKey(current) == jsonKey(entry.Value) {
				name := joinPath(entry.Path)
				if entry.Key != "" {
					name += "." + entry.Key
				}
				report.Stale = append(report.Stale, name)
			}
		}
	}

	sort.Strings(report.Missing)
	sort.Strings(report.Stale)
	sort.Strings(report.Edited)
	return report, nil
}

// currentValue reads what the document holds in an entry's slot.
func currentValue(doc map[string]any, entry ManifestEntry) (any, bool) {
	if entry.Key == "" {
		parent, ok := containerAt(doc, entry.Path[:len(entry.Path)-1])
		if !ok {
			return nil, false
		}
		list, ok := toAnySlice(parent[entry.Path[len(entry.Path)-1]])
		if !ok {
			return nil, false
		}
		want := jsonKey(entry.Value)
		for _, v := range list {
			if jsonKey(v) == want {
				return v, true
			}
		}
		return nil, false
	}
	container, ok := containerAt(doc, entry.Path)
	if !ok {
		return nil, false
	}
	value, present := container[entry.Key]
	return value, present
}

// DriftLine renders the report for `doctor`. Silence would be ambiguous there
// -- an operator cannot tell "clean" from "never checked" -- so every state
// says something.
func DriftLine(plane string, report DriftReport) string {
	switch {
	case report.NoManifest:
		return fmt.Sprintf("%s ownership: no manifest (entries written before this release, or state cleared); `plane disable %s` will fall back to matching current generated output", plane, plane)
	case report.Clean():
		return fmt.Sprintf("%s ownership: manifest matches settings", plane)
	}
	line := plane + " ownership:"
	if n := len(report.Missing); n > 0 {
		line += fmt.Sprintf(" %d entr%s missing from settings (ownership drifted);", n, plural(n))
	}
	if n := len(report.Stale); n > 0 {
		line += fmt.Sprintf(" %d stale guardrail entr%s the manifest does not claim (`plane enable %s` removes the retired floor);", n, plural(n), plane)
	}
	if n := len(report.Edited); n > 0 {
		line += fmt.Sprintf(" %d operator-edited entr%s (left as-is);", n, plural(n))
	}
	return line + " run `guardrail plane enable " + plane + "` to reconcile"
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
