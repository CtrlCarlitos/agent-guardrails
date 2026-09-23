package genconfig

import (
	"os"
	"strings"
	"testing"
)

// Drift was invisible before the manifest: 24 entries behind on Claude and 42
// on OpenCode, discoverable only by regenerating and diffing by hand. Each
// condition below means something different to an operator, so each is named
// separately rather than folded into "out of date".

func TestDriftIsCleanRightAfterAMerge(t *testing.T) {
	path := opencodeMerged(t, map[string]any{})
	report, err := DriftFor("opencode", path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Clean() {
		t.Errorf("a freshly merged config reports drift: %+v", report)
	}
	if got := DriftLine("opencode", report); !strings.Contains(got, "matches") {
		t.Errorf("the clean line does not state the state positively: %q", got)
	}
}

// An operator cannot tell "clean" from "never checked" if absence is silent,
// so the no-manifest case says what it will do instead of saying nothing.
func TestDriftWithoutAManifestSaysSoRatherThanReportingClean(t *testing.T) {
	path := opencodeMerged(t, map[string]any{})
	dir, err := ManifestDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	report, err := DriftFor("opencode", path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Clean() {
		t.Error("a missing manifest reported clean; absence of knowledge is not absence of drift")
	}
	if !report.NoManifest {
		t.Error("the missing manifest was not reported as such")
	}
	if got := DriftLine("opencode", report); !strings.Contains(got, "no manifest") || !strings.Contains(got, "fall back") {
		t.Errorf("the line does not say what removal will do instead: %q", got)
	}
}

// Listed but gone: the floor drifted, or something rewrote the settings.
func TestDriftReportsEntriesMissingFromSettings(t *testing.T) {
	const pattern = "rm -rf /"
	path := opencodeMerged(t, map[string]any{})
	doc := readJSON(t, path)
	perm := doc["permission"].(map[string]any)
	rules := perm["bash"].(map[string]any)
	delete(rules, pattern)
	writeJSON(t, path, doc)

	report, err := DriftFor("opencode", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Missing) == 0 {
		t.Fatalf("a removed floor entry was not reported missing: %+v", report)
	}
	if got := DriftLine("opencode", report); !strings.Contains(got, "missing from settings") {
		t.Errorf("the line does not name the condition: %q", got)
	}
}

// Present but unclaimed: output from a release whose manifest predates it.
// Nothing else would ever notice these -- they are the 9 dead entries the #278
// audit found by hand.
func TestDriftReportsStaleGuardrailEntries(t *testing.T) {
	const pattern = "rm -rf /"
	path := opencodeMerged(t, map[string]any{})

	m, err := LoadManifest("opencode")
	if err != nil || m == nil {
		t.Fatal("no manifest")
	}
	kept := m.Entries[:0]
	for _, e := range m.Entries {
		if e.Key == pattern {
			continue // as if an older release had written it and not recorded it
		}
		kept = append(kept, e)
	}
	m.Entries = kept
	if err := saveManifest(*m); err != nil {
		t.Fatal(err)
	}

	report, err := DriftFor("opencode", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Stale) == 0 {
		t.Fatalf("an unclaimed guardrail entry was not reported stale: %+v", report)
	}
	if got := DriftLine("opencode", report); !strings.Contains(got, "stale") {
		t.Errorf("the line does not name the condition: %q", got)
	}
}

// Edited: reported, never corrected.
func TestDriftReportsOperatorEditsWithoutCorrectingThem(t *testing.T) {
	const pattern = "rm -rf /"
	path := opencodeMerged(t, map[string]any{})
	doc := readJSON(t, path)
	perm := doc["permission"].(map[string]any)
	perm["bash"].(map[string]any)[pattern] = "ask"
	writeJSON(t, path, doc)

	report, err := DriftFor("opencode", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Edited) == 0 {
		t.Fatalf("an operator edit was not reported: %+v", report)
	}
	if got := bashRules(t, path)[pattern]; got != "ask" {
		t.Errorf("reporting drift changed the file: %q is %v", pattern, got)
	}
	if got := DriftLine("opencode", report); !strings.Contains(got, "left as-is") {
		t.Errorf("the line does not say the edit was left alone: %q", got)
	}
}
