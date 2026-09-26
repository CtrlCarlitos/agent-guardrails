package genconfig

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func opencodeMerged(t *testing.T, seed map[string]any) (path string) {
	t.Helper()
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path = filepath.Join(dir, "opencode.json")
	writeJSON(t, path, seed)
	if err := MergePlaneInto(path, "opencode", legacyOpencodeFragment(base, filepath.Join(dir, "guardrail.js"))); err != nil {
		t.Fatal(err)
	}
	return path
}

func bashRules(t *testing.T, path string) map[string]any {
	t.Helper()
	perm, _ := readJSON(t, path)["permission"].(map[string]any)
	rules, _ := perm["bash"].(map[string]any)
	return rules
}

// The centrepiece.
//
// Merging does not simply write guardrail's entries: on a pattern both sides
// name, the stricter verdict wins, so guardrail *overwrites* an operator value
// that was looser. "Guardrail wrote this" therefore never implies "this did
// not exist before guardrail".
//
// A manifest that recorded only ownership would make removal delete the key,
// and the operator's own setting would be gone -- the same harm the manifest
// exists to prevent, reintroduced by the fix for it. So removal restores.
func TestRemovalRestoresAnOperatorValueGuardrailOverwrote(t *testing.T) {
	const pattern = "rm -rf /"
	path := opencodeMerged(t, map[string]any{
		"permission": map[string]any{"bash": map[string]any{pattern: "ask"}},
	})
	if got := bashRules(t, path)[pattern]; got != "deny" {
		t.Fatalf("setup: %q is %v, want guardrail's stricter deny to have won", pattern, got)
	}

	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	if got := bashRules(t, path)[pattern]; got != "ask" {
		t.Errorf("after disable %q is %v, want the operator's original \"ask\" restored", pattern, got)
	}
}

// An entry guardrail generated but did not actually change is not guardrail's.
// The operator already had it, identically; removal must leave it.
func TestRemovalLeavesAnEntryGuardrailNeverChanged(t *testing.T) {
	const pattern = "rm -rf /"
	path := opencodeMerged(t, map[string]any{
		"permission": map[string]any{"bash": map[string]any{pattern: "deny"}},
	})
	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	if got := bashRules(t, path)[pattern]; got != "deny" {
		t.Errorf("after disable %q is %v; the operator had this entry independently and it should survive", pattern, got)
	}
}

// Leave-and-report: if the operator edited an entry after guardrail wrote it,
// the value is theirs now. Silently reverting an edit is the same class of
// harm as deleting one, so removal declines and says so.
func TestRemovalLeavesOperatorEditsAndReportsThem(t *testing.T) {
	const pattern = "rm -rf /"
	path := opencodeMerged(t, map[string]any{})

	doc := readJSON(t, path)
	perm := doc["permission"].(map[string]any)
	rules := perm["bash"].(map[string]any)
	rules[pattern] = "ask" // the operator loosens it by hand afterwards
	writeJSON(t, path, doc)

	report, err := RemovePlaneFromReporting(path, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if got := bashRules(t, path)[pattern]; got != "ask" {
		t.Errorf("after disable %q is %v, want the operator's edit left alone", pattern, got)
	}
	if !slices.ContainsFunc(report.Edited, func(s string) bool { return s == "permission.bash."+pattern }) {
		t.Errorf("the edited entry was not reported: %v", report.Edited)
	}
}

// Every installation that exists today has no manifest, and state directories
// get cleared. Removal must degrade rather than fail, and must say it degraded
// -- silence would look like a clean removal.
func TestRemovalWithoutAManifestFallsBackAndSaysSo(t *testing.T) {
	path := opencodeMerged(t, map[string]any{
		"plugin":     []any{"~/.config/opencode/node_modules/superpowers"},
		"permission": map[string]any{"bash": map[string]any{"my-own-tool *": "ask"}},
	})
	dir, err := ManifestDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	report, err := RemovePlaneFromReporting(path, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Fallback {
		t.Error("the fallback was not reported; a degraded removal must not look like a clean one")
	}
	plugins := stringsAt(t, readJSON(t, path), "plugin")
	if !slices.Contains(plugins, "~/.config/opencode/node_modules/superpowers") {
		t.Errorf("the fallback destroyed the operator's plugins: %v", plugins)
	}
	for _, p := range plugins {
		if filepath.Base(p) == "guardrail.js" {
			t.Errorf("the fallback left guardrail's plugin entry: %v", plugins)
		}
	}
	// Permission entries have no in-band marker, so the fallback regenerates
	// what this binary would write and removes only exact matches. An entry
	// that matches is one guardrail would have written; one that does not is
	// the operator's and is left alone.
	rules := bashRules(t, path)
	if _, ok := rules["rm -rf /"]; ok {
		t.Errorf("the fallback left a guardrail entry matching current output: %v", rules)
	}
	if got := rules["my-own-tool *"]; got != "ask" {
		t.Errorf("the fallback removed an operator entry it could not have written: %v", rules)
	}
}

// Disabling twice must not misbehave: the record is cleared with the entries
// it describes, so the second pass finds nothing to do.
func TestRemovalIsIdempotent(t *testing.T) {
	path := opencodeMerged(t, map[string]any{
		"permission": map[string]any{"bash": map[string]any{"my-own *": "ask"}},
	})
	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	first := readJSON(t, path)
	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	if got := bashRules(t, path)["my-own *"]; got != "ask" {
		t.Errorf("a second disable disturbed the operator's entry: %v", got)
	}
	if len(readJSON(t, path)) != len(first) {
		t.Error("a second disable changed the document again")
	}
}

// Merging is idempotent and gets run repeatedly -- `plane enable` twice, a
// sync, a reinstall. The second merge changes nothing, so its diff is empty;
// writing that diff would erase the record of everything the first merge
// wrote, leaving the entries in the settings file with nothing that knows they
// are guardrail's. That is the condition the manifest exists to end, so the
// record accumulates instead of being replaced.
func TestRepeatedMergeDoesNotEraseTheRecord(t *testing.T) {
	const pattern = "rm -rf /"
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.json")
	writeJSON(t, path, map[string]any{
		"permission": map[string]any{"bash": map[string]any{pattern: "ask"}},
	})
	for i := 0; i < 3; i++ {
		if err := MergePlaneInto(path, "opencode", legacyOpencodeFragment(base, filepath.Join(dir, "guardrail.js"))); err != nil {
			t.Fatalf("merge %d: %v", i, err)
		}
	}
	m, err := LoadManifest("opencode")
	if err != nil || m == nil {
		t.Fatal("no manifest after repeated merges")
	}
	if len(m.Entries) == 0 {
		t.Fatal("repeated merges emptied the manifest")
	}

	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	rules := bashRules(t, path)
	// The operator's original value, not guardrail's own first write, is what
	// comes back.
	if got := rules[pattern]; got != "ask" {
		t.Errorf("after repeated merges and disable %q is %v, want the operator's original \"ask\"", pattern, got)
	}
	for key := range rules {
		if key != pattern {
			t.Errorf("a guardrail entry survived disable after repeated merges: %q", key)
		}
	}
}

// The manifest has to survive the floor retiring (ADR-0028): a hooks-only
// manifest is a normal manifest, not a degenerate one, so nothing about the
// format assumes permission entries exist.
func TestManifestIsWellFormedWithHooksOnly(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "hooks.json")
	writeJSON(t, path, map[string]any{})
	if err := MergePlaneInto(path, "antigravity", AntigravityConfig("guardrail")); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest("antigravity")
	if err != nil || m == nil {
		t.Fatalf("no manifest written for a hooks-only plane: %v", err)
	}
	if len(m.Entries) == 0 {
		t.Fatal("the hooks-only manifest recorded nothing")
	}
	for _, e := range m.Entries {
		if e.Kind == "permission" {
			t.Errorf("a hooks-only plane recorded a permission entry: %+v", e)
		}
	}
	if err := RemovePlaneFrom(path, "antigravity"); err != nil {
		t.Fatal(err)
	}
	if doc := readJSON(t, path); len(doc) != 0 {
		t.Errorf("hooks-only removal left %v", doc)
	}
}
