package genconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// mergeHooks only visited events the new fragment emits. A release that drops a
// hook event (retires a PostToolUse or SessionStart group on a plane) therefore
// left the old guardrail-owned group on disk for every operator upgrading from an
// older registration, and `guardrail setup` failed its convergence check on every
// run (#322). A merge now also removes owned groups under an event the fragment
// no longer emits, and only those: the operator's own groups, legacy unmarked
// guardrail groups (absorbed as in the same-event case), and every event the
// fragment still emits keep today's behaviour.

func hookGroup(id, command string) map[string]any {
	group := map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": command}}}
	if id != "" {
		group["id"] = id
	}
	return group
}

func eventIDs(t *testing.T, doc map[string]any, container, event string) []string {
	t.Helper()
	events, _ := doc[container].(map[string]any)
	groups, _ := events[event].([]any)
	var out []string
	for _, g := range groups {
		m, _ := g.(map[string]any)
		id, _ := m["id"].(string)
		if id == "" {
			id, _ = m["name"].(string)
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func TestMergeRemovesOwnedGroupsUnderAnEventTheNewFragmentDropped(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{
		"model": "keep",
		"hooks": map[string]any{
			"Notification": []any{hookGroup("", "operator-notify")},
			"SessionStart": []any{hookGroup("", "operator-session")},
		},
	})
	older := Fragment{"hooks": map[string]any{
		"PreToolUse":   []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
		"SessionStart": []any{hookGroup("guardrail-claude-session-start", "guardrail hook claude")},
	}}
	newer := Fragment{"hooks": map[string]any{
		"PreToolUse": []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
	}}
	if err := MergePlaneInto(path, "claude", older); err != nil {
		t.Fatal(err)
	}
	if err := ReconcilePlaneInto(path, "claude", newer); err != nil {
		t.Fatal(err)
	}

	doc, _ := ReadJSONObject(path)
	if got := eventIDs(t, doc, "hooks", "SessionStart"); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("SessionStart = %v, want only the operator's group (id \"\")", got)
	}
	if got := eventIDs(t, doc, "hooks", "PreToolUse"); !reflect.DeepEqual(got, []string{"guardrail-claude-pre"}) {
		t.Errorf("PreToolUse = %v, want the current owned group", got)
	}
	if got := eventIDs(t, doc, "hooks", "Notification"); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("Notification = %v, an event the fragment never touched must be left alone", got)
	}
	if doc["model"] != "keep" {
		t.Errorf("unrelated key changed: %v", doc["model"])
	}

	// Ownership converges: nothing recorded is missing, nothing is stale.
	report, err := DriftFor("claude", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Missing) != 0 || len(report.Stale) != 0 {
		t.Errorf("drift after the merge = %+v, want converged", report)
	}

	// Idempotent: a second merge of the same fragment changes nothing.
	before, _ := os.ReadFile(path)
	if err := ReconcilePlaneInto(path, "claude", newer); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("a second merge rewrote the file:\n%s\n---\n%s", before, after)
	}

	// `plane disable` stays exact: only the still-owned group goes.
	if err := RemovePlaneFrom(path, "claude"); err != nil {
		t.Fatal(err)
	}
	doc, _ = ReadJSONObject(path)
	if got := eventIDs(t, doc, "hooks", "SessionStart"); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("after disable, SessionStart = %v, want the operator's group", got)
	}
	if got := eventIDs(t, doc, "hooks", "Notification"); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("after disable, Notification = %v", got)
	}
}

// A plain (non-reconcile) merge, which is what gen-config --merge and sync run,
// must not leave the manifest claiming a group the merge just removed.
func TestPlainMergeAlsoRetiresTheManifestRecordOfARemovedGroup(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	older := Fragment{"hooks": map[string]any{
		"PreToolUse":   []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
		"SessionStart": []any{hookGroup("guardrail-claude-session-start", "guardrail hook claude")},
	}}
	newer := Fragment{"hooks": map[string]any{
		"PreToolUse": []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
	}}
	if err := MergePlaneInto(path, "claude", older); err != nil {
		t.Fatal(err)
	}
	if err := MergePlaneInto(path, "claude", newer); err != nil {
		t.Fatal(err)
	}
	report, err := DriftFor("claude", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Missing) != 0 {
		t.Errorf("the manifest still records a removed group as missing: %+v", report)
	}
}

// A legacy pre-marker guardrail group under a dropped event is absorbed, as it is
// under an event the fragment still emits.
func TestMergeAbsorbsALegacyUnmarkedGroupUnderADroppedEvent(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{"hooks": map[string]any{
		"SessionStart": []any{hookGroup("", "/old/guardrail hook claude"), hookGroup("", "operator-session")},
	}})
	newer := Fragment{"hooks": map[string]any{
		"PreToolUse": []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
	}}
	if err := MergePlaneInto(path, "claude", newer); err != nil {
		t.Fatal(err)
	}
	doc, _ := ReadJSONObject(path)
	events, _ := doc["hooks"].(map[string]any)
	groups, _ := events["SessionStart"].([]any)
	if len(groups) != 1 {
		t.Fatalf("SessionStart = %v, want only the operator's group", groups)
	}
	if m, _ := groups[0].(map[string]any); m["hooks"].([]any)[0].(map[string]any)["command"] != "operator-session" {
		t.Errorf("the wrong group survived: %v", groups[0])
	}
}

// An event that held only owned groups disappears instead of leaving an empty
// array behind.
func TestMergeDropsAnEventThatHeldOnlyOwnedGroups(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	older := Fragment{"hooks": map[string]any{
		"PreToolUse":  []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
		"PostToolUse": []any{hookGroup("guardrail-claude-post", "guardrail hook claude")},
	}}
	newer := Fragment{"hooks": map[string]any{
		"PreToolUse": []any{hookGroup("guardrail-claude-pre", "guardrail hook claude")},
	}}
	if err := MergePlaneInto(path, "claude", older); err != nil {
		t.Fatal(err)
	}
	if err := MergePlaneInto(path, "claude", newer); err != nil {
		t.Fatal(err)
	}
	doc, _ := ReadJSONObject(path)
	events, _ := doc["hooks"].(map[string]any)
	if _, present := events["PostToolUse"]; present {
		t.Errorf("an event with no groups left was kept: %v", events["PostToolUse"])
	}
}

// Antigravity nests its events in a named wrapper with an `enabled` flag; the
// flag and the wrapper stay, the retired event's owned group goes.
func TestMergeRetiresAnAntigravityEventAndKeepsTheWrapper(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "hooks.json")
	older := Fragment{"guardrail": map[string]any{
		"enabled":     true,
		"PreToolUse":  []any{hookGroup("guardrail-antigravity-pre", "guardrail hook antigravity pre")},
		"PostToolUse": []any{hookGroup("guardrail-antigravity-post", "guardrail hook antigravity post")},
	}}
	newer := Fragment{"guardrail": map[string]any{
		"enabled":    true,
		"PreToolUse": []any{hookGroup("guardrail-antigravity-pre", "guardrail hook antigravity pre")},
	}}
	if err := MergePlaneInto(path, "antigravity", older); err != nil {
		t.Fatal(err)
	}
	if err := ReconcilePlaneInto(path, "antigravity", newer); err != nil {
		t.Fatal(err)
	}
	doc, _ := ReadJSONObject(path)
	wrapper, _ := doc["guardrail"].(map[string]any)
	if wrapper["enabled"] != true {
		t.Errorf("the wrapper's enabled flag changed: %v", wrapper["enabled"])
	}
	if _, present := wrapper["PostToolUse"]; present {
		t.Errorf("the retired PostToolUse event was kept: %v", wrapper["PostToolUse"])
	}
	if got := eventIDs(t, doc, "guardrail", "PreToolUse"); !reflect.DeepEqual(got, []string{"guardrail-antigravity-pre"}) {
		t.Errorf("PreToolUse = %v", got)
	}
}

// Codex keeps its groups in hooks.json under `guardrail-codex-` ids and shares
// the merge path, so the same rule applies, and an operator group in the same
// event survives.
func TestMergeRetiresACodexEventAndKeepsTheOperatorsGroup(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "hooks.json")
	writeJSON(t, path, map[string]any{"hooks": map[string]any{
		"SessionStart": []any{hookGroup("", "operator-session")},
	}})
	older := Fragment{"hooks": map[string]any{
		"PreToolUse":   []any{hookGroup("guardrail-codex-PreToolUse", "guardrail hook codex")},
		"SessionStart": []any{hookGroup("guardrail-codex-SessionStart", "guardrail hook codex")},
	}}
	newer := Fragment{"hooks": map[string]any{
		"PreToolUse": []any{hookGroup("guardrail-codex-PreToolUse", "guardrail hook codex")},
	}}
	if err := MergePlaneInto(path, "codex", older); err != nil {
		t.Fatal(err)
	}
	if err := ReconcilePlaneInto(path, "codex", newer); err != nil {
		t.Fatal(err)
	}
	doc, _ := ReadJSONObject(path)
	if got := eventIDs(t, doc, "hooks", "SessionStart"); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("SessionStart = %v, want only the operator's group", got)
	}
	if got := eventIDs(t, doc, "hooks", "PreToolUse"); !reflect.DeepEqual(got, []string{"guardrail-codex-PreToolUse"}) {
		t.Errorf("PreToolUse = %v", got)
	}
}
