package genconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The declarative floor is retired for claude and opencode (ADR-0028 phases C
// and B): the Engine enforces everything it mirrored, and a second drifting
// copy in a file the operator owns is the thing the ADR set out to end. The
// generator must stop emitting it, or a fresh `setup` re-adds what an operator
// just pruned. What stays: hook registration, the plugin entry, and the one
// allow entry that is not a copy of anything (`guardrail fetch`).
func TestClaudeConfigGeneratesNoFloor(t *testing.T) {
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	frag := ClaudeConfig(base, "/x/guardrail")
	if _, ok := frag["hooks"]; !ok {
		t.Fatal("ClaudeConfig dropped the hooks")
	}
	perms, _ := frag["permissions"].(map[string]any)
	if _, ok := perms["deny"]; ok {
		t.Errorf("ClaudeConfig still generates a deny floor: %v", perms["deny"])
	}
	if _, ok := perms["ask"]; ok {
		t.Errorf("ClaudeConfig still generates an ask floor: %v", perms["ask"])
	}
	if got, want := perms["allow"], []string{"Bash(guardrail fetch:*)"}; !reflect.DeepEqual(got, want) {
		t.Errorf("allow = %v, want only %v", got, want)
	}
}

func TestOpencodeConfigGeneratesNoFloor(t *testing.T) {
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	frag := OpencodeConfig(base, "/x/guardrail.js")
	if _, ok := frag["permission"]; ok {
		t.Errorf("OpencodeConfig still generates a permission floor")
	}
	if got, want := frag["plugin"], []string{"/x/guardrail.js"}; !reflect.DeepEqual(got, want) {
		t.Errorf("plugin = %v, want %v", got, want)
	}
}

// Prune removes exactly what guardrail generated, now or in a past release,
// and nothing else. The operator's own entries and every key outside the
// floor survive untouched.
func TestPruneLegacyFloorRemovesOnlyGuardrailsClaudeEntries(t *testing.T) {
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyClaudePermissions(base)
	deny := []any{"Bash(my-own-deny *)"}
	for _, e := range legacy["deny"] {
		deny = append(deny, e)
	}
	ask := []any{}
	for _, e := range legacy["ask"] {
		ask = append(ask, e)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{
		"model": "opus",
		"hooks": map[string]any{"Stop": []any{map[string]any{"id": "mine"}}},
		"permissions": map[string]any{
			"allow": []any{"Bash(graft:*)", "Bash(npx graft:*)", "Bash(guardrail fetch:*)"},
			"deny":  deny,
			"ask":   ask,
		},
	})

	removed, err := PruneLegacyFloor(path, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if want := len(legacy["deny"]) + len(legacy["ask"]); removed != want {
		t.Errorf("removed = %d, want %d", removed, want)
	}
	doc, err := ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := stringsAt(t, doc, "permissions", "deny"); !slices.Equal(got, []string{"Bash(my-own-deny *)"}) {
		t.Errorf("deny = %v, want only the operator's entry", got)
	}
	if got := stringsAt(t, doc, "permissions", "allow"); !slices.Equal(got, []string{"Bash(graft:*)", "Bash(npx graft:*)", "Bash(guardrail fetch:*)"}) {
		t.Errorf("allow = %v, want untouched", got)
	}
	if _, ok := doc["permissions"].(map[string]any)["ask"]; ok {
		t.Error("an emptied ask tier was left behind")
	}
	if doc["model"] != "opus" || doc["hooks"] == nil {
		t.Errorf("unrelated keys changed: %v", doc)
	}

	again, err := PruneLegacyFloor(path, "claude")
	if err != nil || again != 0 {
		t.Errorf("second prune = (%d, %v), want (0, nil): it must be idempotent", again, err)
	}
}

// The six entries an older release wrote and #297 retired as no-ops (`dd`,
// five `git clean` globs) are guardrail's output too, and are what a real
// settings file still carries.
func TestPruneLegacyFloorCoversEntriesRetiredByEarlierReleases(t *testing.T) {
	manifestEnv(t)
	retired := []any{"Bash(dd *)", "Bash(git clean -f*)", "Bash(git clean -xf*)", "Bash(git clean -fx*)", "Bash(git clean -df*)", "Bash(git clean -fd*)", "Bash(rm -rf *)"}
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{"permissions": map[string]any{"deny": retired}})
	removed, err := PruneLegacyFloor(path, "claude")
	if err != nil || removed != len(retired) {
		t.Fatalf("PruneLegacyFloor = (%d, %v), want (%d, nil)", removed, err, len(retired))
	}
	doc, _ := ReadJSONObject(path)
	if _, ok := doc["permissions"]; ok {
		t.Errorf("an emptied permissions block was left behind: %v", doc["permissions"])
	}
}

func TestPruneLegacyFloorRemovesOnlyGuardrailsOpencodeEntries(t *testing.T) {
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyOpencodePermission(base)
	bash := map[string]any{"my-tool *": "deny"}
	for k, v := range legacy["bash"] {
		bash[k] = v
	}
	read := map[string]any{"~/private/**": "deny"}
	for k, v := range legacy["read"] {
		read[k] = v
	}
	edit := map[string]any{}
	for k, v := range legacy["edit"] {
		edit[k] = v
	}
	path := filepath.Join(t.TempDir(), "opencode.json")
	writeJSON(t, path, map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"plugin":  []any{"/x/guardrail.js", "theirs"},
		"permission": map[string]any{
			"bash": bash, "read": read, "edit": edit,
		},
	})
	if _, err := PruneLegacyFloor(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	doc, _ := ReadJSONObject(path)
	perm, _ := doc["permission"].(map[string]any)
	gotBash, _ := perm["bash"].(map[string]any)
	// `*: allow` is a base rule, not a copy of an Engine verdict: kept.
	wantBash := map[string]any{"my-tool *": "deny"}
	if _, ok := legacy["bash"]["*"]; ok {
		wantBash["*"] = legacy["bash"]["*"]
	}
	if !reflect.DeepEqual(gotBash, wantBash) {
		t.Errorf("bash = %v, want %v", gotBash, wantBash)
	}
	if got, _ := perm["read"].(map[string]any); !reflect.DeepEqual(got, map[string]any{"~/private/**": "deny"}) {
		t.Errorf("read = %v, want only the operator's entry", got)
	}
	if _, ok := perm["edit"]; ok {
		t.Error("an emptied edit category was left behind")
	}
	if !reflect.DeepEqual(doc["plugin"], []any{"/x/guardrail.js", "theirs"}) || doc["$schema"] == nil {
		t.Errorf("unrelated keys changed: %v", doc)
	}
}

// A value the operator changed is theirs now. Same key, different value: kept.
func TestPruneLegacyFloorKeepsAnOperatorEditedValue(t *testing.T) {
	manifestEnv(t)
	base, _ := policy.LoadBase()
	legacy := legacyOpencodePermission(base)
	var key string
	for k, v := range legacy["read"] {
		if v == "deny" {
			key = k
			break
		}
	}
	if key == "" {
		t.Skip("no deny read rule in the legacy floor")
	}
	path := filepath.Join(t.TempDir(), "opencode.json")
	writeJSON(t, path, map[string]any{"permission": map[string]any{"read": map[string]any{key: "allow"}}})
	removed, err := PruneLegacyFloor(path, "opencode")
	if err != nil || removed != 0 {
		t.Fatalf("PruneLegacyFloor = (%d, %v), want (0, nil)", removed, err)
	}
	doc, _ := ReadJSONObject(path)
	if got := doc["permission"].(map[string]any)["read"].(map[string]any)[key]; got != "allow" {
		t.Errorf("edited value = %v, want the operator's allow kept", got)
	}
}

func TestLegacyFloorEntriesCountsWithoutWriting(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{"permissions": map[string]any{"deny": []any{"Bash(dd *)", "Bash(mine)"}}})
	before, _ := os.ReadFile(path)
	n, err := LegacyFloorEntries(path, "claude")
	if err != nil || n != 1 {
		t.Fatalf("LegacyFloorEntries = (%d, %v), want (1, nil)", n, err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("counting rewrote the file")
	}
	if n, err := LegacyFloorEntries(filepath.Join(t.TempDir(), "missing.json"), "claude"); err != nil || n != 0 {
		t.Errorf("missing file = (%d, %v), want (0, nil)", n, err)
	}
	if n, _ := LegacyFloorEntries(path, "antigravity"); n != 0 {
		t.Errorf("antigravity has no floor, got %d", n)
	}
}

// Before #270 the opencode generator copied Claude's command globs through
// untranslated, so a real opencode.json still holds `git config … /**` as
// written. Those are guardrail's output too.
func TestPruneLegacyFloorCoversTheUntranslatedOpencodeGlobs(t *testing.T) {
	manifestEnv(t)
	path := filepath.Join(t.TempDir(), "opencode.json")
	writeJSON(t, path, map[string]any{"permission": map[string]any{"bash": map[string]any{
		"git config core.hooksPath /**": "deny",
		"git config alias.* /**":        "deny",
		"my-tool *":                     "deny",
	}}})
	removed, err := PruneLegacyFloor(path, "opencode")
	if err != nil || removed != 2 {
		t.Fatalf("PruneLegacyFloor = (%d, %v), want (2, nil)", removed, err)
	}
	doc, _ := ReadJSONObject(path)
	bash, _ := doc["permission"].(map[string]any)["bash"].(map[string]any)
	if !reflect.DeepEqual(bash, map[string]any{"my-tool *": "deny"}) {
		t.Errorf("bash = %v, want only the operator's rule", bash)
	}
}
