package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Claude Code rewrites ~/.claude/settings.json whenever it changes plugins
// (`claude plugin marketplace add`, `claude plugin install`), and its
// serializer drops the `id` key guardrail puts on each hook group, keeping
// the group itself. Measured on Claude Code 2.1.285: all five guardrail
// groups survived with only `id` removed. The manifest compared exact values,
// so every `dot up` reported "ownership manifest drifted (5 missing)" and
// asked to re-enable, and `plane disable claude` would have left the five
// hooks behind.
func claudeMergedThenIDStripped(t *testing.T) string {
	t.Helper()
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{
		"hooks": map[string]any{
			"Stop": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "node mine.cjs stop"}}}},
		},
	})
	if err := MergePlaneInto(path, "claude", ClaudeConfig(base, "guardrail")); err != nil {
		t.Fatal(err)
	}
	doc := readJSON(t, path)
	stripped := 0
	for _, groups := range doc["hooks"].(map[string]any) {
		for _, g := range groups.([]any) {
			if m := g.(map[string]any); m["id"] != nil {
				delete(m, "id")
				stripped++
			}
		}
	}
	if stripped != 5 {
		t.Fatalf("stripped %d ids, want the 5 guardrail hook groups", stripped)
	}
	writeJSON(t, path, doc)
	return path
}

func TestClaudeHookGroupsWithoutTheirIDAreNotDrift(t *testing.T) {
	path := claudeMergedThenIDStripped(t)
	report, err := DriftFor("claude", path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Clean() {
		t.Errorf("id-stripped guardrail hooks reported as drift: %+v", report)
	}
}

func TestDisableClaudeRemovesHookGroupsWithoutTheirID(t *testing.T) {
	path := claudeMergedThenIDStripped(t)
	if err := RemovePlaneFrom(path, "claude"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hook claude") {
		t.Errorf("guardrail hooks survived disable:\n%s", raw)
	}
	if !strings.Contains(string(raw), "node mine.cjs stop") {
		t.Errorf("the operator's own hook was removed:\n%s", raw)
	}
}

// Only a group identical to the recorded one apart from the missing id
// matches: one the operator edited is theirs, and stays.
func TestAnEditedIDlessHookGroupIsNotGuardrails(t *testing.T) {
	path := claudeMergedThenIDStripped(t)
	doc := readJSON(t, path)
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	pre["matcher"] = "Bash"
	writeJSON(t, path, doc)
	if err := RemovePlaneFrom(path, "claude"); err != nil {
		t.Fatal(err)
	}
	after := readJSON(t, path)
	raw, _ := json.Marshal(after["hooks"])
	if !strings.Contains(string(raw), `"matcher":"Bash"`) {
		t.Errorf("an operator-edited group was removed as guardrail's: %s", raw)
	}
}
