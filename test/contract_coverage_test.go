package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

// #85: the per-plane fixture tests verify one direction — every fixture
// listed in expected.json exists and produces its pinned verdict. Nothing
// verified the reverse: that every tool a plane's contract registers is
// exercised by at least one referenced fixture. A newly contracted tool
// could ship with zero coverage and no test would notice (#42's
// notebook_edit / sed_file / delete_knowledge drift was exactly this).
//
// contractFixtureTools returns tool name -> fixture files, for the fixtures
// expected.json actually references: a dead file must never count as
// coverage. Payload tool-name fields are pinned from the real fixtures:
// claude and codex payloads carry a top-level tool_name, opencode envelopes
// carry tool (V1-native contract names, ADR-0007), antigravity payloads
// carry toolCall.name.
func contractFixtureTools(t *testing.T, plane string) map[string][]string {
	t.Helper()
	expectedPath := filepath.Join("fixtures", plane, "expected.json")
	raw, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("%s: %v", expectedPath, err)
	}
	var expected map[string]json.RawMessage
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatalf("%s: %v", expectedPath, err)
	}
	tools := map[string][]string{}
	for name := range expected {
		payloadPath := filepath.Join("fixtures", plane, name)
		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("%s: referenced by expected.json but unreadable: %v", payloadPath, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(payload, &doc); err != nil {
			t.Fatalf("%s: malformed fixture JSON: %v", payloadPath, err)
		}
		var tool any
		switch plane {
		case "claude", "codex":
			tool = doc["tool_name"]
		case "opencode":
			tool = doc["tool"]
		case "antigravity":
			call, _ := doc["toolCall"].(map[string]any)
			tool = call["name"]
		}
		name, _ := tool.(string)
		if name == "" {
			t.Fatalf("%s: no tool name found (tool_name/tool/toolCall.name missing or not a string)", payloadPath)
		}
		tools[name] = append(tools[name], payloadPath)
	}
	return tools
}

// contractExemptions lists contracted tools that cannot be driven through
// `hook <plane>` stdin, each with its one-line reason. Anything drivable
// gets a fixture instead; this map is the audit trail, not a backlog.
var contractExemptions = map[string]map[string]string{
	"claude":      {},
	"opencode":    {},
	"antigravity": {},
	"codex":       {},
}

func TestEveryContractedToolHasAFixture(t *testing.T) {
	for _, plane := range []string{"claude", "opencode", "antigravity", "codex"} {
		covered := contractFixtureTools(t, plane)
		exempt := contractExemptions[plane]
		var uncovered []string
		for _, spec := range planecontract.RegisteredTools(plane) {
			if len(covered[spec.NativeTool]) > 0 || len(covered[spec.Tool]) > 0 {
				continue
			}
			if _, ok := exempt[spec.NativeTool]; ok {
				continue
			}
			uncovered = append(uncovered, spec.NativeTool)
		}
		if len(uncovered) > 0 {
			t.Errorf("%s: contracted tools with no referenced fixture in fixtures/%s/ (add a fixture + expected.json entry, or an exemption with a reason): %v",
				plane, plane, uncovered)
		}
	}
}

// A fixture file nothing references is dead weight that passes for
// coverage while never running: expected.json is the only index the
// per-plane tests read, so a payload it does not name exercises nothing.
// Non-payload files (expected.json itself, README.md, *.golden.json) are
// exempt; anything else must be referenced or be gone.
func TestEveryFixtureIsExpected(t *testing.T) {
	for _, plane := range []string{"claude", "opencode", "antigravity", "codex"} {
		dir := filepath.Join("fixtures", plane)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		var expected map[string]json.RawMessage
		if err := json.Unmarshal(raw, &expected); err != nil {
			t.Fatalf("%s/expected.json: %v", plane, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || filepath.Ext(name) != ".json" || name == "expected.json" || strings.HasSuffix(name, ".golden.json") {
				continue
			}
			if _, ok := expected[name]; !ok {
				t.Errorf("%s/%s: fixture file no expected.json entry references (reference it, or delete it)", plane, name)
			}
		}
	}
}
