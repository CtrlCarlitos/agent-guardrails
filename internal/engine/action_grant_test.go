package engine

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsAndPOSIXExactActionBindingKeepsFullPatchAndDenyInvariant(t *testing.T) {
	repo := t.TempDir()
	patch := "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: ci\n*** End Patch"
	raw, _ := json.Marshal(map[string]string{"command": patch})
	tc := ToolCall{Plane: "codex", Event: "pre", Tool: "Edit", ContractTool: "apply_patch", Capability: policy.CapabilityMutation, SessionID: "s", RepoRoot: repo, CWD: repo, Arguments: raw, Paths: []string{filepath.Join(repo, ".github", "workflows", "ci.yml")}}
	ask := policy.Verdict{Decision: policy.Ask, RuleID: "P5.ci-infra-lockfile"}
	a, ok := ExactGrantAction(tc, ask)
	if !ok || a.Text != patch || a.Tool != "apply_patch" {
		t.Fatalf("patch lost: %+v %v", a, ok)
	}
	for _, v := range []policy.Verdict{{Decision: policy.Deny, RuleID: ask.RuleID}, {Decision: policy.Allow}, {Decision: policy.Ask, RuleID: "P3.unresolved"}, {Decision: policy.Ask, RuleID: "capability-external"}} {
		if _, ok := ExactGrantAction(tc, v); ok {
			t.Fatalf("grantable %+v", v)
		}
	}
	tc.Event = "post"
	if _, ok := ExactGrantAction(tc, ask); ok {
		t.Fatal("post edit became grantable")
	}
	tc.Event = "pre"
	tc.Plane = "claude"
	if _, ok := ExactGrantAction(tc, ask); ok {
		t.Fatal("expanded to another plane")
	}
}

func TestWindowsAndPOSIXActionStoreIsProtectedMachinery(t *testing.T) {
	for _, p := range []string{"/custom/config/guardrail/actions/request.json", `C:\Users\u\AppData\Roaming\guardrail\actions\request.json`} {
		for _, tool := range []string{"Write", "Edit"} {
			tc := ToolCall{Tool: tool, Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
			v := checkPaths(tc, pathPol())
			if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Fatalf("%s %s: %+v", tool, p, v)
			}
		}
	}
	for _, command := range []string{`python -c "open('/custom/config/guardrail/actions/request.json','w').write('{}')"`, `rm /custom/config/guardrail/actions/request.json`} {
		v := checkPaths(ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Fatalf("%s: %+v", command, v)
		}
	}
}

func TestWindowsAndPOSIXActionStoreContentsCannotBeReadByAgent(t *testing.T) {
	for _, p := range []string{"/custom/config/guardrail/actions/request.json", `C:\Users\u\AppData\Roaming\guardrail\actions\request.json`} {
		pol, err := policy.LoadBase()
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []ToolCall{
			{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"},
			{Tool: "Bash", Command: "cat " + p, RepoRoot: "/repo", CWD: "/repo"},
		} {
			v := checkPaths(tc, pol)
			if v == nil || v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
				t.Fatalf("private record read: %+v", v)
			}
		}
	}
}
