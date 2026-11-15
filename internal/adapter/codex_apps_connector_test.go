package adapter

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #543's recorded denial: Codex's apps connector surfaces GitHub repository
// search as an MCP-shaped identity the registry did not know, so it fell to
// the ungrantable capability-deny. Repository discovery sends query and
// account context to GitHub, so it is External — a per-call operator ask
// (on Codex: blocked with the exact-action grant path, ADR-0014/#349), not
// an allow and not a generic unsupported-capability rejection.
func TestCodexAppsGitHubRepositorySearchAsks(t *testing.T) {
	cwd := filepath.ToSlash(t.TempDir())
	for _, name := range []string{
		// normalized (explain) and surfaced (hook payload) spellings
		"mcp__codex_apps__github__search_repositories",
		"mcp__codex_apps__github_search_repositories",
	} {
		t.Run(name, func(t *testing.T) {
			tc, err := ParseCodex(strings.NewReader(codexEnvelope(cwd, name, map[string]any{
				"link_id":  "link_69967bf06aec8191acddbb6b4330f325",
				"query":    "guardrail user:CtrlCarlitos",
				"per_page": 10,
			})))
			if err != nil {
				t.Fatal(err)
			}
			if tc.Capability != policy.CapabilityExternal {
				t.Fatalf("capability = %v, want External", tc.Capability)
			}
			if !strings.Contains(tc.ContractTool, "search_repositories") {
				t.Fatalf("contract tool = %q", tc.ContractTool)
			}
			v := engine.Evaluate(tc, &policy.Policy{})
			if v.Decision != policy.Ask || v.RuleID != "capability-external" {
				t.Fatalf("verdict = %+v, want ask/capability-external", v)
			}
			var out, stderr bytes.Buffer
			if code := EmitCodex(v, "pre", tc, &out, &stderr); code != 2 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			// The blocked ask must offer the operator path, not the
			// ungrantable "unsupported capability" dead end.
			if !strings.Contains(stderr.String(), "operator") {
				t.Fatalf("stderr lacks the operator path: %q", stderr.String())
			}
			if strings.Contains(stderr.String(), "unsupported") {
				t.Fatalf("stderr reads as unsupported capability: %q", stderr.String())
			}
		})
	}
}

// Unevidenced siblings stay fail-closed: repository discovery is classified
// on its recorded payload only, and creation/mutation tools in the connector
// family keep their own separate checks (the issue's acceptance criteria).
func TestCodexAppsGitHubMutationsStayFailClosed(t *testing.T) {
	cwd := filepath.ToSlash(t.TempDir())
	for _, name := range []string{
		"mcp__codex_apps__github__create_issue",
		"mcp__codex_apps__github_create_issue",
	} {
		tc, err := ParseCodex(strings.NewReader(codexEnvelope(cwd, name, map[string]any{"title": "x"})))
		if err != nil {
			t.Fatal(err)
		}
		v := engine.Evaluate(tc, &policy.Policy{})
		if v.Decision != policy.Deny {
			t.Fatalf("%s verdict = %+v, want fail-closed deny", name, v)
		}
		if v.RuleID == "capability-external" {
			t.Fatalf("%s classified External without recorded evidence", name)
		}
	}
}
