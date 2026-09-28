package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #435: with the shipped base policy these credential stores were readable,
// by `cat` and by the Read tool alike, and anything an agent reads goes to
// the model provider. The agents' own login files were among them.
func TestCredentialStoresAreSecretTier(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	root := repoRootForHost()
	eval := func(tc ToolCall) policy.Verdict {
		tc.Plane, tc.CWD, tc.RepoRoot = "claude", root, root
		return Evaluate(tc, pol)
	}
	for _, path := range []string{
		"~/.config/gh/hosts.yml",
		"~/AppData/Roaming/GitHub CLI/hosts.yml",
		"~/.config/hub",
		"~/_netrc",
		"~/.cargo/credentials.toml",
		"~/.cargo/credentials",
		"~/.terraform.d/credentials.tfrc.json",
		"~/.vault-token",
		"~/.azure/msal_token_cache.json",
		"~/.azure/service_principal_entries.json",
		"~/.password-store/github.gpg",
		"~/.config/op/config",
		"~/.config/fly/config.yml",
		"~/.claude/.credentials.json",
		"~/.codex/auth.json",
		"~/.config/opencode/auth.json",
		"~/.local/share/opencode/auth.json",
		"~/.gemini/oauth_creds.json",
	} {
		cat := eval(ToolCall{Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, Command: "cat '" + path + "'"})
		read := eval(ToolCall{Tool: "Read", NativeTool: "Read", Capability: policy.CapabilityReadDiscovery, Paths: []string{path}})
		sub := eval(ToolCall{Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, Command: "X=$(cat '" + path + "') ./tool"})
		for name, v := range map[string]policy.Verdict{"cat": cat, "Read": read, "$()": sub} {
			if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
				t.Errorf("%s %s -> %s %s, want deny P4.secret-path", name, path, v.Decision, v.RuleID)
			}
		}
	}
	// Configuration next to the credentials stays readable.
	for _, path := range []string{
		"~/.config/gh/config.yml",
		"~/.gitconfig",
		"~/.cargo/config.toml",
		"~/.claude/settings.json",
		"~/.codex/config.toml",
		"~/.config/opencode/opencode.json",
	} {
		read := eval(ToolCall{Tool: "Read", NativeTool: "Read", Capability: policy.CapabilityReadDiscovery, Paths: []string{path}})
		if read.RuleID == "P4.secret-path" {
			t.Errorf("Read %s -> %s %s, want no secret-path verdict", path, read.Decision, read.RuleID)
		}
	}
}
