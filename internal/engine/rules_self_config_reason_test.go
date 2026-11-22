package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

const (
	ownConfigReason     = "write to the agent's own guardrail/shell config: "
	projectFolderReason = "write to a Claude Code project configuration folder: "
)

// A `.claude` folder is protected wherever it is, because a Claude session
// started in that directory loads it. The denial used to call every such path
// "the agent's own guardrail/shell config", which is false for a new folder in
// a scratch directory and sent the agent looking for what it had touched
// (#686). The verdict is unchanged; the reason now says what the path is.
func TestSelfConfigReasonNamesAProjectFolderOutsideTheRepoAndHome(t *testing.T) {
	scratch := outsideCommandFixturePath("scratch") + "/trig/proj"
	for _, tc := range []ToolCall{
		{Tool: "Write", Paths: []string{scratch + "/.claude/commands/trigger.md"}},
		{Tool: "Write", Paths: []string{scratch + "/.claude/settings.json"}},
		{Tool: "Bash", Command: "mkdir -p " + scratch + "/.claude"},
		{Tool: "Bash", Command: "mkdir -p " + scratch + "/.claude/skills/demo"},
		{Tool: "Bash", Command: "printf x > " + scratch + "/.claude/commands/trigger.md"},
	} {
		tc.RepoRoot, tc.CWD = "/repo", "/repo"
		v := checkPathsHostFrameFixture(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%s %s%v -> %+v, want deny P5.self-config", tc.Tool, tc.Command, tc.Paths, v)
			continue
		}
		if !strings.HasPrefix(v.Reason, projectFolderReason) || strings.Contains(v.Reason, "agent's own") {
			t.Errorf("%s %s%v reason = %q, want the project-folder wording", tc.Tool, tc.Command, tc.Paths, v.Reason)
		}
	}
}

// Inside the repository and in a home directory the folder is the agent's own
// configuration, and the reason keeps saying so.
func TestSelfConfigReasonStaysOwnConfigInTheRepoAndHome(t *testing.T) {
	for _, path := range []string{
		"/repo/.claude/settings.json",
		"/repo/.claude/commands/x.md",
		"/repo/sub/.claude/settings.json",
		"/home/u/.claude/settings.json",
		"/Users/u/.claude/commands/x.md",
		"/root/.claude/settings.json",
	} {
		tc := ToolCall{Tool: "Write", Paths: []string{path}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPathsHostFrameFixture(tc, pathPol())
		if v == nil || v.RuleID != "P5.self-config" || !strings.HasPrefix(v.Reason, ownConfigReason) {
			t.Errorf("Write %q -> %+v, want P5.self-config with the own-config wording", path, v)
		}
	}
}

// Everything else the rule protects is not a `.claude` folder and keeps its
// wording wherever it is.
func TestSelfConfigReasonIsUnchangedForOtherProtectedPaths(t *testing.T) {
	scratch := outsideCommandFixturePath("scratch")
	for _, path := range []string{scratch + "/.envrc", scratch + "/guardrail.toml", scratch + "/.bashrc"} {
		tc := ToolCall{Tool: "Write", Paths: []string{path}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPathsHostFrameFixture(tc, pathPol())
		if v == nil || v.RuleID != "P5.self-config" || !strings.HasPrefix(v.Reason, ownConfigReason) {
			t.Errorf("Write %q -> %+v, want P5.self-config with the own-config wording", path, v)
		}
	}
}
