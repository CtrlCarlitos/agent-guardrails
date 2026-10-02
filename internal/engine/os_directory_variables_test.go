package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #489: `cd "$LOCALAPPDATA/guardrail" && cat audit.jsonl` asked
// P3.unresolved. The hook runs with the same OS-provided directory variables
// as the agent's shell, so the Engine resolves a fixed set of them from its
// own environment, as it already did for HOME. The resolved path then meets
// the normal path families: a secret or guardrail's own config is still
// refused.

func evalWithOSDirectories(t *testing.T, cmd string) policy.Verdict {
	t.Helper()
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	return Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: repo, RepoRoot: repo}, pol)
}

// osDirectories points every seeded variable at a fresh absolute directory.
func osDirectories(t *testing.T) map[string]string {
	t.Helper()
	dirs := map[string]string{}
	for _, name := range []string{"USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "TMPDIR"} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name, dir)
		dirs[name] = dir
	}
	return dirs
}

func TestOSDirectoryVariablesResolveFromTheHookEnvironment(t *testing.T) {
	osDirectories(t)
	for _, cmd := range []string{
		`cat "$LOCALAPPDATA/notes/audit.jsonl"`,
		`cd "$LOCALAPPDATA/notes" && cat audit.jsonl`,
		`ls "$TEMP"`,
		`ls "$TMP" "$TMPDIR"`,
		`cat "${APPDATA}/tool/readme.txt"`,
	} {
		if v := evalWithOSDirectories(t, cmd); v.Decision != policy.Allow {
			t.Errorf("%s: %s %s (%s); want allow", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}

func TestResolvedOSDirectoriesStillMeetThePathRules(t *testing.T) {
	dirs := osDirectories(t)
	// Guardrail's own config dir derives from the same variables.
	t.Setenv("XDG_CONFIG_HOME", dirs["APPDATA"])
	for cmd, want := range map[string]struct {
		decision policy.Decision
		rule     string
	}{
		`cat "$USERPROFILE/.ssh/id_ed25519"`:         {policy.Deny, "P4.secret-path"},
		`cd "$USERPROFILE/.ssh" && cat id_ed25519`:   {policy.Deny, "P4.secret-path"},
		`echo x > "$APPDATA/guardrail/waivers.toml"`: {policy.Deny, "P5.self-config"},
		`rm -rf "$LOCALAPPDATA"`:                     {policy.Deny, "P1.rm-rf"},
	} {
		v := evalWithOSDirectories(t, cmd)
		// A secret can be refused by its resolved path or, first, by its
		// mention in the text; either P4 secret rule is a refusal.
		ruleOK := v.RuleID == want.rule || want.rule == "P4.secret-path" && strings.HasPrefix(v.RuleID, "P4.secret")
		if v.Decision != want.decision || !ruleOK {
			t.Errorf("%s: %s %s (%s); want %s %s", cmd, v.Decision, v.RuleID, v.Reason, want.decision, want.rule)
		}
	}
}

func TestOSDirectoryVariablesStayUnresolvedWhenUnknowable(t *testing.T) {
	osDirectories(t)
	t.Setenv("TEMP", "relative/temp")
	for _, cmd := range []string{
		// A relative value is not trusted.
		`cat "$TEMP/a"`,
		// Reassigned to something unknown in the same command.
		`LOCALAPPDATA=$X; cat "$LOCALAPPDATA/a"`,
		`export APPDATA="$(pwd)"; cat "$APPDATA/a"`,
		// Not on the list.
		`cat "$XDG_CONFIG_HOME/a"`,
		`cat "$SOME_OTHER_DIR/a"`,
	} {
		if v := evalWithOSDirectories(t, cmd); v.Decision == policy.Allow {
			t.Errorf("%s: allowed; want it held", cmd)
		}
	}
	os.Unsetenv("LOCALAPPDATA")
	if v := evalWithOSDirectories(t, `cat "$LOCALAPPDATA/a"`); v.Decision == policy.Allow {
		t.Errorf("unset LOCALAPPDATA: allowed; want it held")
	}
}

// A literal reassignment wins over the environment.
func TestALiteralReassignmentOfAnOSDirectoryWins(t *testing.T) {
	osDirectories(t)
	v := evalWithOSDirectories(t, `LOCALAPPDATA=/home/u/.ssh; cat "$LOCALAPPDATA/id_ed25519"`)
	if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Errorf("reassigned to .ssh: %s %s; want deny P4.secret-path", v.Decision, v.RuleID)
	}
}
