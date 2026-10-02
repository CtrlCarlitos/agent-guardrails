package engine

import (
	"os"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #489: on a real Windows profile, deleting one of these directories through
// its variable is refused, exactly as the literal path is. Before, it asked
// P3.unresolved. A scratch directory under TEMP stays allowed, like its
// literal. Uses the runner's real environment: these variables only exist on
// Windows, and relocating them under a temp root changes what deletion means.
func TestWindowsRemovingAnOSDirectoryThroughItsVariableIsDenied(t *testing.T) {
	for _, name := range []string{"USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is not set on this Windows runner", name)
		}
		v := evalWithOSDirectories(t, `rm -rf "$`+name+`"`)
		if v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf(`rm -rf "$%s": %s %s; want deny P1.rm-rf`, name, v.Decision, v.RuleID)
		}
	}
	if v := evalWithOSDirectories(t, `rm -rf "$TEMP/guardrail-scratch-489"`); v.Decision != policy.Allow {
		t.Errorf(`rm -rf "$TEMP/guardrail-scratch-489": %s %s; want allow, as its literal path`, v.Decision, v.RuleID)
	}
}
