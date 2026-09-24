package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ADR-0030: once the first-install bootstrap let `setup` and `plane enable`
// run without a terminal, the engine became the thing that keeps a mediated
// session from re-arming, disarming or re-enrolling its own guard.
func TestGuardrailLifecycleInvocationIsSelfConfigDeny(t *testing.T) {
	commands := []string{
		"guardrail setup",
		"guardrail setup --state disabled",
		"/home/operator/.local/bin/guardrail setup --planes claude",
		"guardrail.exe setup",
		"guardrail plane enable claude",
		"guardrail plane enable --all",
		"guardrail plane disable --all",
		"guardrail plane status extra",
		"guardrail operator enroll",
		"guardrail operator recover-reset",
		"guardrail recover claude-settings",
		`"$(command -v guardrail)" setup`,
		`python3 -c "import subprocess; subprocess.run(['guardrail', 'setup'])"`,
		`python3 -c "import os; os.system('guardrail plane enable claude')"`,
		`node -e "require('child_process').execSync('guardrail operator enroll')"`,
		`python3 -c "subcommand='recover'; executable='guardrail'; run(executable, subcommand)"`,
	}
	for _, command := range commands {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", command, v)
		}
	}
	if v := evalBash(t, `python3 -c "import os; os.system('guardrail setup')"`); v == nil || v.Reason != SelfControlMentionReason {
		t.Errorf("opaque lifecycle mention reason = %+v, want SelfControlMentionReason", v)
	}
	if v := evalBash(t, "guardrail plane enable claude"); v == nil || v.Reason != "the guarded plane cannot change its own guardrail posture (plane)" {
		t.Errorf("direct lifecycle reason = %+v", v)
	}
}

// The read-only and verification subcommands are how a session reports its
// own posture; they change nothing and stay allowed.
func TestReadOnlyGuardrailSubcommandsAreAllowedFromSessions(t *testing.T) {
	for _, command := range []string{
		"guardrail plane status",
		"/home/operator/.local/bin/guardrail plane status",
		"guardrail.exe plane status",
		"guardrail doctor",
		"guardrail doctor --coverage claude",
		"guardrail selftest",
		"guardrail audit",
		"guardrail version",
		"guardrail night status",
		`python3 -c "print('guardrail doctor')"`,
	} {
		if v := evalBash(t, command); v != nil {
			t.Errorf("%q -> %+v, want allow", command, v)
		}
	}
	if v := evalBash(t, "guardrail plane status; guardrail plane disable --all"); v == nil || v.Decision != policy.Deny {
		t.Errorf("a status query must not launder a disable in the same command line: %+v", v)
	}
}
