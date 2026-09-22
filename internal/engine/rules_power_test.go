package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The corpus is the measured inventory from #140: every shape below allowed
// on main before the rule existed. The act — ending the machine's uptime —
// ends the session, kills unsaved work, and cannot be undone by anything the
// agent does afterwards, which is the P1 destructive shape at ask tier (the
// tier chmod 777 gets), not a deny: rebooting a machine the operator handed
// the agent is an operator decision, made per call.

func TestPowerControlCommandsAsk(t *testing.T) {
	commands := []string{
		// The measured corpus from #140.
		`shutdown -h now`,
		`shutdown -r now`,
		`reboot`,
		`poweroff`,
		`halt`,
		`Stop-Computer`,
		`Restart-Computer`,
		// POSIX shutdown flag shapes.
		`shutdown`,
		`shutdown +5`,
		`shutdown 20:30`,
		`shutdown -P`,
		`shutdown -H`,
		`shutdown --poweroff`,
		`shutdown --reboot`,
		`shutdown --halt`,
		// Windows shutdown flag shapes (cmd/PowerShell spelling).
		`shutdown /s`,
		`shutdown /r`,
		`shutdown /r /t 0`,
		`shutdown /s /t 0`,
		`shutdown /g`,
		`shutdown /h`,
		`shutdown /S`, // cmd flags are case-insensitive
		// systemctl verb spellings of the same acts.
		`systemctl reboot`,
		`systemctl poweroff`,
		`systemctl halt`,
		// init/telinit: runlevel 0 halts, 6 reboots.
		`init 0`,
		`init 6`,
		`telinit 0`,
		`telinit 6`,
		// Executable identity is canonicalized, not spelled.
		`REBOOT`,
		`PowerOff`,
	}
	for _, command := range commands {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P1.power" {
			t.Errorf("%q -> %+v, want ask/P1.power", command, v)
		}
	}
}

// The read twins and the cancel/dry-run shapes do work the agent can see the
// result of; they must stay allowed or every reboot rule becomes a wall in
// front of `shutdown --help`.
func TestPowerControlReadTwinsStayAllowed(t *testing.T) {
	commands := []string{
		`shutdown --help`,
		`shutdown -c`,     // cancels a pending shutdown
		`shutdown -k now`, // warning wall message only; powers nothing off
		`shutdown /a`,     // Windows abort of a pending shutdown
		`shutdown /?`,     // Windows help
		`uptime`,
		`who -b`, // last boot time: a read
		`systemctl status`,
		`systemctl list-units`,
		`init 3`, // a multi-user runlevel switch, not halt/reboot
		`telinit 2`,
	}
	for _, command := range commands {
		if v := evalBash(t, command); v != nil {
			t.Errorf("%q -> %+v, want allow", command, v)
		}
	}
}

// ADR-0018: a machine-level act is a per-call operator decision, so an
// overnight window must not answer the ask on the operator's behalf — the
// same posture the External tier holds.
func TestPowerControlAskIsNeverNightRelaxed(t *testing.T) {
	v := evalBash(t, `shutdown -h now`)
	if v == nil || v.RuleID != "P1.power" {
		t.Fatalf("shutdown -h now -> %+v, want ask/P1.power", v)
	}
	relaxed := ApplyNightMode(*v, true)
	if relaxed.Decision != policy.Ask || relaxed.RuleID != "P1.power" {
		t.Errorf("night mode relaxed P1.power: %+v", relaxed)
	}
}

// ADR-0003: the rule is waivable like any ordinary ask — an operator-issued,
// audited waiver clears it. Only the night/grant relaxation paths are closed.
func TestPowerControlIsWaivable(t *testing.T) {
	pol := bashPol()
	pol.Waived["P1.power"] = true
	tc := ToolCall{Tool: "Bash", Command: `reboot`, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkBash(tc, pol); v != nil {
		t.Errorf("waived reboot -> %+v, want allow", v)
	}
}
