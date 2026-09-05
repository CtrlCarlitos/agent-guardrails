package main

import (
	"fmt"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude, opencode, antigravity)")
		return 2
	}
	plane := args[0]

	var tc engine.ToolCall
	var err error
	var antigravityPhase string
	switch plane {
	case "claude":
		tc, err = adapter.ParseClaude(stdin)
	case "opencode":
		tc, err = adapter.ParseOpencode(stdin)
	case "antigravity":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "guardrail: hook antigravity needs a phase (pre, post)")
			return 2
		}
		antigravityPhase = args[1]
		tc, err = adapter.ParseAntigravity(antigravityPhase, stdin)
		if err != nil {
			v := policy.Verdict{Decision: policy.Deny,
				Reason: fmt.Sprintf("guardrail: unparseable payload (%v); failing closed", err)}
			return adapter.EmitAntigravity(v, "pre", stdout)
		}
	default:
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: unsupported plane %q", plane)}, stderr)
		return 2
	}
	if err != nil {
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: unparseable hook payload (%v); failing closed", err)}, stderr)
		return 2
	}

	base, err := policy.LoadBase()
	if err != nil {
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: cannot load base policy (%v); failing closed", err)}, stderr)
		return 2
	}

	var highPriorityWarnings []string
	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(tc.CWD); ok {
		if warn != "" {
			highPriorityWarnings = append(highPriorityWarnings, warn)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: cannot load overlay (%v); failing closed", err))
			adapter.EmitModelWarnings(highPriorityWarnings, stderr)
			return 2
		}
	} else if warn != "" {
		highPriorityWarnings = append(highPriorityWarnings, warn)
	}

	op, opErr := policy.LoadOperatorConfig()
	if opErr != nil {
		highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: operator config unreadable (%v); treating as empty", opErr))
	}
	merged, mergeWarnings, err := policy.Merge(base, ov, version, op, tc.RepoRoot)
	if err != nil {
		highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: invalid overlay (%v); failing closed", err))
		adapter.EmitModelWarnings(highPriorityWarnings, stderr)
		return 2
	}
	postureWarnings := mergeWarnings
	if opErr != nil {
		postureWarnings = append([]string{
			"guardrail: operator configuration could not be loaded; operator-authorized policy changes remain disabled",
		}, mergeWarnings...)
	}

	if tc.Event == "session-start" {
		stderrWarnings := append(append([]string{}, highPriorityWarnings...), mergeWarnings...)
		adapter.EmitModelWarnings(stderrWarnings, stderr)
		text := adapter.PostureText(policy.SortedWaivers(merged), postureWarnings)
		return adapter.EmitClaudeSessionStart(text, stdout)
	}

	v := engine.Evaluate(tc, merged)

	if tc.Event == "pre" && tc.SessionID != "" && !merged.Waived["P7.trifecta"] {
		if session.Path(tc.SessionID) == "" {
			highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: unsafe session id %q; session heuristic disabled", tc.SessionID))
		} else {
			st, loadErr := session.Load(tc.SessionID)
			if loadErr != nil {
				highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: session state read failed (%v)", loadErr))
			}
			isPrivate := engine.IsPrivateDataAccess(tc, merged)
			isNet := engine.IsNetworkAttempt(tc)
			if esc := engine.TrifectaVerdict(v, isPrivate, isNet, st); esc != nil {
				v = *esc
			}
			st.SawPrivateRead = st.SawPrivateRead || isPrivate
			st.SawNetworkCall = st.SawNetworkCall || isNet
			if err := session.Save(tc.SessionID, st); err != nil {
				highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: session state write failed (%v)", err))
			}
		}
	}

	if v.Decision == policy.Allow {
		if rv := recipe.Check(tc); rv != nil {
			v = *rv
		}
	}

	rec := audit.Record{
		SessionID: tc.SessionID,
		Plane:     tc.Plane,
		Tool:      tc.Tool,
		Event:     tc.Event,
		Command:   tc.Command,
		Paths:     tc.Paths,
		Decision:  string(v.Decision),
		RuleID:    v.RuleID,
		Reason:    v.Reason,
		Waivers:   policy.SortedWaivers(merged),
	}
	if err := audit.Write(rec, audit.DefaultPath(merged.Slots.AuditLog)); err != nil {
		highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: audit write failed (%v)", err))
	}
	stderrWarnings := append(append([]string{}, highPriorityWarnings...), mergeWarnings...)
	adapter.EmitModelWarnings(stderrWarnings, stderr)

	switch plane {
	case "claude":
		return adapter.EmitClaude(v, tc.Event, stdout, stderr)
	case "opencode":
		return adapter.EmitOpencode(v, stdout, stderr)
	case "antigravity":
		return adapter.EmitAntigravity(v, antigravityPhase, stdout)
	default:
		return 2
	}
}
