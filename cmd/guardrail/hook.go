package main

import (
	"encoding/json"
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
			b, _ := json.Marshal(map[string]string{
				"decision": "deny",
				"reason":   fmt.Sprintf("guardrail: unparseable payload (%v); failing closed", err),
			})
			stdout.Write(append(b, '\n'))
			return 0
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

	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(tc.CWD); ok {
		if warn != "" {
			adapter.EmitModelWarnings([]string{warn}, stderr)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: cannot load overlay (%v); failing closed", err)}, stderr)
			return 2
		}
	} else if warn != "" {
		adapter.EmitModelWarnings([]string{warn}, stderr)
	}

	op, opErr := policy.LoadOperatorConfig()
	if opErr != nil {
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: operator config unreadable (%v); treating as empty", opErr)}, stderr)
	}
	merged, warnings, err := policy.Merge(base, ov, version, op, tc.RepoRoot)
	if err != nil {
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: invalid overlay (%v); failing closed", err)}, stderr)
		return 2
	}
	if opErr != nil {
		warnings = append(warnings, "guardrail: operator configuration could not be loaded; operator-authorized policy changes remain disabled")
	}
	adapter.EmitModelWarnings(warnings, stderr)

	if tc.Event == "session-start" {
		text := adapter.PostureText(policy.SortedWaivers(merged), warnings)
		return adapter.EmitClaudeSessionStart(text, stdout)
	}

	v := engine.Evaluate(tc, merged)

	if tc.Event == "pre" && tc.SessionID != "" && !merged.Waived["P7.trifecta"] {
		if session.Path(tc.SessionID) == "" {
			adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: unsafe session id %q; session heuristic disabled", tc.SessionID)}, stderr)
		} else {
			st, loadErr := session.Load(tc.SessionID)
			if loadErr != nil {
				adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: session state read failed (%v)", loadErr)}, stderr)
			}
			isPrivate := engine.IsPrivateDataAccess(tc, merged)
			isNet := engine.IsNetworkAttempt(tc)
			if esc := engine.TrifectaVerdict(v, isPrivate, isNet, st); esc != nil {
				v = *esc
			}
			st.SawPrivateRead = st.SawPrivateRead || isPrivate
			st.SawNetworkCall = st.SawNetworkCall || isNet
			if err := session.Save(tc.SessionID, st); err != nil {
				adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: session state write failed (%v)", err)}, stderr)
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
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: audit write failed (%v)", err)}, stderr)
	}

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
