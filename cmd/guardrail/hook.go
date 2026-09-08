package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

var sessionTransaction = session.Transaction

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude, opencode, antigravity)")
		return 2
	}
	plane := args[0]

	var antigravityPhase string
	if plane == "antigravity" {
		if len(args) < 2 {
			fmt.Fprintln(stderr, "guardrail: hook antigravity needs a phase (pre, post)")
			return 2
		}
		antigravityPhase = args[1]
	}

	var highPriorityWarnings []string
	failClosed := func(reason string) int {
		highPriorityWarnings = append(highPriorityWarnings, reason)
		if plane == "antigravity" {
			v := policy.Verdict{Decision: policy.Deny, Reason: reason}
			return adapter.EmitAntigravity(v, antigravityPhase, stdout)
		}
		adapter.EmitModelWarnings(highPriorityWarnings, stderr)
		return 2
	}

	var tc engine.ToolCall
	var err error
	switch plane {
	case "claude":
		tc, err = adapter.ParseClaude(stdin)
	case "opencode":
		tc, err = adapter.ParseOpencode(stdin)
	case "antigravity":
		tc, err = adapter.ParseAntigravity(antigravityPhase, stdin)
	default:
		adapter.EmitModelWarnings([]string{fmt.Sprintf("guardrail: unsupported plane %q", plane)}, stderr)
		return 2
	}
	if err != nil {
		return failClosed(fmt.Sprintf("guardrail: unparseable hook payload (%v); failing closed", err))
	}

	base, err := policy.LoadBase()
	if err != nil {
		return failClosed(fmt.Sprintf("guardrail: cannot load base policy (%v); failing closed", err))
	}

	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(tc.CWD); ok {
		if warn != "" {
			highPriorityWarnings = append(highPriorityWarnings, warn)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			return failClosed(fmt.Sprintf("guardrail: cannot load overlay (%v); failing closed", err))
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
		return failClosed(fmt.Sprintf("guardrail: invalid overlay (%v); failing closed", err))
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

	approvalKey, approvalEnabled := engine.OpenCodeApprovalKey(tc)
	needsP7 := tc.Event == "pre" && engine.TrifectaTrackingEnabled(merged)
	needsState := tc.SessionID != "" && (needsP7 || approvalEnabled)
	var v policy.Verdict
	stateApplied := false
	if tc.Event == "pre" && needsState {
		err := sessionTransaction(tc.SessionID, func(st *session.State) error {
			v = engine.Evaluate(tc, merged)
			if needsP7 {
				if esc := engine.ApplyTrifecta(v, tc, st, merged); esc != nil {
					v = *esc
				}
			}
			if approvalEnabled {
				v = engine.ApplyOpenCodeApproval(v, approvalKey, st, time.Now().UTC())
			}
			return nil
		})
		if err == nil {
			stateApplied = true
		} else if errors.Is(err, session.ErrTransactionCommitted) {
			stateApplied = true
			highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: session transaction committed but lock release failed (%v)", err))
		} else {
			highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: session transaction failed (%v)", err))
		}
	}
	if !stateApplied {
		v = engine.Evaluate(tc, merged)
		if needsP7 {
			if esc := engine.ApplyTrifecta(v, tc, nil, merged); esc != nil {
				v = *esc
			}
		}
	}

	if v.Decision == policy.Allow {
		if rv := recipe.Check(tc); rv != nil {
			v = *rv
		}
	}

	rec := audit.Record{
		SessionID:    tc.SessionID,
		Plane:        tc.Plane,
		Tool:         tc.Tool,
		Event:        tc.Event,
		Command:      tc.Command,
		Paths:        tc.Paths,
		Decision:     string(v.Decision),
		RuleID:       v.RuleID,
		OriginRuleID: v.OriginRuleID,
		Reason:       v.Reason,
		Waivers:      policy.SortedWaivers(merged),
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
