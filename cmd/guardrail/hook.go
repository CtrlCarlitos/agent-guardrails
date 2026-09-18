package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

var sessionTransaction = session.Transaction

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude, opencode, antigravity, codex)")
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
	var tc engine.ToolCall
	failClosed := func(reason string) int {
		highPriorityWarnings = append(highPriorityWarnings, reason)
		if plane == "antigravity" {
			v := policy.Verdict{Decision: policy.Deny, Reason: reason}
			return adapter.EmitAntigravity(v, antigravityPhase, tc, stdout)
		}
		adapter.EmitModelWarnings(highPriorityWarnings, stderr)
		return 2
	}

	var err error
	switch plane {
	case "codex":
		tc, err = adapter.ParseCodex(stdin)
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
	nightState, nightErr := loadNightState(time.Now())
	if nightErr != nil {
		highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: night marker unreadable (%v); night mode remains inactive", nightErr))
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
		if nightState.Active {
			text = nightState.Banner() + "\n" + text
		}
		return adapter.EmitClaudeSessionStart(text, stdout)
	}

	operatorAction, hasOperatorAction := engine.OperatorAction(tc)
	approvalKey, approvalEnabled := engine.OpenCodeApprovalKey(tc)
	approvalEnabled = approvalEnabled && !nightState.Active
	needsP7 := tc.Event == "pre" && engine.TrifectaTrackingEnabled(merged)
	needsNightAnnouncement := nightState.Active && tc.Event == "pre" && plane != "claude"
	needsState := tc.SessionID != "" && (needsP7 || approvalEnabled || needsNightAnnouncement)
	var v policy.Verdict
	stateApplied := false
	announceNight := needsNightAnnouncement && tc.SessionID == ""
	if tc.Event == "pre" && hasOperatorAction {
		scope := approval.Allow
		if operatorAction.Name == "web-host-grant" || operatorAction.Name == "web-host-revoke" {
			scope = approval.Scope(operatorAction.Parameters["scope"])
		}
		r, createErr := approval.SubmitOnDemand(approval.Request{
			Plane: tc.Plane, SessionID: tc.SessionID, RepoRoot: tc.RepoRoot,
			Scope: scope, Reason: "canonical operator action",
			Action: operatorAction.Name, Parameters: operatorAction.Parameters,
		})
		if createErr != nil {
			v = policy.Verdict{Decision: policy.Deny, RuleID: "operator-action-broker", Reason: "operator-action request could not be recorded; failing closed"}
		} else {
			v = policy.Verdict{Decision: policy.Complete, RuleID: "operator-action", Reason: "operator action requires broker approval", OperatorAction: operatorAction.Name, RequestID: r.ID, ApprovalURL: r.ApprovalURL}
		}
		stateApplied = true
	} else if tc.Event == "pre" && needsState {
		err := sessionTransaction(tc.SessionID, func(st *session.State) error {
			if needsNightAnnouncement {
				until := nightState.Until.Format(time.RFC3339Nano)
				if st.NightModeAnnouncements[plane] != until {
					announceNight = true
					if st.NightModeAnnouncements == nil {
						st.NightModeAnnouncements = make(map[string]string)
					}
					st.NightModeAnnouncements[plane] = until
				}
			}
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
			announceNight = needsNightAnnouncement
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
	normalVerdict := v
	if !hasOperatorAction {
		v = engine.ApplyNightMode(v, nightState.Active)
	}
	nightAllowed := normalVerdict.Decision == policy.Ask && v.Decision == policy.Allow && v.RuleID == "ask-allowed-by-night-mode"
	if announceNight {
		v = prependVerdictReason(v, nightState.Banner())
	}

	rec := auditRecord(tc, v, policy.SortedWaivers(merged))
	if err := audit.Write(rec, audit.DefaultPath(merged.Slots.AuditLog)); err != nil {
		highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: audit write failed (%v)", err))
		if nightAllowed {
			v = normalVerdict
			if announceNight {
				v = prependVerdictReason(v, nightState.Banner())
			}
		}
	}
	stderrWarnings := append(append([]string{}, highPriorityWarnings...), mergeWarnings...)
	adapter.EmitModelWarnings(stderrWarnings, stderr)

	switch plane {
	case "codex":
		return adapter.EmitCodex(v, tc.Event, tc, stdout, stderr)
	case "claude":
		return adapter.EmitClaude(v, tc.Event, tc, stdout, stderr)
	case "opencode":
		return adapter.EmitOpencode(v, tc, stdout, stderr)
	case "antigravity":
		return adapter.EmitAntigravity(v, antigravityPhase, tc, stdout)
	default:
		return 2
	}
}

func auditRecord(tc engine.ToolCall, v policy.Verdict, waivers []string) audit.Record {
	rec := audit.Record{
		SessionID:      tc.SessionID,
		Plane:          tc.Plane,
		Tool:           tc.Tool,
		NativeTool:     tc.NativeTool,
		Capability:     string(tc.Capability),
		InputShape:     tc.InputShape,
		AuditKind:      v.AuditKind,
		Event:          tc.Event,
		Decision:       string(v.Decision),
		RuleID:         v.RuleID,
		OriginRuleID:   v.OriginRuleID,
		Reason:         v.Reason,
		Waivers:        waivers,
		OperatorAction: v.OperatorAction,
		RequestID:      v.RequestID,
	}
	if tc.Capability != policy.CapabilityUnknown {
		rec.Command = tc.Command
		rec.Paths = tc.Paths
	}
	return rec
}

func prependVerdictReason(v policy.Verdict, prefix string) policy.Verdict {
	if v.Reason == "" {
		v.Reason = prefix
	} else {
		v.Reason = prefix + "; " + v.Reason
	}
	return v
}

func loadNightState(now time.Time) (night.State, error) {
	path, err := night.DefaultPath()
	if err != nil {
		return night.State{}, err
	}
	return night.Load(path, now)
}
