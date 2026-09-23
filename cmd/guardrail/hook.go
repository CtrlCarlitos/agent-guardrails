package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/coverage"
	"github.com/CtrlCarlitos/agent-guardrails/internal/daemon"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

var sessionTransaction = session.Transaction

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude, opencode, antigravity, codex)")
		return 2
	}
	plane := args[0]
	var tc engine.ToolCall
	var codexMeta codexHookMetadata
	if plane == "codex" {
		originalStderr := stderr
		captured := cappedBuffer{limit: 8 << 10}
		stderr = &captured
		defer func() {
			rawStderr := captured.String()
			_, _ = io.WriteString(originalStderr, rawStderr)
			if code != 0 {
				emitCodexHookDiagnostic(originalStderr, codexMeta, tc, code, rawStderr)
			}
		}()
		var err error
		codexMeta, err = parseCodexHookMetadata(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: handler failure: %s; failing closed\n", safetext.SingleLine(err.Error()))
			return 2
		}
	}

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
		if plane == "codex" {
			reason = "guardrail: handler failure: " + strings.TrimPrefix(reason, "guardrail: ")
		}
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
	if tc.Event != "session-start" && tc.Event != "session-completion" {
		if client, dialErr := daemon.Dial(""); dialErr == nil {
			defer client.Close()
			if v, evalErr := client.Evaluate(tc); evalErr == nil {
				return emitVerdict(plane, antigravityPhase, tc, v, stdout, stderr)
			}
		}
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
		text += "\n\n" + claudePlanePosture()
		if line := claudeCoveragePosture(); line != "" {
			text += "\n\n" + line
		}
		if line := selftestPosture(version); line != "" {
			text += "\n\n" + line
		}
		// ADR-0028's loud-outage posture. Last, and unconditional when it
		// fires: with the floor retired this plane runs ungated during an
		// outage and silently no-ops a failed hook spawn (#151), so the
		// advisory is the only thing that says enforcement stopped. Empty
		// when the engine is reachable.
		if line := engineHealthPosture(currentEngineHealth()); line != "" {
			text += "\n\n" + line
		}
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
	if tc.Event == "session-completion" {
		v = policy.Verdict{Decision: policy.Allow, RuleID: "P8.recipe-lint", Reason: "session checks passed"}
		if rv := recipe.CheckSession(tc.RepoRoot, merged); rv != nil {
			v = *rv
		}
		stateApplied = true
	} else if tc.Event == "pre" && hasOperatorAction {
		scope := approval.Allow
		if operatorAction.Name == "web-host-grant" || operatorAction.Name == "web-host-revoke" {
			scope = approval.Scope(operatorAction.Parameters["scope"])
		}
		if reason, satisfied := engine.OperatorActionSatisfied(operatorAction, merged, op); satisfied {
			v = policy.Verdict{Decision: policy.Deny, RuleID: "operator-action-satisfied", Reason: reason, OperatorAction: operatorAction.Name}
			stateApplied = true
		} else {
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
		}
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
				if tc.HostApproved {
					// Host-owned dialog evidence outranks retry inference.
					v = engine.ApplyOpenCodeHostApproval(v, approvalKey, st, time.Now().UTC())
				} else {
					v = engine.ApplyOpenCodeApproval(v, approvalKey, st, time.Now().UTC())
				}
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
		if rv := recipe.Check(tc, merged); rv != nil {
			v = *rv
		}
	}
	normalVerdict := v
	if !hasOperatorAction {
		v = engine.ApplyNightMode(v, nightState.Active)
	}
	nightAllowed := normalVerdict.Decision == policy.Ask && v.Decision == policy.Allow && v.RuleID == "ask-allowed-by-night-mode"
	// A command grant is tried only on what is still an Ask, so an overnight
	// relaxation that already covers this call does not silently spend one.
	// Consumption re-checks the match under the operator lock and spends the
	// use before the verdict changes: an allow that was not paid for would let
	// a single-use grant authorize an unbounded number of executions, which is
	// the difference the operator was shown at issuance.
	grantAllowed := false
	if !hasOperatorAction && v.Decision == policy.Ask && tc.Event == "pre" {
		if granted := engine.ApplyCommandGrant(v, tc, op, time.Now()); granted.Decision == policy.Allow {
			spent, err := consumeCommandGrant(tc.RepoRoot, v.RuleID, tc.Command, time.Now())
			switch {
			case err != nil:
				highPriorityWarnings = append(highPriorityWarnings,
					fmt.Sprintf("guardrail: grant consumption failed (%v); the rule remains ENFORCED", err))
			case spent:
				v = granted
				grantAllowed = true
			}
		}
	}
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
		if grantAllowed {
			// The whole point of a grant is that the action stops being the
			// one thing in the session with no record, so an allow that could
			// not be recorded is not one this grant bought. The use is already
			// spent and stays spent: restoring it would need a second write on
			// the path that just failed, and an operator re-issuing is the
			// safe direction.
			v = normalVerdict
			highPriorityWarnings = append(highPriorityWarnings,
				"guardrail: the grant's use was consumed but its allow could not be recorded; the rule remains ENFORCED")
		}
	}
	for _, report := range tc.DegradedAllows {
		degraded := audit.Record{
			TS:         report.TS,
			SessionID:  tc.SessionID,
			Plane:      tc.Plane,
			Tool:       report.Tool,
			NativeTool: report.Tool,
			Event:      "pre",
			Decision:   "allow",
			Transport:  "plugin-degraded",
			Reason:     "engine unreachable; degraded allow reported by adapter",
		}
		if err := audit.Write(degraded, audit.DefaultPath(merged.Slots.AuditLog)); err != nil {
			highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: degraded-allow audit write failed (%v)", err))
		}
	}
	stderrWarnings := append(append([]string{}, highPriorityWarnings...), mergeWarnings...)
	adapter.EmitModelWarnings(stderrWarnings, stderr)
	return emitVerdict(plane, antigravityPhase, tc, v, stdout, stderr)
}

func emitVerdict(plane, antigravityPhase string, tc engine.ToolCall, v policy.Verdict, stdout, stderr io.Writer) int {
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

type codexHookMetadata struct {
	HandlerID   string
	HandlerHash string
}

func parseCodexHookMetadata(args []string) (codexHookMetadata, error) {
	meta := codexHookMetadata{HandlerID: "unavailable", HandlerHash: "unavailable"}
	if len(args) == 0 {
		return meta, nil
	}
	if len(args) != 4 || args[0] != "--handler-id" || args[2] != "--handler-hash" {
		return meta, errors.New("Codex hook metadata must be --handler-id <id> --handler-hash <sha256>")
	}
	validID := args[1] == "guardrail-codex-PreToolUse" || args[1] == "guardrail-codex-PostToolUse" || args[1] == "guardrail-codex-SessionStart"
	encoded := strings.TrimPrefix(args[3], "sha256:")
	decoded, hashErr := hex.DecodeString(encoded)
	if !validID || !strings.HasPrefix(args[3], "sha256:") || hashErr != nil || len(decoded) != sha256.Size {
		return meta, errors.New("Codex hook metadata has an invalid handler identity or hash")
	}
	return codexHookMetadata{HandlerID: args[1], HandlerHash: args[3]}, nil
}

func emitCodexHookDiagnostic(stderr io.Writer, meta codexHookMetadata, tc engine.ToolCall, exitCode int, rawStderr string) {
	class := "handler"
	if strings.Contains(rawStderr, "guardrail: policy denial:") {
		class = "policy"
	}
	record := struct {
		Kind                    string `json:"kind"`
		Class                   string `json:"class"`
		DeclaredTool            string `json:"declared_tool"`
		NormalizedIdentity      string `json:"normalized_identity"`
		MatchedContractIdentity string `json:"matched_contract_identity"`
		HandlerID               string `json:"handler_id"`
		HandlerHash             string `json:"handler_hash"`
		TrustHash               string `json:"trust_hash"`
		Session                 string `json:"session"`
		ExitCode                int    `json:"exit_code"`
		Stderr                  string `json:"stderr"`
	}{
		Kind:                    "codex-hook-diagnostic",
		Class:                   class,
		DeclaredTool:            boundedCodexDiagnosticValue(tc.NativeTool, 256),
		NormalizedIdentity:      boundedCodexDiagnosticValue(tc.Tool, 256),
		MatchedContractIdentity: boundedCodexDiagnosticValue(tc.ContractTool, 256),
		HandlerID:               meta.HandlerID,
		HandlerHash:             meta.HandlerHash,
		TrustHash:               "doctor-reconciliation-required",
		Session:                 boundedCodexDiagnosticValue(tc.SessionID, 256),
		ExitCode:                exitCode,
		Stderr:                  boundedCodexDiagnosticValue(rawStderr, 2048),
	}
	raw, _ := json.Marshal(record)
	fmt.Fprintf(stderr, "guardrail: hook diagnostic: %s\n", raw)
}

func boundedCodexDiagnosticValue(value string, limit int) string {
	clean := []rune(safetext.SingleLine(value))
	if len(clean) <= limit {
		return string(clean)
	}
	return string(clean[:limit]) + "…"
}

// claudeCoveragePosture is the advisory line for bundle coverage drift:
// present only when the installed Claude Code exposes tools the contract
// does not know (allow-by-default), empty in steady state, and empty on
// any error — the posture never blocks a session. The scan is cached per
// bundle version, so only the first session after a bump pays for it.
func claudeCoveragePosture() string {
	contracted, _ := claudeContracted()
	d, err := coverage.ClaudeDrift(contracted, version)
	if err != nil || len(d.Uncontracted) == 0 {
		return ""
	}
	return adapter.CoverageDriftLine("claude", "Claude Code "+d.Version, d.Uncontracted)
}

// claudePlanePosture reads the plane's lifecycle state the same way doctor
// and plane status do; read-only, never an approval.
func claudePlanePosture() string {
	unmarked := 0
	if home, err := os.UserHomeDir(); err == nil {
		if doc, err := genconfig.ReadJSONObject(filepath.Join(home, ".claude", "settings.json")); err == nil {
			unmarked = genconfig.CountUnmarkedGuardrailGroups(doc)
		}
	}
	return adapter.PlaneLifecycleLine("claude", claudeSettingsState(), unmarked)
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
