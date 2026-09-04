package main

import (
	"fmt"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude)")
		return 2
	}
	if args[0] != "claude" {
		fmt.Fprintf(stderr, "guardrail: unsupported plane %q\n", args[0])
		return 2
	}

	tc, err := adapter.ParseClaude(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: unparseable hook payload (%v); failing closed\n", err)
		return 2
	}

	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy (%v); failing closed\n", err)
		return 2
	}

	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(tc.CWD); ok {
		if warn != "" {
			fmt.Fprintln(stderr, warn)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: cannot load overlay (%v); failing closed\n", err)
			return 2
		}
	} else if warn != "" {
		fmt.Fprintln(stderr, warn)
	}

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: invalid overlay (%v); failing closed\n", err)
		return 2
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, w)
	}

	if tc.Event == "session-start" {
		text := adapter.PostureText(policy.SortedWaivers(merged), warnings)
		return adapter.EmitClaudeSessionStart(text, stdout)
	}

	v := engine.Evaluate(tc, merged)

	if tc.Event == "pre" && tc.SessionID != "" && !merged.Waived["P7.trifecta"] {
		st, loadErr := session.Load(tc.SessionID)
		if loadErr != nil {
			fmt.Fprintf(stderr, "guardrail: session state read failed (%v)\n", loadErr)
		}
		isPrivate := engine.IsPrivateDataAccess(tc, merged)
		isNet := engine.IsNetworkAttempt(tc)
		if esc := engine.TrifectaVerdict(v, isPrivate, isNet, st); esc != nil {
			v = *esc
		}
		st.SawPrivateRead = st.SawPrivateRead || isPrivate
		st.SawNetworkCall = st.SawNetworkCall || isNet
		if err := session.Save(tc.SessionID, st); err != nil {
			fmt.Fprintf(stderr, "guardrail: session state write failed (%v)\n", err)
		}
	}

	rec := audit.Record{
		SessionID: tc.SessionID,
		Plane:     "claude",
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
		fmt.Fprintf(stderr, "guardrail: audit write failed (%v)\n", err)
	}

	return adapter.EmitClaude(v, tc.Event, stdout, stderr)
}
