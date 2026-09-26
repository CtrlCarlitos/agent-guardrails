package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// The loud-outage posture (ADR-0028).
//
// ADR-0028 retires the declarative floor on claude, opencode and antigravity
// and accepts that an Engine outage leaves those planes ungated. It also
// states the condition that makes the trade defensible: trading silent partial
// coverage for none is only an improvement if the signal is real.
//
// This is the signal. Claude Code silently no-ops a failed hook spawn (#151),
// so nothing in a session announces that enforcement stopped -- calls simply
// start succeeding. Two places can say otherwise: the SessionStart advisory,
// which is the one moment guardrail is guaranteed to be heard, and `doctor`,
// which the operator runs when something already looks wrong.
//
// Kept in its own file so both callers share one implementation, and so this
// lands clear of the codex-hooks work in doctor.go.

// engineSpawnBudget bounds the probe. SessionStart is on the critical path of
// starting work, so a hung probe must not become the outage it is looking for.
const engineSpawnBudget = 5 * time.Second

type engineHealth struct {
	reachable bool
	// detail carries the probe's error, already single-lined: it reaches a
	// model-facing advisory, and an error string is untrusted text.
	detail string
}

// probeEngineHealth judges one spawn attempt. Split from the spawn itself so
// the unreachable path is testable without breaking anything on the host.
func probeEngineHealth(spawn func() error) engineHealth {
	if err := spawn(); err != nil {
		return engineHealth{reachable: false, detail: safetext.SingleLine(err.Error())}
	}
	return engineHealth{reachable: true}
}

// currentEngineHealth probes whether this binary can still spawn itself --
// the exact cost and the exact failure mode every plane's hook pays per tool
// call (#132). A SessionStart that can spawn is a strong signal that the
// per-call hooks will too; one that cannot is a strong signal that they will
// not, and that the session is about to run unmediated.
//
// Inside a test binary it declines rather than spawns: re-exec would run the
// whole suite recursively (#58, the same rule the latency probe follows).
func currentEngineHealth() engineHealth {
	if flag.Lookup("test.v") != nil {
		return engineHealth{reachable: true}
	}
	return probeEngineHealth(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), engineSpawnBudget)
		defer cancel()
		// `version` writes no audit record, so probing costs nothing but time.
		return exec.CommandContext(ctx, os.Args[0], "version").Run()
	})
}

// engineHealthPosture is the SessionStart advisory. It is empty when the
// Engine is reachable.
//
// Silence on the healthy path is deliberate. A line every session is how an
// operator learns to skip this section, and the section has to be readable on
// the day it says something. doctor is where "reachable" gets stated
// positively, because there silence would be ambiguous.
func engineHealthPosture(h engineHealth) string {
	if h.reachable {
		return ""
	}
	return fmt.Sprintf(
		"GUARDRAIL IS NOT ENFORCING. The engine could not be started (%s), and this plane "+
			"does not fail closed when its hook cannot run — it silently proceeds. For the rest of "+
			"this session, tool calls are running UNGATED: destructive commands, secret-tier reads, "+
			"out-of-repo writes and self-config edits are all unchecked, and nothing is being "+
			"recorded in the audit log.\n\n"+
			"Do not rely on guardrail to stop anything while this holds. Treat every destructive or "+
			"outward-reaching action as if there were no guard: say what you are about to do and let "+
			"the operator decide, rather than proceeding autonomously as the posture above otherwise "+
			"instructs.\n\n"+
			"Tell the operator now, and ask them to run `guardrail doctor` and re-enable the "+
			"integration (`guardrail plane enable claude`) before continuing work that matters.",
		h.detail)
}

// engineHealthDoctorLine always says something: doctor is a diagnostic, and an
// operator reading it cannot tell "healthy" from "never checked" if the
// healthy case is silent.
func engineHealthDoctorLine(h engineHealth) string {
	if h.reachable {
		return "engine health: reachable (self-spawn ok)"
	}
	return fmt.Sprintf(
		"engine health: UNREACHABLE (%s) — hooks cannot evaluate, and planes that do not fail "+
			"closed are running ungated right now; re-enable the integration and re-run this check",
		h.detail)
}

// printEngineHealth returns 1 when the Engine is unreachable, else 0.
func printEngineHealth(stdout interface{ Write([]byte) (int, error) }) int {
	h := currentEngineHealth()
	fmt.Fprintln(stdout, engineHealthDoctorLine(h))
	if h.reachable {
		return 0
	}
	return 1
}
