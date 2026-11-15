package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/daemon"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

func cmdDaemon(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail daemon needs a subcommand: start | stop | status")
		return 2
	}

	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
		fs.SetOutput(stderr)
		endpoint := fs.String("endpoint", "", "custom named pipe / socket endpoint")
		idle := fs.Duration("idle", 30*time.Minute, "idle timeout before automatic shutdown")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}

		binPath, _ := os.Executable()
		evaluator := func(tc engine.ToolCall) (policy.Verdict, error) {
			started := time.Now()
			base, err := policy.LoadBase()
			if err != nil {
				return policy.Verdict{}, fmt.Errorf("load base policy: %w", err)
			}
			// The daemon answers only when it would reach the in-process
			// verdict (#151). A policy layer it cannot load is declined, so
			// the hook evaluates in-process and the agent sees that path's
			// fail-closed deny or warning instead of a quiet allow that
			// dropped the layer.
			var ov *policy.Overlay
			pth, ok, warn := policy.FindOverlayPath(tc.CWD)
			if warn != "" {
				return policy.Verdict{}, errors.New("overlay lookup warned; declining to the in-process hook")
			}
			if ok {
				if ov, err = policy.LoadOverlay(pth); err != nil {
					return policy.Verdict{}, fmt.Errorf("load overlay: %w", err)
				}
			}
			op, err := policy.LoadOperatorConfig()
			if err != nil {
				return policy.Verdict{}, fmt.Errorf("load operator config: %w", err)
			}
			// Merge warnings name loosenings it refused (the stricter
			// direction) or waivers in force; the verdict is the same either
			// way, so they do not decline the call.
			merged, _, err := policy.Merge(base, ov, version, op, tc.RepoRoot)
			if err != nil {
				return policy.Verdict{}, fmt.Errorf("merge policy: %w", err)
			}

			v := engine.Evaluate(tc, merged)
			// P7 needs the session's state exactly as the in-process hook
			// keeps it: a transaction when the session is known, the
			// tracking-unavailable reading when it is not or the state
			// cannot be locked.
			if tc.Event == "pre" && engine.TrifectaTrackingEnabled(merged) {
				var esc *policy.Verdict
				stateErr := errors.New("no session")
				if tc.SessionID != "" {
					stateErr = sessionTransaction(tc.SessionID, func(st *session.State) error {
						esc = engine.ApplyTrifecta(v, tc, st, merged)
						return nil
					})
					if errors.Is(stateErr, session.ErrTransactionCommitted) {
						stateErr = nil
					}
				}
				if stateErr != nil {
					esc = engine.ApplyTrifecta(v, tc, nil, merged)
				}
				if esc != nil {
					v = *esc
				}
			}
			if v.Decision == policy.Allow {
				if rv := recipe.Check(tc, merged); rv != nil {
					v = *rv
				}
			}

			// Record audit with transport tag per ADR-0025 controller review
			rec := auditRecord(tc, v, policy.SortedWaivers(merged))
			rec.Transport = "named-pipe-daemon"
			stampHookLatency(&rec, started, false)
			_ = audit.Write(rec, audit.DefaultPath(merged.Slots.AuditLog))

			return v, nil
		}

		server, err := daemon.NewServer(daemon.ServerConfig{
			Endpoint:    *endpoint,
			Evaluator:   evaluator,
			IdleTimeout: *idle,
			BinaryPath:  binPath,
		})
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: cannot start daemon: %v\n", err)
			return 1
		}
		defer server.Close()

		ctx := context.Background()
		if err := server.Serve(ctx); err != nil && !errors.Is(err, daemon.ErrServerClosed) {
			return 1
		}
		return 0

	case "stop":
		fs := flag.NewFlagSet("daemon stop", flag.ContinueOnError)
		fs.SetOutput(stderr)
		endpoint := fs.String("endpoint", "", "custom named pipe / socket endpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}

		client, err := daemon.Dial(*endpoint)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: daemon not running: %v\n", err)
			return 1
		}
		defer client.Close()

		if err := client.Shutdown(); err != nil {
			fmt.Fprintf(stderr, "guardrail: daemon stop failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "guardrail daemon stopped")
		return 0

	case "status":
		fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
		fs.SetOutput(stderr)
		endpoint := fs.String("endpoint", "", "custom named pipe / socket endpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}

		client, err := daemon.Dial(*endpoint)
		if err != nil {
			fmt.Fprintf(stdout, "daemon: not running (%v)\n", err)
			return 1
		}
		defer client.Close()

		ver, err := client.Ping()
		if err != nil {
			fmt.Fprintf(stdout, "daemon: not running (%v)\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "daemon: running (version: %s)\n", ver)
		return 0

	default:
		fmt.Fprintf(stderr, "guardrail daemon: unknown subcommand %q\n", args[0])
		return 2
	}
}
