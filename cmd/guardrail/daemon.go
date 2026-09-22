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
			base, err := policy.LoadBase()
			if err != nil {
				return policy.Verdict{}, fmt.Errorf("load base policy: %w", err)
			}
			var ov *policy.Overlay
			if pth, ok, _ := policy.FindOverlayPath(tc.CWD); ok {
				ov, _ = policy.LoadOverlay(pth)
			}
			op, _ := policy.LoadOperatorConfig()
			merged, _, err := policy.Merge(base, ov, version, op, tc.RepoRoot)
			if err != nil {
				return policy.Verdict{}, fmt.Errorf("merge policy: %w", err)
			}

			v := engine.Evaluate(tc, merged)
			if v.Decision == policy.Allow {
				if rv := recipe.Check(tc); rv != nil {
					v = *rv
				}
			}

			// Record audit with transport tag per ADR-0025 controller review
			rec := auditRecord(tc, v, policy.SortedWaivers(merged))
			rec.Transport = "named-pipe-daemon"
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
