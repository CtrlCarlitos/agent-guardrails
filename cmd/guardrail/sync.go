package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func cmdSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	var flagOutput strings.Builder
	fs.SetOutput(&flagOutput)
	dir := fs.String("dir", ".", "repo directory to sync")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in hook commands")
	planesFlag := fs.String("planes", "claude,opencode,antigravity", "comma-separated planes to sync")
	if err := fs.Parse(args); err != nil {
		message := flagOutput.String()
		if message == "" {
			message = err.Error()
		}
		fmt.Fprintln(stderr, safetext.SingleLine(message))
		return 2
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: cannot resolve --dir: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	repoRoot := absDir
	if root, ok := policy.FindRepoRoot(absDir); ok {
		repoRoot = root
	}
	planes := strings.Split(*planesFlag, ",")
	resolvedBinary := *binary
	for _, p := range planes {
		if strings.TrimSpace(p) != "opencode" {
			continue
		}
		resolvedBinary, err = resolveBinaryPath(*binary)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: sync: cannot resolve --binary: %s\n", safetext.SingleLine(err.Error()))
			return 2
		}
		break
	}

	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: cannot load base policy: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}

	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(absDir); ok {
		if warn != "" {
			fmt.Fprintln(stderr, safetext.SingleLine(warn))
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: sync: cannot load overlay: %s\n", safetext.SingleLine(err.Error()))
			return 2
		}
	} else if warn != "" {
		fmt.Fprintln(stderr, safetext.SingleLine(warn))
	}

	op, opErr := policy.LoadOperatorConfig()
	if opErr != nil {
		fmt.Fprintf(stderr, "guardrail: operator config unreadable (%s); treating as empty\n", safetext.SingleLine(opErr.Error()))
	}
	merged, warnings, err := policy.Merge(base, ov, version, op, repoRoot)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: invalid overlay: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, safetext.SingleLine(w))
	}

	for _, p := range planes {
		plane := strings.TrimSpace(p)
		planeBinary := *binary
		if plane == "opencode" {
			planeBinary = resolvedBinary
		}
		syncPlane(plane, absDir, planeBinary, merged, stdout, stderr)
	}
	return 0
}

func syncPlane(plane, dir, binary string, merged *policy.Policy, stdout, stderr io.Writer) {
	switch plane {
	case "claude":
		target := filepath.Join(dir, ".claude", "settings.json")
		frag := genconfig.ClaudeConfig(merged, binary)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync claude failed: %s\n", safetext.SingleLine(err.Error()))
			return
		}
		fmt.Fprintf(stdout, "synced claude -> %s\n", safetext.SingleLine(target))

	case "opencode":
		pluginDir := filepath.Join(dir, ".guardrail")
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %s\n", safetext.SingleLine(err.Error()))
			return
		}
		pluginPath := filepath.Join(pluginDir, "guardrail.js")
		if err := os.WriteFile(pluginPath, genconfig.OpencodePluginFor(binary), 0o644); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %s\n", safetext.SingleLine(err.Error()))
			return
		}
		absPlugin, err := filepath.Abs(pluginPath)
		if err != nil {
			absPlugin = pluginPath
		}
		target := filepath.Join(dir, "opencode.json")
		frag := genconfig.OpencodeConfig(merged, absPlugin)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %s\n", safetext.SingleLine(err.Error()))
			return
		}
		fmt.Fprintf(stdout, "synced opencode -> %s\n", safetext.SingleLine(target))

	case "antigravity":
		target := filepath.Join(dir, ".agents", "hooks.json")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync antigravity failed: %s\n", safetext.SingleLine(err.Error()))
			return
		}
		frag := genconfig.AntigravityConfig(binary)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync antigravity failed: %s\n", safetext.SingleLine(err.Error()))
			return
		}
		fmt.Fprintf(stdout, "synced antigravity -> %s\n", safetext.SingleLine(target))

	default:
		fmt.Fprintf(stderr, "guardrail: sync: unknown plane %q, skipping\n", safetext.SingleLine(plane))
	}
}
