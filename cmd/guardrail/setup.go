package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// cmdSetup is the install-time reconcile entrypoint: it registers Guardrail
// integration for the target planes (operator approval), then verifies and
// selftests. This task only builds argument parsing, the terminal and
// staging-path refusals, and the header line; setupReconcile is a stub that
// Task 3 replaces with the real enable/verify/selftest flow.
func cmdSetup(args []string, terminal bool, stdout, stderr io.Writer) int {
	if !terminal {
		fmt.Fprintln(stderr, "guardrail: setup requires an interactive local terminal (run it from your shell, not from an agent or CI)")
		return 2
	}

	state := "enabled"
	var planes []string
	planesSet := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--state" && i+1 < len(args):
			i++
			state = args[i]
		case strings.HasPrefix(arg, "--state="):
			state = strings.TrimPrefix(arg, "--state=")
		case arg == "--planes" && i+1 < len(args):
			i++
			planes = strings.Split(args[i], ",")
			planesSet = true
		case strings.HasPrefix(arg, "--planes="):
			planes = strings.Split(strings.TrimPrefix(arg, "--planes="), ",")
			planesSet = true
		default:
			fmt.Fprintf(stderr, "guardrail: setup: unknown flag %q\n", arg)
			return 2
		}
	}

	if state != "enabled" && state != "disabled" {
		fmt.Fprintln(stderr, "guardrail: setup --state must be enabled or disabled")
		return 2
	}

	if planesSet {
		for _, plane := range planes {
			if !isSupportedPlane(plane) {
				fmt.Fprintf(stderr, "guardrail: setup --planes: unsupported plane %q\n", plane)
				return 2
			}
		}
	} else {
		planes = append([]string(nil), supportedPlanes...)
	}

	exe, err := installedExecutable()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: setup: cannot locate running binary: %v\n", err)
		return 1
	}
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	base := filepath.Base(exe)
	if base == ".guardrail-update" || strings.HasSuffix(base, ".old") {
		fmt.Fprintf(stderr, "guardrail: setup refuses to register a staging or superseded binary path: %s\n", exe)
		return 2
	}

	fmt.Fprintf(stdout, "setup: registering %s\n", exe)

	return setupReconcile(planes, state, stdout, stderr)
}

// setupReconcile is a stub for this task: it reports every target plane
// planeInstalled rejects and does nothing else. Task 3 replaces this with
// the real enable/verify/selftest reconcile.
func setupReconcile(planes []string, state string, stdout, stderr io.Writer) int {
	for _, plane := range planes {
		if !planeInstalled(plane) {
			fmt.Fprintf(stdout, "%s: not detected\n", plane)
		}
	}
	return 0
}
