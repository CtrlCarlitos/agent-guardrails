package main

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// Setup gate seams, overridable in tests so no test runs the real doctor or
// selftest. The doctor and selftest defaults are assigned in init: both reach
// run, which dispatches to cmdSetup, so a static initializer would form an
// initialization cycle.
var (
	setupAgyPresent     = func() bool { _, err := exec.LookPath("agy"); return err == nil }
	setupDoctorCoverage func(stdout, stderr io.Writer) int
	setupSelftest       func(stdout, stderr io.Writer) int
	// setupShutdownDaemon stops a running approval daemon. The daemon applies
	// approved plane actions in its own process, and it was spawned from
	// whichever binary first needed it — possibly one this install replaced.
	// Same function update uses; a not-running error is expected and ignored.
	setupShutdownDaemon = approval.ShutdownDaemon
)

func init() {
	setupDoctorCoverage = func(stdout, stderr io.Writer) int {
		return cmdDoctor([]string{"--coverage", "antigravity"}, stdout, stderr)
	}
	setupSelftest = func(stdout, stderr io.Writer) int { return cmdSelftest(nil, stdout, stderr) }
}

// cmdSetup is the install-time reconcile entrypoint: it registers Guardrail
// integration for the target planes (operator approval), then verifies and
// selftests. It parses arguments, refuses non-terminal and staging paths,
// prints the registered path, then hands off to setupReconcile.
func cmdSetup(args []string, terminal bool, stdout, stderr io.Writer) int {
	// With no operator enrolled, an enable is a bootstrap (ADR-0030): it
	// hosts no approval ceremony, so it needs no terminal. Every other run
	// keeps the gate — disable always, and enable once a passkey exists.
	bootstrap := !setupWantsDisable(args) && !operatorEnrolled()
	if !terminal && !bootstrap {
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

// setupReconcile dispatches on the requested state.
func setupReconcile(planes []string, state string, stdout, stderr io.Writer) int {
	if state == "enabled" {
		return setupEnable(planes, stdout, stderr)
	}
	return setupDisable(planes, stdout, stderr)
}

// setupEnable reconciles every detected target plane against this binary,
// approves the whole batch once, then gates on coverage and selftest.
func setupEnable(planes []string, stdout, stderr io.Writer) int {
	var batch []string
	for _, plane := range planes {
		if !planeInstalled(plane) {
			fmt.Fprintf(stdout, "%s: not detected\n", plane)
			continue
		}
		reason, err := setupEnableReason(plane)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: setup: %s: %v\n", plane, err)
			return 1
		}
		if reason == "" {
			fmt.Fprintf(stdout, "%s: already enabled\n", plane)
			continue
		}
		fmt.Fprintf(stdout, "%s: %s\n", plane, reason)
		batch = append(batch, plane)
	}
	bootstrap := len(batch) > 0 && !operatorEnrolled()
	if len(batch) > 0 {
		if bootstrap {
			// First install: no passkey exists, so arm without an approval
			// (ADR-0030). Enable only; everything that loosens still needs
			// an enrolled operator.
			if err := bootstrapPlanes("setup", batch, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "guardrail: setup: %v\n", err)
				return 1
			}
		} else {
			setupStopApprovalDaemon()
			if !planesViaApproval(batch, "plane-enable", "enabled", stdout, stderr) {
				return 1
			}
		}
		// Approval says the daemon ran the merge, not that this binary's
		// shape landed: verify convergence with the same rule that chose
		// the batch. The bootstrap merged in-process; the same check keeps
		// both paths honest.
		for _, plane := range batch {
			reason, err := setupEnableReason(plane)
			if err != nil {
				fmt.Fprintf(stderr, "guardrail: setup: %s: %v\n", plane, err)
				return 1
			}
			if reason != "" {
				fmt.Fprintf(stderr, "guardrail: setup: %s: still differs after approval — the approval daemon may be running another binary; run guardrail setup again\n", plane)
				return 1
			}
		}
	}
	if code := setupGates(stdout, stderr); code != 0 {
		return code
	}
	setupPrintStatus(planes, stdout)
	if bootstrap {
		printBootstrapInstruction("setup", batch, stdout)
	}
	return 0
}

// setupWantsDisable reports whether argv asks for --state disabled. It is
// consulted before the full parse, only to decide the terminal gate; the
// parse below still validates every flag.
func setupWantsDisable(args []string) bool {
	for i, arg := range args {
		if arg == "--state=disabled" || arg == "--state" && i+1 < len(args) && args[i+1] == "disabled" {
			return true
		}
	}
	return false
}

// setupEnableReason says why an installed plane needs (re-)enabling, or ""
// when it is already consistent with this binary. The order matters:
// planeHandlerDrift is only meaningful once the integration is registered.
func setupEnableReason(plane string) (string, error) {
	if !planeIntegrationRegistered(plane) {
		return "not registered; enabling", nil
	}
	if missing := planeFloorDrift(plane); missing > 0 {
		return fmt.Sprintf("permissions floor drifted (%d entries missing); re-enabling", missing), nil
	}
	report, err := planeOwnershipDrift(plane)
	if err != nil {
		return "", err
	}
	if len(report.Missing) > 0 || len(report.Stale) > 0 {
		var conditions []string
		if n := len(report.Missing); n > 0 {
			conditions = append(conditions, fmt.Sprintf("%d missing", n))
		}
		if n := len(report.Stale); n > 0 {
			conditions = append(conditions, fmt.Sprintf("%d stale", n))
		}
		return fmt.Sprintf("ownership manifest drifted (%s); re-enabling", strings.Join(conditions, ", ")), nil
	}
	drifted, err := planeHandlerDrift(plane)
	if err != nil {
		return "", err
	}
	if drifted {
		return "registered handlers differ from this binary; re-enabling", nil
	}
	return "", nil
}

func planeOwnershipDrift(plane string) (genconfig.DriftReport, error) {
	path, err := planeConfigPath(plane)
	if err != nil {
		return genconfig.DriftReport{}, err
	}
	return genconfig.DriftFor(plane, path)
}

// setupDisable removes every registered target plane's integration, approves
// the whole batch once, and skips the coverage and selftest gates entirely:
// disabling this binary's hooks is not a reason to verify them.
func setupDisable(planes []string, stdout, stderr io.Writer) int {
	var batch []string
	for _, plane := range planes {
		switch {
		case planeInstalled(plane) && planeIntegrationRegistered(plane):
			fmt.Fprintf(stdout, "%s: registered; disabling\n", plane)
			batch = append(batch, plane)
		case planeInstalled(plane):
			fmt.Fprintf(stdout, "%s: already disabled\n", plane)
		default:
			fmt.Fprintf(stdout, "%s: not detected\n", plane)
		}
	}
	if len(batch) > 0 {
		if !requireOperatorEnrolled("guardrail setup --state disabled", stderr) {
			return exitNotEnrolled
		}
		if !planesViaApproval(batch, "plane-disable", "disabled", stdout, stderr) {
			return 1
		}
	}
	// Nothing left needs the daemon; stopping it releases this binary so an
	// uninstall can delete it (Windows cannot delete a running image).
	setupStopApprovalDaemon()
	setupPrintStatus(planes, stdout)
	return 0
}

// setupStopApprovalDaemon asks a running approval daemon to exit and waits
// briefly until it stops answering, so the next submit spawns a daemon from
// this binary instead of reaching the one that is closing. The daemon closes
// asynchronously after acknowledging shutdown.
func setupStopApprovalDaemon() {
	socket := approval.DefaultSocketPath()
	if err := setupShutdownDaemon(socket); err != nil {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := approval.ListPending(socket); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// setupGates runs the antigravity coverage gate (when agy is on PATH) and
// then the selftest against this binary.
func setupGates(stdout, stderr io.Writer) int {
	if setupAgyPresent() {
		if code := setupDoctorCoverage(stdout, stderr); code != 0 {
			fmt.Fprintf(stderr, "guardrail: setup: doctor --coverage antigravity failed (exit %d)\n", code)
			return 1
		}
	}
	if code := setupSelftest(stdout, stderr); code != 0 {
		fmt.Fprintln(stderr, "guardrail: setup: selftest failed on this binary; investigate before continuing")
		return 1
	}
	return 0
}

// setupPrintStatus ends the run with the per-plane status block.
func setupPrintStatus(planes []string, stdout io.Writer) {
	fmt.Fprintln(stdout, "setup: plane status")
	for _, plane := range planes {
		fmt.Fprintf(stdout, "%s: %s\n", plane, planeStatusState(plane))
	}
}
