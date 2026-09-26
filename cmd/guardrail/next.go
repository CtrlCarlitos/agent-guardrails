package main

import (
	"fmt"
	"io"
	"slices"
)

// `guardrail next` is the operator's checklist after an install or an update
// (#364): the ordered steps that are still theirs to take, computed from the
// current state, and nothing when nothing applies. It only advises. It never
// changes a file, never opens an approval, and exits 0 whatever it finds, so
// it is safe to run from an installer, an update and a provisioning script.
//
// It shares setupEnableReason with `setup` and `plane enable`, so the three
// can never disagree about whether a plane needs work.

// nextSteps returns the steps in the order to take them, or none.
func nextSteps() ([]string, error) {
	enrolled := operatorEnrolled()
	var steps, needWork []string
	for _, plane := range supportedPlanes {
		if !planeInstalled(plane) {
			continue
		}
		reason, err := setupEnableReason(plane)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", plane, err)
		}
		if reason == "" {
			continue
		}
		needWork = append(needWork, plane)
		if enrolled {
			steps = append(steps, fmt.Sprintf("%s: %s. Run `guardrail plane enable %s` from an interactive terminal and approve it with your passkey.", plane, reason, plane))
			continue
		}
		steps = append(steps, fmt.Sprintf("%s: %s. Run `guardrail setup`: with no operator enrolled it arms the plane without an approval.", plane, reason))
	}
	if !enrolled && anyPlaneInstalled() {
		steps = append(steps, "No operator authenticator is enrolled. Run `guardrail operator enroll` from a real terminal so every later plane change needs your passkey.")
	}
	if len(needWork) > 0 {
		steps = append(steps, "Restart the agents you wired so they load the new hooks.")
		if slices.Contains(needWork, "codex") {
			steps = append(steps, "For Codex, run /hooks inside Codex to review and trust the generated hooks.")
		}
	}
	return steps, nil
}

func anyPlaneInstalled() bool {
	for _, plane := range supportedPlanes {
		if planeInstalled(plane) {
			return true
		}
	}
	return false
}

// printNextSteps writes the block, or nothing for no steps, so the block keeps
// its meaning: when it appears, something is owed.
func printNextSteps(stdout io.Writer, steps []string) {
	if len(steps) == 0 {
		return
	}
	fmt.Fprintln(stdout, "next steps:")
	for i, step := range steps {
		fmt.Fprintf(stdout, "  %d. %s\n", i+1, step)
	}
}

func cmdNext(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "guardrail: next takes no arguments")
		return 2
	}
	steps, err := nextSteps()
	if err != nil {
		// Advice must not fail the caller: an installer or an update ends with
		// this, and a state it cannot read is not a reason to fail them.
		fmt.Fprintf(stderr, "guardrail: next: could not work out the next steps: %v\n", err)
		return 0
	}
	printNextSteps(stdout, steps)
	return 0
}

// updateRunEnv marks the verification runs (`doctor`, `selftest`, `next`) that
// `update` starts on the binary it just installed. The updater prints the
// next-steps block itself, last, so a marked `doctor` does not print it too.
// An updater older than `next` never sets it, which is the point: its `doctor`
// is the only place the block can appear (#374).
const updateRunEnv = "GUARDRAIL_UPDATE_RUN"
