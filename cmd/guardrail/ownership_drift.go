package main

import (
	"fmt"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// doctor's view of the ownership manifest (#278 finding c, ADR-0028).
//
// Kept in its own file so the reporting has one owner and lands clear of the
// other work in doctor.go, which gains a single call.

// printOwnershipDrift reports, per installed plane, whether the settings file
// still matches what guardrail recorded writing.
//
// Only planes that are actually installed are reported: a plane the operator
// does not use has nothing to drift, and a line per absent plane is how this
// section becomes noise.
func printOwnershipDrift(stdout io.Writer) int {
	problems := 0
	for _, plane := range []string{"claude", "opencode", "codex", "antigravity"} {
		if !planeInstalled(plane) {
			continue
		}
		path, err := planeConfigPath(plane)
		if err != nil {
			continue
		}
		report, err := genconfig.DriftFor(plane, path)
		if err != nil {
			continue
		}
		fmt.Fprintln(stdout, genconfig.DriftLine(plane, report))
		// Drift is a problem; "no manifest" is not knowledge of one (#105).
		if !report.NoManifest && !report.Clean() {
			problems++
		}
	}
	return problems
}
