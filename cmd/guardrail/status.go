package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// StatusReport is the machine-readable output of `guardrail status --json`.
type StatusReport struct {
	Proven         bool        `json:"proven"`
	DoctorProblems int         `json:"doctor_problems"`
	Verdict        string      `json:"verdict"`
	Proof          ProofRecord `json:"proof"`
}

// cmdStatus prints the unified enforcement proof state per plane (one line
// each) plus the doctor verdict line, exiting 0 when proven and healthy, 1
// when anything is unproven or doctor finds problems, and 2 on a usage error (#110).
func cmdStatus(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	for _, arg := range args {
		switch arg {
		case "--json":
			asJSON = true
		default:
			fmt.Fprintf(stderr, "guardrail: status: unknown argument %q\n", safetext.SingleLine(arg))
			return 2
		}
	}

	proof := computeProof(version, nil)
	docCode, docProblems := printDoctor(io.Discard, io.Discard)
	verdict := doctorVerdictLine(docProblems)
	if docCode > 1 {
		docProblems++
		verdict = doctorVerdictLine(docProblems)
	}

	// Best-effort refresh of proof.json so subsequent SessionStart checks share
	// the freshly observed hashes and coverage without overwriting a missing
	// selftest pass.
	_ = saveProofRecord(proof)

	overallProven := proof.SelftestPassedAt != "" && docCode <= 1 && docProblems == 0
	for _, plane := range supportedPlanes {
		pp := proof.Planes[plane]
		if pp.Present && !pp.Proven {
			overallProven = false
		}
	}

	if asJSON {
		report := StatusReport{
			Proven:         overallProven,
			DoctorProblems: docProblems,
			Verdict:        verdict,
			Proof:          proof,
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: status: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(raw))
		if overallProven {
			return 0
		}
		return 1
	}

	if proof.SelftestPassedAt != "" {
		fmt.Fprintf(stdout, "guardrail %s  selftest: passed (%s)\n", version, proof.SelftestPassedAt)
	} else {
		fmt.Fprintf(stdout, "guardrail %s  selftest: not passed\n", version)
	}
	for _, plane := range supportedPlanes {
		pp := proof.Planes[plane]
		fmt.Fprintln(stdout, formatPlaneStatusLine(plane, pp))
	}
	fmt.Fprintln(stdout, verdict)

	if overallProven {
		return 0
	}
	return 1
}

func formatPlaneStatusLine(plane string, pp PlaneProof) string {
	if !pp.Present {
		return plane + ": absent"
	}
	if pp.Proven {
		parts := []string{"registered"}
		if plane == "codex" || plane == "claude" {
			parts = append(parts, "floor current")
		}
		if pp.RuntimeVersion != "" {
			parts = append(parts, pp.RuntimeVersion+", coverage current")
		}
		return fmt.Sprintf("%s: proven (%s)", plane, strings.Join(parts, ", "))
	}
	detail := strings.Join(pp.Reasons, "; ")
	if detail == "" {
		detail = safetext.SingleLine(pp.LifecycleState)
	}
	if pp.RuntimeVersion != "" {
		detail = pp.RuntimeVersion + "; " + detail
	}
	return fmt.Sprintf("%s: unproven (%s)", plane, detail)
}
