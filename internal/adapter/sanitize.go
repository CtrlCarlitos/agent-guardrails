package adapter

import (
	"fmt"
	"io"
	"regexp"

	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const maxModelFacingRunes = 200
const maxModelFacingWarnings = 20

var waiverIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func sanitizeForModel(s string) string {
	out := safetext.SingleLine(s)
	if r := []rune(out); len(r) > maxModelFacingRunes {
		out = string(r[:maxModelFacingRunes]) + "…"
	}
	return out
}

func sanitizeWaiverIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if waiverIDPattern.MatchString(id) {
			out = append(out, id)
		}
	}
	return out
}

func sanitizeWarnings(warnings []string) []string {
	if len(warnings) > maxModelFacingWarnings {
		warnings = warnings[:maxModelFacingWarnings]
	}
	out := make([]string, len(warnings))
	for i, warning := range warnings {
		out[i] = sanitizeForModel(warning)
	}
	return out
}

// EmitModelWarnings writes bounded, sanitized warnings to a model-visible stream.
func EmitModelWarnings(warnings []string, stderr io.Writer) {
	for _, warning := range sanitizeWarnings(warnings) {
		fmt.Fprintln(stderr, warning)
	}
}
