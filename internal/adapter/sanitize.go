package adapter

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

const maxModelFacingRunes = 200
const maxModelFacingWarnings = 20

var waiverIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// SanitizeForDisplay makes attacker-influenced text safe to place in a
// human- or model-facing channel. Control characters are stripped so a crafted
// path cannot forge additional status lines, and the result is truncated.
func SanitizeForDisplay(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if r := []rune(out); len(r) > maxModelFacingRunes {
		out = string(r[:maxModelFacingRunes]) + "…"
	}
	return out
}

func sanitizeForModel(s string) string {
	return SanitizeForDisplay(s)
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
