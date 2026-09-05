package adapter

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

const maxModelFacingRunes = 200
const maxModelFacingWarnings = 20

var waiverIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// SanitizeForDisplay makes attacker-influenced text safe to place in a
// human- or model-facing channel. Control characters are stripped so a crafted
// path cannot forge additional status lines.
func SanitizeForDisplay(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func sanitizeForModel(s string) string {
	out := SanitizeForDisplay(s)
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
