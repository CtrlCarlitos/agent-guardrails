package adapter

import (
	"regexp"
	"strings"
)

const maxModelFacingRunes = 200

var waiverIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// sanitizeForModel makes attacker-influenced text safe to place in a channel
// the model reads. Control characters are stripped so a crafted path cannot
// forge additional "guardrail:" lines, and the result is truncated so it
// cannot flood the context window.
func sanitizeForModel(s string) string {
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

func sanitizeWaiverIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if waiverIDPattern.MatchString(id) {
			out = append(out, id)
		}
	}
	return out
}
