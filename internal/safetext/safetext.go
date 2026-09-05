// Package safetext normalizes untrusted text for safe one-line output.
package safetext

import (
	"strings"
	"unicode"
)

// SingleLine replaces Unicode control characters and normalizes whitespace.
func SingleLine(s string) string {
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
