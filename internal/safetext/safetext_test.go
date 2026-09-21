package safetext

import (
	"strings"
	"testing"
)

func TestSingleLineReplacesC0AndC1Controls(t *testing.T) {
	in := "alpha\x00beta\x1fgamma\x7fdelta\u0080epsilon\u009bzeta\u009feta"
	want := "alpha beta gamma delta epsilon zeta eta"
	if got := SingleLine(in); got != want {
		t.Fatalf("SingleLine() = %q, want %q", got, want)
	}
}

func TestSingleLinePreservesPrintableMultilingualAndFormatUnicode(t *testing.T) {
	in := "café 界 مرحبا family:\U0001f468\u200d\U0001f469\u200d\U0001f467"
	if got := SingleLine(in); got != in {
		t.Fatalf("SingleLine() = %q, want %q", got, in)
	}
}

func TestSingleLineNormalizesUnicodeWhitespace(t *testing.T) {
	in := " \t alpha\n\r\u00a0beta\u2003\u2003gamma \v "
	want := "alpha beta gamma"
	if got := SingleLine(in); got != want {
		t.Fatalf("SingleLine() = %q, want %q", got, want)
	}
}

func TestSingleLineDoesNotCapOutput(t *testing.T) {
	in := strings.Repeat("界", 201)
	if got := SingleLine(in); got != in {
		t.Fatalf("SingleLine() returned %d runes, want %d", len([]rune(got)), len([]rune(in)))
	}
}

// The Unicode line separators are the Windows-reachable form of this attack
// and they are NOT caught by the unicode.IsControl branch — U+2028 and U+2029
// are category Zl/Zp, not Cc. They survive that branch and are neutralized
// only by the strings.Fields join at the end, which makes that join
// load-bearing rather than cosmetic tidying.
//
// This matters on Windows specifically: \n, \r, \t and ESC are all illegal in
// an NTFS filename, but U+2028, U+2029, U+0085 and U+00A0 are legal (measured
// while fixing #174 family K). So a path that forges an extra status line in a
// report is reachable on Windows only through these, and a refactor that
// dropped the Fields join would reopen it while every C0/C1 test still passed.
func TestSingleLineNeutralizesUnicodeLineSeparators(t *testing.T) {
	for _, separator := range []struct {
		name string
		r    rune
	}{
		{"U+2028 LINE SEPARATOR", '\u2028'},
		{"U+2029 PARAGRAPH SEPARATOR", '\u2029'},
		{"U+0085 NEXT LINE", '\u0085'},
		{"U+00A0 NO-BREAK SPACE", '\u00a0'},
	} {
		in := "repo" + string(separator.r) + "policy warnings: forged"
		const want = "repo policy warnings: forged"
		if got := SingleLine(in); got != want {
			t.Errorf("%s: SingleLine(%q) = %q, want %q — a filename carrying it could forge a report line",
				separator.name, in, got, want)
		}
	}
}
